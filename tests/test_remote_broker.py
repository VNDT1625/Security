from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.testclient import TestClient

from server.remote_broker.app import CAPABILITIES, create_app
from server.remote_broker.config import BrokerSettings
from server.remote_broker.guacamole import GuacamoleError, GuacamoleTicket, encrypt_json_auth
from server.remote_broker.prewise import RemoteAuthorization
from server.remote_broker.windows import RdpCredential, SsmEphemeralRdpManager


def _settings() -> BrokerSettings:
    return BrokerSettings(
        prewise_api_url="https://api.example.test",
        broker_secret="s" * 40,
        guacamole_url="https://remote.example.test/guacamole",
        guacamole_json_secret_key=b"k" * 16,
        aws_region="ap-southeast-1",
    )


class FakeAuthorizer:
    def __init__(self, *, instance_id: str = "i-0123456789abcdef0") -> None:
        self.instance_id = instance_id
        self.calls = []

    async def consume(self, session_id: str, token: str) -> RemoteAuthorization:
        self.calls.append((session_id, token))
        return RemoteAuthorization(
            session_id=session_id,
            user_id="user-1",
            provider_instance_id=self.instance_id,
            lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


class FakeCredentials:
    def __init__(self) -> None:
        self.created = []
        self.revoked = []

    async def create(self, instance_id, session_id, lease):
        self.created.append((instance_id, session_id, lease))
        return RdpCredential("10.0.1.2", "pw_session", "not-returned")

    async def revoke(self, instance_id, username):
        self.revoked.append((instance_id, username))


class FakeGuacamole:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = []

    async def create_ticket(self, session_id, credential, lease):
        self.calls.append((session_id, credential, lease))
        if self.fail:
            raise GuacamoleError("guacamole failed")
        return GuacamoleTicket("https://remote.example.test/guacamole/#/client/id?token=t")


def test_health_contract_matches_backend_preflight() -> None:
    app = create_app(
        _settings(),
        authorization_client=FakeAuthorizer(),
        credential_manager=FakeCredentials(),
        guacamole_client=FakeGuacamole(),
    )
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "ready": True,
        "protocolVersion": "1",
        "capabilities": CAPABILITIES,
    }


def test_connect_consumes_token_and_redirects_without_credentials() -> None:
    authorizer = FakeAuthorizer()
    credentials = FakeCredentials()
    guacamole = FakeGuacamole()
    app = create_app(
        _settings(),
        authorization_client=authorizer,
        credential_manager=credentials,
        guacamole_client=guacamole,
    )
    response = TestClient(app).get(
        "/connect/session-1/i-0123456789abcdef0",
        params={
            "prewise_session": "session-1",
            "prewise_access_token": "a" * 32,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith(
        "https://remote.example.test/guacamole/"
    )
    assert response.headers["cache-control"].startswith("no-store")
    assert response.headers["referrer-policy"] == "no-referrer"
    assert authorizer.calls == [("session-1", "a" * 32)]
    assert credentials.created[0][:2] == ("i-0123456789abcdef0", "session-1")
    assert "not-returned" not in response.text
    assert "not-returned" not in str(response.headers)


def test_connect_fails_before_consumption_on_path_session_mismatch() -> None:
    authorizer = FakeAuthorizer()
    app = create_app(
        _settings(),
        authorization_client=authorizer,
        credential_manager=FakeCredentials(),
        guacamole_client=FakeGuacamole(),
    )
    response = TestClient(app).get(
        "/connect/session-1/i-0123456789abcdef0",
        params={
            "prewise_session": "different",
            "prewise_access_token": "a" * 32,
        },
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert authorizer.calls == []


def test_connect_rejects_instance_substitution() -> None:
    credentials = FakeCredentials()
    app = create_app(
        _settings(),
        authorization_client=FakeAuthorizer(instance_id="i-0123456789abcdef0"),
        credential_manager=credentials,
        guacamole_client=FakeGuacamole(),
    )
    response = TestClient(app).get(
        "/connect/session-1/i-deadbeef",
        params={
            "prewise_session": "session-1",
            "prewise_access_token": "a" * 32,
        },
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert credentials.created == []


def test_guacamole_failure_revokes_new_windows_user() -> None:
    credentials = FakeCredentials()
    app = create_app(
        _settings(),
        authorization_client=FakeAuthorizer(),
        credential_manager=credentials,
        guacamole_client=FakeGuacamole(fail=True),
    )
    response = TestClient(app, raise_server_exceptions=False).get(
        "/connect/session-1/i-0123456789abcdef0",
        params={
            "prewise_session": "session-1",
            "prewise_access_token": "a" * 32,
        },
        follow_redirects=False,
    )
    assert response.status_code == 503
    assert credentials.revoked == [("i-0123456789abcdef0", "pw_session")]


def test_json_auth_encryption_round_trip_is_guacamole_compatible() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    original = {"username": "prewise", "expires": 1, "connections": {}}
    encrypted = base64.b64decode(encrypt_json_auth(original, key))
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    signed = unpadder.update(padded) + unpadder.finalize()
    signature, plaintext = signed[:32], signed[32:]
    assert signature == hmac.new(key, plaintext, hashlib.sha256).digest()
    assert json.loads(plaintext) == original


class FakeWaiter:
    def wait(self, **kwargs):
        self.kwargs = kwargs


class FakeSsm:
    def __init__(self) -> None:
        self.parameters = None
        self.waiter = FakeWaiter()

    def send_command(self, **kwargs):
        self.parameters = kwargs
        return {"Command": {"CommandId": "cmd-1"}}

    def get_waiter(self, name):
        assert name == "command_executed"
        return self.waiter

    def get_command_invocation(self, **kwargs):
        return {"Status": "Success", "StandardOutputContent": "READY\n"}


class FakeEc2:
    def describe_instances(self, **kwargs):
        return {
            "Reservations": [
                {"Instances": [{"PrivateDnsName": "ip-10-0-1-2.internal"}]}
            ]
        }


def test_ssm_credentials_install_in_guest_lease_cleanup_before_returning() -> None:
    ssm = FakeSsm()
    manager = SsmEphemeralRdpManager(
        "ap-southeast-1", ssm=ssm, ec2=FakeEc2()
    )
    import asyncio

    credential = asyncio.run(
        manager.create(
            "i-interactive",
            "abcdef12-3456-7890-abcd-ef1234567890",
            datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    assert credential.hostname == "ip-10-0-1-2.internal"
    command = ssm.parameters["Parameters"]["commands"][0]
    encoded = command.rsplit(" ", 1)[-1]
    script = base64.b64decode(encoded).decode("utf-16-le")
    assert "Register-ScheduledTask" in script
    assert "S-1-5-32-555" in script
    assert "Remove-LocalUser" in script
    assert credential.password not in command[: command.rfind(" ")]


def test_settings_rejects_weak_secret_and_non_https_public_url(monkeypatch) -> None:
    monkeypatch.setenv("SANDBOX_REMOTE_BROKER_SECRET", "short")
    monkeypatch.setenv("PREWISE_API_URL", "http://api.example.test")
    monkeypatch.setenv("GUACAMOLE_URL", "https://remote.example.test/guacamole")
    monkeypatch.setenv("GUACAMOLE_JSON_SECRET_KEY", "00" * 16)
    try:
        BrokerSettings.from_env()
    except ValueError as exc:
        assert "at least 32 bytes" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("weak secret accepted")
