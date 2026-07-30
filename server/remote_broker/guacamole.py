from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from server.remote_broker.windows import RdpCredential


class GuacamoleError(RuntimeError):
    pass


def encrypt_json_auth(payload: dict, secret_key: bytes) -> str:
    """Sign and encrypt JSON exactly as guacamole-auth-json requires."""

    if len(secret_key) != 16:
        raise ValueError("Guacamole JSON auth requires a 128-bit key")
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    signed = hmac.new(secret_key, plaintext, hashlib.sha256).digest() + plaintext
    padder = padding.PKCS7(128).padder()
    padded = padder.update(signed) + padder.finalize()
    # The extension's documented wire format uses an all-zero IV and does not
    # prepend an IV to the ciphertext.
    encryptor = Cipher(algorithms.AES(secret_key), modes.CBC(bytes(16))).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def _client_identifier(connection_id: str, datasource: str = "json") -> str:
    raw = f"{connection_id}\x00c\x00{datasource}".encode()
    return base64.b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class GuacamoleTicket:
    redirect_url: str


class GuacamoleJsonAuthClient:
    def __init__(
        self,
        base_url: str,
        secret_key: bytes,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.secret_key = secret_key
        self.transport = transport

    async def create_ticket(
        self,
        session_id: str,
        credential: RdpCredential,
        lease_expires_at: datetime,
    ) -> GuacamoleTicket:
        connection_id = f"prewise-{session_id}"
        payload = {
            "username": f"prewise-{session_id}",
            "expires": int(lease_expires_at.timestamp() * 1000),
            "connections": {
                connection_id: {
                    "protocol": "rdp",
                    "parameters": {
                        "hostname": credential.hostname,
                        "port": "3389",
                        "username": credential.username,
                        "password": credential.password,
                        "security": "nla",
                        "ignore-cert": "true",
                        "disable-download": "true",
                        "disable-upload": "true",
                        "enable-drive": "false",
                        "enable-printing": "false",
                        "clipboard-encoding": "UTF-8",
                    },
                }
            },
        }
        encrypted = encrypt_json_auth(payload, self.secret_key)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(8, connect=3),
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"{self.base_url}/api/tokens",
                    data={"data": encrypted},
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise GuacamoleError("Guacamole is unavailable") from exc
        if response.status_code != 200:
            raise GuacamoleError("Guacamole rejected the ephemeral connection")
        try:
            token = str(response.json()["authToken"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GuacamoleError("Guacamole returned an invalid token response") from exc
        if not token:
            raise GuacamoleError("Guacamole returned an empty token")
        client_id = _client_identifier(connection_id)
        return GuacamoleTicket(
            redirect_url=f"{self.base_url}/#/client/{client_id}?token={quote(token, safe='')}"
        )
