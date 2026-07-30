from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _service_url(name: str, value: str) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if (
        parsed.scheme not in ({"http", "https"} if loopback else {"https"})
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} must be a credential-free HTTPS URL")
    return value.rstrip("/")


@dataclass(frozen=True)
class BrokerSettings:
    prewise_api_url: str
    broker_secret: str
    guacamole_url: str
    guacamole_json_secret_key: bytes
    aws_region: str
    ssm_timeout_seconds: int = 90

    @classmethod
    def from_env(cls) -> BrokerSettings:
        broker_secret = _required("SANDBOX_REMOTE_BROKER_SECRET")
        if len(broker_secret.encode("utf-8")) < 32:
            raise ValueError("SANDBOX_REMOTE_BROKER_SECRET must be at least 32 bytes")
        key_text = _required("GUACAMOLE_JSON_SECRET_KEY")
        try:
            key = bytes.fromhex(key_text)
        except ValueError as exc:
            raise ValueError("GUACAMOLE_JSON_SECRET_KEY must be hexadecimal") from exc
        if len(key) != 16:
            raise ValueError("GUACAMOLE_JSON_SECRET_KEY must encode exactly 16 bytes")
        timeout = int(os.getenv("BROKER_SSM_TIMEOUT_SECONDS", "90"))
        if not 15 <= timeout <= 180:
            raise ValueError("BROKER_SSM_TIMEOUT_SECONDS must be between 15 and 180")
        return cls(
            prewise_api_url=_service_url(
                "PREWISE_API_URL", _required("PREWISE_API_URL")
            ),
            broker_secret=broker_secret,
            guacamole_url=_service_url(
                "GUACAMOLE_URL", _required("GUACAMOLE_URL")
            ),
            guacamole_json_secret_key=key,
            aws_region=os.getenv("AWS_REGION", "ap-southeast-1").strip(),
            ssm_timeout_seconds=timeout,
        )
