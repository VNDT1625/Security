from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import httpx


class AuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemoteAuthorization:
    session_id: str
    user_id: str
    provider_instance_id: str
    lease_expires_at: datetime


class PrewiseAuthorizationClient:
    def __init__(
        self,
        base_url: str,
        broker_secret: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.broker_secret = broker_secret
        self.transport = transport

    async def consume(self, session_id: str, access_token: str) -> RemoteAuthorization:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(8, connect=3),
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"{self.base_url}/v1/sandbox-cloud/broker/remote-access/consume",
                    headers={
                        "X-Sandbox-Broker-Secret": self.broker_secret,
                        "Accept": "application/json",
                    },
                    json={"sessionId": session_id, "accessToken": access_token},
                )
        except httpx.HTTPError as exc:
            raise AuthorizationError("Prewise authorization service is unavailable") from exc
        if response.status_code != 200:
            raise AuthorizationError("Remote access credential was rejected")
        try:
            payload = response.json()
            expires = datetime.fromisoformat(str(payload["leaseExpiresAt"]).replace("Z", "+00:00"))
            authorization = RemoteAuthorization(
                session_id=str(payload["sessionId"]),
                user_id=str(payload["userId"]),
                provider_instance_id=str(payload["providerInstanceId"]),
                lease_expires_at=expires.astimezone(UTC),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationError("Prewise authorization response is invalid") from exc
        if (
            payload.get("authorized") is not True
            or payload.get("provider") != "aws"
            or authorization.session_id != session_id
            or authorization.lease_expires_at <= datetime.now(UTC)
        ):
            raise AuthorizationError("Remote authorization binding is invalid")
        return authorization
