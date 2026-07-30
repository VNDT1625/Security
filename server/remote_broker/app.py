from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.responses import RedirectResponse

from server.remote_broker.config import BrokerSettings
from server.remote_broker.guacamole import GuacamoleError, GuacamoleJsonAuthClient
from server.remote_broker.prewise import AuthorizationError, PrewiseAuthorizationClient
from server.remote_broker.windows import SsmEphemeralRdpManager, WindowsCredentialError

logger = logging.getLogger(__name__)
CAPABILITIES = ["lease_enforcement", "one_time_token_consume", "remote_desktop"]


def create_app(
    settings: BrokerSettings | None = None,
    *,
    authorization_client: PrewiseAuthorizationClient | None = None,
    credential_manager: SsmEphemeralRdpManager | None = None,
    guacamole_client: GuacamoleJsonAuthClient | None = None,
) -> FastAPI:
    config = settings or BrokerSettings.from_env()
    authorizer = authorization_client or PrewiseAuthorizationClient(
        config.prewise_api_url, config.broker_secret
    )
    credentials = credential_manager or SsmEphemeralRdpManager(
        config.aws_region, config.ssm_timeout_seconds
    )
    guacamole = guacamole_client or GuacamoleJsonAuthClient(
        config.guacamole_url, config.guacamole_json_secret_key
    )
    app = FastAPI(title="Prewise Remote Broker", docs_url=None, redoc_url=None)
    revoke_tasks: set[asyncio.Task] = set()

    async def revoke_at(instance_id: str, username: str, lease: datetime) -> None:
        delay = max(0, (lease - datetime.now(UTC)).total_seconds())
        await asyncio.sleep(delay)
        try:
            await credentials.revoke(instance_id, username)
        except Exception:
            # The in-guest scheduled task remains authoritative if this best-
            # effort broker cleanup is interrupted or SSM is briefly degraded.
            logger.exception("Lease cleanup failed for instance %s", instance_id)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "status": "ok",
            "ready": True,
            "protocolVersion": "1",
            "capabilities": CAPABILITIES,
        }

    @app.get("/connect/{session_id}/{instance_id}", response_class=RedirectResponse)
    async def connect(
        session_id: str = Path(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9-]+$"),
        instance_id: str = Path(pattern=r"^i-[0-9a-f]{8,17}$"),
        prewise_session: str = Query(min_length=1, max_length=36),
        prewise_access_token: str = Query(min_length=32, max_length=512),
    ) -> RedirectResponse:
        if not secrets.compare_digest(prewise_session, session_id):
            raise HTTPException(401, "Remote session binding is invalid")
        try:
            authorization = await authorizer.consume(session_id, prewise_access_token)
            if not secrets.compare_digest(
                authorization.provider_instance_id, instance_id
            ):
                raise AuthorizationError("Remote instance binding is invalid")
            credential = await credentials.create(
                instance_id, session_id, authorization.lease_expires_at
            )
            try:
                ticket = await guacamole.create_ticket(
                    session_id, credential, authorization.lease_expires_at
                )
            except Exception:
                await credentials.revoke(instance_id, credential.username)
                raise
        except AuthorizationError as exc:
            raise HTTPException(401, str(exc)) from exc
        except (WindowsCredentialError, GuacamoleError) as exc:
            raise HTTPException(503, str(exc)) from exc
        task = asyncio.create_task(
            revoke_at(instance_id, credential.username, authorization.lease_expires_at)
        )
        revoke_tasks.add(task)
        task.add_done_callback(revoke_tasks.discard)
        response = RedirectResponse(ticket.redirect_url, status_code=303)
        response.headers.update(
            {
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
        )
        return response

    return app
