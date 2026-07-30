"""Production authentication and abuse controls for Streamable HTTP MCP."""

from __future__ import annotations

import hmac
import re
import time
from collections import defaultdict, deque
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import select
from starlette.datastructures import Headers

from backend.config import settings
from backend.db import SessionLocal, initialize_database
from backend.models import ApiKey, AuditLog, OAuthTokenRecord, User
from backend.routers.auth import ActorContext, require_api_key_entitlement
from backend.security_utils import hash_api_key, hash_metadata, session_key, utcnow
from backend.services.quota_service import reserve_scan_quota


@dataclass(frozen=True)
class MCPIdentity:
    user_id: str | None
    api_key_id: str | None
    client_ip: str
    user_agent: str
    scopes: tuple[str, ...] = ()

    @property
    def authenticated(self) -> bool:
        return self.user_id is not None


current_mcp_identity: ContextVar[MCPIdentity | None] = ContextVar(
    "current_mcp_identity", default=None
)

_SAFE_AUDIT_ERROR_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")

# Public OAuth endpoints that still cost database writes or answer a credential
# probe, and therefore need an IP-keyed throttle even though they need no token.
_PUBLIC_THROTTLED_PATHS = frozenset(
    {"/register", "/authorize", "/token", "/revoke", "/oauth/consent"}
)


def authorize_mcp_tool(required_scope: str | None, *, external_share: bool = False) -> bool:
    """Apply tool-level least privilege for authenticated remote MCP calls.

    Local stdio has no HTTP identity and remains available to the local operator.
    ``mcp:invoke`` is retained as a compatibility umbrella for existing clients,
    except that external sample sharing always requires its dedicated scope.
    """
    identity = current_mcp_identity.get()
    granted = set(identity.scopes) if identity is not None else set()
    # Sending a user's sample to a third-party reputation provider is data
    # egress and always requires its dedicated scope, on every transport. This
    # check must precede the no-identity shortcut: otherwise any code path that
    # reaches a tool without the API-key middleware installed (a future ASGI
    # mount that forgets the wrapper) silently permits external sharing, with
    # quota and audit logging skipped as well.
    if external_share:
        return "mcp:file:share_external" in granted
    if identity is None:
        return True
    if required_scope is None:
        return True
    assessment_scopes = {
        "assess:url",
        "assess:content",
        "assess:prompt",
        "assess:file",
        "assess:action",
    }
    # Keys that already advertise granular assessment permissions are held to
    # them. A credential containing only mcp:invoke remains a legacy umbrella.
    if granted & assessment_scopes:
        return required_scope in granted
    return "mcp:invoke" in granted


def audit_mcp_tool_call(
    tool_name: str,
    result: dict[str, Any],
    *,
    elapsed_ms: float,
    quota_consumed: bool,
) -> None:
    """Persist one privacy-minimized audit event per authenticated tool call."""
    identity = current_mcp_identity.get()
    if identity is None or not identity.authenticated:
        return
    metadata: dict[str, Any] = {
        "tool": tool_name[:100],
        "ok": bool(result.get("ok", "error" not in result)),
        "elapsed_ms": round(max(0.0, elapsed_ms), 2),
        "quota_consumed": quota_consumed,
        "request_id": str(result.get("request_id", ""))[:64],
    }
    if result.get("verdict"):
        metadata["verdict"] = str(result["verdict"])[:32]
    if isinstance(result.get("risk_score"), (int, float)):
        metadata["risk_score"] = round(float(result["risk_score"]), 4)
    provider = result.get("provider")
    if isinstance(provider, dict):
        metadata["provider_status"] = str(provider.get("status", ""))[:32]
        metadata["sample_shared"] = bool(provider.get("sample_shared", False))
    if result.get("error"):
        # Error text may originate in a provider or user-derived validation
        # message. Persist only a machine-like code; never a prompt, owner ID,
        # URL or other free-form value.
        candidate = str(result["error"]).strip().lower()
        metadata["error"] = (
            candidate if _SAFE_AUDIT_ERROR_CODE.fullmatch(candidate) else "tool_error"
        )

    with SessionLocal() as db:
        db.add(
            AuditLog(
                actor_user_id=identity.user_id,
                actor_api_key_id=identity.api_key_id,
                actor_channel="mcp",
                action="mcp.tool.invoke",
                resource_type="mcp_tool",
                source_ip_hash=hash_metadata(identity.client_ip),
                user_agent_hash=hash_metadata(identity.user_agent),
                extra_metadata=metadata,
            )
        )
        db.commit()


def reserve_mcp_scan_quota() -> MCPIdentity | None:
    """Consume one plan scan for the authenticated MCP user."""
    identity = current_mcp_identity.get()
    if identity is None:
        return None
    with SessionLocal() as db:
        user = db.get(User, identity.user_id) if identity.user_id else None
        api_key = db.get(ApiKey, identity.api_key_id) if identity.api_key_id else None
        actor = ActorContext(
            user=user,
            api_key=api_key,
            channel="mcp",
            anonymous_id=None if user is not None else hash_metadata(identity.client_ip),
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/mcp",
                "headers": [(b"user-agent", identity.user_agent.encode("latin-1", "ignore"))],
                "client": (identity.client_ip, 0),
            }
        )
        reserve_scan_quota(db, actor, request)
    return identity


class MCPApiKeyMiddleware:
    """Authenticate every HTTP MCP request before it reaches the MCP protocol layer.

    Stdio remains local and does not pass through this middleware. Streamable HTTP
    requires a scoped API key in production. Anonymous HTTP can only be enabled
    explicitly for controlled demos.
    """

    def __init__(self, app: Any) -> None:
        self.app = app
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._last_prune = time.monotonic()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            initialize_database()
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # OAuth discovery, registration, authorization and token endpoints are
        # public: authentication is enforced only on the protected MCP resource.
        # They are not, however, free. /oauth/consent does an unauthenticated API
        # key lookup and answers 401/403/303, which is a credential-validation
        # oracle; /register and /authorize each write a database row per call.
        # Throttle them by source IP instead of waving them through.
        if path != "/mcp":
            if path in _PUBLIC_THROTTLED_PATHS:
                public_headers = Headers(scope=scope)
                public_ip = scope.get("client", ("unknown", 0))[0]
                if not self._consume(
                    f"public:{path}:{hash_metadata(public_ip)}",
                    settings.mcp_public_endpoint_rate_limit_per_min,
                ):
                    await self._reject(
                        send,
                        429,
                        "rate_limited",
                        public_headers.get("x-request-id", "")[:64],
                    )
                    return
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = headers.get("x-request-id", "")[:64]
        client_ip = scope.get("client", ("unknown", 0))[0]
        raw_key = self._bearer(headers.get("authorization", ""))

        if raw_key is None and settings.mcp_allow_anonymous:
            identity = f"anon:{hash_metadata(client_ip)}"
            if not self._consume(identity, settings.mcp_anonymous_rate_limit_per_min):
                await self._reject(send, 429, "rate_limited", request_id)
                return
            token = current_mcp_identity.set(
                MCPIdentity(
                    None,
                    None,
                    client_ip,
                    headers.get("user-agent", ""),
                    ("mcp:invoke",),
                )
            )
            try:
                await self.app(scope, receive, send)
            finally:
                current_mcp_identity.reset(token)
            return

        if raw_key is None:
            await self._reject(send, 401, "missing_api_key", request_id, authenticate=True)
            return

        with SessionLocal() as db:
            record = None
            oauth_token = None
            if raw_key.startswith("pw_live_"):
                record = db.execute(
                    select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_key))
                ).scalar_one_or_none()
            elif raw_key.startswith("pw_oauth_at_"):
                oauth_token = db.execute(
                    select(OAuthTokenRecord).where(
                        OAuthTokenRecord.access_token_hash == session_key(raw_key)
                    )
                ).scalar_one_or_none()
                if (
                    oauth_token is None
                    or oauth_token.revoked_at is not None
                    or oauth_token.access_expires_at <= utcnow()
                    or "mcp:invoke" not in (oauth_token.scopes or [])
                ):
                    oauth_token = None
            if oauth_token is not None:
                user = db.get(User, oauth_token.user_id)
                if user is None or user.status != "active":
                    await self._reject(send, 401, "invalid_access_token", request_id, authenticate=True)
                    return
                api_key_id = None
                user_id = user.id
                granted_scopes = tuple(oauth_token.scopes or [])
            else:
                user = None
            valid = (
                record is not None
                and record.status == "active"
                and record.revoked_at is None
                and (record.expires_at is None or record.expires_at > utcnow())
            )
            if oauth_token is None and (not valid or record is None):
                await self._reject(send, 401, "invalid_api_key", request_id, authenticate=True)
                return
            if oauth_token is not None:
                pass
            else:
                user = db.get(User, record.user_id)
            if user is None or user.status != "active":
                await self._reject(send, 401, "invalid_api_key", request_id, authenticate=True)
                return
            try:
                require_api_key_entitlement(db, user.id)
            except HTTPException:
                await self._reject(send, 403, "plan_entitlement_required:team", request_id)
                return
            if oauth_token is None and "mcp:invoke" not in (record.scopes or []):
                await self._reject(send, 403, "missing_scope:mcp:invoke", request_id)
                return
            identity = f"key:{record.id}" if oauth_token is None else f"oauth:{oauth_token.id}"
            if not self._consume(identity, settings.mcp_api_key_rate_limit_per_min):
                await self._reject(send, 429, "rate_limited", request_id)
                return

            if oauth_token is None:
                record.last_used_at = utcnow()
                db.add(
                AuditLog(
                    actor_user_id=user.id,
                    actor_api_key_id=record.id,
                    actor_channel="mcp",
                    action="mcp.invoke",
                    resource_type="mcp_session",
                    source_ip_hash=hash_metadata(client_ip),
                    user_agent_hash=hash_metadata(headers.get("user-agent")),
                    extra_metadata={"request_id": request_id, "path": scope.get("path", "/mcp")},
                    )
                )
                api_key_id = record.id
                user_id = user.id
                granted_scopes = tuple(record.scopes or [])
                db.commit()
            else:
                db.add(
                    AuditLog(
                        actor_user_id=user.id,
                        actor_channel="mcp",
                        action="mcp.invoke",
                        resource_type="oauth_session",
                        resource_id=oauth_token.id,
                        source_ip_hash=hash_metadata(client_ip),
                        user_agent_hash=hash_metadata(headers.get("user-agent")),
                        extra_metadata={"request_id": request_id, "client_id": oauth_token.client_id},
                    )
                )
                db.commit()

        scope.setdefault("state", {})["prewise_api_key_id"] = api_key_id
        scope["state"]["prewise_user_id"] = user_id
        token = current_mcp_identity.set(
            MCPIdentity(
                user_id,
                api_key_id,
                client_ip,
                headers.get("user-agent", ""),
                granted_scopes,
            )
        )
        try:
            await self.app(scope, receive, send)
        finally:
            current_mcp_identity.reset(token)

    @staticmethod
    def _bearer(value: str) -> str | None:
        scheme, separator, credential = value.partition(" ")
        if not separator or not hmac.compare_digest(scheme.lower(), "bearer"):
            return None
        credential = credential.strip()
        accepted = credential.startswith("pw_live_") or credential.startswith("pw_oauth_at_")
        return credential if accepted and len(credential) >= 40 else None

    def _consume(self, identity: str, limit: int) -> bool:
        now = time.monotonic()
        # Timestamps inside a bucket expire, but the bucket key never did, so a
        # keyed-by-source-IP limiter grew one permanent dict entry per source
        # address. Prune empty buckets on a slow cadence.
        if now - self._last_prune >= 60:
            for key, tracked in list(self._buckets.items()):
                while tracked and now - tracked[0] >= 60:
                    tracked.popleft()
                if not tracked:
                    self._buckets.pop(key, None)
            self._last_prune = now
        bucket = self._buckets[identity]
        while bucket and now - bucket[0] >= 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    @staticmethod
    async def _reject(
        send: Any,
        status: int,
        detail: str,
        request_id: str,
        *,
        authenticate: bool = False,
    ) -> None:
        import json

        body = json.dumps(
            {"error": "mcp_access_denied", "detail": detail, "request_id": request_id},
            separators=(",", ":"),
        ).encode()
        headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]
        if authenticate:
            metadata = settings.mcp_public_url.rstrip("/") + "/.well-known/oauth-protected-resource/mcp"
            headers.append(
                (b"www-authenticate", f'Bearer realm="prewise-mcp", resource_metadata="{metadata}"'.encode())
            )
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
