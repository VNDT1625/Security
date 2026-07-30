"""Persistent OAuth 2.1 authorization server for remote MCP clients."""

from __future__ import annotations

import html
import secrets
from datetime import UTC, timedelta
from urllib.parse import urlencode, urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from sqlalchemy import or_, select
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from backend.config import settings
from backend.db import SessionLocal
from backend.models import (
    ApiKey,
    OAuthAuthorizationCode,
    OAuthAuthorizationRequest,
    OAuthClient,
    OAuthTokenRecord,
    User,
)
from backend.security_utils import hash_api_key, session_key, utcnow


def _lock_authorization_code(db, code_hash: str):
    """Fetch an authorization code FOR UPDATE where the backend supports it.

    SQLite has no row-level locking but serialises writers, so the plain read is
    equivalent there; PostgreSQL gets a real lock.
    """
    statement = select(OAuthAuthorizationCode).where(
        OAuthAuthorizationCode.code_hash == code_hash
    )
    if db.bind is not None and db.bind.dialect.name != "sqlite":
        statement = statement.with_for_update()
    return db.execute(statement).scalar_one_or_none()


OAUTH_REQUIRED_SCOPES = ["mcp:invoke"]
OAUTH_SCOPES = [
    "mcp:invoke",
    "mcp:file:share_external",
]


class PrewiseOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with SessionLocal() as db:
            record = db.get(OAuthClient, client_id)
            return OAuthClientInformationFull.model_validate(record.client_metadata) if record else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise ValueError("client_id is required")
        data = client_info.model_dump(mode="json", exclude_none=True)
        # ``model_dump`` includes ``client_secret``, so the previous version wrote
        # the plaintext secret into the JSON metadata column while the
        # ``client_secret_hash`` column it also wrote was never read. Any dump of
        # that table handed out working client credentials.
        #
        # MCP clients are public clients and PKCE (S256) is mandatory on this
        # server, so a client secret adds nothing: registering everyone as
        # ``token_endpoint_auth_method="none"`` removes the secret from the
        # threat model instead of trying to store it safely.
        data.pop("client_secret", None)
        data.pop("client_secret_expires_at", None)
        data["token_endpoint_auth_method"] = "none"
        with SessionLocal() as db:
            db.merge(
                OAuthClient(
                    client_id=client_info.client_id,
                    client_secret_hash=None,
                    client_metadata=data,
                )
            )
            db.commit()

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        request_id = secrets.token_urlsafe(32)
        scopes = params.scopes or OAUTH_REQUIRED_SCOPES
        if "mcp:invoke" not in scopes or not set(scopes).issubset(set(OAUTH_SCOPES)):
            raise ValueError("invalid MCP OAuth scope request")
        with SessionLocal() as db:
            db.add(
                OAuthAuthorizationRequest(
                    id=request_id,
                    client_id=client.client_id or "",
                    redirect_uri=str(params.redirect_uri),
                    state=params.state,
                    scopes=scopes,
                    code_challenge=params.code_challenge,
                    resource=params.resource,
                    expires_at=utcnow() + timedelta(minutes=10),
                )
            )
            db.commit()
        return f"{settings.mcp_public_url.rstrip('/')}/oauth/consent?request={request_id}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        with SessionLocal() as db:
            row = db.get(OAuthAuthorizationCode, session_key(authorization_code))
            if (
                row is None
                or row.client_id != client.client_id
                or row.used_at is not None
                or row.expires_at <= utcnow()
            ):
                return None
            return AuthorizationCode(
                code=authorization_code,
                scopes=list(row.scopes),
                expires_at=row.expires_at.replace(tzinfo=UTC).timestamp(),
                client_id=row.client_id,
                code_challenge=row.code_challenge,
                redirect_uri=row.redirect_uri,
                redirect_uri_provided_explicitly=True,
                resource=row.resource,
            )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        now = utcnow()
        access = "pw_oauth_at_" + secrets.token_urlsafe(40)
        refresh = "pw_oauth_rt_" + secrets.token_urlsafe(48)
        with SessionLocal() as db:
            # Consume the code under a row lock. ``db.get`` takes no lock, so two
            # concurrent /token calls could both observe ``used_at is None`` and
            # both commit, minting two independent token families from a code
            # that is documented as single-use.
            code = _lock_authorization_code(db, session_key(authorization_code.code))
            if code is None or code.used_at is not None or code.expires_at <= now:
                raise ValueError("invalid or expired authorization code")
            code.used_at = now
            db.add(
                OAuthTokenRecord(
                    user_id=code.user_id,
                    client_id=code.client_id,
                    access_token_hash=session_key(access),
                    refresh_token_hash=session_key(refresh),
                    scopes=list(code.scopes),
                    resource=code.resource,
                    access_expires_at=now + timedelta(minutes=settings.mcp_oauth_access_token_minutes),
                    refresh_expires_at=now + timedelta(days=settings.mcp_oauth_refresh_token_days),
                )
            )
            db.commit()
        return OAuthToken(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.mcp_oauth_access_token_minutes * 60,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        with SessionLocal() as db:
            row = db.execute(
                select(OAuthTokenRecord).where(
                    OAuthTokenRecord.refresh_token_hash == session_key(refresh_token)
                )
            ).scalar_one_or_none()
            if (
                row is None
                or row.client_id != client.client_id
                or row.revoked_at is not None
                or row.rotated_at is not None
                or row.refresh_expires_at <= utcnow()
            ):
                return None
            return RefreshToken(
                token=refresh_token,
                client_id=row.client_id,
                scopes=list(row.scopes),
                expires_at=int(row.refresh_expires_at.replace(tzinfo=UTC).timestamp()),
            )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        now = utcnow()
        access = "pw_oauth_at_" + secrets.token_urlsafe(40)
        rotated_refresh = "pw_oauth_rt_" + secrets.token_urlsafe(48)
        with SessionLocal() as db:
            old = db.execute(
                select(OAuthTokenRecord).where(
                    OAuthTokenRecord.refresh_token_hash == session_key(refresh_token.token)
                )
            ).scalar_one_or_none()
            if old is None or old.rotated_at is not None or old.revoked_at is not None:
                raise ValueError("invalid refresh token")
            granted = scopes or list(old.scopes)
            if not set(granted).issubset(set(old.scopes)):
                raise ValueError("scope escalation is not allowed")
            old.rotated_at = now
            db.add(
                OAuthTokenRecord(
                    family_id=old.family_id,
                    user_id=old.user_id,
                    client_id=old.client_id,
                    access_token_hash=session_key(access),
                    refresh_token_hash=session_key(rotated_refresh),
                    scopes=granted,
                    resource=old.resource,
                    access_expires_at=now + timedelta(minutes=settings.mcp_oauth_access_token_minutes),
                    refresh_expires_at=now + timedelta(days=settings.mcp_oauth_refresh_token_days),
                )
            )
            db.commit()
        return OAuthToken(
            access_token=access,
            refresh_token=rotated_refresh,
            expires_in=settings.mcp_oauth_access_token_minutes * 60,
            scope=" ".join(granted),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        now = utcnow()
        with SessionLocal() as db:
            if token.startswith("pw_live_"):
                key = db.execute(
                    select(ApiKey).where(ApiKey.key_hash == hash_api_key(token))
                ).scalar_one_or_none()
                if (
                    key
                    and key.status == "active"
                    and key.revoked_at is None
                    and (key.expires_at is None or key.expires_at > now)
                    and "mcp:invoke" in (key.scopes or [])
                ):
                    return AccessToken(token=token, client_id=f"api-key:{key.id}", scopes=["mcp:invoke"])
                return None
            row = db.execute(
                select(OAuthTokenRecord).where(
                    OAuthTokenRecord.access_token_hash == session_key(token)
                )
            ).scalar_one_or_none()
            if row is None or row.revoked_at is not None or row.access_expires_at <= now:
                return None
            user = db.get(User, row.user_id)
            if user is None or user.status != "active":
                return None
            return AccessToken(
                token=token,
                client_id=row.client_id,
                scopes=list(row.scopes),
                expires_at=int(row.access_expires_at.replace(tzinfo=UTC).timestamp()),
                resource=row.resource,
            )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        digest = session_key(token.token)
        with SessionLocal() as db:
            row = db.execute(
                select(OAuthTokenRecord).where(
                    or_(
                        OAuthTokenRecord.access_token_hash == digest,
                        OAuthTokenRecord.refresh_token_hash == digest,
                    )
                )
            ).scalar_one_or_none()
            if row:
                now = utcnow()
                for family in db.execute(
                    select(OAuthTokenRecord).where(OAuthTokenRecord.family_id == row.family_id)
                ).scalars():
                    family.revoked_at = now
                db.commit()


def _expired_page() -> str:
    """Terminal page for an unknown/expired consent request — no credential input."""
    return (
        '<!doctype html><html lang="vi"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Yêu cầu đã hết hạn</title><style>"
        "body{font-family:system-ui;background:#0e1116;color:#eef2f7;display:grid;"
        "place-items:center;min-height:100vh;margin:0}.card{width:min(430px,calc(100% - 36px));"
        "background:#171b22;border:1px solid #303743;border-radius:18px;padding:28px}"
        "p{color:#aab4c2;line-height:1.6}</style></head><body><main class=\"card\">"
        "<h1>Yêu cầu kết nối đã hết hạn</h1>"
        "<p>Liên kết này không còn hiệu lực hoặc đã được sử dụng.</p>"
        "<p><strong>Không nhập API key vào trang này.</strong> Hãy quay lại ứng dụng "
        "của bạn và bắt đầu lại quá trình kết nối từ đầu.</p>"
        "</main></body></html>"
    )


def _form(
    request_id: str,
    error: str = "",
    scopes: list[str] | None = None,
    *,
    client_label: str = "",
    redirect_origin: str = "",
) -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    scope_items = "".join(f"<li>{html.escape(scope)}</li>" for scope in (scopes or []))
    scope_html = f"<p>Quyền được yêu cầu:</p><ul>{scope_items}</ul>" if scope_items else ""
    # Client registration is open, so the requesting application must be named on
    # the page. Without this the consent screen reads as a first-party Prewise
    # page asking for a long-lived API key on behalf of "ChatGPT", and any
    # attacker who registers a client can send a victim a genuine consent link
    # that redirects the resulting code to their own callback.
    who_html = (
        '<div class="who">Ứng dụng <strong>'
        + html.escape(client_label or "không xác định")
        + "</strong> đang yêu cầu quyền truy cập.<br>Mã sẽ được gửi tới: <code>"
        + html.escape(redirect_origin or "không xác định")
        + "</code><br><span class=\"warn\">Chỉ tiếp tục nếu bạn vừa tự khởi tạo kết nối này "
        "và nhận ra ứng dụng ở trên.</span></div>"
    )
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kết nối Prewise</title><style>
body{{font-family:system-ui;background:#0e1116;color:#eef2f7;display:grid;place-items:center;min-height:100vh;margin:0}}.card{{width:min(430px,calc(100% - 36px));background:#171b22;border:1px solid #303743;border-radius:18px;padding:28px;box-sizing:border-box}}h1{{margin:0 0 8px}}p{{color:#aab4c2}}label{{display:block;margin:16px 0 6px}}input{{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #465063;background:#0e1116;color:white}}button{{width:100%;margin-top:20px;padding:12px;border:0;border-radius:9px;background:#ff9f43;font-weight:700}}.hint{{font-size:13px;color:#778292}}.error{{background:#4a1f25;color:#ffbec5;padding:10px;border-radius:8px}}.who{{background:#1f2530;border:1px solid #465063;border-radius:10px;padding:12px;font-size:14px;line-height:1.55}}.who code{{color:#ffd08a;word-break:break-all}}.warn{{color:#ffbec5}}</style></head><body><main class="card"><h1>Kết nối Prewise</h1>{who_html}<p>Nhập API key một lần để ứng dụng trên sử dụng Security AI theo plan và quota của bạn.</p>{scope_html}{error_html}<form method="post"><input type="hidden" name="request" value="{html.escape(request_id)}"><label>Prewise API key</label><input name="api_key" type="password" autocomplete="off" required placeholder="pw_live_..."><p class="hint">API key chỉ được kiểm tra, không được lưu dưới dạng văn bản rõ.</p><button type="submit">Cho phép kết nối</button></form></main></body></html>"""


def install_oauth_routes(server) -> None:
    @server.custom_route("/oauth/consent", methods=["GET", "POST"])
    async def oauth_consent(request: Request) -> Response:
        initialize_request = request.query_params.get("request", "")
        form = await request.form() if request.method == "POST" else None
        request_id = str(form.get("request", "")) if form else initialize_request
        with SessionLocal() as db:
            pending = db.get(OAuthAuthorizationRequest, request_id)
            if pending is None or pending.consumed_at is not None or pending.expires_at <= utcnow():
                # No pending record means the requesting client cannot be named,
                # so the page must not ask for an API key: an unidentifiable form
                # collecting a long-lived credential is the exact shape of the
                # phishing surface this page was hardened against.
                return HTMLResponse(_expired_page(), status_code=400)
            client_row = db.get(OAuthClient, pending.client_id)
            metadata = (client_row.client_metadata or {}) if client_row else {}
            client_label = str(metadata.get("client_name") or pending.client_id)[:120]
            redirect_origin = urlsplit(pending.redirect_uri).netloc or pending.redirect_uri

            def render(message: str = "", status_code: int = 200) -> HTMLResponse:
                return HTMLResponse(
                    _form(
                        request_id,
                        message,
                        list(pending.scopes),
                        client_label=client_label,
                        redirect_origin=redirect_origin,
                    ),
                    status_code=status_code,
                )

            if request.method == "GET":
                return render()

            raw_key = str(form.get("api_key", "")).strip()
            key = db.execute(
                select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_key))
            ).scalar_one_or_none()
            user = None
            if (
                key
                and key.status == "active"
                and key.revoked_at is None
                and (key.expires_at is None or key.expires_at > utcnow())
                and "mcp:invoke" in (key.scopes or [])
            ):
                user = db.get(User, key.user_id)
            if user is None or user.status != "active":
                return render("Thông tin xác thực không hợp lệ.", 401)
            requested_sensitive = set(pending.scopes) - {"mcp:invoke"}
            if not requested_sensitive.issubset(set(key.scopes or [])):
                return render("API key không cấp đủ quyền nhạy cảm được yêu cầu.", 403)

            code = secrets.token_urlsafe(32)
            db.add(
                OAuthAuthorizationCode(
                    code_hash=session_key(code),
                    user_id=user.id,
                    client_id=pending.client_id,
                    redirect_uri=pending.redirect_uri,
                    scopes=list(pending.scopes),
                    code_challenge=pending.code_challenge,
                    resource=pending.resource,
                    expires_at=utcnow() + timedelta(minutes=5),
                )
            )
            pending.consumed_at = utcnow()
            db.commit()
            query = {"code": code}
            if pending.state:
                query["state"] = pending.state
            separator = "&" if "?" in pending.redirect_uri else "?"
            return RedirectResponse(pending.redirect_uri + separator + urlencode(query), status_code=303)
