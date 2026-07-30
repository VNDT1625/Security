"""Database-backed authentication, sessions, API keys, and account endpoints."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Annotated, Any, Literal, NoReturn
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import selectinload

from backend.config import settings
from backend.db import get_db
from backend.models import (
    ApiKey,
    DailyQuotaUsage,
    PasswordResetToken,
    ReportShare,
    ScanEvent,
    ScanEvidence,
    SessionRecord,
    Subscription,
    User,
    UserFeedback,
)
from backend.security_utils import (
    create_api_key_value,
    create_password_salt,
    create_session_token,
    format_short_datetime,
    hash_api_key,
    hash_metadata,
    hash_password,
    mask_api_key,
    session_key,
    utcnow,
    verify_password,
)
from backend.services.llm_provider_config_service import (
    get_runtime_llm_config,
    safe_config_payload,
    save_user_llm_config,
    test_runtime_llm_config,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["auth"])
bearer_scheme = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]

SESSION_TTL_SECONDS = 12 * 60 * 60


class Credentials(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=1)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized:
            raise ValueError("Email không hợp lệ.")
        local, _, domain = normalized.partition("@")
        if not local or "." not in domain:
            raise ValueError("Email không hợp lệ.")
        return normalized


class RegisterInput(Credentials):
    displayName: str = Field(min_length=1)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 12:
            raise ValueError("Mật khẩu phải có ít nhất 12 ký tự.")
        if len(value) > 256:
            raise ValueError("Mật khẩu không được vượt quá 256 ký tự.")
        if not any(char.isalpha() for char in value) or not any(char.isdigit() for char in value):
            raise ValueError("Mật khẩu phải chứa cả chữ và số.")
        return value


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=512)
    newPassword: str = Field(min_length=12, max_length=256)

    @field_validator("newPassword")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        if not any(char.isalpha() for char in value) or not any(char.isdigit() for char in value):
            raise ValueError("Mật khẩu mới phải chứa cả chữ và số.")
        return value


class ProfileUpdate(BaseModel):
    displayName: str = Field(min_length=1, max_length=200)
    organizationName: str | None = Field(default=None, max_length=200)
    jobTitle: str | None = Field(default=None, max_length=160)
    countryCode: str = Field(default="VN", pattern=r"^[A-Z]{2}$")
    locale: Literal["vi", "en"] = "vi"
    timezone: Literal[
        "Asia/Ho_Chi_Minh",
        "Asia/Singapore",
        "Asia/Tokyo",
        "Asia/Seoul",
        "Europe/London",
        "America/New_York",
        "UTC",
    ] = "Asia/Ho_Chi_Minh"

    @field_validator("displayName")
    @classmethod
    def normalize_display_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("Tên hiển thị không được để trống.")
        return normalized

    @field_validator("organizationName", "jobTitle")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        normalized = " ".join(value.split()) if value is not None else ""
        return normalized or None


class PasswordChange(BaseModel):
    currentPassword: str = Field(min_length=1, max_length=256)
    newPassword: str = Field(min_length=12, max_length=256)

    @field_validator("newPassword")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        if not any(char.isalpha() for char in value) or not any(char.isdigit() for char in value):
            raise ValueError("Mật khẩu mới phải chứa cả chữ và số.")
        return value


class AISettingsInput(BaseModel):
    provider: str = Field(pattern="^(auto|adapter|local|endpoint)$")
    baseUrl: str = Field(default="", max_length=1000)
    model: str = Field(default="", max_length=300)
    apiKey: str | None = Field(default=None, max_length=1000)
    clearApiKey: bool = False
    weightPercent: int | None = Field(default=None, ge=0, le=100)


class UserProfile(BaseModel):
    id: str
    email: str
    displayName: str
    avatarUrl: str | None = None
    role: str = "user"
    organizationName: str | None = None
    jobTitle: str | None = None
    countryCode: str = "VN"
    locale: str = "vi"
    timezone: str = "Asia/Ho_Chi_Minh"
    emailVerified: bool = False
    status: str = "active"
    createdAt: str | None = None
    updatedAt: str | None = None
    lastLoginAt: str | None = None


class PlanInfo(BaseModel):
    tier: str
    label: str
    renewsAt: str | None = None
    dailyScanLimit: int
    aiCreditDailyLimit: int
    deepScanDailyLimit: int
    chatFollowupLimit: int
    autoMessageContext: bool = False
    autoWebContext: bool = False


class Session(BaseModel):
    token: str
    user: UserProfile
    plan: PlanInfo


def _user_profile(user: User) -> UserProfile:
    """Map the persisted account record to the public profile contract."""

    def iso(value: object | None) -> str | None:
        return value.isoformat() if value is not None and hasattr(value, "isoformat") else None

    return UserProfile(
        id=user.id,
        email=user.email,
        displayName=user.display_name,
        avatarUrl=user.avatar_url,
        role=user.role,
        organizationName=user.organization_name,
        jobTitle=user.job_title,
        countryCode=user.country_code,
        locale=user.preferred_locale,
        timezone=user.timezone,
        emailVerified=user.email_verified_at is not None,
        status=user.status,
        createdAt=iso(user.created_at),
        updatedAt=iso(user.updated_at),
        lastLoginAt=iso(user.last_login_at),
    )


class ScanRecordEvidence(BaseModel):
    source: str
    message: str
    severity: str
    feature: str | None = None


class ScanRecord(BaseModel):
    id: str
    timestamp: str
    type: str
    score: int
    riskLevel: str
    target: str
    decision: str
    confidence: int
    modelVersion: str
    evidence: list[ScanRecordEvidence] = Field(default_factory=list)


class ScanRecordDetail(ScanRecord):
    """Privacy-minimised result that can be reopened by the owning account."""

    createdAt: str
    modality: str
    latencyMs: float = 0
    reasons: list[str] = Field(default_factory=list)
    schemaVersion: str | None = None
    scoringVersion: str | None = None
    riskCore: dict[str, Any] | None = None


class DeleteHistoryResult(BaseModel):
    deleted: int


class ApiKeyInfo(BaseModel):
    key: str
    createdAt: str
    prefix: str
    lastUsedAt: str | None = None
    scopes: list[str] = Field(default_factory=list)
    status: str = "active"
    secretAvailable: bool = False


class ApiKeyRotateInput(BaseModel):
    scopes: list[str] = Field(
        default_factory=lambda: [
            "assess:url", "assess:content", "assess:prompt", "assess:file",
            "assess:action", "mcp:invoke",
        ],
        max_length=20,
    )

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, scopes: list[str]) -> list[str]:
        allowed = {
            "assess:url", "assess:content", "assess:prompt", "assess:file",
            "assess:action", "mcp:invoke", "mcp:file:share_external", "logs:read",
        }
        normalized = list(dict.fromkeys(scopes))
        if not normalized or any(scope not in allowed for scope in normalized):
            raise ValueError("API key scope không hợp lệ.")
        return normalized


class QuotaInfo(BaseModel):
    usageDay: str
    usedToday: int
    dailyScanLimit: int
    remaining: int
    aiUsedToday: int
    aiEvaluationUsedToday: int
    aiExplanationUsedToday: int
    aiCreditDailyLimit: int
    aiRemaining: int
    deepUsedToday: int
    deepScanDailyLimit: int
    deepRemaining: int


class ExtensionActivation(BaseModel):
    valid: bool
    user: UserProfile
    plan: PlanInfo
    quota: QuotaInfo
    keyPrefix: str


@dataclass(frozen=True)
class AuthenticatedSession:
    token: str
    user: User
    db_session_id: str


@dataclass(frozen=True)
class ActorContext:
    user: User | None = None
    api_key: ApiKey | None = None
    channel: str = "web"
    anonymous_id: str | None = None


def unauthorized() -> NoReturn:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        headers={"WWW-Authenticate": "Bearer"},
    )


_PLAN_ENTITLEMENT_DEFAULTS: dict[str, dict[str, int | bool]] = {
    "free": {
        "ai_credit_daily_limit": 5,
        "deep_scan_daily_limit": 100,
        "chat_followup_limit": 3,
        "auto_message_context": False,
        "auto_web_context": False,
    },
    "pro": {
        "ai_credit_daily_limit": 50,
        "deep_scan_daily_limit": 100,
        "chat_followup_limit": 20,
        "auto_message_context": True,
        "auto_web_context": True,
    },
    "team": {
        "ai_credit_daily_limit": 100,
        "deep_scan_daily_limit": 100,
        "chat_followup_limit": 50,
        "auto_message_context": True,
        "auto_web_context": True,
    },
    "enterprise": {
        "ai_credit_daily_limit": 999_999,
        "deep_scan_daily_limit": 999_999,
        "chat_followup_limit": 999_999,
        "auto_message_context": True,
        "auto_web_context": True,
    },
}


def _plan_entitlements(tier: str, features: dict | None = None) -> dict[str, int | bool]:
    values = dict(_PLAN_ENTITLEMENT_DEFAULTS.get(tier, _PLAN_ENTITLEMENT_DEFAULTS["free"]))
    for key in values:
        if features and key in features:
            values[key] = features[key]
    return values


def build_free_plan_info() -> PlanInfo:
    entitlements = _plan_entitlements("free")
    return PlanInfo(
        tier="free",
        label="FREE",
        renewsAt=None,
        dailyScanLimit=1000,
        aiCreditDailyLimit=int(entitlements["ai_credit_daily_limit"]),
        deepScanDailyLimit=int(entitlements["deep_scan_daily_limit"]),
        chatFollowupLimit=int(entitlements["chat_followup_limit"]),
        autoMessageContext=bool(entitlements["auto_message_context"]),
        autoWebContext=bool(entitlements["auto_web_context"]),
    )


def _active_subscription(db: DbSession, user_id: str) -> Subscription | None:
    rows = db.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id, Subscription.status.in_(("trialing", "active")))
        .order_by(Subscription.created_at.desc())
    ).scalars()
    now = utcnow()
    for subscription in rows:
        expires_at = (
            subscription.trial_ends_at
            if subscription.status == "trialing" and subscription.trial_ends_at is not None
            else subscription.renews_at
        )
        if expires_at is None or expires_at > now:
            return subscription
    return None


def build_plan_info(db: DbSession, user_id: str) -> PlanInfo:
    subscription = _active_subscription(db, user_id)
    if subscription is None:
        return build_free_plan_info()

    plan = subscription.plan
    entitlements = _plan_entitlements(
        subscription.plan_tier,
        plan.features if plan is not None else None,
    )
    renews_at = subscription.renews_at
    return PlanInfo(
        tier=subscription.plan_tier,
        label=plan.label if plan is not None else subscription.plan_tier.upper(),
        renewsAt=renews_at.strftime("%d/%m/%Y") if renews_at is not None else None,
        dailyScanLimit=plan.daily_scan_limit if plan and plan.daily_scan_limit is not None else 999_999,
        aiCreditDailyLimit=int(entitlements["ai_credit_daily_limit"]),
        deepScanDailyLimit=int(entitlements["deep_scan_daily_limit"]),
        chatFollowupLimit=int(entitlements["chat_followup_limit"]),
        autoMessageContext=bool(entitlements["auto_message_context"]),
        autoWebContext=bool(entitlements["auto_web_context"]),
    )


def build_actor_plan_info(db: DbSession, actor: ActorContext) -> PlanInfo:
    return build_plan_info(db, actor.user.id) if actor.user is not None else build_free_plan_info()


def require_api_key_entitlement(db: DbSession, user_id: str) -> PlanInfo:
    """Keep Team/API credentials unavailable after downgrade or expiry."""

    plan = build_plan_info(db, user_id)
    if plan.tier not in {"team", "enterprise"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key và MCP endpoint yêu cầu gói Team hoặc cao hơn.",
        )
    return plan


def _create_api_key_record(
    db: DbSession,
    user_id: str,
    scopes: list[str] | None = None,
    rotated_from_id: str | None = None,
) -> tuple[ApiKey, str]:
    key = create_api_key_value()
    record = ApiKey(
        user_id=user_id,
        key_prefix=key[:16],
        key_tail=key[-4:],
        key_hash=hash_api_key(key),
        scopes=scopes or [
            "assess:url", "assess:content", "assess:prompt", "assess:file",
            "assess:action", "mcp:invoke",
        ],
        rotated_from_id=rotated_from_id,
        created_at=utcnow(),
    )
    db.add(record)
    db.flush()
    return record, key


def _active_api_key(db: DbSession, user_id: str) -> ApiKey:
    record = db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == user_id, ApiKey.status == "active")
        .order_by(ApiKey.created_at.desc())
    ).scalar_one_or_none()
    if record is None:
        record, _ = _create_api_key_record(db, user_id)
        db.commit()
        db.refresh(record)
    return record


def _api_key_info(record: ApiKey, plaintext: str | None = None) -> ApiKeyInfo:
    return ApiKeyInfo(
        key=plaintext if plaintext is not None else mask_api_key(record.key_prefix, record.key_tail),
        createdAt=format_short_datetime(record.created_at),
        prefix=record.key_prefix,
        lastUsedAt=format_short_datetime(record.last_used_at) if record.last_used_at else None,
        scopes=list(record.scopes or []),
        status=record.status,
        secretAvailable=plaintext is not None,
    )


def create_user(
    db: DbSession, email: str, password: str, display_name: str, plan_tier: str | None = None
) -> User:
    normalized = email.strip().lower()
    salt = create_password_salt()
    user = User(
        email=normalized,
        display_name=display_name.strip(),
        password_salt=salt,
        password_hash=hash_password(password, salt),
    )
    db.add(user)
    db.flush()
    # Public registration never infers paid access from user-controlled fields.
    # Trusted internal callers may still provision a paid tier explicitly.
    assigned_tier = plan_tier or "free"
    db.add(Subscription(user_id=user.id, plan_tier=assigned_tier))
    if assigned_tier in {"team", "enterprise"}:
        _create_api_key_record(db, user.id)
    db.commit()
    db.refresh(user)
    return user


def build_session(db: DbSession, user: User, request: Request | None = None) -> Session:
    token = create_session_token()
    db_record = SessionRecord(
        user_id=user.id,
        token_hash=session_key(token),
        expires_at=utcnow() + timedelta(seconds=SESSION_TTL_SECONDS),
        source_ip_hash=hash_metadata(request.client.host if request and request.client else None),
        user_agent_hash=hash_metadata(request.headers.get("user-agent") if request else None),
    )
    user.last_login_at = utcnow()
    db.add(db_record)
    db.commit()
    return Session(
        token=token,
        user=_user_profile(user),
        plan=build_plan_info(db, user.id),
    )


def verify_user(db: DbSession, email: str, password: str) -> User:
    normalized = email.strip().lower()
    user = db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
    if user is None or user.status != "active" or not verify_password(
        password, user.password_salt, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email hoặc mật khẩu không đúng.",
        )
    return user


def require_session(
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
) -> AuthenticatedSession:
    if credentials is None or credentials.scheme.lower() != "bearer":
        unauthorized()

    token_hash = session_key(credentials.credentials)
    record = db.execute(
        select(SessionRecord).where(SessionRecord.token_hash == token_hash)
    ).scalar_one_or_none()
    if record is None or record.revoked_at is not None or record.expires_at <= utcnow():
        if record is not None:
            db.delete(record)
            db.commit()
        unauthorized()

    user = db.get(User, record.user_id)
    if user is None or user.status != "active":
        unauthorized()
    return AuthenticatedSession(token=credentials.credentials, user=user, db_session_id=record.id)


CurrentSession = Annotated[AuthenticatedSession, Depends(require_session)]


def require_admin(auth: CurrentSession) -> AuthenticatedSession:
    if auth.user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bạn không có quyền quản trị.",
        )
    return auth


def resolve_actor(
    credentials: HTTPAuthorizationCredentials | None,
    db: DbSession,
    request: Request | None = None,
) -> ActorContext:
    if credentials is None:
        source = request.client.host if request and request.client else "anonymous"
        return ActorContext(channel="web", anonymous_id=hash_metadata(source))

    if credentials.scheme.lower() != "bearer":
        unauthorized()

    raw = credentials.credentials
    token_hash = session_key(raw)
    session = db.execute(
        select(SessionRecord).where(SessionRecord.token_hash == token_hash)
    ).scalar_one_or_none()
    if session is not None and session.revoked_at is None and session.expires_at > utcnow():
        user = db.get(User, session.user_id)
        if user is not None and user.status == "active":
            return ActorContext(user=user, channel="web")

    api_key = db.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw))).scalar_one_or_none()
    if (
        api_key is not None
        and api_key.status == "active"
        and api_key.revoked_at is None
        and (api_key.expires_at is None or api_key.expires_at > utcnow())
    ):
        user = db.get(User, api_key.user_id)
        if user is not None and user.status == "active":
            require_api_key_entitlement(db, user.id)
            now = utcnow()
            write_interval = timedelta(
                seconds=settings.api_key_last_used_write_interval_seconds
            )
            if api_key.last_used_at is None or api_key.last_used_at <= now - write_interval:
                api_key.last_used_at = now
                db.commit()
            return ActorContext(user=user, api_key=api_key, channel="api")

    unauthorized()


def require_api_key_scope(actor: ActorContext, scope: str) -> None:
    """Enforce least-privilege scopes for external API/Extension/MCP keys.

    Browser sessions are authorized by the signed-in user and are not API keys.
    """
    if actor.api_key is None:
        return
    if scope not in (actor.api_key.scopes or []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key không có quyền {scope}.",
        )


@router.get("/auth/extension/verify", response_model=ExtensionActivation)
def verify_extension_key(
    credentials: BearerCredentials,
    request: Request,
    db: DbSession = Depends(get_db),
) -> ExtensionActivation:
    actor = resolve_actor(credentials, db, request)
    if actor.user is None or actor.api_key is None:
        unauthorized()
    require_api_key_scope(actor, "assess:url")
    plan = build_plan_info(db, actor.user.id)
    today = date.today()
    usage = db.execute(
        select(DailyQuotaUsage).where(
            DailyQuotaUsage.user_id == actor.user.id,
            DailyQuotaUsage.usage_day == today,
        )
    ).scalar_one_or_none()
    used = usage.scan_count if usage is not None else 0
    ai_used = usage.ai_credit_count if usage is not None else 0
    ai_evaluation_used = usage.ai_evaluation_count if usage is not None else 0
    ai_explanation_used = usage.ai_explanation_count if usage is not None else 0
    deep_used = usage.deep_scan_count if usage is not None else 0
    limit = plan.dailyScanLimit
    ai_limit = plan.aiCreditDailyLimit
    deep_limit = plan.deepScanDailyLimit
    remaining = max(0, limit - used) if limit < 999_999 else 999_999
    return ExtensionActivation(
        valid=True,
        user=_user_profile(actor.user),
        plan=plan,
        quota=QuotaInfo(
            usageDay=today.isoformat(),
            usedToday=used,
            dailyScanLimit=limit,
            remaining=remaining,
            aiUsedToday=ai_used,
            aiEvaluationUsedToday=ai_evaluation_used,
            aiExplanationUsedToday=ai_explanation_used,
            aiCreditDailyLimit=ai_limit,
            aiRemaining=max(0, ai_limit - ai_used) if ai_limit < 999_999 else 999_999,
            deepUsedToday=deep_used,
            deepScanDailyLimit=deep_limit,
            deepRemaining=max(0, deep_limit - deep_used) if deep_limit < 999_999 else 999_999,
        ),
        keyPrefix=actor.api_key.key_prefix,
    )


@router.post("/auth/login", response_model=Session)
def login(
    cred: Credentials,
    request: Request,
    db: DbSession = Depends(get_db),
) -> Session:
    return build_session(db, verify_user(db, str(cred.email), cred.password), request)


@router.post("/auth/register", response_model=Session)
def register(
    cred: RegisterInput,
    request: Request,
    db: DbSession = Depends(get_db),
) -> Session:
    email = str(cred.email).strip().lower()
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email đã được đăng ký.",
        )
    return build_session(db, create_user(db, email, cred.password, cred.displayName), request)


@router.post("/auth/password/forgot")
def forgot_password(payload: PasswordResetRequest, db: DbSession = Depends(get_db)) -> dict:
    if settings.app_env == "production":
        from backend.services.release_email_service import email_configured

        if not email_configured():
            raise HTTPException(
                status_code=503,
                detail="Dịch vụ gửi email khôi phục chưa được cấu hình.",
            )
    email = payload.email.strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    response: dict = {"ok": True, "message": "Nếu email tồn tại, hướng dẫn đặt lại mật khẩu đã được tạo."}
    if user is None or user.status != "active":
        return response
    now = utcnow()
    for old in db.execute(select(PasswordResetToken).where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))).scalars():
        old.used_at = now
    token = create_session_token()
    db.add(PasswordResetToken(user_id=user.id, token_hash=session_key(token), expires_at=now + timedelta(minutes=30)))
    db.commit()
    # Echoing the token is account takeover for anyone who knows an email address,
    # so it requires an explicit opt-in flag and is refused outright in production.
    if settings.expose_password_reset_token and settings.app_env != "production":
        response["resetToken"] = token
    else:
        from backend.services.release_email_service import send_password_reset_email

        query = urlencode({"mode": "reset", "token": token})
        try:
            send_password_reset_email(
                recipient=user.email,
                reset_url=f"{settings.password_reset_web_url}?{query}",
            )
        except Exception:
            # Never let delivery failure reveal whether the address exists. The
            # token stays valid so a retry after fixing SMTP still works.
            logger.warning("password reset email delivery failed", exc_info=True)
    return response


@router.post("/auth/password/reset")
def reset_password(payload: PasswordResetConfirm, db: DbSession = Depends(get_db)) -> dict[str, bool]:
    now = utcnow()
    record = db.execute(select(PasswordResetToken).where(PasswordResetToken.token_hash == session_key(payload.token))).scalar_one_or_none()
    if record is None or record.used_at is not None or record.expires_at <= now:
        raise HTTPException(status_code=400, detail="Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.")
    user = db.get(User, record.user_id)
    if user is None or user.status != "active":
        raise HTTPException(status_code=400, detail="Không thể đặt lại mật khẩu cho tài khoản này.")
    salt = create_password_salt()
    user.password_salt = salt
    user.password_hash = hash_password(payload.newPassword, salt)
    record.used_at = now
    db.execute(SessionRecord.__table__.update().where(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None)).values(revoked_at=now))
    db.commit()
    return {"ok": True}


@router.post("/auth/logout")
def logout(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict[str, bool]:
    record = db.get(SessionRecord, auth.db_session_id)
    if record is not None:
        record.revoked_at = utcnow()
        db.commit()
    return {"ok": True}


@router.get("/account/plan", response_model=PlanInfo)
def get_plan(auth: CurrentSession, db: DbSession = Depends(get_db)) -> PlanInfo:
    return build_plan_info(db, auth.user.id)


@router.get("/account/profile", response_model=UserProfile)
def get_profile(auth: CurrentSession) -> UserProfile:
    """Return the current server-authoritative identity and role.

    Desktop clients persist a session locally, so roles must be refreshed from
    the database rather than trusting the role saved at the time of login.
    """
    return _user_profile(auth.user)


@router.post("/account/subscription/cancel", response_model=PlanInfo)
def cancel_subscription(auth: CurrentSession, db: DbSession = Depends(get_db)) -> PlanInfo:
    subscription = _active_subscription(db, auth.user.id)
    if subscription is None or subscription.plan_tier == "free":
        raise HTTPException(status_code=409, detail="Tài khoản không có gói trả phí đang hoạt động.")
    subscription.status = "canceled"
    subscription.canceled_at = utcnow()
    db.add(Subscription(user_id=auth.user.id, plan_tier="free", status="active"))
    db.commit()
    return build_plan_info(db, auth.user.id)


@router.patch("/account/profile", response_model=UserProfile)
def update_profile(
    payload: ProfileUpdate,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> UserProfile:
    auth.user.display_name = payload.displayName
    auth.user.organization_name = payload.organizationName
    auth.user.job_title = payload.jobTitle
    auth.user.country_code = payload.countryCode
    auth.user.preferred_locale = payload.locale
    auth.user.timezone = payload.timezone
    db.commit()
    db.refresh(auth.user)
    return _user_profile(auth.user)


@router.post("/account/password")
def change_password(
    payload: PasswordChange,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict[str, bool]:
    if not verify_password(
        payload.currentPassword,
        auth.user.password_salt,
        auth.user.password_hash,
    ):
        raise HTTPException(status_code=400, detail="Mật khẩu hiện tại không đúng.")
    if verify_password(payload.newPassword, auth.user.password_salt, auth.user.password_hash):
        raise HTTPException(status_code=400, detail="Mật khẩu mới phải khác mật khẩu hiện tại.")

    salt = create_password_salt()
    auth.user.password_salt = salt
    auth.user.password_hash = hash_password(payload.newPassword, salt)
    db.execute(
        SessionRecord.__table__.update()
        .where(
            SessionRecord.user_id == auth.user.id,
            SessionRecord.id != auth.db_session_id,
            SessionRecord.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    db.commit()
    return {"ok": True}


@router.get("/account/history", response_model=list[ScanRecord])
def get_scan_history(auth: CurrentSession, db: DbSession = Depends(get_db)) -> list[ScanRecord]:
    rows = db.execute(
        select(ScanEvent)
        .options(selectinload(ScanEvent.evidence))
        .where(ScanEvent.user_id == auth.user.id)
        .order_by(ScanEvent.created_at.desc())
        .limit(200)
    ).scalars()
    records: list[ScanRecord] = []
    for row in rows:
        scan_type = {"url": "URL", "email": "Email", "sms": "SMS"}.get(
            row.modality.lower(), row.modality.upper()
        )
        records.append(
            ScanRecord(
                id=row.request_id,
                timestamp=format_short_datetime(row.created_at),
                type=scan_type,
                score=round(row.risk_score * 100),
                riskLevel=row.risk_level,
                target=_safe_history_target(row),
                decision=row.decision,
                confidence=round(row.confidence * 100),
                modelVersion=row.model_version,
                evidence=_history_evidence(row),
            )
        )
    return records


_HISTORY_SECRET_KEYS = {
    "api_key", "authorization", "body", "content", "cookie", "email", "headers",
    "input", "message", "operator_context", "password", "phone", "prompt", "secret",
    "subject", "target", "token", "url",
}


def _safe_history_text(value: str, limit: int = 500) -> str:
    """Mask identifiers and common credentials in history/export responses."""
    import re

    text = " ".join(value.split())
    text = re.sub(r"https?://\S+", "[URL đã che]", text, flags=re.IGNORECASE)
    text = re.sub(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])", "[email đã che]", text)
    text = re.sub(r"(?<!\w)(?:\+?\d[\s().-]?){8,19}(?!\w)", "[số đã che]", text)
    text = re.sub(
        r"\b(password|passcode|mật khẩu|mat khau|otp|mã otp|token)\b\s*[:=\-]?\s*\S+",
        r"\1: [ĐÃ CHE]",
        text,
        flags=re.IGNORECASE,
    )
    return text[:limit]


def _safe_history_target(row: ScanEvent) -> str:
    if row.modality.lower() == "url" and row.normalized_url:
        try:
            parsed = urlsplit(row.normalized_url)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                port = f":{parsed.port}" if parsed.port else ""
                path = "/…" if parsed.path not in {"", "/"} else ""
                return f"{parsed.scheme}://{parsed.hostname}{port}{path}"
        except (ValueError, UnicodeError):
            pass
        return "Website đã được che"
    preview = _safe_history_text(row.input_preview or "", 160)
    return preview or "Nội dung đã được ẩn để bảo vệ riêng tư"


def _safe_risk_core(value: Any, *, depth: int = 0) -> Any:
    """Keep scoring metadata while removing raw inputs and credential-shaped fields."""
    if depth > 8:
        return "[đã rút gọn]"
    if isinstance(value, dict):
        return {
            str(key): _safe_risk_core(item, depth=depth + 1)
            for key, item in value.items()
            if str(key).lower() not in _HISTORY_SECRET_KEYS
        }
    if isinstance(value, list):
        return [_safe_risk_core(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return _safe_history_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:200]


def _history_evidence(row: ScanEvent) -> list[ScanRecordEvidence]:
    return [
        ScanRecordEvidence(
            source=_safe_history_text(item.source, 120),
            message=_safe_history_text(item.message),
            severity=item.severity,
            feature=_safe_history_text(item.feature, 160) if item.feature else None,
        )
        for item in row.evidence
    ]


@router.get("/account/history/{request_id}", response_model=ScanRecordDetail)
def get_scan_history_detail(
    request_id: str,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> ScanRecordDetail:
    row = db.execute(
        select(ScanEvent)
        .options(selectinload(ScanEvent.evidence))
        .where(ScanEvent.request_id == request_id, ScanEvent.user_id == auth.user.id)
    ).scalar_one_or_none()
    if row is None:
        # Deliberately do not reveal whether another account owns this request id.
        raise HTTPException(status_code=404, detail="Không tìm thấy lượt phân tích này.")
    scan_type = {"url": "URL", "email": "Email", "sms": "SMS"}.get(
        row.modality.lower(), row.modality.upper()
    )
    evidence = _history_evidence(row)
    trace = row.risk_core_trace or (row.extra_metadata or {}).get("risk_core")
    return ScanRecordDetail(
        id=row.request_id,
        timestamp=format_short_datetime(row.created_at),
        createdAt=row.created_at.isoformat() + "Z",
        type=scan_type,
        modality=row.modality.lower(),
        score=round(row.risk_score * 100),
        riskLevel=row.risk_level,
        target=_safe_history_target(row),
        decision=row.decision,
        confidence=round(row.confidence * 100),
        modelVersion=row.model_version,
        latencyMs=float(row.latency_ms),
        evidence=evidence,
        reasons=[item.message for item in evidence[:10]],
        schemaVersion=row.schema_version or (row.extra_metadata or {}).get("schema_version"),
        scoringVersion=row.scoring_version or (row.extra_metadata or {}).get("scoring_version"),
        riskCore=_safe_risk_core(trace) if isinstance(trace, dict) else None,
    )


def _delete_owned_history(db: DbSession, user_id: str, request_id: str | None = None) -> int:
    query = select(ScanEvent.id).where(ScanEvent.user_id == user_id)
    if request_id is not None:
        query = query.where(ScanEvent.request_id == request_id)
    event_ids = list(db.execute(query).scalars())
    if not event_ids:
        return 0
    # Explicit deletes make the cascade deterministic even when SQLite foreign keys
    # were disabled by a legacy connection.
    db.execute(delete(UserFeedback).where(UserFeedback.scan_event_id.in_(event_ids)))
    db.execute(delete(ReportShare).where(ReportShare.scan_event_id.in_(event_ids)))
    db.execute(delete(ScanEvidence).where(ScanEvidence.scan_event_id.in_(event_ids)))
    db.execute(delete(ScanEvent).where(ScanEvent.id.in_(event_ids)))
    db.commit()
    return len(event_ids)


@router.delete("/account/history/{request_id}", response_model=DeleteHistoryResult)
def delete_scan_history_record(
    request_id: str,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> DeleteHistoryResult:
    deleted = _delete_owned_history(db, auth.user.id, request_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Không tìm thấy lượt phân tích này.")
    return DeleteHistoryResult(deleted=deleted)


@router.delete("/account/history", response_model=DeleteHistoryResult)
def clear_scan_history(auth: CurrentSession, db: DbSession = Depends(get_db)) -> DeleteHistoryResult:
    return DeleteHistoryResult(deleted=_delete_owned_history(db, auth.user.id))


@router.get("/account/api-key", response_model=ApiKeyInfo)
def get_api_key(auth: CurrentSession, db: DbSession = Depends(get_db)) -> ApiKeyInfo:
    require_api_key_entitlement(db, auth.user.id)
    return _api_key_info(_active_api_key(db, auth.user.id))


@router.get("/account/quota", response_model=QuotaInfo)
def get_quota(auth: CurrentSession, db: DbSession = Depends(get_db)) -> QuotaInfo:
    today = date.today()
    plan = build_plan_info(db, auth.user.id)
    usage = db.execute(
        select(DailyQuotaUsage).where(
            DailyQuotaUsage.user_id == auth.user.id,
            DailyQuotaUsage.usage_day == today,
        )
    ).scalar_one_or_none()
    used = usage.scan_count if usage is not None else 0
    ai_used = usage.ai_credit_count if usage is not None else 0
    ai_evaluation_used = usage.ai_evaluation_count if usage is not None else 0
    ai_explanation_used = usage.ai_explanation_count if usage is not None else 0
    deep_used = usage.deep_scan_count if usage is not None else 0
    limit = plan.dailyScanLimit
    ai_limit = plan.aiCreditDailyLimit
    deep_limit = plan.deepScanDailyLimit
    remaining = max(0, limit - used) if limit < 999_999 else 999_999
    return QuotaInfo(
        usageDay=today.isoformat(),
        usedToday=used,
        dailyScanLimit=limit,
        remaining=remaining,
        aiUsedToday=ai_used,
        aiEvaluationUsedToday=ai_evaluation_used,
        aiExplanationUsedToday=ai_explanation_used,
        aiCreditDailyLimit=ai_limit,
        aiRemaining=max(0, ai_limit - ai_used) if ai_limit < 999_999 else 999_999,
        deepUsedToday=deep_used,
        deepScanDailyLimit=deep_limit,
        deepRemaining=max(0, deep_limit - deep_used) if deep_limit < 999_999 else 999_999,
    )


@router.get("/account/ai-settings")
def get_account_ai_settings(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    """Return only the current user's provider preference; never return its key."""
    try:
        from backend.services.ai_context_weight_service import get_user_ai_context_weight_payload

        plan = build_plan_info(db, auth.user.id)
        from backend.services.llm_provider_config_service import get_user_llm_policy

        return {
            **safe_config_payload(get_runtime_llm_config(db, user_id=auth.user.id)),
            **get_user_llm_policy(db),
            **get_user_ai_context_weight_payload(
                db, user_id=auth.user.id, plan_tier=plan.tier
            ),
        }
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/account/ai-settings")
def update_account_ai_settings(
    payload: AISettingsInput,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    try:
        from backend.services.ai_context_weight_service import (
            get_user_ai_context_weight_payload,
            set_user_ai_context_weight_percent,
            validate_user_ai_context_weight_percent,
        )

        plan = build_plan_info(db, auth.user.id)
        if payload.weightPercent is not None:
            # Validate every field before either service commits. This prevents
            # a rejected weight from partially saving the provider selection.
            validate_user_ai_context_weight_percent(
                db, plan_tier=plan.tier, percent=payload.weightPercent
            )
        configured = save_user_llm_config(
            db,
            user_id=auth.user.id,
            provider=payload.provider,  # type: ignore[arg-type]
            base_url=payload.baseUrl,
            model=payload.model,
            api_key=payload.apiKey,
            clear_api_key=payload.clearApiKey,
            commit=False,
        )
        if payload.weightPercent is not None:
            set_user_ai_context_weight_percent(
                db,
                user_id=auth.user.id,
                plan_tier=plan.tier,
                percent=payload.weightPercent,
                commit=False,
            )
        db.commit()
        from backend.services.llm_provider_config_service import get_user_llm_policy

        return {
            **safe_config_payload(configured),
            **get_user_llm_policy(db),
            **get_user_ai_context_weight_payload(
                db, user_id=auth.user.id, plan_tier=plan.tier
            ),
        }
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise


@router.post("/account/ai-settings/test")
def test_account_ai_settings(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    try:
        return test_runtime_llm_config(
            get_runtime_llm_config(db, user_id=auth.user.id)
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        # Keep provider details and credentials out of the response.
        raise HTTPException(status_code=502, detail="Không kết nối hoặc gọi được model đã chọn.") from exc


@router.post("/account/api-key/rotate", response_model=ApiKeyInfo)
def rotate_api_key(
    auth: CurrentSession,
    payload: ApiKeyRotateInput = ApiKeyRotateInput(),
    db: DbSession = Depends(get_db),
) -> ApiKeyInfo:
    require_api_key_entitlement(db, auth.user.id)
    current = list(db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == auth.user.id, ApiKey.status == "active")
        .order_by(ApiKey.created_at.desc())
    ).scalars())
    previous_id = current[0].id if current else None
    for key in current:
        key.status = "revoked"
        key.revoked_at = utcnow()
    record, plaintext = _create_api_key_record(
        db, auth.user.id, payload.scopes, rotated_from_id=previous_id
    )
    db.commit()
    db.refresh(record)
    return _api_key_info(record, plaintext)


@router.delete("/account/api-key")
def revoke_api_key(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict[str, bool]:
    require_api_key_entitlement(db, auth.user.id)
    keys = db.execute(
        select(ApiKey).where(ApiKey.user_id == auth.user.id, ApiKey.status == "active")
    ).scalars()
    for key in keys:
        key.status = "revoked"
        key.revoked_at = utcnow()
    db.commit()
    return {"ok": True}
