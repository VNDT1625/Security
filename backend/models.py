"""SQLAlchemy ORM models for the production persistence layer."""

from __future__ import annotations

import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db import Base
from backend.security_utils import utcnow


def uuid_str() -> str:
    return str(uuid.uuid4())


class ProductWaitlistEntry(Base):
    """A release notification subscription for one public product."""

    __tablename__ = "product_waitlist_entries"
    __table_args__ = (
        UniqueConstraint("email", "product", name="uq_waitlist_email_product"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    product: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    unsubscribed_at: Mapped[object | None] = mapped_column(DateTime)
    notified_at: Mapped[object | None] = mapped_column(DateTime)


class ProductRelease(Base):
    """A validated public download manifest published by an administrator."""

    __tablename__ = "product_releases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    product: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    download_url: Mapped[str] = mapped_column(String(2000), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_note: Mapped[str | None] = mapped_column(String(500))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    published_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    published_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    avatar_url: Mapped[str | None] = mapped_column(String(1000))
    password_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    password_algorithm: Mapped[str] = mapped_column(String(32), default="pbkdf2_sha256")
    role: Mapped[str] = mapped_column(String(32), default="user", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    email_verified_at: Mapped[object | None] = mapped_column(DateTime)
    last_login_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    sessions: Mapped[list[SessionRecord]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_keys: Mapped[list[ApiKey]] = relationship(back_populates="user")
    subscriptions: Mapped[list[Subscription]] = relationship(back_populates="user")


class SystemSetting(Base):
    """Small persistent global controls managed through the admin console."""

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class LLMProviderSetting(Base):
    """Encrypted OpenAI-compatible provider configuration managed by admins."""

    __tablename__ = "llm_provider_settings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="default")
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="auto")
    base_url: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    api_key_ciphertext: Mapped[str] = mapped_column(Text, nullable=False, default="")
    allowed_user_providers: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=lambda: ["auto", "adapter", "local", "endpoint"]
    )
    allowed_user_models: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    updated_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class UserLLMProviderSetting(Base):
    """Encrypted AI provider preference owned by one user account."""

    __tablename__ = "user_llm_provider_settings"

    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="auto")
    base_url: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    api_key_ciphertext: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class UserAIContextSetting(Base):
    """Per-account AI scoring preference constrained by the global policy."""

    __tablename__ = "user_ai_context_settings"
    __table_args__ = (
        CheckConstraint(
            "weight_percent >= 0 AND weight_percent <= 100",
            name="ck_user_ai_context_weight_percent",
        ),
    )

    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    weight_percent: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class GmailOAuthState(Base):
    __tablename__ = "gmail_oauth_states"

    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code_verifier_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    consumed_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class GmailConnection(Base):
    __tablename__ = "gmail_connections"
    __table_args__ = (UniqueConstraint("user_id", name="uq_gmail_connection_user"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    gmail_address: Mapped[str] = mapped_column(String(320), default="", nullable=False)
    access_token_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token_ciphertext: Mapped[str] = mapped_column(Text, default="", nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    token_expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    last_used_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[object | None] = mapped_column(DateTime)
    source_ip_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="sessions")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120), default="Default key", nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    key_tail: Mapped[str] = mapped_column(String(8), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: [
            "assess:url", "assess:content", "assess:prompt", "assess:file",
            "assess:action", "mcp:invoke",
        ],
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    expires_at: Mapped[object | None] = mapped_column(DateTime)
    last_used_at: Mapped[object | None] = mapped_column(DateTime)
    rotated_from_id: Mapped[str | None] = mapped_column(ForeignKey("api_keys.id"))
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    revoked_at: Mapped[object | None] = mapped_column(DateTime)

    user: Mapped[User] = relationship(back_populates="api_keys", foreign_keys=[user_id])


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    client_secret_hash: Mapped[str | None] = mapped_column(String(64))
    client_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class OAuthAuthorizationRequest(Base):
    __tablename__ = "oauth_authorization_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str | None] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(180), nullable=False)
    resource: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    consumed_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class OAuthAuthorizationCode(Base):
    __tablename__ = "oauth_authorization_codes"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(180), nullable=False)
    resource: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    used_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class OAuthTokenRecord(Base):
    __tablename__ = "oauth_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    family_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    access_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    resource: Mapped[str | None] = mapped_column(Text)
    access_expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    refresh_expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    revoked_at: Mapped[object | None] = mapped_column(DateTime)
    rotated_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class Plan(Base):
    __tablename__ = "plans"

    tier: Mapped[str] = mapped_column(String(32), primary_key=True)
    label: Mapped[str] = mapped_column(String(40), nullable=False)
    daily_scan_limit: Mapped[int | None] = mapped_column(Integer)
    monthly_price_vnd: Mapped[int | None] = mapped_column(Integer)
    yearly_price_vnd: Mapped[int | None] = mapped_column(Integer)
    features: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    plan_tier: Mapped[str] = mapped_column(ForeignKey("plans.tier"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    provider: Mapped[str | None] = mapped_column(String(80))
    provider_customer_id: Mapped[str | None] = mapped_column(String(200))
    provider_subscription_id: Mapped[str | None] = mapped_column(String(200))
    trial_ends_at: Mapped[object | None] = mapped_column(DateTime)
    renews_at: Mapped[object | None] = mapped_column(DateTime)
    canceled_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    user: Mapped[User] = relationship(back_populates="subscriptions")
    plan: Mapped[Plan] = relationship()


class DailyQuotaUsage(Base):
    __tablename__ = "daily_quota_usage"
    __table_args__ = (
        UniqueConstraint("user_id", "usage_day", name="uq_quota_user_day"),
        UniqueConstraint("api_key_id", "usage_day", name="uq_quota_api_key_day"),
        UniqueConstraint("anonymous_id", "usage_day", name="uq_quota_anonymous_day"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    api_key_id: Mapped[str | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"))
    anonymous_id: Mapped[str | None] = mapped_column(String(128))
    usage_day: Mapped[object] = mapped_column(Date, nullable=False)
    scan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ai_credit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ai_evaluation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ai_explanation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    deep_scan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    limit_snapshot: Mapped[int | None] = mapped_column(Integer)
    ai_limit_snapshot: Mapped[int | None] = mapped_column(Integer)
    deep_limit_snapshot: Mapped[int | None] = mapped_column(Integer)
    last_scan_at: Mapped[object | None] = mapped_column(DateTime)
    last_ai_at: Mapped[object | None] = mapped_column(DateTime)
    last_deep_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    api_key_id: Mapped[str | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"))
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    modality: Mapped[str] = mapped_column(String(32), nullable=False)
    normalized_url: Mapped[str | None] = mapped_column(Text)
    input_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    input_preview: Mapped[str | None] = mapped_column(Text)
    input_size_bytes: Mapped[int | None] = mapped_column(Integer)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str] = mapped_column(String(200), nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    schema_version: Mapped[str | None] = mapped_column(String(16))
    scoring_version: Mapped[str | None] = mapped_column(String(64))
    raw_score: Mapped[float | None] = mapped_column(Float)
    final_score: Mapped[float | None] = mapped_column(Float)
    risk_core_trace: Mapped[dict | None] = mapped_column(JSON)
    source_ip_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    extra_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, index=True, nullable=False)

    evidence: Mapped[list[ScanEvidence]] = relationship(
        back_populates="scan_event", cascade="all, delete-orphan"
    )


class ScanEvidence(Base):
    __tablename__ = "scan_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    scan_event_id: Mapped[str] = mapped_column(
        ForeignKey("scan_events.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="info", nullable=False)
    feature: Mapped[str | None] = mapped_column(String(160))
    contribution: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)

    scan_event: Mapped[ScanEvent] = relationship(back_populates="evidence")


class ReportShare(Base):
    """Revocable, expiring public view of a strictly redacted scan snapshot."""

    __tablename__ = "report_shares"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    scan_event_id: Mapped[str] = mapped_column(ForeignKey("scan_events.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    revoked_at: Mapped[object | None] = mapped_column(DateTime, index=True)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, index=True, nullable=False)


class AssessmentCache(Base):
    __tablename__ = "assessment_cache"

    cache_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    modality: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    response: Mapped[dict] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class URLTelemetryObservation(Base):
    """Minimal IOC observation; raw machine identifiers and system logs are excluded."""

    __tablename__ = "url_telemetry_observations"
    __table_args__ = (
        UniqueConstraint("sensor_hash", "event_id", name="uq_url_telemetry_sensor_event"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    api_key_id: Mapped[str | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL")
    )
    exact_url_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    campaign_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True, nullable=False)
    verdict: Mapped[str] = mapped_column(String(24), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(24), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    malware_family: Mapped[str | None] = mapped_column(String(120))
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    observed_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class ThreatFeedIndicator(Base):
    """Normalized public threat-feed IOC used for local private lookups."""

    __tablename__ = "threat_feed_indicators"
    __table_args__ = (
        UniqueConstraint("source", "exact_url_key", name="uq_threat_feed_source_url"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    source: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(160), index=True)
    indicator_type: Mapped[str] = mapped_column(String(24), default="url", nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False)
    exact_url_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    campaign_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True, nullable=False)
    verdict: Mapped[str] = mapped_column(String(24), default="malicious", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.9, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    extra_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    first_seen_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(DateTime, index=True, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class ThreatFeedSyncState(Base):
    """ETag, scheduling, and audit state for one configured feed."""

    __tablename__ = "threat_feed_sync_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="never", nullable=False)
    etag: Mapped[str | None] = mapped_column(String(255))
    last_modified: Mapped[str | None] = mapped_column(String(255))
    last_attempt_at: Mapped[object | None] = mapped_column(DateTime)
    last_success_at: Mapped[object | None] = mapped_column(DateTime, index=True)
    next_allowed_at: Mapped[object | None] = mapped_column(DateTime, index=True)
    records_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_upserted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class PaymentOrder(Base):
    __tablename__ = "payment_orders"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    reference: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    amount_vnd: Mapped[int] = mapped_column(Integer, nullable=False)
    credits: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # Null for sandbox-credit orders; set for a fixed subscription package.
    plan_tier: Mapped[str | None] = mapped_column(String(32), index=True)
    billing_period: Mapped[str | None] = mapped_column(String(16))
    expires_at: Mapped[object | None] = mapped_column(DateTime, index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(40), default="sepay", nullable=False)
    provider_transaction_id: Mapped[str | None] = mapped_column(String(160), unique=True)
    provider_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    paid_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class SandboxWallet(Base):
    __tablename__ = "sandbox_wallets"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    credits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[object] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class CloudSandboxSession(Base):
    __tablename__ = "cloud_sandbox_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="provisioning", index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(24), default="aws", nullable=False)
    sandbox_tier: Mapped[str] = mapped_column(String(24), default="pro", index=True, nullable=False)
    mode: Mapped[str] = mapped_column(String(16), default="auto", index=True, nullable=False)
    lease_minutes: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    provider_instance_id: Mapped[str | None] = mapped_column(String(100), unique=True)
    remote_url: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    agent_token_hash: Mapped[str | None] = mapped_column(String(64))
    remote_access_token_hash: Mapped[str | None] = mapped_column(String(64))
    remote_access_token_expires_at: Mapped[object | None] = mapped_column(DateTime)
    remote_access_token_used_at: Mapped[object | None] = mapped_column(DateTime)
    sample_filename: Mapped[str | None] = mapped_column(String(260))
    sample_storage_path: Mapped[str | None] = mapped_column(Text)
    sample_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    sample_size: Mapped[int | None] = mapped_column(Integer)
    sample_status: Mapped[str] = mapped_column(String(32), default="none", index=True, nullable=False)
    sample_report: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    sample_uploaded_at: Mapped[object | None] = mapped_column(DateTime)
    sample_completed_at: Mapped[object | None] = mapped_column(DateTime)
    ready_at: Mapped[object | None] = mapped_column(DateTime)
    lease_expires_at: Mapped[object | None] = mapped_column(DateTime)
    expires_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    termination_reason: Mapped[str | None] = mapped_column(String(32))
    termination_requested_at: Mapped[object | None] = mapped_column(DateTime)
    cleanup_completed_at: Mapped[object | None] = mapped_column(DateTime)
    terminated_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class SandboxRun(Base):
    __tablename__ = "sandbox_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    scan_event_id: Mapped[str | None] = mapped_column(ForeignKey("scan_events.id", ondelete="SET NULL"))
    sandbox_type: Mapped[str] = mapped_column(String(24), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    final_url: Mapped[str | None] = mapped_column(Text)
    execution_status: Mapped[str] = mapped_column(String(32), nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    resolved_ip: Mapped[str | None] = mapped_column(String(80))
    content_type: Mapped[str | None] = mapped_column(String(200))
    bytes_read: Mapped[int | None] = mapped_column(Integer)
    page_title: Mapped[str | None] = mapped_column(Text)
    elapsed_ms: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    tls: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    page_signals: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    redirects: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    issues: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    scan_steps: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    network_events: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    browser_events: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    canary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class AdminJob(Base):
    __tablename__ = "admin_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    job_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_step: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    spec_id: Mapped[str | None] = mapped_column(String(200), index=True)
    data_path: Mapped[str | None] = mapped_column(Text)
    models: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    started_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    started_at: Mapped[object | None] = mapped_column(DateTime)
    completed_at: Mapped[object | None] = mapped_column(DateTime)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class AdminJobEvent(Base):
    __tablename__ = "admin_job_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    job_id: Mapped[str] = mapped_column(ForeignKey("admin_jobs.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    extra_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    model_name: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    modality: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="candidate", index=True, nullable=False)
    artifact_uri: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_uri: Mapped[str | None] = mapped_column(Text)
    tokenizer_uri: Mapped[str | None] = mapped_column(Text)
    training_dataset_uri: Mapped[str | None] = mapped_column(Text)
    validation_dataset_uri: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    f1: Mapped[float | None] = mapped_column(Float)
    accuracy: Mapped[float | None] = mapped_column(Float)
    precision_score: Mapped[float | None] = mapped_column(Float)
    recall: Mapped[float | None] = mapped_column(Float)
    trained_by_job_id: Mapped[str | None] = mapped_column(ForeignKey("admin_jobs.id", ondelete="SET NULL"))
    promoted_at: Mapped[object | None] = mapped_column(DateTime)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_api_key_id: Mapped[str | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"))
    actor_channel: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    source_ip_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    extra_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)


class UserFeedback(Base):
    __tablename__ = "user_feedback"

    __table_args__ = (
        UniqueConstraint("user_id", "idempotency_key", name="uq_user_feedback_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    scan_event_id: Mapped[str] = mapped_column(ForeignKey("scan_events.id", ondelete="CASCADE"))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    label: Mapped[str] = mapped_column(String(40), nullable=False)
    reason: Mapped[str] = mapped_column(String(40), default="other", nullable=False)
    corrected_risk_level: Mapped[str | None] = mapped_column(String(32))
    comment: Mapped[str | None] = mapped_column(Text)
    comment_sha256: Mapped[str | None] = mapped_column(String(64))
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="received", nullable=False)
    admin_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )
