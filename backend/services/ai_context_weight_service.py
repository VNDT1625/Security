"""Persistent global controls for URL scoring and URL-result caching."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.models import SystemSetting, UserAIContextSetting
from backend.security_utils import utcnow

AI_CONTEXT_WEIGHT_KEY = "ai_context_weight_percent"
AI_CONTEXT_WEIGHT_MIN_KEY = "ai_context_weight_min_percent"
AI_CONTEXT_WEIGHT_MAX_KEY = "ai_context_weight_max_percent"
AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT = 100
AI_CONTEXT_WEIGHT_MAX_PERCENT = 40
AI_CONTEXT_WEIGHT_DEFAULT_PERCENT = 0
AI_CONTEXT_WEIGHT_ELIGIBLE_TIERS = frozenset({"pro", "team", "enterprise"})
URL_ASSESSMENT_CACHE_ENABLED_KEY = "url_assessment_cache_enabled"
THREAT_FEED_SCHEDULER_ENABLED_KEY = "threat_feed_scheduler_enabled"
THREAT_FEED_OPENPHISH_ENABLED_KEY = "threat_feed_openphish_enabled"
OPERATIONAL_MAINTENANCE_SCHEDULER_ENABLED_KEY = "operational_maintenance_scheduler_enabled"


def normalize_ai_context_weight(
    value: int, *, minimum: int = 0, maximum: int = AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT
) -> int:
    return max(minimum, min(maximum, int(value)))


def get_ai_context_weight_policy(db: Session) -> dict[str, int]:
    minimum_record = db.get(SystemSetting, AI_CONTEXT_WEIGHT_MIN_KEY)
    maximum_record = db.get(SystemSetting, AI_CONTEXT_WEIGHT_MAX_KEY)
    minimum = normalize_ai_context_weight(minimum_record.value if minimum_record else 0)
    maximum = normalize_ai_context_weight(
        maximum_record.value if maximum_record else AI_CONTEXT_WEIGHT_MAX_PERCENT
    )
    if minimum > maximum:
        minimum = maximum
    default_record = db.get(SystemSetting, AI_CONTEXT_WEIGHT_KEY)
    default = normalize_ai_context_weight(
        default_record.value if default_record else AI_CONTEXT_WEIGHT_DEFAULT_PERCENT,
        minimum=minimum,
        maximum=maximum,
    )
    return {"minPercent": minimum, "maxPercent": maximum, "percent": default}


def get_ai_context_weight_percent(db: Session) -> int:
    return get_ai_context_weight_policy(db)["percent"]


def get_effective_ai_context_weight_percent(
    db: Session, *, user_id: str | None, plan_tier: str
) -> int:
    """Resolve the runtime weight. AI weighting is a paid-plan capability."""

    if plan_tier not in AI_CONTEXT_WEIGHT_ELIGIBLE_TIERS:
        return 0
    policy = get_ai_context_weight_policy(db)
    record = db.get(UserAIContextSetting, user_id) if user_id else None
    selected = record.weight_percent if record is not None else policy["percent"]
    return normalize_ai_context_weight(
        selected, minimum=policy["minPercent"], maximum=policy["maxPercent"]
    )


def get_user_ai_context_weight_payload(
    db: Session, *, user_id: str, plan_tier: str
) -> dict[str, int | bool | str]:
    policy = get_ai_context_weight_policy(db)
    record = db.get(UserAIContextSetting, user_id)
    eligible = plan_tier in AI_CONTEXT_WEIGHT_ELIGIBLE_TIERS
    selected = record.weight_percent if record is not None else policy["percent"]
    selected = normalize_ai_context_weight(
        selected, minimum=policy["minPercent"], maximum=policy["maxPercent"]
    )
    return {
        **policy,
        "weightPercent": selected if eligible else 0,
        "weightEligible": eligible,
        "weightSource": "account" if eligible and record is not None else "global",
    }


def set_user_ai_context_weight_percent(
    db: Session, *, user_id: str, plan_tier: str, percent: int, commit: bool = True
) -> int:
    validate_user_ai_context_weight_percent(
        db, plan_tier=plan_tier, percent=percent
    )
    record = db.get(UserAIContextSetting, user_id)
    if record is None:
        db.add(UserAIContextSetting(user_id=user_id, weight_percent=int(percent)))
    else:
        record.weight_percent = int(percent)
        record.updated_at = utcnow()
    if commit:
        db.commit()
    else:
        db.flush()
    return int(percent)


def validate_user_ai_context_weight_percent(
    db: Session, *, plan_tier: str, percent: int
) -> None:
    if plan_tier not in AI_CONTEXT_WEIGHT_ELIGIBLE_TIERS:
        raise PermissionError("Trọng số AI riêng yêu cầu gói Pro hoặc cao hơn.")
    policy = get_ai_context_weight_policy(db)
    if not policy["minPercent"] <= int(percent) <= policy["maxPercent"]:
        raise ValueError(
            f"Trọng số AI phải từ {policy['minPercent']} đến {policy['maxPercent']}."
        )


def set_ai_context_weight_percent(
    db: Session,
    percent: int,
    *,
    updated_by_user_id: str | None,
) -> int:
    policy = get_ai_context_weight_policy(db)
    value = normalize_ai_context_weight(
        percent, minimum=policy["minPercent"], maximum=policy["maxPercent"]
    )
    setting = db.get(SystemSetting, AI_CONTEXT_WEIGHT_KEY)
    if setting is None:
        setting = SystemSetting(
            key=AI_CONTEXT_WEIGHT_KEY,
            value=value,
            updated_by_user_id=updated_by_user_id,
        )
        db.add(setting)
    else:
        setting.value = value
        setting.updated_by_user_id = updated_by_user_id
        setting.updated_at = utcnow()
    db.commit()
    return value


def set_ai_context_weight_policy(
    db: Session,
    *,
    percent: int,
    min_percent: int,
    max_percent: int,
    updated_by_user_id: str | None,
) -> dict[str, int]:
    minimum = int(min_percent)
    maximum = int(max_percent)
    default = int(percent)
    if not 0 <= minimum <= maximum <= AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT:
        raise ValueError("Biên trọng số phải thỏa 0 ≤ min ≤ max ≤ 100.")
    if not minimum <= default <= maximum:
        raise ValueError("Trọng số mặc định phải nằm trong biên min/max.")
    for key, value in (
        (AI_CONTEXT_WEIGHT_MIN_KEY, minimum),
        (AI_CONTEXT_WEIGHT_MAX_KEY, maximum),
        (AI_CONTEXT_WEIGHT_KEY, default),
    ):
        setting = db.get(SystemSetting, key)
        if setting is None:
            db.add(SystemSetting(key=key, value=value, updated_by_user_id=updated_by_user_id))
        else:
            setting.value = value
            setting.updated_by_user_id = updated_by_user_id
            setting.updated_at = utcnow()
    db.commit()
    return {"minPercent": minimum, "maxPercent": maximum, "percent": default}


def get_url_assessment_cache_enabled(db: Session, *, default: bool) -> bool:
    setting = db.get(SystemSetting, URL_ASSESSMENT_CACHE_ENABLED_KEY)
    if setting is None:
        return bool(default)
    return bool(setting.value)


def set_url_assessment_cache_enabled(
    db: Session,
    enabled: bool,
    *,
    updated_by_user_id: str | None,
) -> bool:
    setting = db.get(SystemSetting, URL_ASSESSMENT_CACHE_ENABLED_KEY)
    value = int(bool(enabled))
    if setting is None:
        setting = SystemSetting(
            key=URL_ASSESSMENT_CACHE_ENABLED_KEY,
            value=value,
            updated_by_user_id=updated_by_user_id,
        )
        db.add(setting)
    else:
        setting.value = value
        setting.updated_by_user_id = updated_by_user_id
        setting.updated_at = utcnow()
    db.commit()
    return bool(value)


def _get_boolean_setting(db: Session, key: str, *, default: bool) -> bool:
    setting = db.get(SystemSetting, key)
    return bool(default) if setting is None else bool(setting.value)


def _set_boolean_setting(
    db: Session,
    key: str,
    enabled: bool,
    *,
    updated_by_user_id: str | None,
) -> bool:
    setting = db.get(SystemSetting, key)
    value = int(bool(enabled))
    if setting is None:
        db.add(SystemSetting(key=key, value=value, updated_by_user_id=updated_by_user_id))
    else:
        setting.value = value
        setting.updated_by_user_id = updated_by_user_id
        setting.updated_at = utcnow()
    db.commit()
    return bool(value)


def get_operational_switches(
    db: Session,
    *,
    threat_feed_scheduler_default: bool,
    openphish_default: bool,
    maintenance_scheduler_default: bool,
) -> dict[str, bool]:
    """Return runtime-controllable background jobs with env values as fallback."""

    return {
        "threatFeedSchedulerEnabled": _get_boolean_setting(
            db,
            THREAT_FEED_SCHEDULER_ENABLED_KEY,
            default=threat_feed_scheduler_default,
        ),
        "openphishEnabled": _get_boolean_setting(
            db,
            THREAT_FEED_OPENPHISH_ENABLED_KEY,
            default=openphish_default,
        ),
        "operationalMaintenanceSchedulerEnabled": _get_boolean_setting(
            db,
            OPERATIONAL_MAINTENANCE_SCHEDULER_ENABLED_KEY,
            default=maintenance_scheduler_default,
        ),
    }


def set_operational_switches(
    db: Session,
    *,
    threat_feed_scheduler_enabled: bool,
    openphish_enabled: bool,
    operational_maintenance_scheduler_enabled: bool,
    updated_by_user_id: str | None,
) -> dict[str, bool]:
    """Persist the three runtime controls used by the Admin console."""

    return {
        "threatFeedSchedulerEnabled": _set_boolean_setting(
            db,
            THREAT_FEED_SCHEDULER_ENABLED_KEY,
            threat_feed_scheduler_enabled,
            updated_by_user_id=updated_by_user_id,
        ),
        "openphishEnabled": _set_boolean_setting(
            db,
            THREAT_FEED_OPENPHISH_ENABLED_KEY,
            openphish_enabled,
            updated_by_user_id=updated_by_user_id,
        ),
        "operationalMaintenanceSchedulerEnabled": _set_boolean_setting(
            db,
            OPERATIONAL_MAINTENANCE_SCHEDULER_ENABLED_KEY,
            operational_maintenance_scheduler_enabled,
            updated_by_user_id=updated_by_user_id,
        ),
    }
