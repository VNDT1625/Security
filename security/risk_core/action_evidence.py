"""Action evidence collection, normalization and event-aware deduplication."""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

from .action_config import ActionRiskConfig
from .action_types import (
    ActionRiskInput,
    EvidenceCategory,
    EvidenceGroup,
    EvidenceRelationship,
    EvidenceSource,
    SecurityEvidence,
)


@dataclass(frozen=True)
class ActionClassification:
    sensitive: bool
    credential: bool
    otp: bool
    transfer: bool
    external_destination: bool | None
    destination_authorized: bool | None
    privileged: bool
    irreversible: bool
    workflow_approved: bool
    intent_match_score: float | None


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _destination_state(target_url: str | None, assets: tuple[str, ...]) -> tuple[bool | None, bool | None, str]:
    if not target_url:
        return None, None, ""
    try:
        parsed = urlsplit(target_url)
    except ValueError:
        return None, None, ""
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None, None, ""
    external = True
    if host == "localhost":
        external = False
    else:
        try:
            external = ipaddress.ip_address(host).is_global
        except ValueError:
            external = not host.endswith((".local", ".internal"))
    approved_hosts = {
        item.split(":", 1)[1].lower().rstrip(".")
        for item in assets
        if item.lower().startswith("approved_destination:") and ":" in item
    }
    authorized = host in approved_hosts or any(host.endswith(f".{item}") for item in approved_hosts)
    return external, authorized, _fingerprint(host)


def _intent_match(action_type: str, user_intent: str | None, planned_action: str | None) -> float | None:
    source = " ".join(item for item in (user_intent, planned_action) if item).lower()
    if not source:
        return None
    aliases = {
        "submit_form": ("submit", "form", "gửi biểu mẫu", "đăng nhập"),
        "send_email": ("send", "email", "mail", "gửi thư"),
        "upload_file": ("upload", "tải lên", "gửi tệp"),
        "call_api": ("api", "request", "gọi"),
        "execute_file": ("execute", "run", "chạy", "thực thi"),
        "payment_or_transfer": ("payment", "transfer", "thanh toán", "chuyển tiền"),
        "copy_data": ("copy", "sao chép"),
        "download_file": ("download", "tải xuống"),
        "open_url": ("open", "visit", "mở", "truy cập"),
        "click_link": ("click", "nhấp"),
        "open_file": ("open", "mở tệp"),
    }
    words = aliases.get(action_type, (action_type.replace("_", " "),))
    return 1.0 if any(word in source for word in words) else 0.15


def classify_action(value: ActionRiskInput, config: ActionRiskConfig) -> ActionClassification:
    data_types = {item.strip().lower() for item in value.data_types if item.strip()}
    external, authorized, _ = _destination_state(value.target_url, value.available_assets)
    workflow_approved = any(
        item.lower().startswith("approved_workflow:")
        and value.workflow_id
        and item.split(":", 1)[1] == value.workflow_id
        for item in value.available_assets
    )
    return ActionClassification(
        sensitive=bool(data_types & config.sensitive_types),
        credential=bool(data_types & config.credential_types),
        otp=bool(data_types & config.otp_types),
        transfer=value.action_type in config.transfer_actions,
        external_destination=external,
        destination_authorized=authorized,
        privileged=value.action_type in config.privileged_actions
        or (value.permission_level or "").lower() in {"admin", "root", "system"},
        irreversible=value.action_type in config.irreversible_actions,
        workflow_approved=workflow_approved,
        intent_match_score=_intent_match(
            value.action_type, value.user_intent, value.planned_action
        ),
    )


def _evidence(
    value: ActionRiskInput,
    category: EvidenceCategory,
    suffix: str,
    severity: float,
    reliability: float,
    reason_code: str,
    summary: str,
    *,
    relationship: EvidenceRelationship = EvidenceRelationship.INDEPENDENT_RISK,
    direct: bool = False,
    metadata: dict | None = None,
) -> SecurityEvidence:
    return SecurityEvidence(
        id=f"{value.action_id}:{suffix}",
        category=category,
        event_id=value.action_id,
        source=EvidenceSource.ACTION_RULE,
        severity=severity,
        reliability=reliability,
        relationship=relationship,
        direct=direct,
        reason_code=reason_code,
        summary=summary,
        metadata=dict(metadata or {}),
    )


def collect_action_evidence(
    value: ActionRiskInput,
    config: ActionRiskConfig,
) -> tuple[list[SecurityEvidence], list[str], list[str], ActionClassification]:
    """Collect structured facts; never infer a critical floor from raw keywords."""
    classification = classify_action(value, config)
    evidence: list[SecurityEvidence] = []
    missing: list[str] = []
    rules: list[str] = []
    data_types = {item.strip().lower() for item in value.data_types if item.strip()}
    permission = (value.permission_level or "").strip().lower()
    external, authorized, destination_hash = _destination_state(
        value.target_url, value.available_assets
    )

    if classification.credential:
        rules.append("credential-data-classified")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.CREDENTIAL_ACCESS,
                "credential-access",
                70,
                0.90,
                "SECRET_READ",
                "Hành động có truy cập dữ liệu xác thực đã được phân loại.",
                relationship=EvidenceRelationship.SAME_EVENT,
            )
        )
    if classification.otp:
        rules.append("otp-data-classified")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.SENSITIVE_DATA_ACCESS,
                "otp-access",
                72,
                0.90,
                "OTP_READ",
                "Hành động có truy cập mã xác thực dùng một lần đã được phân loại.",
                relationship=EvidenceRelationship.SAME_EVENT,
            )
        )
    elif classification.sensitive:
        rules.append("sensitive-data-classified")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.SENSITIVE_DATA_ACCESS,
                "sensitive-access",
                55,
                0.82,
                "SENSITIVE_DATA_ACCESS",
                "Hành động xử lý dữ liệu nhạy cảm.",
                relationship=EvidenceRelationship.SAME_EVENT,
            )
        )

    if classification.transfer:
        if external is None:
            missing.append("destination")
        elif external:
            rules.append("external-transfer")
            evidence.append(
                _evidence(
                    value,
                    EvidenceCategory.EXTERNAL_TRANSFER,
                    "external-transfer",
                    62,
                    0.90,
                    "EXTERNAL_TRANSFER",
                    "Dữ liệu hoặc tác vụ được chuyển tới một đích bên ngoài.",
                    metadata={"destination_hash": destination_hash},
                )
            )
        if not data_types:
            missing.extend(["payload_classification", "data_sensitivity"])

    if classification.intent_match_score is None:
        missing.append("user_intent")
    elif classification.intent_match_score < 0.5:
        rules.append("intent-mismatch")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.INTENT_MISMATCH,
                "intent-mismatch",
                58,
                0.72,
                "INTENT_MISMATCH",
                "Hành động dự kiến không khớp rõ với ý định đã khai báo.",
            )
        )

    if (classification.sensitive or classification.privileged) and not permission:
        missing.append("permission_context")
    if value.legal_review_required:
        missing.append("legal_context")
        rules.append("legal-review-required")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.MISSING_CONTEXT,
                "legal-review-required",
                20,
                0.90,
                "LEGAL_REVIEW_REQUIRED",
                "Chưa có đủ căn cứ pháp lý để tự động cho phép hành động.",
            )
        )
    if classification.transfer and external and authorized is False:
        rules.append("unauthorized-destination")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.POLICY_VIOLATION,
                "unauthorized-destination",
                72,
                0.88 if permission else 0.60,
                "UNAUTHORIZED_EXTERNAL_TRANSFER",
                "Đích bên ngoài chưa nằm trong phạm vi được cấp phép.",
                metadata={"destination_hash": destination_hash},
            )
        )

    if value.destination_risk_score is not None:
        destination_score = max(0.0, min(100.0, value.destination_risk_score))
        if destination_score >= 20:
            rules.append("destination-risk")
            evidence.append(
                _evidence(
                    value,
                    EvidenceCategory.DESTINATION_REPUTATION,
                    "destination-risk",
                    destination_score,
                    max(0.25, min(1.0, value.destination_confidence or 0.50)),
                    "UNTRUSTED_DESTINATION",
                    "Lõi URL ghi nhận rủi ro tại đích nhận.",
                    metadata={"destination_hash": destination_hash},
                )
            )

    # Direct floors require a complete, structured behavior pattern. A word in
    # a URL, prompt or document never sets these flags.
    confirmed_unauthorized = permission in {"none", "denied", "restricted", "untrusted"}
    confirmed_external_transfer = (
        classification.transfer
        and external is True
        and authorized is False
        and confirmed_unauthorized
    )
    if classification.credential and confirmed_external_transfer:
        rules.append("confirmed-credential-exfiltration")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.CREDENTIAL_EXFILTRATION,
                "confirmed-credential-exfiltration",
                100,
                0.98,
                "CONFIRMED_CREDENTIAL_EXFILTRATION",
                "Dữ liệu xác thực đang được truyền tới đích ngoài không được cấp phép.",
                direct=True,
                metadata={
                    "confirmed": True,
                    "direct_kind": "confirmed_credential_exfiltration",
                    "destination_hash": destination_hash,
                },
            )
        )
    if classification.otp and confirmed_external_transfer:
        rules.append("confirmed-otp-exfiltration")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.OTP_EXPOSURE,
                "confirmed-otp-exfiltration",
                100,
                0.98,
                "CONFIRMED_OTP_EXFILTRATION",
                "Mã xác thực dùng một lần đang được truyền tới đích ngoài không được cấp phép.",
                direct=True,
                metadata={
                    "confirmed": True,
                    "direct_kind": "confirmed_otp_exfiltration",
                    "destination_hash": destination_hash,
                },
            )
        )
    if value.action_type == "execute_file" and "confirmed_malware" in data_types:
        rules.append("confirmed-malware-execution")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.MALWARE_EXECUTION,
                "confirmed-malware-execution",
                100,
                0.98,
                "CONFIRMED_MALWARE_EXECUTION",
                "Một tệp đã được xác nhận là mã độc đang được thực thi.",
                direct=True,
                metadata={"confirmed": True, "direct_kind": "confirmed_malware_execution"},
            )
        )
    destructive = data_types & config.confirmed_destructive_types
    if value.action_type in {"execute_file", "call_api"} and destructive:
        kind = (
            "confirmed_mass_encryption_or_deletion"
            if destructive & {"confirmed_mass_deletion", "confirmed_mass_encryption"}
            else "confirmed_destructive_system_command"
        )
        rules.append(kind.replace("_", "-"))
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.DESTRUCTIVE_ACTION,
                kind,
                100,
                0.98,
                "CONFIRMED_DESTRUCTIVE_ACTION",
                "Một hành động phá hủy đã được xác nhận đang được thực hiện.",
                direct=True,
                metadata={"confirmed": True, "direct_kind": kind},
            )
        )
    if "confirmed_privilege_escalation" in data_types:
        rules.append("confirmed-privilege-escalation")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.PRIVILEGE_ESCALATION,
                "confirmed-privilege-escalation",
                100,
                0.98,
                "CONFIRMED_PRIVILEGE_ESCALATION",
                "Hành vi nâng quyền trái phép đã được xác nhận.",
                direct=True,
                metadata={
                    "confirmed": True,
                    "direct_kind": "confirmed_privilege_escalation",
                },
            )
        )

    if value.action_type in {"execute_file", "open_file"} and not data_types:
        missing.append("payload_classification")
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.UNKNOWN_PAYLOAD,
                "unknown-payload",
                35,
                0.65,
                "UNKNOWN_PAYLOAD",
                "Không có kết quả phân loại tệp hoặc nội dung sẽ được mở.",
            )
        )

    for name in sorted(set(missing)):
        evidence.append(
            _evidence(
                value,
                EvidenceCategory.MISSING_CONTEXT,
                f"missing-{name}",
                20,
                1.0,
                f"MISSING_{name.upper()}",
                f"Thiếu trường ngữ cảnh bắt buộc: {name}.",
                relationship=EvidenceRelationship.SUPPORTING_EVIDENCE,
                metadata={"field": name},
            )
        )
    return evidence, sorted(set(missing)), sorted(set(rules)), classification


def normalize_evidence(items: list[SecurityEvidence]) -> list[SecurityEvidence]:
    """Clamp and deterministically remove exact duplicates."""
    unique: dict[str, SecurityEvidence] = {}
    for item in items:
        normalized = SecurityEvidence(
            id=item.id,
            category=EvidenceCategory(item.category),
            event_id=item.event_id,
            source=EvidenceSource(item.source),
            severity=max(0.0, min(100.0, float(item.severity))),
            reliability=max(0.0, min(1.0, float(item.reliability))),
            relationship=EvidenceRelationship(item.relationship),
            direct=bool(item.direct),
            reason_code=str(item.reason_code),
            summary=str(item.summary),
            metadata=dict(item.metadata),
        )
        prior = unique.get(normalized.id)
        if prior is None or (
            normalized.severity * normalized.reliability
            > prior.severity * prior.reliability
        ):
            unique[normalized.id] = normalized
    return sorted(unique.values(), key=lambda item: (item.category.value, item.event_id, item.id))


def _soft_or(scores: list[float]) -> float:
    remainder = 1.0
    for score in scores:
        remainder *= 1.0 - max(0.0, min(100.0, score)) / 100.0
    return 100.0 * (1.0 - remainder)


def deduplicate_evidence(
    items: list[SecurityEvidence],
    config: ActionRiskConfig,
) -> tuple[list[SecurityEvidence], list[EvidenceGroup]]:
    """Collapse same-event detectors while preserving independent risks."""
    by_event: dict[tuple[EvidenceCategory, str], list[SecurityEvidence]] = defaultdict(list)
    for item in normalize_evidence(items):
        by_event[(item.category, item.event_id)].append(item)

    retained: list[SecurityEvidence] = []
    groups: list[EvidenceGroup] = []
    for (category, event_id), group in sorted(
        by_event.items(), key=lambda value: (value[0][0].value, value[0][1])
    ):
        same = [
            item
            for item in group
            if item.relationship == EvidenceRelationship.SAME_EVENT
        ]
        supporting = [
            item
            for item in group
            if item.relationship == EvidenceRelationship.SUPPORTING_EVIDENCE
        ]
        independent = [
            item
            for item in group
            if item.relationship == EvidenceRelationship.INDEPENDENT_RISK
        ]
        primary_pool = same or supporting
        strongest = max(
            primary_pool or independent,
            key=lambda item: (item.severity * item.reliability, item.id),
        )
        if same:
            retained.append(strongest)
        support_bonus = min(
            config.supporting_bonus_cap,
            sum(item.severity * item.reliability for item in supporting)
            * config.supporting_bonus_ratio,
        )
        if supporting:
            retained.append(
                max(
                    supporting,
                    key=lambda item: (item.severity * item.reliability, item.id),
                )
            )
        retained.extend(independent)
        base = strongest.severity * strongest.reliability + support_bonus
        independent_scores = [
            item.severity * item.reliability
            for item in independent
            if item.id != strongest.id
        ]
        score = _soft_or([min(100.0, base), *independent_scores])
        groups.append(
            EvidenceGroup(
                category=category,
                event_id=event_id,
                score=round(score, 4),
                evidence_ids=tuple(sorted(item.id for item in group)),
                reason_codes=tuple(
                    sorted({item.reason_code for item in group if item.reason_code})
                ),
                strongest_evidence_id=strongest.id,
            )
        )
    deduplicated = {item.id: item for item in retained}
    return (
        sorted(
            deduplicated.values(),
            key=lambda item: (item.category.value, item.event_id, item.id),
        ),
        groups,
    )
