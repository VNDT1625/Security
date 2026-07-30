"""Provider-neutral TLS configuration assessment for Risk Core criterion 9.

Criterion 9 is about the transport configuration, not certificate identity or
certificate age.  Certificate validation failures belong to criterion 10 and a
newly issued certificate is not suspicious by itself.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from .types import CriterionStatus

CRITERION_ID = 9

__all__ = [
    "CRITERION_ID",
    "TLSConfigurationEvidence",
    "TLSConfigurationState",
    "evaluate_tls_configuration",
]


class TLSConfigurationState(StrEnum):
    ABNORMAL = "abnormal"
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class TLSConfigurationEvidence:
    """Deterministic result ready for the Risk Core observation adapter."""

    state: TLSConfigurationState
    status: CriterionStatus
    summary: str
    finding_type: str | None = None
    severity: float = 0.0
    evidence_quality: float = 0.0
    protocols: tuple[str, ...] = ()
    ciphers: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()
    source: str = "sandbox_tls"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_risk(self) -> bool:
        return self.state is TLSConfigurationState.ABNORMAL

    @property
    def checked(self) -> bool:
        return self.state in {
            TLSConfigurationState.ABNORMAL,
            TLSConfigurationState.HEALTHY,
        }


_PROTOCOL_KEYS = (
    "protocol",
    "version",
    "tls_version",
    "negotiated_protocol",
    "supported_protocols",
    "enabled_protocols",
    "protocols",
)
_CIPHER_KEYS = (
    "cipher",
    "cipher_suite",
    "negotiated_cipher",
    "supported_ciphers",
    "enabled_ciphers",
    "cipher_suites",
    "ciphers",
)

_OBSOLETE_PROTOCOLS = {
    "SSL2",
    "SSL20",
    "SSLV2",
    "SSLV20",
    "SSL3",
    "SSL30",
    "SSLV3",
    "SSLV30",
    "TLS1",
    "TLS10",
    "TLSV1",
    "TLSV10",
    "TLS11",
    "TLSV11",
}

_WEAK_CIPHER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?:^|[_-])NULL(?:$|[_-])", re.I), "null_encryption"),
    (re.compile(r"(?:^|[_-])EXPORT(?:$|[_-])", re.I), "export_cipher"),
    (re.compile(r"(?:^|[_-])RC4(?:$|[_-])", re.I), "rc4_cipher"),
    (re.compile(r"(?:^|[_-])(?:3DES|DES3|DES-CBC3)(?:$|[_-])", re.I), "3des_cipher"),
    (
        re.compile(r"(?:^|[_-])DES(?:$|[_-])(?!EDE|CBC3)", re.I),
        "single_des_cipher",
    ),
    (re.compile(r"(?:^|[_-])(?:ADH|AECDH|ANON)(?:$|[_-])", re.I), "anonymous_cipher"),
    (re.compile(r"(?:^|[_-])MD5(?:$|[_-])", re.I), "md5_cipher"),
)


def evaluate_tls_configuration(
    *,
    facts: Mapping[str, Any] | None = None,
    tls: Mapping[str, Any] | None = None,
    source: str = "sandbox_tls",
    unavailable_reason: str | None = None,
) -> TLSConfigurationEvidence:
    """Assess supplied TLS facts without making network requests.

    ``facts`` may be the complete sandbox result and ``tls`` may be its TLS
    sub-dictionary.  An explicit ``tls`` argument takes precedence.  Only
    observed configuration facts are evaluated; certificate age, issuer,
    hostname matching, expiry and chain validity are intentionally ignored.
    """

    fact_map = facts if isinstance(facts, Mapping) else {}
    tls_map = tls if isinstance(tls, Mapping) else _nested_tls(fact_map)
    scheme = _observed_scheme(fact_map)

    if scheme == "http":
        return TLSConfigurationEvidence(
            state=TLSConfigurationState.NOT_APPLICABLE,
            status=CriterionStatus.NOT_APPLICABLE,
            summary=(
                "The observed URL did not use TLS; criterion 8 covers the missing "
                "HTTPS transport."
            ),
            source=source,
            metadata={"criterion_id": CRITERION_ID, "scheme": scheme},
        )

    protocols = _collect_values(tls_map, _PROTOCOL_KEYS)
    ciphers = _collect_values(tls_map, _CIPHER_KEYS)
    issues = _configuration_issues(tls_map, protocols, ciphers)
    has_configuration_fact = bool(protocols or ciphers or _feature_facts_present(tls_map))

    metadata: dict[str, Any] = {
        "criterion_id": CRITERION_ID,
        "scheme": scheme or None,
        "protocols": list(protocols),
        "ciphers": list(ciphers),
    }

    if issues:
        metadata["issues"] = list(issues)
        severity = _severity(issues)
        return TLSConfigurationEvidence(
            state=TLSConfigurationState.ABNORMAL,
            # Weak TLS is a security defect, not proof of malicious intent.
            status=CriterionStatus.SUSPICIOUS,
            summary="Unsafe TLS configuration observed: " + ", ".join(issues) + ".",
            finding_type="tls_configuration_abnormal",
            severity=severity,
            evidence_quality=_evidence_quality(tls_map, protocols, ciphers),
            protocols=protocols,
            ciphers=ciphers,
            issues=issues,
            source=source,
            metadata=metadata,
        )

    if not has_configuration_fact:
        return TLSConfigurationEvidence(
            state=TLSConfigurationState.UNAVAILABLE,
            status=CriterionStatus.UNAVAILABLE,
            summary=(
                unavailable_reason
                or "The sandbox returned no protocol, cipher, or TLS feature facts."
            ),
            source=source,
            metadata=metadata,
        )

    return TLSConfigurationEvidence(
        state=TLSConfigurationState.HEALTHY,
        status=CriterionStatus.CLEAN,
        summary="No unsafe TLS configuration was observed in the supplied scan facts.",
        evidence_quality=_evidence_quality(tls_map, protocols, ciphers),
        protocols=protocols,
        ciphers=ciphers,
        source=source,
        metadata=metadata,
    )


def _nested_tls(facts: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("tls", "tls_configuration", "ssl"):
        value = facts.get(key)
        if isinstance(value, Mapping):
            return value
    for key in ("response", "sandbox", "http", "result"):
        nested = facts.get(key)
        if isinstance(nested, Mapping):
            value = _nested_tls(nested)
            if value:
                return value
    return {}


def _observed_scheme(facts: Mapping[str, Any]) -> str:
    explicit = facts.get("scheme")
    if isinstance(explicit, str) and explicit.lower() in {"http", "https"}:
        return explicit.lower()
    for key in ("final_url", "normalized_url", "url", "requested_url"):
        value = facts.get(key)
        if isinstance(value, str):
            scheme = urlsplit(value).scheme.lower()
            if scheme in {"http", "https"}:
                return scheme
    return ""


def _collect_values(tls: Mapping[str, Any], keys: Sequence[str]) -> tuple[str, ...]:
    values: list[str] = []
    for key in keys:
        raw = tls.get(key)
        for value in _flatten_strings(raw):
            stripped = value.strip()
            if stripped and stripped not in values:
                values.append(stripped)
    return tuple(values)


def _flatten_strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        result: list[str] = []
        for key, enabled in value.items():
            if enabled is True and isinstance(key, str):
                result.append(key)
        return tuple(result)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if (
            len(value) == 3
            and isinstance(value[0], str)
            and isinstance(value[1], str)
            and isinstance(value[2], int)
        ):
            # Python's SSLSocket.cipher() shape: (name, protocol, secret_bits).
            return (value[0],)
        result = []
        for item in value:
            if isinstance(item, str):
                result.append(item)
            elif (
                isinstance(item, Sequence)
                and not isinstance(item, (str, bytes, bytearray))
                and item
                and isinstance(item[0], str)
            ):
                result.append(item[0])
        return tuple(result)
    return ()


def _normalise_protocol(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def _configuration_issues(
    tls: Mapping[str, Any],
    protocols: tuple[str, ...],
    ciphers: tuple[str, ...],
) -> tuple[str, ...]:
    issues: list[str] = []
    for protocol in protocols:
        if _normalise_protocol(protocol) in _OBSOLETE_PROTOCOLS:
            _append_unique(issues, f"obsolete_protocol:{protocol}")
    for cipher in ciphers:
        for pattern, label in _WEAK_CIPHER_PATTERNS:
            if pattern.search(cipher):
                _append_unique(issues, f"{label}:{cipher}")
                break

    if _is_true(tls, "compression", "tls_compression", "compression_enabled"):
        _append_unique(issues, "tls_compression_enabled")
    if _is_true(tls, "insecure_renegotiation", "unsafe_renegotiation"):
        _append_unique(issues, "insecure_renegotiation")
    if _is_explicit_false(tls, "secure_renegotiation") and not _tls13_only(protocols):
        _append_unique(issues, "secure_renegotiation_disabled")
    if _is_true(tls, "heartbleed_vulnerable", "vulnerable_to_heartbleed", "heartbleed"):
        _append_unique(issues, "heartbleed_vulnerable")
    return tuple(issues)


def _feature_facts_present(tls: Mapping[str, Any]) -> bool:
    return any(
        key in tls
        for key in (
            "compression",
            "tls_compression",
            "compression_enabled",
            "insecure_renegotiation",
            "unsafe_renegotiation",
            "secure_renegotiation",
            "heartbleed_vulnerable",
            "vulnerable_to_heartbleed",
            "heartbleed",
        )
    )


def _tls13_only(protocols: tuple[str, ...]) -> bool:
    normalised = {_normalise_protocol(protocol) for protocol in protocols}
    return bool(normalised) and normalised <= {"TLS13", "TLSV13"}


def _is_true(values: Mapping[str, Any], *keys: str) -> bool:
    return any(values.get(key) is True for key in keys)


def _is_explicit_false(values: Mapping[str, Any], *keys: str) -> bool:
    return any(key in values and values[key] is False for key in keys)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _severity(issues: tuple[str, ...]) -> float:
    if any(
        issue.startswith(("obsolete_protocol:SSL", "heartbleed_vulnerable", "null_encryption"))
        for issue in issues
    ):
        return 1.0
    if any(
        issue.startswith(("export_cipher", "rc4_cipher", "single_des_cipher"))
        for issue in issues
    ):
        return 0.9
    return 0.75


def _evidence_quality(
    tls: Mapping[str, Any],
    protocols: tuple[str, ...],
    ciphers: tuple[str, ...],
) -> float:
    explicit_inventory = any(
        key in tls
        for key in (
            "supported_protocols",
            "enabled_protocols",
            "protocols",
            "supported_ciphers",
            "enabled_ciphers",
            "cipher_suites",
            "ciphers",
        )
    )
    if explicit_inventory and protocols and ciphers:
        return 1.0
    if explicit_inventory:
        return 0.9
    if protocols and ciphers:
        return 0.8
    return 0.65
