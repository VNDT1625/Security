"""CoreGuide v2 criterion registry and conservative observation-to-evidence adapters.

Every criterion has an explicit implementation. A detector only emits risk when its
required observation is present; missing data becomes NOT_CHECKED/UNAVAILABLE rather
than a fabricated clean verdict.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from .brand_content import assess_brand_content
from .business_content import (
    BusinessAssessment,
    assess_business_address,
    assess_business_email,
    assess_coercive_content,
    assess_content_quality,
    assess_legal_identity,
    assess_privacy_policy,
    assess_promotion_claim,
    assess_terms_refund,
)
from .config import RiskConfig
from .contact_information import assess_contact_information
from .domain_lifecycle import evaluate_domain_lifecycle
from .normalization import make_finding_key, make_incident_key, normalize_url
from .owner_identity import assess_owner_identity
from .redirect_chain import assess_redirect_chain
from .registrar_identity import assess_registrar_identity
from .tls_configuration import evaluate_tls_configuration
from .types import CriterionStatus, EvidenceV2, MatchedSubject, ProviderVerdict


@dataclass
class ScanObservations:
    url: str
    findings: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    completed: set[int] = field(default_factory=set)
    unavailable: dict[int, str] = field(default_factory=dict)
    not_applicable: dict[int, str] = field(default_factory=dict)

    def risk(
        self,
        criterion_id: int,
        finding_type: str,
        severity: float,
        quality: float,
        summary: str,
        *,
        source: str = "internal",
        incident: str = "scan",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.completed.add(criterion_id)
        self.findings.setdefault(criterion_id, []).append(
            {
                "finding_type": finding_type,
                "severity": severity,
                "quality": quality,
                "summary": summary,
                "source": source,
                "incident": incident,
                "metadata": metadata or {},
            }
        )

    def clean(self, *criterion_ids: int) -> None:
        self.completed.update(criterion_ids)


def _replace_assessment(
    obs: ScanObservations,
    criterion_id: int,
    assessment: BusinessAssessment,
    *,
    source: str,
) -> None:
    obs.findings.pop(criterion_id, None)
    obs.completed.discard(criterion_id)
    obs.not_applicable.pop(criterion_id, None)
    if assessment.status == "not_applicable":
        obs.not_applicable[criterion_id] = assessment.summary
    elif assessment.status == "clean":
        obs.clean(criterion_id)
    else:
        obs.risk(
            criterion_id,
            assessment.finding_type or "business_content_risk",
            assessment.severity,
            assessment.quality,
            assessment.summary,
            source=source,
            metadata=assessment.metadata,
        )


def build_criteria_evidence(observations: ScanObservations, config: RiskConfig) -> list[EvidenceV2]:
    """Produce one auditable status/evidence record for all criteria 1..50."""
    keys = normalize_url(observations.url)
    output: list[EvidenceV2] = []
    for criterion in config.criteria:
        cid = criterion.criterion_id
        findings = observations.findings.get(cid, [])
        if findings:
            for index, finding in enumerate(findings):
                finding_type = str(finding["finding_type"])
                severity = max(0.0, min(1.0, float(finding["severity"])))
                quality = max(0.0, min(1.0, float(finding["quality"])))
                source = str(finding.get("source", "internal"))
                output.append(
                    _evidence(
                        keys,
                        cid,
                        source,
                        finding_type,
                        CriterionStatus.MALICIOUS
                        if severity >= 0.75
                        else CriterionStatus.SUSPICIOUS,
                        ProviderVerdict.MALICIOUS
                        if severity >= 0.75
                        else ProviderVerdict.SUSPICIOUS,
                        severity,
                        quality,
                        str(finding["summary"]),
                        index,
                        str(finding.get("incident", "scan")),
                        dict(finding.get("metadata", {})),
                    )
                )
            continue
        if cid in observations.not_applicable:
            output.append(
                _status(
                    keys,
                    cid,
                    CriterionStatus.NOT_APPLICABLE,
                    observations.not_applicable[cid],
                    applicability=True,
                )
            )
        elif cid in observations.completed or cid == 50:
            output.append(
                _status(keys, cid, CriterionStatus.CLEAN, "Check completed without a risk finding.")
            )
        elif cid in observations.unavailable:
            output.append(
                _status(keys, cid, CriterionStatus.UNAVAILABLE, observations.unavailable[cid])
            )
        else:
            output.append(
                _status(
                    keys,
                    cid,
                    CriterionStatus.NOT_CHECKED,
                    "Required observation was not collected in this scan mode.",
                )
            )
    return output


def add_offline_url_findings(obs: ScanObservations, legacy_evidence: list[Any]) -> None:
    mapping = {
        "punycode_domain": 6,
        "homoglyph": 6,
        "high_entropy_domain": 6,
        "brand_domain_mismatch": 5,
        "brand_typosquatting": 5,
        "deceptive_subdomain": 7,
        "excessive_subdomains": 7,
        "no_https": 8,
        "risky_tld": 12,
        # A deceptive tenant on a shared platform is a URL/subdomain signal.
        # It is not evidence that unrelated malicious sites share the same IP.
        "shared_hosting_abuse_context": 7,
        "is_shortlink": 17,
        "redirect_parameter": 18,
        "nested_url_redirect": 16,
        "ip_host": 18,
        "long_url": 18,
        "credential_theft_intent": 29,
        "credential_lure_cluster": 29,
        "brand_credential_lure_combination": 29,
        "suspicious_keywords": 29,
        "dangerous_download": 34,
        "disguised_executable_download": 34,
        "archive_download_lure": 34,
        "url_obfuscation": 18,
        "at_symbol": 18,
        "embedded_credentials": 18,
        "nonstandard_port": 18,
        "excessive_query_parameters": 18,
        # A very confident URL-classifier verdict is a reputation-style signal, so
        # it lands on criterion 12 ("Uy tín tên miền thấp"). It is scoped to the
        # URL path only: this mapper is reached exclusively from assess_url, so
        # the email, SMS and prompt modes are unaffected.
        "model_high_confidence_phishing": 12,
    }
    checked = {5, 6, 7, 8, 12, 16, 17, 18, 29, 34}
    obs.clean(*checked)
    severity = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "info": 0.0}
    for item in legacy_evidence:
        cid = mapping.get(item.feature or "")
        if cid and (item.contribution or 0) > 0:
            obs.risk(
                cid,
                item.feature,
                severity[item.severity.value],
                0.8 if item.source == "url_risk_core" else 0.5,
                item.message,
                source="internal_url",
            )


def add_domain_intelligence(obs: ScanObservations, intelligence: Any) -> None:
    if not intelligence.available:
        for cid in (1, 11, 12):
            obs.unavailable[cid] = "Domain intelligence providers unavailable."
        for cid in (2, 3, 4, 42):
            obs.not_applicable[cid] = (
                "No public registration/history record was available for this domain; "
                "the scanner did not infer a value."
            )
        return
    if getattr(intelligence, "registration_available", False) and intelligence.age_days is not None:
        obs.clean(1)
    else:
        obs.unavailable[1] = (
            getattr(intelligence, "registration_error", None)
            or "The registration date was unavailable from WHOIS/RDAP providers."
        )
    lifecycle = evaluate_domain_lifecycle(
        expires_at=getattr(intelligence, "expires_at", None),
        expiry_days=getattr(intelligence, "expiry_days", None),
        source=str(getattr(intelligence, "registration_source", "") or "domain_registration"),
        unavailable_reason=getattr(intelligence, "registration_error", None),
    )
    if not lifecycle.checked:
        obs.unavailable[2] = lifecycle.summary
    elif lifecycle.is_risk:
        obs.risk(
            2,
            lifecycle.finding_type or "domain_lifecycle_abnormal",
            lifecycle.severity,
            lifecycle.evidence_quality,
            lifecycle.summary,
            source=lifecycle.source,
            metadata=lifecycle.metadata,
        )
    else:
        obs.clean(2)
    # Certificate issuance age is contextual metadata only. Criterion 9 is
    # completed from negotiated TLS protocol/cipher facts in the HTTP sandbox.
    if getattr(intelligence, "registrant", None):
        obs.clean(3)
    else:
        obs.not_applicable[3] = (
            "Registrant identity is privacy-redacted or not published by the registry."
        )
    registrar_names = tuple(getattr(intelligence, "registrar_candidates", ()) or ())
    if not registrar_names:
        registrar_names = (getattr(intelligence, "registrar", None),)
    registrar_assessment = assess_registrar_identity(registrar_names)
    if registrar_assessment.status == "unavailable":
        obs.unavailable[4] = registrar_assessment.summary
    elif registrar_assessment.status == "conflict":
        obs.risk(
            4,
            "registrar_identity_conflict",
            0.75,
            0.9,
            registrar_assessment.summary,
            source="registration_cross_check",
            metadata={"registrars": list(registrar_assessment.names)},
        )
    else:
        obs.clean(4)
    if intelligence.listed is None:
        obs.unavailable[11] = "Public reputation history was unavailable."
        obs.unavailable[12] = "Public domain reputation was unavailable."
        obs.not_applicable[42] = "No public website-history source returned an observation."
    else:
        obs.clean(11, 12, 42)
    if (
        getattr(intelligence, "registration_available", False)
        and intelligence.age_days is not None
        and intelligence.age_days < 180
    ):
        severity = (
            1.0 if intelligence.age_days < 30 else 0.75 if intelligence.age_days < 90 else 0.5
        )
        obs.risk(
            1,
            "young_domain",
            severity,
            0.8,
            f"Domain age is {intelligence.age_days} days (verified by registration intelligence).",
            source="domain_intelligence",
        )
    if intelligence.listed:
        obs.risk(
            11,
            "public_malicious_listing",
            1.0,
            0.8,
            "Public reputation intelligence reports a malicious exact domain result.",
            source=intelligence.reputation_source,
        )
        malicious_count = int(
            getattr(intelligence, "malicious_observations", 0) or 0
        )
        if malicious_count >= 2:
            obs.risk(
                12,
                "repeated_malicious_domain_history",
                0.65,
                0.85,
                (
                    "Public reputation history contains "
                    f"{malicious_count} malicious observations for this domain."
                ),
                source=intelligence.reputation_source,
                metadata={"malicious_observations": malicious_count},
            )
        obs.risk(
            42,
            "historical_public_abuse",
            1.0,
            0.8,
            (
                "Public scan history contains malicious observations for this domain "
                f"({getattr(intelligence, 'malicious_observations', 1)} records)."
            ),
            source=intelligence.reputation_source,
        )


def add_structured_observations(obs: ScanObservations, values: dict[str, Any]) -> None:
    """Map validated adapter observations to every CoreGuide criterion.

    Adapters supply booleans/numbers plus provenance; absent keys remain not_checked.
    A truthy risk key activates its criterion, while an explicit false completes it cleanly.
    This keeps detection semantics centralized without pretending unavailable data is safe.
    """
    specs: dict[int, tuple[str, str, float, float]] = {
        2: ("domain_lifecycle_abnormal", "abnormal_domain_lifecycle", 0.75, 0.8),
        3: ("owner_identity_conflict", "owner_identity_conflict", 0.75, 0.8),
        4: ("registrar_abuse_rate_high", "registrar_abuse_rate_high", 0.75, 0.8),
        9: ("tls_configuration_abnormal", "tls_configuration_abnormal", 0.75, 1.0),
        10: ("certificate_invalid", "certificate_invalid", 1.0, 1.0),
        12: ("domain_reputation_low", "domain_reputation_low", 0.75, 0.8),
        13: ("ip_reputation_low", "ip_reputation_low", 0.75, 0.8),
        14: ("server_location_conflict", "server_location_conflict", 0.75, 0.8),
        15: ("malicious_hosting_density", "malicious_hosting_density", 0.75, 0.8),
        19: ("brand_content_impersonation", "brand_content_impersonation", 1.0, 0.8),
        20: ("contact_information_invalid", "contact_information_invalid", 0.75, 0.8),
        21: ("business_email_mismatch", "business_email_mismatch", 0.75, 0.8),
        22: ("business_address_invalid", "business_address_invalid", 0.75, 0.8),
        23: ("legal_identity_conflict", "legal_identity_conflict", 1.0, 1.0),
        24: ("privacy_policy_missing", "privacy_policy_missing", 0.5, 1.0),
        25: ("terms_refund_missing", "terms_refund_missing", 0.5, 1.0),
        26: ("content_identity_conflict", "content_identity_conflict", 0.75, 0.8),
        27: ("price_outlier", "price_outlier", 0.75, 0.8),
        28: ("coercive_content", "coercive_content", 0.75, 1.0),
        29: ("sensitive_data_request", "sensitive_data_request", 1.0, 1.0),
        30: ("untrusted_sensitive_form", "untrusted_sensitive_form", 1.0, 1.0),
        31: ("irreversible_payment_risk", "irreversible_payment_risk", 0.75, 0.8),
        32: ("payee_identity_mismatch", "payee_identity_mismatch", 1.0, 1.0),
        33: ("unnecessary_browser_permission", "unnecessary_browser_permission", 0.75, 1.0),
        34: ("dangerous_download", "dangerous_download", 1.0, 1.0),
        35: ("malicious_javascript_behavior", "malicious_javascript_behavior", 1.0, 1.0),
        36: ("risky_third_party_script", "risky_third_party_script", 0.75, 1.0),
        37: ("deceptive_popup", "deceptive_popup", 0.75, 1.0),
        38: ("malvertising_behavior", "malvertising_behavior", 1.0, 1.0),
        39: ("impersonating_copied_content", "impersonating_copied_content", 0.75, 0.8),
        40: ("forged_image_asset", "forged_image_asset", 0.75, 0.8),
        41: ("social_identity_conflict", "social_identity_conflict", 0.75, 0.8),
        42: ("historical_abuse", "historical_abuse", 1.0, 0.8),
        43: ("abrupt_content_repurpose", "abrupt_content_repurpose", 0.75, 0.8),
        44: ("abnormal_dns_churn", "abnormal_dns_churn", 0.75, 0.8),
        45: ("email_security_conflict", "email_security_conflict", 0.75, 1.0),
        46: ("brand_metadata_mismatch", "brand_metadata_mismatch", 0.75, 1.0),
        47: ("support_channel_invalid", "support_channel_invalid", 0.75, 0.8),
        48: ("verified_user_complaints", "verified_user_complaints", 0.75, 0.8),
        49: ("review_manipulation", "review_manipulation", 0.75, 0.8),
    }
    source = str(values.get("source", "structured_adapter"))
    incident = str(values.get("incident", "structured_scan"))
    summaries = values.get("summaries", {})
    for cid, (key, finding, default_severity, default_quality) in specs.items():
        if key not in values:
            continue
        value = values[key]
        obs.clean(cid)
        if value is False or value is None or value == 0:
            continue
        detail = value if isinstance(value, dict) else {}
        severity = float(detail.get("severity", default_severity))
        quality = float(detail.get("quality", default_quality))
        summary = str(detail.get("summary") or summaries.get(key) or finding.replace("_", " "))
        metadata = {k: v for k, v in detail.items() if k not in {"severity", "quality", "summary"}}
        obs.risk(
            cid,
            finding,
            severity,
            quality,
            summary,
            source=source,
            incident=str(detail.get("incident", incident)),
            metadata=metadata,
        )


def mark_context_applicability(
    obs: ScanObservations,
    *,
    commercial: bool | None = None,
    uses_business_email: bool | None = None,
) -> None:
    if commercial is False:
        for cid in (20, 21, 22, 23, 24, 25, 27, 31, 32, 47):
            obs.not_applicable[cid] = "Verified non-commercial website context."
    if uses_business_email is False:
        obs.not_applicable[45] = "No business-email use was observed."


def add_dns_intelligence(obs: ScanObservations, intelligence: Any) -> None:
    """Add current DNS posture; churn remains unavailable until historical snapshots exist."""
    if not intelligence.available:
        reason = "; ".join(intelligence.errors[:3]) or "DNS provider unavailable."
        obs.not_applicable[44] = f"No public DNS baseline could be established: {reason}"
        obs.unavailable[45] = reason
        return
    # The cross-source history collector replaces this baseline state once a
    # previous local fingerprint exists.
    obs.not_applicable[44] = "First DNS snapshot stored as a local comparison baseline."
    if not intelligence.mx:
        obs.not_applicable[45] = "No MX record was observed; business email security is not applicable."
        return
    obs.clean(45)
    # DKIM selectors are chosen by each mail provider. Failing to find the
    # conventional ``default`` selector is not evidence that DKIM is absent.
    missing = [
        name
        for name, present in (("SPF", intelligence.spf), ("DMARC", intelligence.dmarc))
        if not present
    ]
    if missing:
        severity = 0.6 if len(missing) >= 2 else 0.35
        obs.risk(45, "weak_email_security", severity, 0.8,
                 "Missing or unobserved email controls: " + ", ".join(missing) + ".",
                 source="cloudflare_dns")


def add_http_sandbox(obs: ScanObservations, report: Any) -> None:
    # Static HTTP/HTML inspection cannot verify runtime permission, popup or JS
    # behaviour checks. Those belong to the browser sandbox.
    covered = {
        8, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        36, 39, 41, 46, 47, 48, 49,
    }
    if not report.ok:
        reason = report.issues[0].message if report.issues else "HTTP sandbox unavailable."
        for cid in covered:
            obs.unavailable[cid] = reason
        redirect_issues = [
            issue
            for issue in report.issues
            if issue.code in {"redirect_loop", "too_many_redirects"}
        ]
        if redirect_issues:
            issue = redirect_issues[0]
            obs.risk(
                16,
                issue.code,
                0.7,
                1.0,
                issue.message,
                source="http_sandbox",
            )
        certificate_issues = [
            issue for issue in report.issues if issue.code == "tls_certificate_error"
        ]
        if certificate_issues:
            issue = certificate_issues[0]
            obs.risk(
                10,
                issue.code,
                1.0,
                1.0,
                issue.message,
                source="http_sandbox",
                metadata={"detail": getattr(issue, "detail", "")},
            )
        else:
            obs.unavailable[10] = reason
        obs.unavailable[9] = (
            "TLS configuration could not be negotiated because the HTTP sandbox failed."
        )
        return
    obs.clean(*covered)
    tls_result = evaluate_tls_configuration(
        facts={
            "url": str(getattr(report, "url", "") or ""),
            "final_url": str(getattr(report, "final_url", "") or ""),
        },
        tls=report.tls if isinstance(report.tls, dict) else {},
        source="http_sandbox_tls",
    )
    if tls_result.state.value == "not_applicable":
        obs.not_applicable[9] = tls_result.summary
        obs.not_applicable[10] = "The observed URL did not use TLS, so no certificate was presented."
    elif tls_result.state.value == "unavailable":
        obs.unavailable[9] = tls_result.summary
        # A successful verified HTTPS request is still concrete evidence that
        # certificate validation completed, even if cipher facts were absent.
        obs.clean(10)
    elif tls_result.is_risk:
        obs.risk(
            9,
            tls_result.finding_type or "tls_configuration_abnormal",
            min(tls_result.severity, 0.7),
            tls_result.evidence_quality,
            tls_result.summary,
            source=tls_result.source,
            metadata=tls_result.metadata,
        )
        obs.clean(10)
    else:
        obs.clean(9, 10)
    signals = report.page_signals if isinstance(report.page_signals, dict) else {}
    commercial = bool(signals.get("is_commercial"))
    mark_context_applicability(obs, commercial=commercial)
    redirect_result = assess_redirect_chain(
        str(getattr(report, "url", "") or obs.url),
        redirects=getattr(report, "redirects", ()) or (),
        final_url=str(getattr(report, "final_url", "") or ""),
    )
    if redirect_result.status == "suspicious":
        obs.risk(
            16,
            redirect_result.finding_type or "observed_redirect_anomaly",
            redirect_result.severity,
            redirect_result.quality,
            redirect_result.summary,
            source="http_sandbox",
            metadata=redirect_result.metadata,
        )
    if redirect_result.shortlink_expanded and not obs.findings.get(17):
        obs.risk(
            17,
            "shortlink_expanded",
            0.35,
            1.0,
            "The sandbox expanded a shortened URL to its final destination.",
            source="http_sandbox",
            metadata=redirect_result.metadata,
        )

    contact = assess_contact_information(
        commercial=commercial,
        emails=signals.get("emails", ()) or (),
        phones=signals.get("phones", ()) or (),
        support_links=signals.get("support_links", ()) or (),
    )
    obs.findings.pop(20, None)
    obs.completed.discard(20)
    obs.not_applicable.pop(20, None)
    if contact.status == "not_applicable":
        obs.not_applicable[20] = contact.summary
    elif contact.status == "clean":
        obs.clean(20)
    else:
        obs.risk(
            20,
            contact.finding_type or "contact_information_missing_or_invalid",
            contact.severity,
            contact.quality,
            contact.summary,
            source="http_sandbox",
            metadata=contact.metadata,
        )
    _replace_assessment(
        obs,
        21,
        assess_business_email(
            str(getattr(report, "final_url", "") or getattr(report, "url", "") or obs.url),
            commercial=commercial,
            emails=signals.get("emails", ()) or (),
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        22,
        assess_business_address(
            commercial=commercial,
            addresses=signals.get("addresses", ()) or (),
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        23,
        assess_legal_identity(
            commercial=commercial,
            legal_names=signals.get("legal_names", ()) or (),
            business_ids=signals.get("business_ids", ()) or (),
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        24,
        assess_privacy_policy(
            collects_sensitive_data=bool(signals.get("collects_sensitive_data")),
            privacy_links=signals.get("privacy_policy_links", ()) or (),
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        25,
        assess_terms_refund(
            commercial=commercial,
            terms_links=signals.get("terms_links", ()) or (),
            refund_links=signals.get("refund_links", ()) or (),
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        26,
        assess_content_quality(
            word_count=int(signals.get("word_count") or 0),
            unique_word_ratio=(
                float(signals["unique_word_ratio"])
                if signals.get("unique_word_ratio") is not None
                else None
            ),
            placeholder_hits=signals.get("placeholder_hits", ()) or (),
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        27,
        assess_promotion_claim(
            int(signals["max_discount_percent"])
            if signals.get("max_discount_percent") is not None
            else None
        ),
        source="http_sandbox",
    )
    _replace_assessment(
        obs,
        28,
        assess_coercive_content(
            urgency_hits=signals.get("urgency_hits", ()) or (),
            sensitive_context=bool(signals.get("collects_sensitive_data")),
            transaction_context=bool(
                signals.get("payment_methods")
                or signals.get("payment_recipient_hints")
                or signals.get("prices")
            ),
            external_form=bool(signals.get("external_form_actions")),
        ),
        source="http_sandbox",
    )
    if commercial and not signals.get("payment_methods"):
        obs.not_applicable[31] = "No payment method was presented on this page."
    if commercial and not signals.get("payment_recipient_hints"):
        obs.not_applicable[32] = "No payment recipient was presented on this page."
    if not signals.get("social_links"):
        obs.not_applicable[41] = "No social profile was linked from the inspected page."
    obs.not_applicable[39] = (
        "No curated copied-content reference matched this page; no similarity was inferred."
    )
    if not signals.get("review_context"):
        obs.not_applicable[48] = "No public review or complaint context was present."
        obs.not_applicable[49] = "No public review context was present."
    if not signals.get("metadata") and not getattr(report, "page_title", ""):
        obs.not_applicable[46] = "No title or identity metadata was present."
    issue_map = {
        "tls_certificate_error": 10,
        "meta_refresh": 16,
        "external_iframe": 36,
        "irreversible_payment_method": 31,
        "unverified_payment_recipient": 32,
        "metadata_identity_mismatch": 46,
        "invalid_support_channel": 47,
        "user_complaint_signal": 48,
        "review_manipulation_pattern": 49,
    }
    issue_codes = {issue.code for issue in report.issues}
    legacy_external_sensitive_form = (
        "external_form_action" in issue_codes
        and "password_form" in issue_codes
    )
    if (
        "urgency_language" in issue_codes
        and (
            "external_form_action" in issue_codes
            or "password_form" in issue_codes
            or commercial
        )
    ):
        obs.risk(
            28,
            "coercive_action_context",
            0.7,
            0.9,
            "Urgency language is coupled with a transaction, password, or external-form action.",
            source="http_sandbox",
        )
    if "secret_recovery_request" in issue_codes:
        obs.risk(
            29,
            "high_risk_secret_request",
            1.0,
            1.0,
            "The page requests a wallet recovery phrase or private key.",
            source="http_sandbox",
        )
    # Password, OTP and card fields are common on legitimate sites. They become
    # an actionable finding when submitted to a different origin.
    if "external_sensitive_form_action" in issue_codes or legacy_external_sensitive_form:
        obs.risk(
            29,
            "sensitive_form_with_external_destination",
            0.95,
            1.0,
            "A sensitive form submits credentials or payment identifiers to a different origin.",
            source="http_sandbox",
        )
        obs.risk(
            30,
            "untrusted_sensitive_form_destination",
            1.0,
            1.0,
            "A sensitive form submits data to a different origin.",
            source="http_sandbox",
        )
    for issue in report.issues:
        cid = issue_map.get(issue.code)
        if cid:
            sev = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35}.get(
                issue.severity.value, 0.5
            )
            obs.risk(cid, issue.code, sev, 1.0, issue.message, source="http_sandbox")


def add_browser_sandbox(obs: ScanObservations, report: Any) -> None:
    covered = {16, 19, 28, 29, 30, 33, 34, 35, 36, 37, 38, 39, 40, 41, 46, 48, 49}
    if not report.ok:
        reason = report.issues[0].message if report.issues else "Browser sandbox unavailable."
        for cid in covered:
            obs.unavailable[cid] = reason
        return
    obs.clean(*covered)
    identity = report.page_identity if isinstance(report.page_identity, dict) else {}
    visual = report.visual_analysis if isinstance(report.visual_analysis, dict) else {}
    if visual.get("status") == "no_reference":
        obs.not_applicable[19] = "No curated brand visual reference is installed for this page."
        obs.not_applicable[40] = "No curated image reference is installed for forgery comparison."
    brand_content = assess_brand_content(
        str(getattr(report, "final_url", "") or getattr(report, "url", "") or obs.url),
        title=str(getattr(report, "page_title", "") or ""),
        site_name=str(identity.get("site_name") or ""),
        legal_names=tuple(identity.get("legal_names", ()) or ()),
        password_fields=int(identity.get("password_fields") or 0),
        sensitive_fields=int(identity.get("sensitive_fields") or 0),
    )
    if brand_content.status == "clean":
        obs.not_applicable.pop(19, None)
        obs.clean(19)
    elif brand_content.status == "suspicious":
        obs.not_applicable.pop(19, None)
        obs.risk(
            19,
            brand_content.finding_type or "brand_content_impersonation",
            brand_content.severity,
            brand_content.quality,
            brand_content.summary,
            source="browser_identity",
            metadata=brand_content.metadata,
        )

    contact = assess_contact_information(
        commercial=bool(identity.get("is_commercial")),
        emails=identity.get("emails", ()) or (),
        phones=identity.get("phones", ()) or (),
        support_links=identity.get("support_links", ()) or (),
    )
    if contact.status == "not_applicable":
        obs.not_applicable[20] = contact.summary
    elif contact.status == "clean":
        obs.not_applicable.pop(20, None)
        obs.findings.pop(20, None)
        obs.clean(20)
    else:
        obs.not_applicable.pop(20, None)
        obs.risk(
            20,
            contact.finding_type or "contact_information_missing_or_invalid",
            contact.severity,
            contact.quality,
            contact.summary,
            source="browser_identity",
            metadata=contact.metadata,
        )
    if not identity.get("social_links"):
        obs.not_applicable[41] = "No social profile was linked from the rendered page."
    obs.not_applicable[39] = (
        "No curated copied-content reference matched this rendered page."
    )
    review_context = bool(
        identity.get("review_elements")
        or identity.get("rating_mentions")
        or identity.get("structured_ratings")
    )
    if not review_context:
        obs.not_applicable[48] = "No public review or complaint context was rendered."
        obs.not_applicable[49] = "No public review context was rendered."
    if not identity.get("site_name") and not getattr(report, "page_title", ""):
        obs.not_applicable[46] = "No rendered title or site identity metadata was present."
    issue_map = {
        "canary_exfiltration_blocked": 35,
        "private_network_request_blocked": 35,
        "websocket_request_blocked": 35,
        "visual_brand_impersonation": 19,
        "permission_request_blocked": 33,
        "download_attempt_blocked": 34,
        "deceptive_popup": 37,
        "malvertising_behavior": 38,
        "forged_brand_image": 40,
    }
    issue_codes = {issue.code for issue in report.issues}
    credential_field = bool(
        {"otp_input_detected", "password_input_detected"} & issue_codes
    ) or bool(identity.get("sensitive_fields"))
    credential_exposure = bool(
        {
            "cross_origin_form_action",
            "canary_exfiltration_blocked",
            "visual_brand_impersonation",
        }
        & issue_codes
    )
    if credential_field and credential_exposure:
        obs.risk(
            29,
            "credential_field_with_deception_or_exfiltration",
            0.95,
            1.0,
            "A password or OTP field is correlated with impersonation or cross-origin data exposure.",
            source="browser_sandbox",
        )
    if credential_field and "cross_origin_form_action" in issue_codes:
        obs.risk(
            30,
            "untrusted_sensitive_form_destination",
            1.0,
            1.0,
            "A rendered sensitive form submits to a different origin.",
            source="browser_sandbox",
        )
    for issue in report.issues:
        cid = issue_map.get(issue.code)
        if cid:
            sev = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35}.get(
                issue.severity.value, 0.5
            )
            obs.risk(cid, issue.code, sev, 1.0, issue.message, source="browser_sandbox")


def add_cross_source_intelligence(
    obs: ScanObservations,
    *,
    domain_intelligence: Any = None,
    dns_intelligence: Any = None,
    ip_intelligence: Any = None,
    sandbox_reports: tuple[tuple[object, bool], ...] = (),
    history_store: Any = None,
) -> None:
    """Complete checks that require facts from more than one collector."""
    browser_report = next((report for report, browser in sandbox_reports if browser), None)
    http_report = next((report for report, browser in sandbox_reports if not browser), None)
    identity = (
        browser_report.page_identity
        if browser_report is not None and isinstance(browser_report.page_identity, dict)
        else {}
    )
    page_signals = (
        http_report.page_signals
        if http_report is not None and isinstance(http_report.page_signals, dict)
        else {}
    )
    commercial = bool(identity.get("is_commercial") or page_signals.get("is_commercial"))
    if browser_report is not None or http_report is not None:
        mark_context_applicability(obs, commercial=commercial)

    _add_ip_reputation_and_location(
        obs,
        domain_intelligence=domain_intelligence,
        dns_intelligence=dns_intelligence,
        ip_intelligence=ip_intelligence,
        identity=identity,
    )
    _add_identity_comparison(
        obs,
        domain_intelligence=domain_intelligence,
        identity=identity,
        commercial=commercial,
    )
    _add_local_history(
        obs,
        dns_intelligence=dns_intelligence,
        browser_report=browser_report,
        http_report=http_report,
        identity=identity,
        history_store=history_store,
    )


def _add_ip_reputation_and_location(
    obs: ScanObservations,
    *,
    domain_intelligence: Any,
    dns_intelligence: Any,
    ip_intelligence: Any,
    identity: dict[str, Any],
) -> None:
    addresses = list(getattr(dns_intelligence, "addresses", ()) or ())
    primary_ip = str(getattr(ip_intelligence, "ip", "") or (addresses[0] if addresses else ""))
    reputation_ips = set(getattr(domain_intelligence, "reputation_ips", ()) or ())
    malicious_ips = set(getattr(domain_intelligence, "malicious_ips", ()) or ())
    if primary_ip and primary_ip in reputation_ips:
        obs.clean(13)
        if primary_ip in malicious_ips:
            obs.risk(
                13,
                "malicious_ip_in_public_scan_history",
                0.9,
                0.8,
                "The current server IP appears in malicious public scan observations.",
                source=getattr(domain_intelligence, "reputation_source", "public_scan_history"),
                metadata={"ip": primary_ip},
            )
    else:
        obs.unavailable[13] = (
            "Public scan history did not return an observation for the current IP."
        )

    edge_network = _is_shared_edge_network(ip_intelligence)
    shared_available = bool(
        getattr(domain_intelligence, "shared_hosting_available", False)
    )
    shared_domains = tuple(
        getattr(domain_intelligence, "shared_malicious_domains", ()) or ()
    )
    shared_observations = int(
        getattr(domain_intelligence, "shared_malicious_observations", 0) or 0
    )
    if edge_network:
        obs.not_applicable[15] = (
            "The IP belongs to a shared CDN/edge provider; co-hosted domains are not attributed "
            "to this website."
        )
    elif not shared_available:
        obs.unavailable[15] = "Reverse-IP malicious-hosting history was unavailable."
    else:
        obs.clean(15)
        if len(shared_domains) >= 3 and shared_observations >= 3:
            obs.risk(
                15,
                "malicious_shared_hosting_context",
                0.65,
                0.8,
                (
                    f"The current IP has malicious observations for "
                    f"{len(shared_domains)} other domains."
                ),
                source="urlscan_reverse_ip",
                metadata={
                    "ip": primary_ip,
                    "distinct_malicious_domains": list(shared_domains[:20]),
                    "malicious_observations": shared_observations,
                },
            )

    declared_country = _declared_country(identity.get("addresses", []))
    server_country = str(getattr(ip_intelligence, "country_code", "") or "").upper()
    if not declared_country:
        obs.not_applicable[14] = "The page did not publish a business country for comparison."
    elif not server_country:
        obs.not_applicable[14] = "Server country enrichment was not available."
    elif edge_network:
        obs.not_applicable[14] = (
            "The server uses shared CDN/edge infrastructure, so GeoIP is not an origin-location fact."
        )
    else:
        if declared_country != server_country:
            obs.not_applicable[14] = (
                f"Context only: published business country {declared_country} differs from "
                f"server GeoIP country {server_country}; this is not scored as malicious."
            )
        else:
            obs.not_applicable[14] = (
                f"Context only: published business and server GeoIP country are both {server_country}."
            )


def _is_shared_edge_network(ip_intelligence: Any) -> bool:
    identity = " ".join(
        str(getattr(ip_intelligence, field, "") or "")
        for field in ("as_name", "isp")
    ).casefold()
    return any(
        marker in identity
        for marker in (
            "akamai",
            "amazon cloudfront",
            "cloudflare",
            "fastly",
            "github",
            "google cloud",
            "microsoft azure",
            "netlify",
            "vercel",
        )
    )


def _add_identity_comparison(
    obs: ScanObservations,
    *,
    domain_intelligence: Any,
    identity: dict[str, Any],
    commercial: bool,
) -> None:
    registrant = str(getattr(domain_intelligence, "registrant", "") or "")
    legal_names = [str(value) for value in identity.get("legal_names", []) if value]
    owner = assess_owner_identity(
        registrant or None,
        structured_legal_names=legal_names,
    )
    obs.completed.discard(3)
    obs.findings.pop(3, None)
    obs.not_applicable.pop(3, None)
    obs.unavailable.pop(3, None)
    if owner.status == "not_applicable":
        obs.not_applicable[3] = owner.evidence[0].summary
    elif owner.status == "clean":
        obs.clean(3)
    elif owner.status == "suspicious":
        finding = owner.evidence[0]
        obs.risk(
            3,
            finding.finding_type,
            finding.severity,
            finding.quality,
            finding.summary,
            source=finding.source,
            metadata=dict(finding.metadata),
        )
    # NOT_CHECKED intentionally leaves criterion 3 without a fabricated verdict.

    if owner.status == "suspicious":
        obs.not_applicable.pop(3, None)
        obs.risk(
            23,
            "legal_identity_conflict",
            owner.evidence[0].severity,
            owner.evidence[0].quality,
            owner.evidence[0].summary,
            source=owner.evidence[0].source,
        )
    if not commercial:
        obs.not_applicable[23] = "Verified non-commercial website context."
    elif legal_names:
        obs.not_applicable.pop(23, None)
        obs.clean(23)


def _add_local_history(
    obs: ScanObservations,
    *,
    dns_intelligence: Any,
    browser_report: Any,
    http_report: Any,
    identity: dict[str, Any],
    history_store: Any,
) -> None:
    domain = str(getattr(dns_intelligence, "domain", "") or "")
    if not domain or history_store is None:
        obs.not_applicable[43] = "Local content history is not available for comparison."
        return
    visual = (
        browser_report.visual_analysis
        if browser_report is not None and isinstance(browser_report.visual_analysis, dict)
        else {}
    )
    page_signals = (
        http_report.page_signals
        if http_report is not None and isinstance(http_report.page_signals, dict)
        else {}
    )
    title = str(
        getattr(browser_report, "page_title", "")
        or getattr(http_report, "page_title", "")
        or ""
    )
    comparison = history_store.observe(
        domain,
        {
            "dns": {
                "addresses": list(getattr(dns_intelligence, "addresses", ()) or ()),
                "nameservers": list(getattr(dns_intelligence, "nameservers", ()) or ()),
                "mx": list(getattr(dns_intelligence, "mx", ()) or ()),
            },
            "content": {
                "fingerprint": identity.get("content_fingerprint")
                or page_signals.get("content_fingerprint")
                or "",
                "title": title,
                "site_name": identity.get("site_name") or "",
                "visual_hash": visual.get("dhash64") or "",
            },
        },
    )
    if comparison.dns_observations >= 2:
        obs.not_applicable.pop(44, None)
        obs.clean(44)
        if comparison.dns_changed and comparison.dns_distinct_snapshots >= 3:
            obs.risk(
                44,
                "abnormal_dns_churn",
                0.75,
                0.8,
                (
                    "DNS fingerprint changed repeatedly across "
                    f"{comparison.dns_observations} local observations."
                ),
                source="local_scan_history",
            )
    if comparison.content_observations < 2:
        obs.not_applicable[43] = "First rendered-content fingerprint stored as a baseline."
    else:
        obs.not_applicable.pop(43, None)
        obs.clean(43)
        if comparison.content_changed and comparison.title_changed:
            obs.risk(
                43,
                "abrupt_content_repurpose",
                0.75,
                0.8,
                "Rendered content and page title both changed since the previous local scan.",
                source="local_scan_history",
                metadata={"previous_title": comparison.previous_title},
            )


def _declared_country(addresses: object) -> str:
    text = " ".join(str(value) for value in addresses if value).casefold() if isinstance(addresses, list) else ""
    aliases = {
        "VN": ("viet nam", "vietnam"),
        "US": ("united states", "usa"),
        "GB": ("united kingdom", "great britain"),
        "SG": ("singapore",),
        "TH": ("thailand",),
        "MY": ("malaysia",),
        "ID": ("indonesia",),
        "CN": ("china",),
        "JP": ("japan",),
        "KR": ("south korea", "korea"),
        "AU": ("australia",),
        "DE": ("germany",),
        "FR": ("france",),
    }
    return next(
        (code for code, values in aliases.items() if any(value in text for value in values)),
        "",
    )


CRITERION_FIELDS: dict[int, str] = {
    1: "domain_age",
    2: "domain_expiry",
    3: "domain_owner",
    4: "registrar_abuse",
    5: "domain_impersonation",
    6: "confusable_characters",
    7: "deceptive_subdomain",
    8: "insecure_transport",
    9: "tls_anomaly",
    10: "certificate_error",
    11: "blacklist",
    12: "domain_reputation",
    13: "ip_reputation",
    14: "server_location",
    15: "malicious_shared_hosting",
    16: "redirect_anomaly",
    17: "short_url",
    18: "url_parameter_anomaly",
    19: "brand_content_impersonation",
    20: "contact_information",
    21: "business_email",
    22: "business_address",
    23: "legal_identity",
    24: "privacy_policy",
    25: "terms_refund",
    26: "content_quality",
    27: "price_anomaly",
    28: "pressure_language",
    29: "sensitive_data_request",
    30: "login_form",
    31: "payment_method",
    32: "payment_recipient",
    33: "browser_permissions",
    34: "downloaded_file",
    35: "malicious_javascript",
    36: "third_party_script",
    37: "scam_popup",
    38: "malvertising",
    39: "copied_content",
    40: "fake_image",
    41: "social_identity",
    42: "website_history",
    43: "content_change",
    44: "dns_anomaly",
    45: "email_security",
    46: "metadata_identity",
    47: "support_channel",
    48: "user_complaints",
    49: "fake_reviews",
}


def add_structured_snapshot(obs: ScanObservations, snapshot: dict[str, Any]) -> None:
    """Evaluate typed collector observations for every internal criterion."""
    for cid, field_name in CRITERION_FIELDS.items():
        value = snapshot.get(field_name)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError(f"snapshot.{field_name} must be an object")
        status = str(value.get("status", "unknown"))
        if status == "clean":
            obs.clean(cid)
        elif status == "unavailable":
            obs.unavailable[cid] = str(value.get("summary", "Collector unavailable."))
        elif status == "not_applicable":
            reason = str(value.get("summary", ""))
            if not reason:
                raise ValueError(f"snapshot.{field_name} not_applicable requires evidence")
            obs.not_applicable[cid] = reason
        elif status in {"suspicious", "malicious"}:
            obs.risk(
                cid,
                str(value.get("finding_type", field_name)),
                float(value.get("severity", 1.0 if status == "malicious" else 0.5)),
                float(value.get("quality", 0.5)),
                str(value.get("summary", field_name)),
                source=str(value.get("source", "collector")),
                incident=str(value.get("incident", field_name)),
                metadata=dict(value.get("metadata", {})),
            )
        elif status not in {"not_checked", "unknown"}:
            raise ValueError(f"snapshot.{field_name}.status is invalid: {status}")


if set(CRITERION_FIELDS) != set(range(1, 50)):
    raise RuntimeError("Every internal criterion 1..49 must have an observation field")


def _status(
    keys: Any, cid: int, status: CriterionStatus, summary: str, applicability: bool = False
) -> EvidenceV2:
    verdict = ProviderVerdict.CLEAN if status == CriterionStatus.CLEAN else ProviderVerdict.UNKNOWN
    evidence = _evidence(
        keys,
        cid,
        "risk_registry",
        f"criterion_{cid}_status",
        status,
        verdict,
        0,
        0,
        summary,
        0,
        "status",
        {},
    )
    if applicability:
        evidence.applicability_evidence_ids = (evidence.evidence_id,)
    return evidence


def _evidence(
    keys: Any,
    cid: int,
    source: str,
    finding_type: str,
    status: CriterionStatus,
    verdict: ProviderVerdict,
    severity: float,
    quality: float,
    summary: str,
    index: int,
    incident: str,
    metadata: dict[str, Any],
) -> EvidenceV2:
    stable = f"{keys.exact_subject_key}:{cid}:{source}:{finding_type}:{index}"
    evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, stable))
    data = {"summary": summary, **metadata}
    return EvidenceV2(
        evidence_id=evidence_id,
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(keys.exact_subject_key, finding_type, source),
        incident_key=make_incident_key(keys.campaign_subject_key, incident, "scan"),
        criterion_id=cid,
        source_id=source,
        organization_id=source,
        source_family="direct_behavior" if source.endswith("sandbox") else "internal",
        matched_subject=MatchedSubject.EXACT_URL,
        finding_type=finding_type,
        status=status,
        provider_verdict=verdict,
        severity=severity,
        evidence_quality=quality,
        match_strength=1.0,
        freshness_factor=1.0,
        authority_tier=4 if source.endswith("sandbox") else 3,
        observed_at="scan_cutoff",
        metadata=data,
    )
