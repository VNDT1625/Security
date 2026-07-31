"""InferenceService — orchestrates Layer 1 (models) + Policy into AssessResponse.

The "one Robust Risk Core" reception desk (design.md CONTRA-3.1): routes each modality
to the right predictor, merges evidence, applies the Policy Engine, and produces the
unified contract response.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any, Literal
from urllib.parse import urlsplit

from ai.adapters.file_adapter import analyze_file_bytes
from ai.adapters.text_adapter import extract_message_urls
from ai.adapters.url_adapter import parse_url_parts
from ai.inference.engine import InferenceEngine
from backend.config import settings
from backend.services.adapter_registry import AdapterOutcome, AdapterRegistry
from backend.services.phone_intelligence_service import query_ipqs_phone
from backend.services.threat_feed_service import collect_local_threat_feed_evidence
from backend.services.url_telemetry_service import collect_distributed_url_evidence
from security.attachment_security import (
    MalwareScanResult,
    OCRResult,
    ocr_image_bytes,
    scan_clamav_bytes,
)
from security.dns_intelligence import dns_intelligence_service
from security.domain_intelligence import domain_intelligence_service
from security.email_message_parser import parse_email_bytes
from security.exe_sandbox import ExeSandboxRunner
from security.ip_intelligence import ip_intelligence_service
from security.legal_rag import LocalLegalRAG
from security.misp_adapter import collect_misp
from security.policy_engine import PolicyEngine, score_to_level
from security.risk_core import (
    ActionPolicyDecision,
    ActionRiskInput,
    ActionRiskLevel,
    EvidenceBasedActionRiskEngine,
    LightGBMRiskAdapter,
    PolicyEngineV2,
    default_config,
)
from security.risk_core import assess as assess_risk_v2
from security.risk_core.detectors import (
    ScanObservations,
    add_browser_sandbox,
    add_cross_source_intelligence,
    add_dns_intelligence,
    add_domain_intelligence,
    add_http_sandbox,
    add_offline_url_findings,
    add_structured_observations,
    build_criteria_evidence,
)
from security.risk_core.external_adapters import collect_external
from security.risk_core.action_explanation import build_action_audit_record
from security.risk_core.url_overrides import URL_OVERRIDE_RULES
from security.scan_history import local_scan_history
from security.url_basic_intelligence import build_url_basic_intelligence
from security.urlvet_adapter import collect_urlvet
from shared.adapter_schemas import (
    AdapterFinding,
    AdapterRunStatus,
    AdapterTask,
    AdapterTrace,
    AssessPhoneResponse,
    Layer1Snapshot,
    MessageContextInput,
    MessageContextOutput,
    PhoneIntelligenceInput,
    PhoneIntelligenceOutput,
    WebContextInput,
    WebContextOutput,
)
from shared.schemas import (
    AgentContext,
    AgentRiskResponse,
    AssessResponse,
    Decision,
    Evidence,
    LegalEvidenceStatus,
    Modality,
    RiskCoreTrace,
    RiskLevel,
    Severity,
)

_WEB_OBSERVATION_KEYS = {
    "brand_content_impersonation",
    "contact_information_invalid",
    "business_email_mismatch",
    "business_address_invalid",
    "legal_identity_conflict",
    "privacy_policy_missing",
    "terms_refund_missing",
    "content_identity_conflict",
    "price_outlier",
    "coercive_content",
    "sensitive_data_request",
    "untrusted_sensitive_form",
    "irreversible_payment_risk",
    "payee_identity_mismatch",
    "unnecessary_browser_permission",
    "dangerous_download",
    "malicious_javascript_behavior",
    "risky_third_party_script",
    "deceptive_popup",
    "malvertising_behavior",
    "impersonating_copied_content",
    "forged_image_asset",
    "social_identity_conflict",
    "brand_metadata_mismatch",
    "support_channel_invalid",
    "review_manipulation",
}


def _url_model_feature_context(
    domain_intelligence: object | None,
    dns_intelligence: object | None,
    urlvet_evidence: list[Any],
    local_feed_evidence: list[Any],
) -> dict[str, object]:
    """Build bounded dynamic URL features from completed non-AI collectors."""

    context: dict[str, object] = {
        "local_feed_checked": 1.0,
        "local_feed_hit": float(bool(local_feed_evidence)),
    }
    if dns_intelligence is not None:
        available = bool(getattr(dns_intelligence, "available", False))
        addresses = tuple(getattr(dns_intelligence, "addresses", ()) or ())
        nameservers = tuple(getattr(dns_intelligence, "nameservers", ()) or ())
        mx_records = tuple(getattr(dns_intelligence, "mx", ()) or ())
        context.update(
            {
                "dns_available": float(available),
                "dns_resolves": float(bool(addresses)),
                "dns_record_count": float(
                    len(addresses) + len(nameservers) + len(mx_records)
                ),
            }
        )
    if domain_intelligence is not None:
        age_days = getattr(domain_intelligence, "age_days", None)
        context.update(
            {
                "rdap_available": float(age_days is not None),
                "domain_age_days": float(age_days or 0),
            }
        )
    for item in urlvet_evidence:
        metadata = getattr(item, "metadata", {})
        values = metadata.get("feature_context") if isinstance(metadata, dict) else None
        if isinstance(values, dict):
            context.update(values)
    return context


class InferenceService:
    def __init__(
        self,
        engine: InferenceEngine | None = None,
        policy: PolicyEngine | None = None,
        adapter_registry: AdapterRegistry | None = None,
        adapter_max_risk_contribution: float = 0.25,
        legal_rag: LocalLegalRAG | None = None,
        action_risk_engine: EvidenceBasedActionRiskEngine | None = None,
        security_core_mode: Literal["legacy", "shadow", "new_engine"] | None = None,
    ):
        self.engine = engine or InferenceEngine()
        self.policy = policy or PolicyEngine()
        self.adapter_registry = adapter_registry
        self.legal_rag = legal_rag or LocalLegalRAG()
        self.adapter_max_risk_contribution = max(
            0.0, min(0.5, adapter_max_risk_contribution)
        )
        self.action_risk_engine = action_risk_engine or EvidenceBasedActionRiskEngine(
            lightgbm=LightGBMRiskAdapter.from_onnx(
                settings.action_lightgbm_model_path
            )
        )
        self.security_core_mode = security_core_mode or settings.security_core_mode
        self._recent_results: dict[str, tuple[float, AssessResponse]] = {}
        self._recent_results_lock = threading.Lock()
        self._recent_results_ttl = 5 * 60

    @property
    def models_loaded(self) -> bool:
        return self.engine.models_loaded

    @property
    def model_status(self) -> dict:
        return self.engine.model_status

    @property
    def adapter_cache_token(self) -> str:
        if self.adapter_registry is None:
            return "adapters:none"
        return self.adapter_registry.cache_token

    def context_ai_ready(self, task: AdapterTask) -> bool:
        return bool(
            self.adapter_registry is not None
            and self.adapter_registry.is_llm_ready(task)
        )

    def _finalize_score(self, base: float, evidence: list[Evidence]) -> float:
        return self.policy.combine_evidence_score(base, evidence)

    def _reasons(self, evidence: list[Evidence]) -> list[str]:
        ranked = sorted(
            evidence,
            key=lambda e: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[
                e.severity.value
            ],
            reverse=True,
        )
        return [e.message for e in ranked[:3]]

    def _confidence(self, score: float, evidence: list[Evidence], version: str = "") -> float:
        """Estimate confidence from risk separation, evidence strength, and model source."""
        clipped = max(0.0, min(1.0, float(score)))
        boundary_certainty = abs(clipped - 0.5) * 2.0
        severity_weight = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.55,
            "low": 0.3,
            "info": 0.12,
        }
        evidence_strength = min(
            1.0,
            sum(severity_weight.get(item.severity.value, 0.0) for item in evidence) / 3.0,
        )
        lower_version = version.lower()
        if "transformer" in lower_version:
            model_bonus = 0.12
        elif "lgbm" in lower_version or "onnx" in lower_version:
            model_bonus = 0.08
        elif "heuristic" in lower_version:
            model_bonus = 0.03
        else:
            model_bonus = 0.05
        ambiguous_penalty = 0.08 if 0.35 <= clipped <= 0.65 else 0.0
        confidence = (
            0.35
            + boundary_certainty * 0.38
            + evidence_strength * 0.17
            + model_bonus
            - ambiguous_penalty
        )
        return round(max(0.2, min(0.98, confidence)), 4)

    def _missing_adapter(self, task: AdapterTask) -> AdapterOutcome:
        return AdapterOutcome(
            AdapterTrace(task=task, status=AdapterRunStatus.NOT_CONFIGURED)
        )

    @staticmethod
    def _disabled_adapter(task: AdapterTask) -> AdapterOutcome:
        return AdapterOutcome(
            AdapterTrace(
                task=task,
                status=AdapterRunStatus.DISABLED,
                error="Context AI was not requested for this assessment.",
            )
        )

    @staticmethod
    def _set_scoring_mode(
        outcome: AdapterOutcome,
        mode: Literal["off", "shadow", "active"],
    ) -> AdapterOutcome:
        outcome.trace = outcome.trace.model_copy(
            update={"scoring_mode": "none" if mode == "off" else mode}
        )
        return outcome

    @staticmethod
    def _shadow_evidence(items: list[Evidence]) -> list[Evidence]:
        return [item.model_copy(update={"contribution": 0.0}) for item in items]

    @staticmethod
    def _sandbox_web_context(
        context: str,
        metadata: dict[str, Any],
        sandbox_reports: tuple[tuple[object, bool], ...],
    ) -> tuple[str, dict[str, Any]]:
        """Build a bounded, text-only context; screenshots and raw DOM never leave the sandbox."""

        safe_metadata = dict(metadata)
        text_parts = [context] if context else []
        forms: list[dict[str, Any]] = list(metadata.get("forms", [])) if isinstance(metadata.get("forms"), list) else []
        actions: list[dict[str, Any]] = list(metadata.get("actions", [])) if isinstance(metadata.get("actions"), list) else []
        identity_keys = (
            "page_title",
            "description",
            "site_name",
            "language",
            "legal_names",
            "addresses",
            "payment_methods",
            "complaint_terms",
        )
        for report, _is_browser in sandbox_reports:
            identity = getattr(report, "page_identity", None)
            if isinstance(identity, dict):
                for key in identity_keys:
                    value = identity.get(key)
                    if isinstance(value, list):
                        value = ", ".join(str(item)[:200] for item in value[:20])
                    if value not in (None, "", []):
                        text_parts.append(f"{key}: {str(value)[:2000]}")
                forms.append(
                    {
                        "count": int(identity.get("forms", 0) or 0),
                        "password_fields": int(identity.get("password_fields", 0) or 0),
                    }
                )
            behaviors = getattr(report, "behaviors", None)
            if isinstance(behaviors, list):
                for item in behaviors[:30]:
                    if not isinstance(item, dict):
                        continue
                    actions.append(
                        {
                            key: str(item.get(key, ""))[:500]
                            for key in ("code", "category", "severity", "message")
                            if item.get(key) not in (None, "")
                        }
                    )
        safe_metadata["forms"] = forms[:100]
        safe_metadata["actions"] = actions[:100]
        return "\n".join(text_parts)[:200_000], safe_metadata

    def _message_outcome(
        self, text: str, modality: str, metadata: dict[str, Any]
    ) -> AdapterOutcome:
        if self.adapter_registry is None:
            return self._missing_adapter(AdapterTask.MESSAGE_CONTEXT)
        adapter_modality = {
            "chat_message": "chat",
            "transcript": "call_transcript",
        }.get(modality, modality)
        if adapter_modality not in {"email", "sms", "text", "chat", "call_transcript"}:
            adapter_modality = "text"
        return self.adapter_registry.invoke_message(
            MessageContextInput(
                content=text,
                modality=adapter_modality,
                metadata=metadata,
            )
        )

    def _web_outcome(
        self,
        url: str,
        content: str,
        metadata: dict[str, Any],
        layer1_score: float,
        layer1_evidence: list[Evidence],
        model_version: str,
    ) -> AdapterOutcome:
        if self.adapter_registry is None:
            return self._missing_adapter(AdapterTask.WEB_CONTEXT)
        return self.adapter_registry.invoke_web(
            WebContextInput(
                url=url,
                content=content,
                forms=metadata.get("forms", []) if isinstance(metadata.get("forms", []), list) else [],
                actions=(
                    metadata.get("actions", [])
                    if isinstance(metadata.get("actions", []), list)
                    else []
                ),
                stated_purpose=str(metadata.get("stated_purpose", "")),
                layer1=Layer1Snapshot(
                    risk_score=max(0.0, min(1.0, layer1_score)),
                    confidence=self._confidence(layer1_score, layer1_evidence, model_version),
                    evidence=[
                        item.model_dump(mode="json") for item in layer1_evidence[:50]
                    ],
                    model_version=model_version,
                ),
                metadata={
                    key: value
                    for key, value in metadata.items()
                    if key not in {"forms", "actions", "stated_purpose"}
                },
            )
        )

    def _adapter_evidence(
        self,
        outcome: AdapterOutcome,
        findings: list[AdapterFinding],
        confidence: float,
    ) -> list[Evidence]:
        if outcome.trace.status != AdapterRunStatus.COMPLETED:
            return []
        output = []
        for finding in findings:
            contribution = min(
                self.adapter_max_risk_contribution,
                finding.risk_signal
                * max(0.0, min(1.0, confidence))
                * self.adapter_max_risk_contribution,
            )
            output.append(
                Evidence(
                    source=outcome.trace.task.value,
                    adapter=outcome.trace.adapter_id,
                    evidence_id=finding.evidence_id,
                    category=finding.category,
                    message=finding.summary,
                    severity=Severity(finding.severity),
                    feature=finding.category,
                    contribution=round(contribution, 4),
                )
            )
        return output

    @staticmethod
    def _web_observations(output: WebContextOutput | None, adapter_id: str) -> dict[str, Any]:
        if output is None:
            return {}
        values: dict[str, Any] = {
            "source": f"web_context:{adapter_id}",
            "incident": "web_context",
        }
        for key, observation in output.observations.items():
            if key in _WEB_OBSERVATION_KEYS:
                values[key] = observation.model_dump()
        return values

    @staticmethod
    def _embedded_url_core_score(url: str, evidence: list[Evidence]) -> float:
        """Score an embedded URL with the same deterministic Risk Core, without network I/O."""

        observations = ScanObservations(url)
        add_offline_url_findings(observations, evidence)
        config = default_config()
        result = assess_risk_v2(
            build_criteria_evidence(observations, config),
            config=config,
            override_rules=URL_OVERRIDE_RULES,
        )
        return max(0.0, min(1.0, result.risk_score / 100.0))

    def evaluate_url_context(
        self,
        response: AssessResponse,
        url: str,
        context: str = "",
        metadata: dict[str, Any] | None = None,
        *,
        sandbox_reports: tuple[tuple[object, bool], ...] = (),
    ) -> AssessResponse:
        """Attach one shadow AI evaluation to an already completed URL assessment."""

        web_context, web_metadata = self._sandbox_web_context(
            context, dict(metadata or {}), sandbox_reports
        )
        outcome = self._web_outcome(
            url,
            web_context,
            web_metadata,
            response.risk_score,
            response.evidence,
            response.model_version,
        )
        self._set_scoring_mode(outcome, "shadow")
        web_output = outcome.output if isinstance(outcome.output, WebContextOutput) else None
        contextual_evidence = self._adapter_evidence(
            outcome,
            web_output.findings if web_output else [],
            web_output.confidence if web_output else 0.0,
        )
        response.evidence.extend(self._shadow_evidence(contextual_evidence))
        response.contextual_analysis = outcome.trace
        return response

    # ------------------------------------------------------------------ url
    def assess_url(
        self,
        url: str,
        context: str = "",
        metadata: dict[str, Any] | None = None,
        *,
        sandbox_reports: tuple[tuple[object, bool], ...] = (),
        context_ai_mode: Literal["off", "shadow", "active"] = "shadow",
    ) -> AssessResponse:
        # Direct service consumers (including MCP) receive the same product
        # policy result without DNS, threat-intelligence, model, or sandbox work.
        from shared.trusted_popular_domains import trusted_popular_assessment

        trusted_result = trusted_popular_assessment(url)
        if trusted_result is not None:
            return trusted_result
        t0 = time.perf_counter()
        metadata = dict(metadata or {})
        cache_material = url if not context else f"{url}\n{context}"
        cache_material = f"{cache_material}\n{self.adapter_cache_token}\n{context_ai_mode}"
        cache_key = self._cache_key("url", cache_material)
        # A live sandbox observation must never be replaced with an older quick scan.
        cached = None if sandbox_reports else self._cached_result(cache_key)
        if cached is not None:
            return cached

        observations = ScanObservations(url)
        domain_result = None
        dns_result = None
        ip_result = None
        urlvet_evidence = []
        misp_evidence = []
        host = urlsplit(url if "://" in url else f"https://{url}").hostname
        domain = parse_url_parts(url).registrable_domain if host else None
        if domain and host:
            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="url-enrichment") as pool:
                domain_future = pool.submit(domain_intelligence_service.inspect, domain, url)
                dns_future = pool.submit(dns_intelligence_service.inspect, host)
                urlvet_future = pool.submit(
                    collect_urlvet,
                    url,
                    base_url=settings.urlvet_api_url,
                    enabled=settings.urlvet_enabled,
                    timeout=settings.urlvet_timeout_seconds,
                )
                misp_future = pool.submit(
                    collect_misp,
                    url,
                    enabled=settings.misp_enabled,
                    base_url=settings.misp_base_url,
                    api_key=settings.misp_api_key,
                    verify_tls=settings.misp_verify_tls,
                    timeout=settings.misp_timeout_seconds,
                    last=settings.misp_lookup_last,
                )
                ip_future = None
                try:
                    dns_result = dns_future.result()
                    add_dns_intelligence(observations, dns_result)
                    if dns_result.addresses:
                        primary_address = next(
                            (address for address in dns_result.addresses if ":" not in address),
                            dns_result.addresses[0],
                        )
                        ip_future = pool.submit(ip_intelligence_service.inspect, primary_address)
                except Exception as exc:
                    for criterion_id in (44, 45):
                        observations.unavailable[criterion_id] = (
                            f"DNS intelligence unavailable: {type(exc).__name__}"
                        )
                try:
                    domain_result = domain_future.result()
                    add_domain_intelligence(observations, domain_result)
                except Exception as exc:
                    for criterion_id in (1, 3, 4, 11, 12):
                        observations.unavailable[criterion_id] = (
                            f"Domain intelligence unavailable: {type(exc).__name__}"
                        )
                if ip_future is not None:
                    try:
                        ip_result = ip_future.result()
                    except Exception:
                        ip_result = None
                urlvet_evidence = urlvet_future.result()
                misp_evidence = misp_future.result()
        else:
            urlvet_evidence = collect_urlvet(
                url,
                base_url=settings.urlvet_api_url,
                enabled=settings.urlvet_enabled,
                timeout=settings.urlvet_timeout_seconds,
            )
            misp_evidence = collect_misp(
                url,
                enabled=settings.misp_enabled,
                base_url=settings.misp_base_url,
                api_key=settings.misp_api_key,
                verify_tls=settings.misp_verify_tls,
                timeout=settings.misp_timeout_seconds,
                last=settings.misp_lookup_last,
            )

        local_feed_evidence = collect_local_threat_feed_evidence(url)
        feature_context = _url_model_feature_context(
            domain_result,
            dns_result,
            urlvet_evidence,
            local_feed_evidence,
        )
        try:
            pred = self.engine.predict_url(url, context=feature_context)
        except TypeError as exc:
            # Preserve compatibility with injected engines that implement the
            # original one-argument protocol.
            if "unexpected keyword argument 'context'" not in str(exc):
                raise
            pred = self.engine.predict_url(url)

        web_context, web_metadata = self._sandbox_web_context(
            context, metadata, sandbox_reports
        )
        contextual = (
            self._disabled_adapter(AdapterTask.WEB_CONTEXT)
            if context_ai_mode == "off"
            else self._web_outcome(
                url,
                web_context,
                web_metadata,
                pred.risk_score,
                pred.evidence,
                pred.model_version,
            )
        )
        self._set_scoring_mode(contextual, context_ai_mode)
        web_output = (
            contextual.output if isinstance(contextual.output, WebContextOutput) else None
        )
        contextual_evidence = self._adapter_evidence(
            contextual,
            web_output.findings if web_output else [],
            web_output.confidence if web_output else 0.0,
        )
        displayed_contextual_evidence = (
            contextual_evidence
            if context_ai_mode == "active"
            else self._shadow_evidence(contextual_evidence)
        )
        evidence = [*pred.evidence, *displayed_contextual_evidence]
        # URL model/rules above only produce evidence. Risk Core v2 below is the
        # sole scorer and policy engine for every URL caller.
        response = self._build(
            0.0,
            Decision.ALLOW,
            evidence,
            Modality.URL,
            pred.model_version,
            t0,
        )
        response.contextual_analysis = contextual.trace

        add_offline_url_findings(observations, pred.evidence)
        if web_output and context_ai_mode == "active":
            add_structured_observations(
                observations,
                self._web_observations(web_output, contextual.trace.adapter_id),
            )

        for sandbox_report, is_browser_report in sandbox_reports:
            detector = add_browser_sandbox if is_browser_report else add_http_sandbox
            detector(observations, sandbox_report)
        add_cross_source_intelligence(
            observations,
            domain_intelligence=domain_result,
            dns_intelligence=dns_result,
            ip_intelligence=ip_result,
            sandbox_reports=sandbox_reports,
            history_store=local_scan_history,
        )

        config = default_config()
        v2_evidence = build_criteria_evidence(observations, config)
        v2_evidence.extend(local_feed_evidence)
        v2_evidence.extend(
            collect_external(url, config, provider_config=settings.model_dump())
        )
        v2_evidence.extend(urlvet_evidence)
        v2_evidence.extend(misp_evidence)
        v2_evidence.extend(collect_distributed_url_evidence(url))
        risk = assess_risk_v2(
            v2_evidence,
            config=config,
            override_rules=URL_OVERRIDE_RULES,
        )
        policy = PolicyEngineV2().decide(risk)
        trace = asdict(risk)
        trace.update(
            {
                "schema_version": "2",
                "scoring_version": risk.scan_version,
                "raw_score": risk.base_risk_score,
                "final_score": risk.risk_score,
                "confidence": risk.confidence_score,
                "verdict": risk.risk_level,
                "decision": policy.decision.value,
                "next_action": policy.next_action.value,
            }
        )
        response.risk_core = RiskCoreTrace.model_validate(trace)
        response.schema_version = "2"
        response.scoring_version = risk.scan_version
        response.raw_score = round(risk.base_risk_score / 100, 4)
        response.final_score = round(risk.risk_score / 100, 4)
        # Risk Core V2 is authoritative. Keep legacy response fields synchronized
        # so API and frontend consumers cannot display a weaker, conflicting verdict.
        response.risk_score = response.final_score
        response.risk_level = score_to_level(response.risk_score)
        response.confidence = round(risk.confidence_score / 100, 4)
        response.decision = {
            "allow": Decision.ALLOW,
            "warn": Decision.WARN,
            "require_review": Decision.ASK_USER_CONFIRMATION,
            "soft_block": Decision.BLOCK,
            "hard_block": Decision.BLOCK,
        }[policy.decision.value]
        scored_reasons = [
            item.reason
            for item in sorted(
                risk.criteria,
                key=lambda item: item.evidence_strength,
                reverse=True,
            )
            if item.evidence_strength > 0 and item.reason
        ]
        response.reasons = scored_reasons[:3] or risk.reasoning[:3]
        if domain:
            response.url_intelligence = build_url_basic_intelligence(
                domain,
                domain_result,
                dns_result,
                ip_result,
            )
        if not sandbox_reports:
            self._store_result(cache_key, response)
        return response

    def assess_sandbox_report(self, url: str, report: object, *, browser: bool = False) -> RiskCoreTrace:
        observations = ScanObservations(url)
        (add_browser_sandbox if browser else add_http_sandbox)(observations, report)
        config = default_config()
        risk = assess_risk_v2(build_criteria_evidence(observations, config), config=config)
        policy = PolicyEngineV2().decide(risk)
        trace = asdict(risk)
        trace.update({
            "schema_version": "2", "scoring_version": risk.scan_version,
            "raw_score": risk.base_risk_score, "final_score": risk.risk_score,
            "confidence": risk.confidence_score, "verdict": risk.risk_level,
            "decision": policy.decision.value, "next_action": policy.next_action.value,
        })
        return RiskCoreTrace.model_validate(trace)


    # ------------------------------------------------------------------ text
    def assess_text(
        self,
        text: str,
        modality: str = "email",
        metadata: dict | None = None,
        *,
        context_ai_mode: Literal["off", "shadow", "active"] = "active",
    ):
        t0 = time.perf_counter()
        enriched_metadata = dict(metadata or {})
        enriched_metadata.setdefault("modality", modality)
        pred = self.engine.predict_text(text, enriched_metadata)
        embedded_url_evidence: list[Evidence] = []
        embedded_url_floor = 0.0
        embedded_url_assessments: list[dict[str, Any]] = []
        embedded_urls = extract_message_urls(text, enriched_metadata)
        analysis_depth = str(enriched_metadata.get("analysis_depth", "quick")).lower()
        full_url_analysis = analysis_depth in {"balanced", "deep", "pro"}
        max_links = 1 if analysis_depth == "quick" else 3 if analysis_depth in {"deep", "pro"} else 2
        for index, embedded_url in enumerate(embedded_urls[:max_links], start=1):
            if full_url_analysis:
                try:
                    url_response = self.assess_url(
                        embedded_url,
                        context=text[:2_000],
                        metadata={"source": f"{modality}_embedded_link"},
                        # The message-level evaluator already receives the surrounding
                        # context. Embedded links use deterministic URL Core only so a
                        # single message never triggers hidden extra LLM calls.
                        context_ai_mode="off",
                    )
                    embedded_core_score = url_response.risk_score
                    url_evidence = url_response.evidence
                    embedded_url_assessments.append({
                        "index": index,
                        "url": embedded_url,
                        "status": (
                            "partial"
                            if url_response.risk_core
                            and url_response.risk_core.unavailable_checks
                            else "completed"
                        ),
                        "risk_score": round(embedded_core_score, 4),
                        "risk_level": url_response.risk_level.value,
                        "request_id": url_response.request_id,
                        "reasons": url_response.reasons[:3],
                    })
                except Exception as exc:
                    url_pred = self.engine.predict_url(embedded_url)
                    embedded_core_score = self._embedded_url_core_score(
                        embedded_url, url_pred.evidence
                    )
                    url_evidence = url_pred.evidence
                    embedded_url_assessments.append({
                        "index": index,
                        "url": embedded_url,
                        "status": "fallback_offline",
                        "risk_score": round(embedded_core_score, 4),
                        "error": type(exc).__name__,
                    })
            else:
                url_pred = self.engine.predict_url(embedded_url)
                embedded_core_score = self._embedded_url_core_score(
                    embedded_url, url_pred.evidence
                )
                url_evidence = url_pred.evidence
                embedded_url_assessments.append({
                    "index": index,
                    "url": embedded_url,
                    "status": "offline",
                    "risk_score": round(embedded_core_score, 4),
                })
            # A high URL-core verdict is independent technical evidence. It can set
            # a strong floor, but only externally confirmed maliciousness may set
            # the design's 90-point mandatory floor (passed via message metadata).
            if embedded_core_score >= 0.90 and any(item.severity == Severity.CRITICAL for item in url_evidence):
                embedded_url_floor = max(embedded_url_floor, 0.90)
            elif embedded_core_score >= 0.80:
                embedded_url_floor = max(embedded_url_floor, 0.80)
            elif embedded_core_score >= 0.65:
                embedded_url_floor = max(embedded_url_floor, 0.65)
            for item in url_evidence:
                if item.severity == Severity.INFO:
                    continue
                embedded_url_evidence.append(
                    item.model_copy(
                        update={
                            "source": f"embedded_url_{index}:{item.source}",
                            "message": f"Liên kết {index}: {item.message}",
                        }
                    )
                )
        contextual = (
            self._disabled_adapter(AdapterTask.MESSAGE_CONTEXT)
            if context_ai_mode == "off"
            else self._message_outcome(text, modality, enriched_metadata)
        )
        self._set_scoring_mode(contextual, context_ai_mode)
        message_output = (
            contextual.output if isinstance(contextual.output, MessageContextOutput) else None
        )
        contextual_evidence = self._adapter_evidence(
            contextual,
            message_output.findings if message_output else [],
            message_output.confidence if message_output else 0.0,
        )
        displayed_contextual_evidence = (
            contextual_evidence
            if context_ai_mode == "active"
            else self._shadow_evidence(contextual_evidence)
        )
        evidence = [*pred.evidence, *embedded_url_evidence, *displayed_contextual_evidence]
        # Core evidence is already represented in pred.risk_score. Only independent
        # contextual-adapter findings are blended here, preventing double counting.
        score = max(
            embedded_url_floor,
            self._finalize_score(
                pred.risk_score,
                contextual_evidence if context_ai_mode == "active" else [],
            ),
        )
        decision = self.policy.evaluate_human(score)
        mod = Modality(modality) if modality in Modality._value2member_map_ else Modality.TEXT
        response = self._build(score, decision, evidence, mod, pred.model_version, t0)
        response.contextual_analysis = contextual.trace
        response.embedded_url_assessments = embedded_url_assessments
        response.analysis_coverage = {
            "message_core": "completed",
            "semantic_model": "completed" if self.engine.model_status.get("modalities_ready", {}).get("text") else "unavailable",
            "message_context_ai": contextual.trace.status.value,
            "embedded_urls": (
                "not_applicable"
                if not embedded_urls
                else "completed"
                if embedded_url_assessments
                and all(item.get("status") == "completed" for item in embedded_url_assessments)
                else "partial"
            ),
            "email_headers": "completed" if modality == "email" and any(enriched_metadata.get(key) for key in ("from", "sender", "reply_to", "return_path")) else ("not_applicable" if modality != "email" else "unavailable"),
            "authentication_results": "completed" if modality == "email" and any(enriched_metadata.get(key) for key in ("authentication", "spf", "dkim", "dmarc")) else ("not_applicable" if modality != "email" else "unavailable"),
            "attachments": "completed" if modality == "email" and "attachments" in enriched_metadata else ("not_applicable" if modality != "email" else "unavailable"),
            "qr_decode": "completed" if modality == "email" and "qr_urls" in enriched_metadata else ("not_applicable" if modality != "email" else "unavailable"),
            "phone_reputation": "not_applicable" if modality != "sms" else "unavailable",
        }
        response.message_metadata = {
            key: enriched_metadata.get(key)
            for key in ("source", "sender", "from", "reply_to", "return_path", "subject", "message_id", "authentication", "forwarded", "analysis_depth")
            if enriched_metadata.get(key) not in (None, "", [], {})
        }
        return response

    def assess_email_bytes(
        self,
        data: bytes,
        filename: str = "message.eml",
        *,
        analysis_depth: Literal["quick", "balanced", "deep", "pro"] = "balanced",
        context_ai_mode: Literal["off", "shadow", "active"] = "active",
        operator_context: str = "",
        gmail_context: dict[str, Any] | None = None,
    ) -> AssessResponse:
        """Parse and assess a raw RFC822/MIME message without executing content."""

        parsed = parse_email_bytes(data, filename)
        metadata = dict(parsed.metadata)
        metadata["analysis_depth"] = analysis_depth
        coverage = dict(parsed.coverage)
        if operator_context:
            metadata["operator_context"] = operator_context[:2_000]
        if gmail_context:
            labels = [str(value)[:80] for value in gmail_context.get("label_ids", [])[:30]]
            metadata.update(
                {
                    "source": "gmail",
                    "gmail_message_id": str(gmail_context.get("message_id", ""))[:200],
                    "gmail_thread_id": str(gmail_context.get("thread_id", ""))[:200],
                    "gmail_label_ids": labels,
                    "gmail_spam_or_phishing": "SPAM" in labels or "PHISHING" in labels,
                }
            )
            coverage["gmail_context"] = "completed"
        antivirus_statuses: list[str] = []
        ocr_statuses: list[str] = []
        sandbox_statuses: list[str] = []
        ocr_texts: list[str] = []
        ocr_urls: list[str] = []
        attachment_deadline = time.monotonic() + max(
            5.0, min(float(settings.email_attachment_budget_seconds), 60.0)
        )
        active_scan_limit = max(1, min(int(settings.email_attachment_active_scan_limit), 30))
        ocr_image_limit = max(1, min(int(settings.email_ocr_image_limit), 10))
        ocr_images_seen = 0
        sandbox_files_seen = 0

        for attachment_index, attachment in enumerate(parsed.attachments[:30], start=1):
            remaining = attachment_deadline - time.monotonic()
            if attachment_index > active_scan_limit or remaining <= 0.5:
                antivirus = MalwareScanResult(
                    "unavailable", detail="Chưa quét vì đã đạt giới hạn tài nguyên của email."
                )
            else:
                antivirus = scan_clamav_bytes(
                    attachment.data,
                    host=settings.clamav_host,
                    port=settings.clamav_port,
                    timeout_seconds=min(
                        float(settings.attachment_scan_timeout_seconds), remaining
                    ),
                    max_bytes=settings.max_upload_bytes,
                )
            antivirus_statuses.append(antivirus.status)
            attachment.metadata["malware_scan_status"] = antivirus.status
            if antivirus.detail:
                attachment.metadata["malware_scan_detail"] = antivirus.detail
            if antivirus.malicious:
                attachment.metadata["malicious"] = True
                attachment.metadata["malware_signature"] = antivirus.signature

            detected_type = str(attachment.metadata.get("detected_type", ""))
            if detected_type.startswith("image/"):
                ocr_images_seen += 1
                if analysis_depth in {"deep", "pro"}:
                    remaining = attachment_deadline - time.monotonic()
                    if ocr_images_seen > ocr_image_limit or remaining <= 1.0:
                        ocr = OCRResult(
                            "unavailable",
                            detail="Chưa OCR vì đã đạt giới hạn tài nguyên của email.",
                        )
                    else:
                        ocr = ocr_image_bytes(
                            attachment.data,
                            executable=settings.tesseract_executable,
                            languages=settings.tesseract_languages,
                            timeout_seconds=min(
                                float(settings.attachment_ocr_timeout_seconds), remaining
                            ),
                        )
                    ocr_statuses.append(ocr.status)
                    attachment.metadata["ocr_status"] = ocr.status
                    if ocr.text:
                        attachment.metadata["ocr_text_preview"] = ocr.text[:500]
                        ocr_texts.append(ocr.text)
                        ocr_urls.extend(extract_message_urls(ocr.text))
                    if ocr.detail:
                        attachment.metadata["ocr_detail"] = ocr.detail
                else:
                    ocr_statuses.append("unavailable")
                    attachment.metadata["ocr_status"] = "requires_deep_analysis"

            is_executable = (
                detected_type == "application/x-dosexec"
                or bool(attachment.metadata.get("dangerous_extension"))
            )
            if is_executable:
                sandbox_files_seen += 1
                if analysis_depth == "pro" and settings.email_attachment_sandbox_enabled:
                    remaining = attachment_deadline - time.monotonic()
                    if (
                        sandbox_files_seen > max(1, int(settings.email_sandbox_file_limit))
                        or remaining < 15.0
                    ):
                        sandbox_statuses.append("unavailable")
                        attachment.metadata["sandbox_status"] = "resource_limit"
                    else:
                        sandbox = ExeSandboxRunner(
                            timeout_seconds=min(120, max(15, int(remaining)))
                        ).inspect(attachment.data, attachment.filename)
                        sandbox_statuses.append(
                            "completed" if sandbox.get("ok") else "unavailable"
                        )
                        attachment.metadata["sandbox_status"] = sandbox.get(
                            "execution_status", "failed"
                        )
                        attachment.metadata["sandbox_verdict"] = sandbox.get(
                            "verdict", "unknown"
                        )
                        attachment.metadata["sandbox_malicious"] = (
                            sandbox.get("verdict") == "dangerous"
                        )
                else:
                    sandbox_statuses.append("unavailable")
                    attachment.metadata["sandbox_status"] = (
                        "not_configured"
                        if analysis_depth == "pro"
                        else "requires_pro_analysis"
                    )

        if antivirus_statuses:
            completed_count = antivirus_statuses.count("completed")
            coverage["malware_signature_scan"] = (
                "completed"
                if completed_count == len(antivirus_statuses)
                else "partial"
                if completed_count
                else "unavailable"
            )
        if ocr_statuses:
            completed_count = ocr_statuses.count("completed")
            coverage["ocr"] = (
                "completed"
                if completed_count == len(ocr_statuses)
                else "partial"
                if completed_count
                else "unavailable"
            )
        if sandbox_statuses:
            completed_count = sandbox_statuses.count("completed")
            coverage["attachment_sandbox"] = (
                "completed"
                if completed_count == len(sandbox_statuses)
                else "partial"
                if completed_count
                else "unavailable"
            )
        if ocr_urls:
            metadata["attachment_urls"] = list(
                dict.fromkeys([*metadata.get("attachment_urls", []), *ocr_urls])
            )[:50]
        assessed_body = parsed.body
        if ocr_texts:
            assessed_body = f"{assessed_body}\n\n[OCR]\n" + "\n".join(ocr_texts)
        response = self.assess_text(
            assessed_body,
            "email",
            metadata,
            context_ai_mode=context_ai_mode,
        )
        attachment_evidence: list[Evidence] = []
        attachment_score = 0.0
        for index, attachment in enumerate(parsed.attachments[:30], start=1):
            score, evidence = analyze_file_bytes(attachment.data, attachment.filename)
            attachment_score = max(attachment_score, score)
            for item in evidence:
                if item.severity == Severity.INFO:
                    continue
                attachment_evidence.append(item.model_copy(update={
                    "source": f"email_attachment_{index}:{item.source}",
                    "message": f"Tệp {attachment.filename}: {item.message}",
                }))
            if attachment.metadata.get("type_mismatch"):
                attachment_evidence.append(Evidence(
                    source=f"email_attachment_{index}",
                    message=f"Tệp {attachment.filename} có loại nội dung thật không khớp phần mở rộng.",
                    severity=Severity.HIGH,
                    feature="E-FILE-01-type-mismatch",
                    contribution=0.15,
                ))
                attachment_score = max(attachment_score, 0.70)
        if attachment_evidence:
            response.evidence.extend(attachment_evidence)
            response.risk_score = round(max(response.risk_score, attachment_score), 4)
            response.risk_level = score_to_level(response.risk_score)
            response.decision = self.policy.evaluate_human(response.risk_score)
            response.reasons = self._reasons(response.evidence)
            response.confidence = self._confidence(response.risk_score, response.evidence, response.model_version)
        response.analysis_coverage.update(coverage)
        response.message_metadata = {
            key: value
            for key, value in metadata.items()
            if key not in {"raw_html", "received_hops"}
        }
        response.message_metadata["analysis_depth"] = analysis_depth
        response.message_metadata["attachment_count"] = len(parsed.attachments)
        return response

    def assess_untrusted_content(
        self,
        text: str,
        modality: str = "text",
        metadata: dict | None = None,
        *,
        context_ai_mode: Literal["off", "shadow", "active"] = "active",
    ) -> AssessResponse:
        """Gate external data before it enters an agent's instruction context."""
        t0 = time.perf_counter()
        enriched_metadata = dict(metadata or {})
        enriched_metadata.setdefault("modality", modality)
        text_pred = self.engine.predict_text(text, enriched_metadata)
        prompt_pred = self.engine.predict_prompt(text)
        source = str(enriched_metadata.get("source", ""))
        if source == "webpage":
            source_url = str(enriched_metadata.get("source_url") or enriched_metadata.get("url") or "")
            if source_url:
                url_pred = self.engine.predict_url(source_url)
            else:
                url_pred = None
            contextual = (
                self._disabled_adapter(AdapterTask.WEB_CONTEXT)
                if context_ai_mode == "off"
                else self._web_outcome(
                    source_url,
                    text,
                    enriched_metadata,
                    url_pred.risk_score if url_pred else 0.0,
                    url_pred.evidence if url_pred else [],
                    url_pred.model_version if url_pred else "no-url-layer1",
                )
            )
            contextual_output = (
                contextual.output if isinstance(contextual.output, WebContextOutput) else None
            )
        else:
            contextual_modality = "chat" if source == "chat_message" else modality
            contextual = (
                self._disabled_adapter(AdapterTask.MESSAGE_CONTEXT)
                if context_ai_mode == "off"
                else self._message_outcome(
                    text, contextual_modality, enriched_metadata
                )
            )
            contextual_output = (
                contextual.output if isinstance(contextual.output, MessageContextOutput) else None
            )
        self._set_scoring_mode(contextual, context_ai_mode)
        contextual_findings = contextual_output.findings if contextual_output else []
        contextual_confidence = contextual_output.confidence if contextual_output else 0.0
        contextual_evidence = self._adapter_evidence(
            contextual, contextual_findings, contextual_confidence
        )
        displayed_contextual_evidence = (
            contextual_evidence
            if context_ai_mode == "active"
            else self._shadow_evidence(contextual_evidence)
        )
        evidence = [
            *text_pred.evidence,
            *prompt_pred.evidence,
            *displayed_contextual_evidence,
        ]
        score = self._finalize_score(
            max(text_pred.risk_score, prompt_pred.risk_score),
            contextual_evidence if context_ai_mode == "active" else [],
        )
        decision = self.policy.evaluate_human(score)
        mod = Modality(modality) if modality in Modality._value2member_map_ else Modality.TEXT
        response = self._build(
            score,
            decision,
            evidence,
            mod,
            f"untrusted-content[{text_pred.model_version}+{prompt_pred.model_version}]",
            t0,
        )
        response.contextual_analysis = contextual.trace
        return response

    def assess_phone(
        self,
        phone_number: str,
        *,
        country_hint: str = "",
        sms: str = "",
        transcript: str = "",
        metadata: dict[str, Any] | None = None,
        context_ai_mode: Literal["off", "shadow", "active"] = "active",
    ) -> AssessPhoneResponse:
        metadata = dict(metadata or {})
        assessment: AssessResponse | None = None
        if sms:
            assessment = self.assess_text(
                sms, "sms", metadata, context_ai_mode=context_ai_mode
            )
        if transcript:
            transcript_assessment = self.assess_text(
                transcript,
                "call_transcript",
                metadata,
                context_ai_mode=context_ai_mode,
            )
            if assessment is None:
                assessment = transcript_assessment
            else:
                evidence = [*assessment.evidence, *transcript_assessment.evidence]
                score = max(assessment.risk_score, transcript_assessment.risk_score)
                assessment.evidence = evidence
                assessment.risk_score = round(score, 4)
                assessment.risk_level = score_to_level(score)
                assessment.decision = self.policy.evaluate_human(score)
                assessment.reasons = self._reasons(evidence)
                assessment.confidence = self._confidence(
                    score, evidence, assessment.model_version
                )
        if assessment is not None:
            digits = "".join(char for char in phone_number if char.isdigit())
            local_phone_evidence: list[Evidence] = []
            if not digits:
                assessment.analysis_coverage["phone_format"] = "not_applicable"
                assessment.message_metadata["sender_type"] = "alphanumeric"
            else:
                assessment.analysis_coverage["phone_format"] = "completed"
                assessment.message_metadata["sender_type"] = "phone_number"
                assessment.message_metadata["phone_country_hint"] = country_hint.upper()[:2]
                if len(digits) < 8 or len(digits) > 15:
                    local_phone_evidence.append(Evidence(
                        source="phone_format",
                        message="Số gửi không có độ dài hợp lệ theo chuẩn số điện thoại quốc tế.",
                        severity=Severity.LOW,
                        feature="S-ID-01-invalid-format",
                        contribution=0.04,
                    ))
                elif (
                    country_hint.strip().upper() == "VN"
                    and phone_number.strip().startswith("+")
                    and not digits.startswith("84")
                ):
                    local_phone_evidence.append(Evidence(
                        source="phone_format",
                        message="Mã quốc gia của số gửi không khớp ngữ cảnh Việt Nam đã chọn.",
                        severity=Severity.LOW,
                        feature="S-ID-01-country-mismatch",
                        contribution=0.04,
                    ))
            if local_phone_evidence:
                assessment.evidence.extend(local_phone_evidence)
                assessment.risk_score = round(
                    self._finalize_score(assessment.risk_score, local_phone_evidence), 4
                )
                assessment.risk_level = score_to_level(assessment.risk_score)
                assessment.decision = self.policy.evaluate_human(assessment.risk_score)
                assessment.reasons = self._reasons(assessment.evidence)
                assessment.confidence = self._confidence(
                    assessment.risk_score, assessment.evidence, assessment.model_version
                )
        if self.adapter_registry is None:
            outcome = query_ipqs_phone(
                phone_number,
                country_hint=country_hint,
                api_key=settings.ipqs_phone_api_key,
                endpoint=settings.ipqs_phone_api_url,
                timeout_seconds=settings.phone_intelligence_timeout_seconds,
            )
        else:
            outcome = self.adapter_registry.invoke_phone(
                PhoneIntelligenceInput(
                    phone_number=phone_number,
                    country_hint=country_hint,
                    metadata=metadata,
                )
            )
            if outcome.trace.status in {
                AdapterRunStatus.NOT_CONFIGURED,
                AdapterRunStatus.DISABLED,
                AdapterRunStatus.ARTIFACT_MISSING,
            } and settings.ipqs_phone_api_key:
                outcome = query_ipqs_phone(
                    phone_number,
                    country_hint=country_hint,
                    api_key=settings.ipqs_phone_api_key,
                    endpoint=settings.ipqs_phone_api_url,
                    timeout_seconds=settings.phone_intelligence_timeout_seconds,
                )
        phone = outcome.output if isinstance(outcome.output, PhoneIntelligenceOutput) else None
        if assessment is not None:
            assessment.phone_intelligence = outcome.trace
            assessment.analysis_coverage["phone_reputation"] = (
                "completed"
                if outcome.trace.status == AdapterRunStatus.COMPLETED
                else "unavailable"
            )
            if phone:
                phone_evidence = self._adapter_evidence(
                    outcome, phone.findings, phone.confidence
                )
                if phone_evidence:
                    evidence = [*assessment.evidence, *phone_evidence]
                    score = self._finalize_score(assessment.risk_score, phone_evidence)
                    assessment.evidence = evidence
                    assessment.risk_score = round(score, 4)
                    assessment.risk_level = score_to_level(score)
                    assessment.decision = self.policy.evaluate_human(score)
                    assessment.reasons = self._reasons(evidence)
                    assessment.confidence = self._confidence(
                        score, evidence, assessment.model_version
                    )
        return AssessPhoneResponse(
            phone_intelligence=outcome.trace,
            provider=phone.provider if phone else "",
            provider_status=phone.provider_status if phone else "unavailable",
            reputation=phone.reputation if phone else None,
            metadata=phone.metadata if phone else {},
            assessment=assessment,
        )

    # ---------------------------------------------------------------- prompt
    def assess_prompt(self, text: str) -> AssessResponse:
        t0 = time.perf_counter()
        pred = self.engine.predict_prompt(text)
        decision = self.policy.evaluate_human(pred.risk_score)
        return self._build(
            pred.risk_score, decision, pred.evidence, Modality.PROMPT, pred.model_version, t0
        )

    # ------------------------------------------------------------------ file
    def assess_file(self, data: bytes, filename: str = "") -> AssessResponse:
        t0 = time.perf_counter()
        score, evidence = analyze_file_bytes(data, filename)
        decision = self.policy.evaluate_human(score)
        return self._build(score, decision, evidence, Modality.FILE, "static-file-1", t0)

    # ---------------------------------------------------------------- action
    def assess_action(
        self,
        action_type: str,
        target_url: str | None,
        data_types: list[str],
        agent_context: AgentContext,
    ) -> AgentRiskResponse:
        action_id = str(uuid.uuid4())
        available_assets = tuple(
            getattr(agent_context, "available_assets", ()) or ()
        )
        # Preserve the established calculation for legacy/shadow comparison.
        evidence: list[Evidence] = []
        base = 0.05
        destination_assessment: AssessResponse | None = None
        if target_url:
            pred = self.engine.predict_url(target_url)
            base = pred.risk_score
            evidence = pred.evidence
            if self.security_core_mode != "legacy":
                destination_assessment = self.assess_url(
                    target_url,
                    context_ai_mode="off",
                )
        base = self._finalize_score(base, evidence)
        legacy_decision = self.policy.evaluate_action(
            action_type, base, data_types, list(available_assets)
        )
        legacy_score = self.policy.effective_action_score(
            action_type, base, data_types
        )
        decision = legacy_decision
        eff = legacy_score
        level = score_to_level(legacy_score)
        confidence = self._confidence(legacy_score, evidence, "policy-action")
        action_core = None
        new_result = None
        if self.security_core_mode != "legacy":
            workflow_id = next(
                (
                    item.split(":", 1)[1]
                    for item in available_assets
                    if item.startswith("workflow_id:") and ":" in item
                ),
                None,
            )
            new_result = self.action_risk_engine.evaluate(
                ActionRiskInput(
                    action_id=action_id,
                    action_type=action_type,
                    target_url=target_url,
                    data_types=tuple(data_types),
                    user_intent=getattr(agent_context, "user_intent", None),
                    planned_action=getattr(agent_context, "planned_action", None),
                    permission_level=getattr(agent_context, "permission_level", None),
                    available_assets=available_assets,
                    session_id=getattr(agent_context, "session_id", None),
                    workflow_id=workflow_id,
                    destination_risk_score=(
                        float(destination_assessment.risk_score) * 100.0
                        if destination_assessment is not None
                        else None
                    ),
                    destination_confidence=(
                        float(destination_assessment.confidence)
                        if destination_assessment is not None
                        else None
                    ),
                )
            )
            new_result.mode = self.security_core_mode
            new_result.legacy_comparison = {
                "legacy_score": round(legacy_score * 100.0, 4),
                "new_score": new_result.danger_score,
                "new_composite_score": new_result.composite_score,
                "legacy_decision": legacy_decision.value,
                "new_decision": new_result.decision.value,
                "disagrees": (
                    legacy_decision.value
                    != {
                        ActionPolicyDecision.ALLOW: Decision.ALLOW,
                        ActionPolicyDecision.ALLOW_WITH_LOG: Decision.ALLOW,
                        ActionPolicyDecision.WARN: Decision.WARN,
                        ActionPolicyDecision.ASK_CONFIRM: Decision.ASK_USER_CONFIRMATION,
                        ActionPolicyDecision.SANDBOX: Decision.ASK_USER_CONFIRMATION,
                        ActionPolicyDecision.TEMPORARY_BLOCK: Decision.BLOCK,
                        ActionPolicyDecision.BLOCK: Decision.BLOCK,
                    }[new_result.decision].value
                ),
                "difference_reason": new_result.reason_codes[-1]
                if new_result.reason_codes
                else "",
            }
            action_core = new_result.to_trace()
            action_core["audit"] = build_action_audit_record(
                new_result,
                workflow_id=workflow_id,
            )
            if self.security_core_mode == "new_engine":
                decision = {
                    ActionPolicyDecision.ALLOW: Decision.ALLOW,
                    ActionPolicyDecision.ALLOW_WITH_LOG: Decision.ALLOW,
                    ActionPolicyDecision.WARN: Decision.WARN,
                    ActionPolicyDecision.ASK_CONFIRM: Decision.ASK_USER_CONFIRMATION,
                    ActionPolicyDecision.SANDBOX: Decision.ASK_USER_CONFIRMATION,
                    ActionPolicyDecision.TEMPORARY_BLOCK: Decision.BLOCK,
                    ActionPolicyDecision.BLOCK: Decision.BLOCK,
                }[new_result.decision]
                eff = (
                    new_result.composite_score / 100.0
                    if new_result.danger_score is None
                    else new_result.danger_score / 100.0
                )
                level = {
                    ActionRiskLevel.SAFE: RiskLevel.SAFE,
                    ActionRiskLevel.SUSPICIOUS: RiskLevel.MEDIUM,
                    ActionRiskLevel.DANGEROUS: RiskLevel.HIGH,
                    ActionRiskLevel.CRITICAL: RiskLevel.CRITICAL,
                    ActionRiskLevel.INSUFFICIENT_INFORMATION: RiskLevel.LOW,
                }[new_result.risk_level]
                confidence = new_result.confidence / 100.0
                evidence = [
                    *(
                        destination_assessment.evidence
                        if destination_assessment is not None
                        else evidence
                    ),
                    *[
                        Evidence(
                            source=item.source.value,
                            message=item.summary,
                            severity=(
                                Severity.CRITICAL
                                if item.severity >= 90
                                else Severity.HIGH
                                if item.severity >= 70
                                else Severity.MEDIUM
                                if item.severity >= 40
                                else Severity.LOW
                            ),
                            feature=item.category.value,
                            contribution=round(item.severity / 100.0, 4),
                            evidence_id=item.id,
                            category=item.category.value,
                        )
                        for item in new_result.evidence_after_dedup
                    ],
                ]

        legal_status = "unavailable"
        legal_evidence_status = LegalEvidenceStatus.INSUFFICIENT_BASIS
        legal_review_required = True
        legal_reason = "Không đánh giá được căn cứ pháp lý cục bộ; cần người dùng rà soát."
        legal_references = []
        try:
            legal = self.legal_rag.assess_action(
                action_type,
                data_types,
                available_assets=list(available_assets),
                user_intent=getattr(agent_context, "user_intent", None) or "",
                planned_action=getattr(agent_context, "planned_action", None) or "",
            )
            legal_status = legal.status
            legal_evidence_status = LegalEvidenceStatus(legal.evidence_status)
            legal_review_required = legal.requires_review
            legal_reason = legal.reason
            legal_references = [item.model_dump() for item in legal.references]
            for item in legal.references[:4]:
                page_label = (
                    f"tr. {item.page_start}"
                    if item.page_start == item.page_end
                    else f"tr. {item.page_start}-{item.page_end}"
                )
                evidence.append(
                    Evidence(
                        source="legal_rag",
                        evidence_id=item.chunk_id,
                        category=item.legal_weight,
                        feature="official_legal_reference",
                        message=(
                            f"Căn cứ cần đối chiếu: {item.title} "
                            f"({item.document_number}), {page_label}; trạng thái {item.status}."
                        ),
                        severity=Severity.INFO,
                        contribution=0.0,
                    )
                )
        except Exception as exc:
            legal_status = "unavailable"
            legal_evidence_status = LegalEvidenceStatus.INSUFFICIENT_BASIS
            legal_review_required = True
            legal_references = []
            legal_reason = (
                "Tầng RAG pháp lý không khả dụng "
                f"({type(exc).__name__}); không được mặc định hành động là tuân thủ."
            )

        # Legal retrieval may only make the gate more conservative. It never
        # lowers a technical decision or directly changes the numerical risk score.
        if legal_review_required and decision in {Decision.ALLOW, Decision.WARN}:
            decision = Decision.ASK_USER_CONFIRMATION

        rid = action_id
        summary = (
            new_result.explanation
            if self.security_core_mode == "new_engine" and new_result is not None
            else self._safe_summary(decision, action_type, data_types)
        )
        if legal_reason:
            summary = f"{summary} {legal_reason}"
        if action_core is not None:
            action_core["final_public_decision"] = decision.value
            action_core["legal_review_required"] = legal_review_required
        return AgentRiskResponse(
            decision=decision,
            verdict=decision,
            risk_level=level,
            risk_score=round(eff, 4),
            confidence=confidence,
            safe_summary=summary,
            reasoning=summary,
            evidence=evidence,
            recommended_agent_behavior=self.policy.recommend_behavior(decision, agent_context),
            requires_user_confirmation=decision == Decision.ASK_USER_CONFIRMATION,
            legal_rag_status=legal_status,
            legal_evidence_status=legal_evidence_status,
            legal_review_required=legal_review_required,
            legal_references=legal_references,
            security_core=action_core,
            request_id=rid,
        )

    def _safe_summary(self, decision: Decision, action_type: str, data_types: list[str]) -> str:
        if decision == Decision.BLOCK:
            return f"Agent định thực hiện '{action_type}' tới đích không đáng tin" + (
                " kèm dữ liệu nhạy cảm." if data_types else "."
            )
        if decision == Decision.ASK_USER_CONFIRMATION:
            return f"Hành động '{action_type}' có rủi ro trung bình — cần người dùng xác nhận."
        if decision == Decision.WARN:
            return f"Hành động '{action_type}' có dấu hiệu đáng ngờ nhẹ."
        return f"Hành động '{action_type}' ở mức rủi ro thấp."

    # ------------------------------------------------------------------ util
    @staticmethod
    def _cache_key(modality: str, content: str) -> str:
        normalized = " ".join(content.strip().split()).lower()
        return f"{modality}:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"

    def _cached_result(self, key: str) -> AssessResponse | None:
        now = time.monotonic()
        with self._recent_results_lock:
            cached = self._recent_results.get(key)
            if cached is None or now - cached[0] >= self._recent_results_ttl:
                self._recent_results.pop(key, None)
                return None
            response = cached[1].model_copy(deep=True)
        return response.model_copy(update={"request_id": str(uuid.uuid4()), "latency_ms": 0.0})

    def _store_result(self, key: str, response: AssessResponse) -> None:
        with self._recent_results_lock:
            self._recent_results[key] = (time.monotonic(), response.model_copy(deep=True))

    def _build(self, score, decision, evidence, modality, version, t0) -> AssessResponse:
        return AssessResponse(
            risk_score=round(score, 4),
            risk_level=score_to_level(score),
            decision=decision,
            confidence=self._confidence(score, evidence, version),
            modality=modality,
            reasons=self._reasons(evidence),
            evidence=evidence,
            model_version=version,
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
            request_id=str(uuid.uuid4()),
        )
