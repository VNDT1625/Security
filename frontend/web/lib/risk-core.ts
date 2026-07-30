export type RiskCoreRecord = Record<string, unknown>;

export interface RiskCoreView {
  source: "risk_core_v2" | "legacy";
  schemaVersion?: string;
  scoringVersion?: string;
  score: number;
  rawScore?: number;
  confidence?: number;
  level?: string;
  decision?: string;
  nextAction?: string;
  criteria: RiskCoreRecord[];
  evidence: RiskCoreRecord[];
  mitigations: RiskCoreRecord[];
  overrides: RiskCoreRecord[];
  effectiveOverride?: RiskCoreRecord;
  caps: RiskCoreRecord[];
  conflicts: RiskCoreRecord[];
  unavailableChecks: string[];
  notCheckedChecks: string[];
  reasoning: string[];
}

export interface ScanCheck {
  id: string;
  label: string;
  status: "safe" | "danger" | "review" | "unavailable";
  detail: string;
  source: string;
}

const PROVIDER_NAMES: Record<string, string> = {
  "51": "ScamAdviser", "52": "Criminal IP", "53": "Hudson Rock",
  "54": "Have I Been Pwned", "55": "PhishTank", "56": "CyRadar",
  "57": "National Cybersecurity Association", "58": "NCSC", "59": "ScamVN",
  "60": "IP Quality Score", "61": "Google Safe Browsing", "62": "Bfore",
  "63": "APIVoid", "64": "PhishDestroy", urlvet: "url.vet",
  distributed_telemetry: "IOC đa máy",
};

const record = (value: unknown): RiskCoreRecord | undefined =>
  value != null && typeof value === "object" && !Array.isArray(value) ? value as RiskCoreRecord : undefined;
const records = (value: unknown): RiskCoreRecord[] => Array.isArray(value) ? value.filter((item) => record(item)) as RiskCoreRecord[] : [];
const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.filter((item) => typeof item === "string" || typeof item === "number").map(String)
  : [];
const number = (value: unknown): number | undefined => typeof value === "number" && Number.isFinite(value) ? value : undefined;
const text = (value: unknown): string | undefined => typeof value === "string" && value.trim() ? value : undefined;
const clamp = (value: number) => Math.max(0, Math.min(100, value));
const CRITERION_STATUS_LABEL: Record<string, string> = {
  clean: "Đã kiểm tra · không phát hiện",
  suspicious: "Đáng ngờ",
  malicious: "Nguy hiểm",
  not_applicable: "Không áp dụng",
  unavailable: "Không khả dụng",
  not_checked: "Chưa kiểm tra",
};
const criterionRecords = (value: unknown): RiskCoreRecord[] => records(value).map((item) => {
  const contribution = number(item.adjusted_score);
  const weight = number(item.max_weight);
  return {
    ...item,
    status: CRITERION_STATUS_LABEL[String(item.status ?? "")] ?? item.status,
    contribution: contribution == null
      ? item.contribution
      : weight == null
        ? contribution.toFixed(2)
        : `${contribution.toFixed(2)} / ${weight.toFixed(2)}`,
  };
});

/** Maps the additive API payload without deriving v2 policy fields locally. */
export function mapRiskResult(payload: unknown, legacyScore?: number): RiskCoreView {
  const outer = record(payload) ?? {};
  const core = record(outer.risk_core);
  if (core) {
    return {
      source: "risk_core_v2",
      schemaVersion: text(core.schema_version),
      scoringVersion: text(core.scoring_version),
      score: clamp(
        number(core.blended_final_score)
        ?? number(core.final_score)
        ?? number(core.risk_score)
        ?? 0
      ),
      rawScore: number(core.raw_score) ?? number(core.base_risk_score),
      confidence: number(core.confidence_score) ?? number(core.confidence),
      level: text(outer.risk_level) ?? text(core.risk_level) ?? text(core.verdict),
      decision: text(outer.decision) ?? text(core.decision),
      nextAction: text(core.next_action),
      criteria: criterionRecords(core.criteria), evidence: records(core.evidence), mitigations: records(core.mitigations),
      overrides: records(core.overrides), effectiveOverride: record(core.effective_override), caps: records(core.caps),
      conflicts: records(core.conflicts), unavailableChecks: strings(core.unavailable_checks),
      notCheckedChecks: strings(core.not_checked_checks), reasoning: strings(core.reasoning),
    };
  }
  const normalized = number(outer.risk_score);
  return {
    source: "legacy", score: clamp(normalized == null ? legacyScore ?? 0 : normalized <= 1 ? normalized * 100 : normalized),
    confidence: number(outer.confidence) == null ? undefined : clamp((number(outer.confidence) as number) <= 1 ? (number(outer.confidence) as number) * 100 : number(outer.confidence) as number),
    level: text(outer.risk_level) ?? text(outer.threat_level), decision: text(outer.decision),
    criteria: records(outer.score_layers), evidence: records(outer.evidence), mitigations: [], overrides: [], caps: [], conflicts: [],
    unavailableChecks: [], notCheckedChecks: [], reasoning: strings(outer.reasons),
  };
}

export function displayValue(item: RiskCoreRecord, keys: string[], fallback = "—"): string {
  for (const key of keys) { const value = item[key]; if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value); }
  return fallback;
}

const checkStatus = (value: unknown): ScanCheck["status"] =>
  value === "danger" || value === "safe" || value === "review" || value === "unavailable"
    ? value : "unavailable";

/** Builds a UI-only checklist without converting provider no-hit into trust points. */
export function extractScanChecks(evidence: RiskCoreRecord[]): ScanCheck[] {
  const checks: ScanCheck[] = [];
  const seen = new Set<string>();
  for (const item of evidence) {
    const sourceId = String(item.source_id ?? "");
    const metadata = record(item.metadata) ?? {};
    const embedded = Array.isArray(metadata.checks) ? metadata.checks : [];
    for (const raw of embedded) {
      const check = record(raw);
      if (!check) continue;
      const id = String(check.id ?? `${sourceId}-${checks.length}`);
      if (seen.has(id)) continue;
      seen.add(id);
      checks.push({
        id,
        label: String(check.label ?? PROVIDER_NAMES[sourceId] ?? sourceId),
        status: checkStatus(check.status),
        detail: String(check.detail ?? metadata.summary ?? ""),
        source: PROVIDER_NAMES[sourceId] ?? sourceId,
      });
    }
    if (embedded.length || !PROVIDER_NAMES[sourceId]) continue;
    const id = `provider-${sourceId}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const adapterStatus = String(metadata.adapter_status ?? "");
    const providerVerdict = String(item.provider_verdict ?? "");
    const status = String(item.status ?? "");
    const dangerous = providerVerdict.includes("malicious") || providerVerdict.includes("suspicious")
      || status === "malicious" || status === "suspicious";
    const completed = adapterStatus === "completed";
    checks.push({
      id,
      label: PROVIDER_NAMES[sourceId],
      status: dangerous ? "danger" : completed ? "safe" : "unavailable",
      detail: String(metadata.summary ?? (completed
        ? "Đã quét và chưa ghi nhận chỉ báo độc hại."
        : "Nguồn chưa được cấu hình hoặc không khả dụng.")),
      source: PROVIDER_NAMES[sourceId],
    });
  }
  return checks;
}
