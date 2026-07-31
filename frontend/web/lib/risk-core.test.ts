import { describe, expect, it } from "vitest";
import { mapRiskResult } from "./risk-core";

describe("mapRiskResult", () => {
  it("ưu tiên payload risk_core và không tự suy policy", () => {
    const result = mapRiskResult({ risk_score: .1, risk_core: { schema_version: "2", scoring_version: "core-2", final_score: 83, raw_score: 91, confidence: 72, verdict: "HIGH", decision: "BLOCK", next_action: "Do not open", criteria: [{ id: "c1", points: 10 }], unavailable_checks: ["sandbox"], reasoning: ["Correlated evidence"] } });
    expect(result.source).toBe("risk_core_v2");
    expect(result.score).toBe(83);
    expect(result.level).toBe("HIGH");
    expect(result.decision).toBe("BLOCK");
    expect(result.unavailableChecks).toEqual(["sandbox"]);
  });

  it("không dùng điểm cũ khi thiếu kết quả của lõi", () => {
    const result = mapRiskResult({ risk_score: .42, threat_level: "medium" });
    expect(result).toMatchObject({
      source: "unavailable",
      score: 0,
      level: "insufficient_information",
      decision: "ASK_USER_CONFIRMATION",
      confidence: undefined,
    });
  });

  it("dùng duy nhất điểm cuối của lõi và quyết định cấp ngoài cùng", () => {
    const result = mapRiskResult({
      risk_score: .68,
      risk_level: "high",
      decision: "BLOCK",
      risk_core: {
        schema_version: "2",
        scoring_version: "core-2",
        final_score: 60,
        raw_score: 12,
        confidence: 80,
        verdict: "dangerous",
        decision: "soft_block",
      },
    });
    expect(result).toMatchObject({ score: 60, level: "high", decision: "BLOCK" });
  });

  it("ưu tiên bằng chứng lõi và giữ nguyên lý do cùng bằng chứng của mức sàn", () => {
    const matchedEvidenceIds = ["payee", "legal-identity", "metadata-identity"];
    const reason =
      "Trang yêu cầu thanh toán nhưng chưa xác minh người nhận và danh tính pháp lý.";
    const result = mapRiskResult({
      evidence: [{ evidence_id: "outer-only", finding_type: "url_obfuscation" }],
      decision: "BLOCK",
      risk_core: {
        schema_version: "2",
        final_score: 60,
        confidence: 66,
        evidence: matchedEvidenceIds.map((evidence_id) => ({
          evidence_id,
          status: "suspicious",
        })),
        effective_override: {
          rule_id: "url-unverified-payee-without-business-identity-v1",
          matched_evidence_ids: matchedEvidenceIds,
          reason,
        },
      },
    });

    expect(result.evidence.map((item) => item.evidence_id)).toEqual(
      matchedEvidenceIds,
    );
    expect(result.evidence).not.toContainEqual(
      expect.objectContaining({ evidence_id: "outer-only" }),
    );
    expect(result.effectiveOverride).toMatchObject({
      matched_evidence_ids: matchedEvidenceIds,
      reason,
    });
  });
});
