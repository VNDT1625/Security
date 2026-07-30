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

  it("giữ tương thích legacy 0..1 và không tạo confidence giả", () => {
    const result = mapRiskResult({ risk_score: .42, threat_level: "medium" });
    expect(result).toMatchObject({ source: "legacy", score: 42, level: "medium", confidence: undefined });
  });

  it("ưu tiên điểm đã phối hợp và quyết định cấp ngoài cùng", () => {
    const result = mapRiskResult({
      risk_score: .68,
      risk_level: "high",
      decision: "BLOCK",
      risk_core: {
        schema_version: "2",
        scoring_version: "core-2",
        final_score: 60,
        blended_final_score: 68,
        raw_score: 12,
        confidence: 80,
        verdict: "dangerous",
        decision: "soft_block",
      },
    });
    expect(result).toMatchObject({ score: 68, level: "high", decision: "BLOCK" });
  });
});
