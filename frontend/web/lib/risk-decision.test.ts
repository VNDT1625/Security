import { describe, expect, it } from "vitest";
import { getRiskLevelForDecision } from "./risk";

describe("getRiskLevelForDecision", () => {
  it("không tự hạ quyết định chặn chỉ vì điểm dưới 70", () => {
    expect(getRiskLevelForDecision("BLOCK", 60).key).toBe("danger");
  });

  it("không tự nâng quyết định cho phép chỉ vì điểm cũ cao", () => {
    expect(getRiskLevelForDecision("ALLOW", 80).key).toBe("safe");
  });

  it("chỉ dùng ngưỡng điểm khi phản hồi cũ chưa có quyết định", () => {
    expect(getRiskLevelForDecision(undefined, 55).key).toBe("warn");
  });
});
