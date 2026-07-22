import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AccountHistoryPage from "./page";
import { getApiClient } from "@/lib/api";
import { persistResultRecord } from "@/lib/result-storage";

const navigation = vi.hoisted(() => ({ push: vi.fn() }));

vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
vi.mock("@/lib/api", () => ({ getApiClient: vi.fn() }));
vi.mock("@/lib/result-storage", () => ({ persistResultRecord: vi.fn() }));

const summary = {
  id: "scan-123",
  timestamp: "22/07 10:00",
  type: "URL" as const,
  score: 72,
  riskLevel: "high" as const,
  target: "https://example.test/…",
  decision: "block",
  confidence: 91,
  modelVersion: "risk-core-test",
  evidence: [{ source: "scanner", message: "Tín hiệu giả mạo", severity: "high", feature: "spoofing" }],
};

const detail = {
  ...summary,
  createdAt: "2026-07-22T10:00:00Z",
  modality: "url" as const,
  latencyMs: 12,
  reasons: ["Tín hiệu giả mạo"],
  schemaVersion: "2",
  scoringVersion: "risk-v2",
  riskCore: { final_score: 72 },
};

function client(overrides: Record<string, unknown> = {}) {
  return {
    getScanHistory: vi.fn().mockResolvedValue([summary]),
    getScanHistoryDetail: vi.fn().mockResolvedValue(detail),
    deleteScanHistory: vi.fn().mockResolvedValue({ deleted: 1 }),
    clearScanHistory: vi.fn().mockResolvedValue({ deleted: 1 }),
    ...overrides,
  };
}

async function openDetails() {
  render(<AccountHistoryPage />);
  fireEvent.click(await screen.findByRole("button", { name: /chi tiết/i }));
  return screen.findByRole("button", { name: /mở báo cáo đầy đủ/i });
}

describe("AccountHistoryPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getApiClient).mockReturnValue(client() as never);
  });

  it("reconstructs a safe local record and opens the full result", async () => {
    const api = client();
    vi.mocked(getApiClient).mockReturnValue(api as never);
    const open = await openDetails();
    fireEvent.click(open);

    await waitFor(() => expect(api.getScanHistoryDetail).toHaveBeenCalledWith("scan-123"));
    expect(persistResultRecord).toHaveBeenCalledWith("server-scan-123", expect.objectContaining({
      content: "https://example.test/…",
      dataSource: "account-history",
      result: expect.objectContaining({ request_id: "scan-123", risk_core: { final_score: 72 } }),
    }));
    expect(navigation.push).toHaveBeenCalledWith("/result/server-scan-123?score=72&type=url&demo=0");
  });

  it("exports the owner-safe detail as a JSON download", async () => {
    const api = client();
    vi.mocked(getApiClient).mockReturnValue(api as never);
    const createObjectURL = vi.fn().mockReturnValue("blob:report");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    await openDetails();
    fireEvent.click(screen.getByRole("button", { name: /xuất json/i }));

    await waitFor(() => expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob)));
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:report");
    expect(await screen.findByText(/đã xuất báo cáo json an toàn/i)).toBeInTheDocument();
  });

  it("requires confirmation and removes only the selected record", async () => {
    const api = client();
    vi.mocked(getApiClient).mockReturnValue(api as never);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await openDetails();
    fireEvent.click(screen.getByRole("button", { name: /xóa bản ghi/i }));

    await waitFor(() => expect(api.deleteScanHistory).toHaveBeenCalledWith("scan-123"));
    expect(screen.queryByText("https://example.test/…")).not.toBeInTheDocument();
    expect(await screen.findByRole("status")).toHaveTextContent(/đã xóa lượt quét/i);
  });
});
