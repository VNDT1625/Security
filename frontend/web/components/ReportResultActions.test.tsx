import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getApiClient } from "@/lib/api";
import { ReportSiteButton, safeSharePayload, ShareReportButton } from "./ReportResultActions";

vi.mock("@/lib/api", () => ({ getApiClient: vi.fn() }));

describe("ReportResultActions", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    Reflect.deleteProperty(navigator, "share");
    Reflect.deleteProperty(navigator, "clipboard");
  });

  it("creates a redacted share payload without the scanned content", () => {
    const payload = safeSharePayload(81.4, "https://prewise.test/shared-report/public-token");
    expect(payload).toEqual({
      title: "Báo cáo an toàn Prewise",
      text: expect.stringContaining("81/100"),
      url: "https://prewise.test/shared-report/public-token",
    });
    expect(JSON.stringify(payload)).not.toContain("password");
    expect(JSON.stringify(payload)).not.toContain("/result/");
  });

  it("uses Web Share when available", async () => {
    const share = vi.fn().mockResolvedValue(undefined);
    const createReportShare = vi.fn().mockResolvedValue({ id: "share-1", shareToken: "portable-token", expiresAt: new Date().toISOString() });
    vi.mocked(getApiClient).mockReturnValue({ createReportShare } as never);
    Object.defineProperty(navigator, "share", { configurable: true, value: share });
    render(<ShareReportButton score={72} requestId="scan-123" />);

    fireEvent.click(screen.getByRole("button", { name: /chia sẻ/i }));

    await waitFor(() => expect(share).toHaveBeenCalledWith(expect.objectContaining({
      text: expect.stringContaining("72/100"),
      url: expect.stringContaining("/shared-report/portable-token"),
    })));
    expect(createReportShare).toHaveBeenCalledWith({ requestId: "scan-123", expiresIn: "24h" });
    expect(share.mock.calls[0][0].text).not.toContain("secret");
  });

  it("copies the redacted summary when Web Share is unavailable", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.mocked(getApiClient).mockReturnValue({
      createReportShare: vi.fn().mockResolvedValue({ id: "share-1", shareToken: "portable-token", expiresAt: new Date().toISOString() }),
    } as never);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(<ShareReportButton score={44} requestId="scan-123" />);

    fireEvent.click(screen.getByRole("button", { name: /chia sẻ/i }));

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    expect(writeText.mock.calls[0][0]).toContain("44/100");
    expect(writeText.mock.calls[0][0]).toContain("/shared-report/portable-token");
    expect(writeText.mock.calls[0][0]).not.toContain("/result/");
    expect(await screen.findByText(/đã sao chép liên kết/i)).toBeInTheDocument();
  });

  it("revokes a created portable link", async () => {
    const revokeReportShare = vi.fn().mockResolvedValue(undefined);
    vi.mocked(getApiClient).mockReturnValue({
      createReportShare: vi.fn().mockResolvedValue({ id: "share-1", shareToken: "portable-token", expiresAt: new Date().toISOString() }),
      revokeReportShare,
    } as never);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } });
    render(<ShareReportButton score={44} requestId="scan-123" />);
    fireEvent.click(screen.getByRole("button", { name: /tạo link chia sẻ/i }));
    await screen.findByRole("button", { name: /thu hồi/i });
    fireEvent.click(screen.getByRole("button", { name: /thu hồi/i }));
    await waitFor(() => expect(revokeReportShare).toHaveBeenCalledWith("share-1"));
    expect(await screen.findByText(/đã thu hồi liên kết/i)).toBeInTheDocument();
  });

  it("submits a structured site report and never adds page content", async () => {
    const submitFeedback = vi.fn().mockResolvedValue({ id: "feedback-1", status: "received" });
    vi.mocked(getApiClient).mockReturnValue({ submitFeedback } as never);
    render(<ReportSiteButton requestId="scan-123" />);

    fireEvent.click(screen.getByRole("button", { name: /báo cáo website/i }));
    fireEvent.click(screen.getByRole("radio", { name: /bằng chứng hiển thị/i }));
    fireEvent.change(screen.getByLabelText(/mô tả thêm/i), { target: { value: "Sai nguồn bằng chứng" } });
    fireEvent.click(screen.getByRole("button", { name: /gửi báo cáo/i }));

    await waitFor(() => expect(submitFeedback).toHaveBeenCalledOnce());
    expect(submitFeedback).toHaveBeenCalledWith({
      requestId: "scan-123",
      feedbackType: "report_site",
      reason: "incorrect_evidence",
      details: "Sai nguồn bằng chứng",
      idempotencyKey: expect.any(String),
    });
    expect(await screen.findByText(/đã nhận báo cáo/i)).toBeInTheDocument();
  });

  it("keeps the report form open and announces API errors", async () => {
    vi.mocked(getApiClient).mockReturnValue({
      submitFeedback: vi.fn().mockRejectedValue(new Error("Bạn cần đăng nhập.")),
    } as never);
    render(<ReportSiteButton requestId="scan-123" />);

    fireEvent.click(screen.getByRole("button", { name: /báo cáo website/i }));
    fireEvent.click(screen.getByRole("button", { name: /gửi báo cáo/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Bạn cần đăng nhập.");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("disables site reporting when no backend request id exists", () => {
    render(<ReportSiteButton />);
    const button = screen.getByRole("button", { name: /báo cáo website/i });
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription(/không thể báo cáo kết quả minh họa/i);
  });
});
