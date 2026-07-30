import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AnalyzePage from "./page";
import { getApiClient } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/components/PrewiseUI", () => ({
  PrewiseShell: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock("@/context/AuthContext", () => ({
  useAuth: () => ({ plan: { tier: "free" } }),
}));
vi.mock("@/lib/api", () => ({ getApiClient: vi.fn() }));
vi.mock("@/lib/result-storage", () => ({ persistResultRecord: vi.fn() }));
vi.mock("@/lib/auth-session", () => ({ fetchWithAnonymousSessionFallback: vi.fn() }));

describe("Gmail demo access notice", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("explains the test-user restriction before leaving for Google", async () => {
    const client = {
      getGmailStatus: vi.fn().mockResolvedValue({
        configured: true,
        connected: false,
        address: "",
        status: "not_connected",
      }),
      connectGmail: vi.fn(),
    };
    vi.mocked(getApiClient).mockReturnValue(client as never);

    render(<AnalyzePage />);
    fireEvent.click(screen.getByRole("tab", { name: "Email" }));
    fireEvent.click(screen.getByRole("button", { name: "Chọn từ Gmail" }));

    const notice = await screen.findByRole("dialog");
    expect(notice).toHaveTextContent("Gmail của bạn cần thuộc danh sách người dùng thử nghiệm");
    expect(notice).toHaveTextContent("đây không phải lỗi tài khoản hay lỗi hệ thống");
    expect(client.connectGmail).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Đóng" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});
