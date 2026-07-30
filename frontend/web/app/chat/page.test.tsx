import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ChatPage from "./page";

const refreshQuota = vi.fn().mockResolvedValue(undefined);

vi.mock("@/components/PrewiseUI", () => ({
    PrewiseShell: ({ children }: { children: React.ReactNode }) => (
        <div data-testid="prewise-shell">{children}</div>
    ),
}));

vi.mock("@/components/ChatMessage", () => ({
    default: () => <div data-testid="chat-message" />,
}));

vi.mock("@/hooks/useChatSession", () => ({
    useChatSession: () => ({
        messages: [],
        sendMessage: vi.fn().mockResolvedValue(undefined),
        isStreaming: false,
        error: null,
        retryLast: vi.fn().mockResolvedValue(undefined),
    }),
}));

vi.mock("@/context/AuthContext", () => ({
    useAuth: () => ({
        quota: {
            getRemaining: () => 1000,
            getLimitForPlan: () => 1000,
            consume: vi.fn(),
        },
        quotaInfo: {
            remaining: 1000,
            dailyScanLimit: 1000,
            aiCreditDailyLimit: 5,
            aiRemaining: 5,
        },
        refreshQuota,
        session: {
            plan: { aiCreditDailyLimit: 5 },
        },
    }),
}));

describe("ChatPage visual and interaction contract", () => {
    beforeEach(() => {
        refreshQuota.mockClear();
    });

    it("renders inside the product shell with analysis guidance and quotas", () => {
        render(<ChatPage />);

        expect(screen.getByTestId("prewise-shell")).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Trợ lý phân tích" })).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Bạn muốn kiểm tra điều gì?" })).toBeInTheDocument();
        expect(screen.getByText("Core scans")).toBeInTheDocument();
        expect(screen.getByText("AI credits")).toBeInTheDocument();
    });

    it("uses quick starts and exposes structured legal context", async () => {
        const user = userEvent.setup();
        render(<ChatPage />);

        await user.click(screen.getByRole("button", { name: /Kiểm tra một URL/i }));
        expect(screen.getByRole("textbox", { name: "Nội dung cần đánh giá" }))
            .toHaveValue("Hãy kiểm tra URL này:\n");

        await user.click(screen.getByRole("button", { name: /Hỏi pháp luật/i }));
        expect(screen.getByRole("textbox", { name: "Quốc gia" })).toHaveValue("VN");
        expect(screen.getByRole("textbox", { name: "Chủ thể" })).toBeInTheDocument();
        expect(screen.getByRole("textbox", { name: "Hành động" })).toBeInTheDocument();
    });
});
