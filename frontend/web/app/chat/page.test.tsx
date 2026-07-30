import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ChatPage from "./page";

const mocks = vi.hoisted(() => ({
    sendMessage: vi.fn().mockResolvedValue(undefined),
    refreshQuota: vi.fn().mockResolvedValue(undefined),
    getScanHistory: vi.fn().mockResolvedValue([
        {
            id: "019f-test-history-0001",
            timestamp: "31/07 14:00",
            type: "URL",
            score: 82,
            riskLevel: "high",
            target: "https://example.test/path",
            decision: "BLOCK",
        },
    ]),
}));

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
        sendMessage: mocks.sendMessage,
        isStreaming: false,
        error: null,
        retryLast: vi.fn().mockResolvedValue(undefined),
    }),
}));

vi.mock("@/context/AuthContext", () => ({
    useAuth: () => ({
        quotaInfo: {
            aiCreditDailyLimit: 5,
            aiRemaining: 4,
        },
        refreshQuota: mocks.refreshQuota,
    }),
}));

vi.mock("@/lib/api", () => ({
    getApiClient: () => ({
        getScanHistory: mocks.getScanHistory,
    }),
}));

describe("ChatPage question-and-answer contract", () => {
    beforeEach(() => {
        mocks.sendMessage.mockClear();
        mocks.refreshQuota.mockClear();
        mocks.getScanHistory.mockClear();
    });

    it("is a Q&A workspace and clearly separates itself from Analyze", async () => {
        render(<ChatPage />);

        expect(screen.getByTestId("prewise-shell")).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Trợ lý an toàn số" })).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Bạn muốn hỏi điều gì?" })).toBeInTheDocument();
        expect(screen.getByText("Chat không dùng lượt Analyze")).toBeInTheDocument();
        expect(screen.queryByText("Core scans")).not.toBeInTheDocument();
        expect(screen.queryByText("Kiểm tra một URL")).not.toBeInTheDocument();

        expect(await screen.findByRole("button", {
            name: "Gắn kết quả @019f-test-history-0001",
        })).toBeInTheDocument();
    });

    it("attaches an owned history @ID and sends it as context without scan content", async () => {
        const user = userEvent.setup();
        render(<ChatPage />);

        await user.click(await screen.findByRole("button", {
            name: "Gắn kết quả @019f-test-history-0001",
        }));

        const input = screen.getByRole("textbox", { name: "Câu hỏi cho trợ lý" });
        expect(input).toHaveValue("@019f-test-history-0001 ");
        expect(screen.getByText(/@019f-tes… · URL · 82\/100/)).toBeInTheDocument();

        await user.type(input, "Tại sao kết quả này bị cảnh báo?");
        await user.click(screen.getByRole("button", { name: "Gửi câu hỏi" }));

        await waitFor(() => expect(mocks.sendMessage).toHaveBeenCalledWith(
            "Tại sao kết quả này bị cảnh báo?",
            {
                content: "",
                modality: "text",
                analysis_id: "019f-test-history-0001",
            },
        ));
        expect(mocks.refreshQuota).toHaveBeenCalledOnce();
    });

    it("sends an ordinary security question without Analyze context", async () => {
        const user = userEvent.setup();
        render(<ChatPage />);

        const input = screen.getByRole("textbox", { name: "Câu hỏi cho trợ lý" });
        await user.type(input, "Tôi nên làm gì khi bị lộ mật khẩu?");
        await user.click(screen.getByRole("button", { name: "Gửi câu hỏi" }));

        await waitFor(() => expect(mocks.sendMessage).toHaveBeenCalledWith(
            "Tôi nên làm gì khi bị lộ mật khẩu?",
            undefined,
        ));
    });
});
