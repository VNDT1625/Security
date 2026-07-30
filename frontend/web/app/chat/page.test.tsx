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
        {
            id: "019f-test-history-older",
            timestamp: "31/07 13:00",
            type: "Email",
            score: 24,
            riskLevel: "low",
            target: "older@example.test",
            decision: "ALLOW",
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

    it("exposes exactly the legal-adapter and @ID-history purposes", async () => {
        render(<ChatPage />);

        expect(screen.getByTestId("prewise-shell")).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Trợ lý an toàn số" })).toBeInTheDocument();
        expect(screen.getByRole("heading", {
            name: "Hỏi pháp luật an ninh mạng",
        })).toBeInTheDocument();
        expect(screen.getByRole("tab", { name: "Pháp luật an ninh mạng" }))
            .toHaveAttribute("aria-selected", "true");
        expect(screen.getByRole("tab", { name: "Hỏi theo @ID lịch sử" }))
            .toBeInTheDocument();
        expect(screen.getByText("Dùng adapter pháp luật")).toBeInTheDocument();
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
            undefined,
        ));
        expect(mocks.refreshQuota).toHaveBeenCalledOnce();
    });

    it("opens newest-first history suggestions when the user types @", async () => {
        const user = userEvent.setup();
        render(<ChatPage />);

        await screen.findByRole("button", {
            name: "Gắn kết quả @019f-test-history-0001",
        });
        const input = screen.getByRole("textbox", { name: "Câu hỏi cho trợ lý" });
        await user.type(input, "@");

        const picker = screen.getByRole("listbox", { name: "Gợi ý lịch sử" });
        const options = screen.getAllByRole("option");
        expect(picker).toBeInTheDocument();
        expect(options).toHaveLength(2);
        expect(options[0]).toHaveAccessibleName("Chọn lịch sử @019f-test-history-0001");
        expect(options[1]).toHaveAccessibleName("Chọn lịch sử @019f-test-history-older");

        await user.click(options[0]);
        expect(input).toHaveValue("@019f-test-history-0001 ");
    });

    it("forces legal questions through the legal adapter context", async () => {
        const user = userEvent.setup();
        render(<ChatPage />);

        await user.type(screen.getByRole("textbox", { name: "Chủ thể" }), "doanh nghiệp");
        await user.type(screen.getByRole("textbox", { name: "Hành động" }), "thông báo sự cố");
        await user.type(
            screen.getByRole("textbox", { name: "Dữ liệu hoặc tài sản liên quan" }),
            "dữ liệu cá nhân",
        );
        const input = screen.getByRole("textbox", { name: "Câu hỏi cho trợ lý" });
        await user.type(input, "Tôi phải thông báo trong thời hạn nào?");
        await user.click(screen.getByRole("button", { name: "Gửi câu hỏi" }));

        await waitFor(() => expect(mocks.sendMessage).toHaveBeenCalledWith(
            "Tôi phải thông báo trong thời hạn nào?",
            undefined,
            expect.objectContaining({
                jurisdiction: "VN",
                actor: "doanh nghiệp",
                action: "thông báo sự cố",
                data_or_asset: "dữ liệu cá nhân",
            }),
        ));
    });
});
