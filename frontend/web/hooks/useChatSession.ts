"use client";

/**
 * Hook quản lý một phiên chat streaming có ngữ cảnh.
 *
 * Bọc `ApiClient.openChatStream()` (một AsyncGenerator phát các `ChatChunk`
 * delta và kết thúc bằng `ChatFinal`) thành một API React thân thiện:
 * danh sách tin nhắn, hàm gửi, cờ đang stream, lỗi và hàm thử lại.
 *
 * Luồng gửi (khớp Luồng 2 trong design.md):
 *   1. Thêm bong bóng `user` với câu hỏi.
 *   2. Tạo bong bóng `assistant` rỗng làm placeholder (hiệu ứng đang gõ).
 *   3. Mở `openChatStream({ question, context, history })` và lặp generator,
 *      nối từng `chunk.delta` vào text của bong bóng assistant.
 *   4. Khi generator kết thúc, gắn `ChatFinal.assessment` (nếu có) để render
 *      RiskBadge + EvidencePanel trong bong bóng phản hồi.
 *
 * Xử lý lỗi (Requirement 8.5): nếu luồng ném lỗi (WS đóng giữa chừng), đặt
 * thông báo lỗi tiếng Việt mà KHÔNG mất lịch sử hội thoại; `retryLast()` gửi
 * lại câu hỏi gần nhất của người dùng.
 *
 * _Requirements: 8.1, 8.5_
 */

import { useCallback, useRef, useState } from "react";

import { getApiClient } from "@/lib/api";
import type { ChatMessageModel, ChatRequest, LegalContext } from "@/lib/types";

/** Ngữ cảnh nội dung đang xét kèm theo câu hỏi (tùy chọn). */
export type ChatContext = ChatRequest["context"];

/** Thông báo hiển thị khi kết nối bị gián đoạn giữa chừng. */
const DISCONNECT_MESSAGE = "Mất kết nối, đang thử lại";

/** Giá trị trả về của `useChatSession`. */
export interface UseChatSessionResult {
    /** Toàn bộ tin nhắn theo thứ tự thời gian (user + assistant). */
    messages: ChatMessageModel[];
    /** Gửi một câu hỏi kèm ngữ cảnh tùy chọn; bỏ qua nếu rỗng sau trim. */
    sendMessage: (text: string, context?: ChatContext, legalContext?: LegalContext) => Promise<void>;
    /** True trong khi đang nhận luồng phản hồi. */
    isStreaming: boolean;
    /** Thông báo lỗi tiếng Việt, hoặc null khi không có lỗi. */
    error: string | null;
    /** Gửi lại câu hỏi gần nhất của người dùng (dùng khi mất kết nối). */
    retryLast: () => Promise<void>;
}

/** Sinh id duy nhất cho một tin nhắn (không phụ thuộc backend). */
function createMessageId(prefix: string): string {
    return `${prefix}-${Date.now().toString(36)}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;
}

/**
 * Quản lý trạng thái một phiên chat streaming.
 *
 * @returns {@link UseChatSessionResult} gồm messages, sendMessage,
 *   isStreaming, error và retryLast.
 */
export function useChatSession(): UseChatSessionResult {
    const [messages, setMessages] = useState<ChatMessageModel[]>([]);
    const [isStreaming, setIsStreaming] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);

    /**
     * Câu hỏi + ngữ cảnh của lần gửi gần nhất, giữ trong ref để `retryLast`
     * truy cập được mà không tạo phụ thuộc closure gây stale.
     */
    const lastRequestRef = useRef<{
        question: string;
        context?: ChatContext;
        legalContext?: LegalContext;
    } | null>(null);

    /**
     * Chạy một luồng chat cho `question` đã cho.
     *
     * Giả định bong bóng `user` đã (hoặc sẽ) tồn tại; hàm này chỉ tạo bong
     * bóng assistant, mở luồng và cập nhật tăng dần. `history` được chụp từ
     * `messages` hiện tại thông qua functional update để tránh stale closure.
     */
    const runStream = useCallback(
        async (question: string, context?: ChatContext, legalContext?: LegalContext): Promise<void> => {
            const assistantId = createMessageId("assistant");

            // Tạo placeholder assistant; đồng thời chụp history hiện có.
            let history: ChatMessageModel[] = [];
            setMessages((prev) => {
                history = prev;
                const placeholder: ChatMessageModel = {
                    id: assistantId,
                    role: "assistant",
                    text: "",
                    createdAt: Date.now(),
                };
                return [...prev, placeholder];
            });

            setIsStreaming(true);
            setError(null);

            try {
                const api = getApiClient();
                const stream = api.openChatStream({
                    question,
                    context,
                    legal_context: legalContext,
                    history,
                });

                // Lặp generator: nối từng delta vào bong bóng assistant.
                let result = await stream.next();
                while (!result.done) {
                    const { delta } = result.value;
                    setMessages((prev) =>
                        prev.map((msg) =>
                            msg.id === assistantId
                                ? { ...msg, text: msg.text + delta }
                                : msg,
                        ),
                    );
                    result = await stream.next();
                }

                // Giá trị trả về của generator là ChatFinal (kèm assessment).
                const final = result.value;
                if (final && (final.assessment || final.legalAnswer)) {
                    setMessages((prev) =>
                        prev.map((msg) =>
                            msg.id === assistantId
                                ? { ...msg, assessment: final.assessment,
                                    legalAnswer: final.legalAnswer }
                                : msg,
                        ),
                    );
                }
            } catch {
                // WS đóng giữa chừng: giữ nguyên lịch sử, chỉ báo lỗi.
                setError(DISCONNECT_MESSAGE);
            } finally {
                setIsStreaming(false);
            }
        },
        [],
    );

    const sendMessage = useCallback(
        async (text: string, context?: ChatContext, legalContext?: LegalContext): Promise<void> => {
            const question = text.trim();
            // Bỏ qua câu hỏi rỗng sau trim: không thêm bong bóng user (8.1/8.4).
            if (question.length === 0) {
                return;
            }

            // Thêm bong bóng user và ghi nhớ lần gửi để retry.
            const userMessage: ChatMessageModel = {
                id: createMessageId("user"),
                role: "user",
                text: question,
                createdAt: Date.now(),
            };
            setMessages((prev) => [...prev, userMessage]);
            lastRequestRef.current = { question, context, legalContext };

            await runStream(question, context, legalContext);
        },
        [runStream],
    );

    const retryLast = useCallback(async (): Promise<void> => {
        const last = lastRequestRef.current;
        if (last === null) {
            return;
        }
        // Gửi lại câu hỏi gần nhất mà KHÔNG thêm bong bóng user mới.
        await runStream(last.question, last.context, last.legalContext);
    }, [runStream]);

    return { messages, sendMessage, isStreaming, error, retryLast };
}
