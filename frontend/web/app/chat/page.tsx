"use client";

/**
 * Trang CHAT — trải nghiệm thử nhanh có ngữ cảnh (streaming).
 *
 * Mục đích (UI_wireframe §1.5): khách mới dán URL/nội dung email vào ô chat,
 * trợ lý đánh giá độ tin cậy + giải thích lý do theo thời gian thực. Cuối phiên
 * luôn gợi ý cài Extension để "bảo vệ thật".
 *
 * Trách nhiệm (design.md — Chat; Luồng 2 streaming):
 *   - Dùng `useChatSession()` cho messages/sendMessage/isStreaming/error/retryLast.
 *   - Bong bóng chào mừng của assistant khi chưa có tin nhắn nào.
 *   - Danh sách hội thoại render qua <ChatMessage>, con trỏ đang gõ ở bong bóng
 *     assistant cuối cùng khi đang stream.
 *   - Ô nhập dưới cùng: textarea + "Gửi ▶" + affordance "📎 Tải file .eml" +
 *     hiển thị quota "Còn lại hôm nay: X/50 scan" (∞ cho pro/team).
 *   - Chặn câu hỏi rỗng (Req 8.4); kiểm tra quota trước khi gửi; nếu hết quota
 *     hiển thị CTA nâng cấp/Extension và KHÔNG gửi; ngược lại tiêu thụ 1 lượt
 *     rồi gọi sendMessage với context suy ra từ đầu vào (url vs email).
 *   - Banner lỗi khi mất kết nối WS + nút "Thử lại" gọi retryLast() (Req 8.5).
 *
 * An toàn hiển thị (Req 18): mọi nội dung render qua JSX escaping.
 *
 * _Requirements: 8.1, 8.2, 8.3, 8.4, 8.6_
 */

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";

import ChatMessage from "@/components/ChatMessage";
import { useAuth } from "@/context/AuthContext";
import { useChatSession, type ChatContext } from "@/hooks/useChatSession";
import { looksLikeUrl } from "@/lib/quick-scan";
import type { LegalContext } from "@/lib/types";

/** Nội dung bong bóng chào mừng của trợ lý (UI_wireframe §1.5). */
const WELCOME_TEXT =
    "🛡 Chào bạn! Dán URL hoặc nội dung email vào đây, tôi sẽ đánh giá độ tin cậy và giải thích lý do.";

/** Thông điệp khi người dùng hết lượt quét trong ngày. */
const QUOTA_EXCEEDED_TEXT =
    "Bạn đã hết lượt quét miễn phí hôm nay. Nâng cấp gói hoặc cài Extension để tiếp tục được bảo vệ.";

/**
 * ChatPage — giao diện chat đánh giá có ngữ cảnh.
 */
export default function ChatPage(): JSX.Element {
    const { messages, sendMessage, isStreaming, error, retryLast } =
        useChatSession();
    const { quota, quotaInfo, refreshQuota, session } = useAuth();

    // Nội dung ô nhập (controlled) + thông báo hết quota (client-side).
    const [input, setInput] = useState("");
    const [quotaBlocked, setQuotaBlocked] = useState(false);
    const [activeContext, setActiveContext] = useState<ChatContext | null>(null);
    const [legalMode, setLegalMode] = useState(false);
    const [legalContext, setLegalContext] = useState<LegalContext>({
        jurisdiction: "VN",
        as_of_date: new Date().toISOString().slice(0, 10),
        actor: "",
        action: "",
        data_or_asset: "",
    });

    // Vùng cuộn danh sách tin nhắn — tự cuộn tới tin mới nhất.
    const scrollRef = useRef<HTMLDivElement | null>(null);
    const emlInputRef = useRef<HTMLInputElement | null>(null);

    // Số lượt còn lại + giới hạn theo gói hiện tại (∞ cho pro/team).
    const remaining = quotaInfo?.remaining ?? quota.getRemaining();
    const limit = quotaInfo?.dailyScanLimit ?? quota.getLimitForPlan();
    const remainingLabel = limit >= 999_999
        ? "∞"
        : `${remaining}/${limit}`;
    const aiLimit = quotaInfo?.aiCreditDailyLimit ?? session?.plan.aiCreditDailyLimit ?? 5;
    const aiRemaining = quotaInfo?.aiRemaining ?? aiLimit;
    const aiRemainingLabel = aiLimit >= 999_999 ? "∞" : `${aiRemaining}/${aiLimit}`;

    // Có ít nhất một kết quả đánh giá từ assistant → hiện CTA cài Extension.
    const hasAssessment = useMemo(
        () => messages.some((m) => m.role === "assistant" && m.assessment),
        [messages],
    );

    // Tự cuộn xuống cuối mỗi khi có tin nhắn mới hoặc delta stream.
    useEffect(() => {
        const el = scrollRef.current;
        if (el) {
            el.scrollTop = el.scrollHeight;
        }
    }, [messages, isStreaming]);

    // id của bong bóng assistant cuối cùng (để gắn con trỏ đang gõ khi stream).
    const lastAssistantId = useMemo(() => {
        for (let i = messages.length - 1; i >= 0; i--) {
            if (messages[i].role === "assistant") {
                return messages[i].id;
            }
        }
        return null;
    }, [messages]);

    /** Gửi câu hỏi hiện tại: chặn rỗng, kiểm tra quota, dựng context. */
    async function handleSend(): Promise<void> {
        const question = input.trim();

        // (Req 8.4) Câu hỏi rỗng sau trim → không gửi.
        if (question.length === 0) {
            return;
        }

        const startsNewAssessment = !legalMode && (
            activeContext === null ||
            looksLikeUrl(question) ||
            question.length > 240 ||
            question.includes("\n"));

        // Chỉ nội dung mới tiêu thụ scan. Câu hỏi tiếp nối tái sử dụng assessment.
        if (startsNewAssessment && remaining <= 0) {
            setQuotaBlocked(true);
            return;
        }

        // Dựng context từ đầu vào: url nếu trông giống URL, ngược lại email —
        // để trợ lý trả về đánh giá đúng đối tượng (chat có ngữ cảnh).
        const context: ChatContext | undefined = legalMode ? undefined : startsNewAssessment
            ? {
                content: question,
                modality: looksLikeUrl(question) ? "url" : "email",
            }
            : (activeContext ?? undefined);

        if (startsNewAssessment) {
            if (quotaInfo === null) quota.consume();
            setActiveContext(context);
        }
        setQuotaBlocked(false);
        setInput("");
        try {
            await sendMessage(question, context, legalMode ? legalContext : undefined);
        } finally {
            await refreshQuota();
        }
    }

    /** Gửi bằng Enter (Shift+Enter để xuống dòng). */
    function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>): void {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            void handleSend();
        }
    }

    const showWelcome = messages.length === 0;

    return (
        <div className="mx-auto flex min-h-[calc(100dvh-4rem)] w-full max-w-3xl min-w-0 flex-col px-3 py-3 pb-[calc(4.5rem+env(safe-area-inset-bottom))] sm:px-4 sm:py-6 sm:pb-6">
            {/* Danh sách hội thoại (cuộn) */}
            <div
                ref={scrollRef}
                className="flex-1 space-y-4 overflow-y-auto pb-4"
                aria-live="polite"
            >
                {/* Bong bóng chào mừng khi chưa có tin nhắn nào */}
                {showWelcome && (
                    <ChatMessage
                        message={{
                            id: "welcome",
                            role: "assistant",
                            text: WELCOME_TEXT,
                            createdAt: 0,
                        }}
                    />
                )}

                {/* Danh sách tin nhắn thực tế */}
                {messages.map((message) => (
                    <ChatMessage
                        key={message.id}
                        message={message}
                        isStreaming={
                            isStreaming && message.id === lastAssistantId
                        }
                    />
                ))}

                {/* CTA cài Extension sau khi có kết quả đánh giá */}
                {hasAssessment && (
                    <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                        💡 Muốn được bảo vệ tự động khi duyệt web?{" "}
                        <Link
                            href="/downloads"
                            className="font-semibold text-amber-900 underline underline-offset-2 hover:text-amber-950"
                        >
                            Cài Extension
                        </Link>
                    </div>
                )}
            </div>

            {/* Banner lỗi mất kết nối WS + nút thử lại (Req 8.5) */}
            {error && (
                <div
                    role="alert"
                    className="mb-3 flex flex-col items-stretch justify-between gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-2.5 text-sm text-red-700 sm:flex-row sm:items-center"
                >
                    <span>⚠ {error}</span>
                    <button
                        type="button"
                        onClick={() => {
                            void retryLast();
                        }}
                        className="min-h-11 shrink-0 rounded-md border border-red-300 bg-white px-3 py-2 font-medium text-red-700 hover:bg-red-100"
                    >
                        Thử lại
                    </button>
                </div>
            )}

            {/* Thông báo hết quota + CTA nâng cấp/Extension */}
            {quotaBlocked && (
                <div
                    role="alert"
                    className="mb-3 rounded-lg border border-orange-200 bg-orange-50 px-4 py-2.5 text-sm text-orange-800"
                >
                    {QUOTA_EXCEEDED_TEXT}{" "}
                    <a
                        href="/pricing"
                        className="font-semibold underline underline-offset-2"
                    >
                        Xem gói nâng cấp
                    </a>
                </div>
            )}

            {/* Ô nhập cố định dưới cùng */}
            <div className="rounded-xl border border-gray-200 bg-white p-3 shadow-sm">
                <label className="mb-2 flex items-center gap-2 text-sm font-medium text-gray-700">
                    <input type="checkbox" checked={legalMode}
                        onChange={(event) => setLegalMode(event.target.checked)} />
                    ⚖ Câu hỏi pháp luật
                </label>
                {legalMode && (
                    <div className="mb-3 grid grid-cols-1 gap-2 rounded-lg border border-blue-100 bg-blue-50 p-3 sm:grid-cols-2">
                        <input value={legalContext.jurisdiction} aria-label="Quốc gia"
                            onChange={(e) => setLegalContext({ ...legalContext, jurisdiction: e.target.value })}
                            placeholder="Quốc gia (VN)" className="rounded border px-3 py-2 text-sm text-gray-800" />
                        <input type="date" value={legalContext.as_of_date} aria-label="Ngày áp dụng"
                            onChange={(e) => setLegalContext({ ...legalContext, as_of_date: e.target.value })}
                            className="rounded border px-3 py-2 text-sm text-gray-800" />
                        <input value={legalContext.actor} aria-label="Chủ thể"
                            onChange={(e) => setLegalContext({ ...legalContext, actor: e.target.value })}
                            placeholder="Chủ thể, ví dụ: doanh nghiệp" className="rounded border px-3 py-2 text-sm text-gray-800" />
                        <input value={legalContext.action} aria-label="Hành động"
                            onChange={(e) => setLegalContext({ ...legalContext, action: e.target.value })}
                            placeholder="Hành động cần đánh giá" className="rounded border px-3 py-2 text-sm text-gray-800" />
                        <input value={legalContext.data_or_asset} aria-label="Dữ liệu hoặc tài sản"
                            onChange={(e) => setLegalContext({ ...legalContext, data_or_asset: e.target.value })}
                            placeholder="Dữ liệu/tài sản liên quan" className="rounded border px-3 py-2 text-sm text-gray-800 sm:col-span-2" />
                    </div>
                )}
                <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-end">
                    <textarea
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        rows={2}
                        placeholder={legalMode ? "Nhập câu hỏi pháp luật..." : "Dán URL hoặc nội dung email..."}
                        aria-label="Nội dung cần đánh giá"
                        className="min-h-11 min-w-0 flex-1 resize-none rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-800 outline-none focus:border-blue-400 focus:ring-1 focus:ring-blue-400"
                    />
                    <button
                        type="button"
                        onClick={() => void handleSend()}
                        disabled={isStreaming || input.trim().length === 0}
                        className="min-h-11 shrink-0 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        Gửi ▶
                    </button>
                </div>

                <div className="mt-2 flex flex-col items-stretch justify-between gap-2 text-xs text-gray-500 sm:flex-row sm:items-center">
                    <input
                        ref={emlInputRef}
                        type="file"
                        accept=".eml,message/rfc822"
                        className="hidden"
                        aria-hidden="true"
                        onChange={(event) => {
                            const file = event.target.files?.[0];
                            if (!file) return;
                            void file.text().then((raw) => {
                                setLegalMode(false);
                                setInput(raw.slice(0, 200_000));
                            });
                            event.target.value = "";
                        }}
                    />
                    <button
                        type="button"
                        onClick={() => emlInputRef.current?.click()}
                        className="min-h-11 rounded-md px-2 py-2 text-left text-gray-500 hover:bg-gray-100"
                        aria-label="Tải file .eml"
                    >
                        📎 Tải file .eml
                    </button>

                    {/* Quota còn lại hôm nay theo gói (∞ cho pro/team) */}
                    <span className="break-words" title="Nội dung mới dùng 1 scan; AI Evaluate và AI Explain là hai lần gọi riêng.">Core: {remainingLabel} scan · AI: {aiRemainingLabel} credit</span>
                </div>
            </div>
        </div>
    );
}
