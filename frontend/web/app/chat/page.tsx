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

import Link from "next/link";
import {
    ArrowUpRight,
    LockKeyhole,
    MailWarning,
    Paperclip,
    RefreshCw,
    Scale,
    ScanSearch,
    Send,
    ShieldCheck,
    Sparkles,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import ChatMessage from "@/components/ChatMessage";
import { PrewiseShell } from "@/components/PrewiseUI";
import { useAuth } from "@/context/AuthContext";
import { useChatSession, type ChatContext } from "@/hooks/useChatSession";
import { looksLikeUrl } from "@/lib/quick-scan";
import type { LegalContext } from "@/lib/types";

import styles from "./chat.module.css";

/** Nội dung bong bóng chào mừng của trợ lý (UI_wireframe §1.5). */
const WELCOME_TEXT =
    "Dán URL, email hoặc tin nhắn đáng ngờ. Prewise sẽ kiểm tra tín hiệu, chấm điểm rủi ro và giải thích bằng chứng.";

/** Thông điệp khi người dùng hết lượt quét trong ngày. */
const QUOTA_EXCEEDED_TEXT =
    "Bạn đã hết lượt quét miễn phí hôm nay. Nâng cấp gói hoặc cài Extension để tiếp tục được bảo vệ.";

const QUICK_STARTS = [
    {
        label: "Kiểm tra một URL",
        detail: "Tên miền, chuyển hướng và dấu hiệu giả mạo",
        value: "Hãy kiểm tra URL này:\n",
        icon: ScanSearch,
    },
    {
        label: "Phân tích email",
        detail: "Người gửi, ý đồ và yêu cầu nhạy cảm",
        value: "Hãy phân tích nội dung email sau:\n",
        icon: MailWarning,
    },
    {
        label: "Hỏi tiếp về kết quả",
        detail: "Giải thích rủi ro bằng ngôn ngữ dễ hiểu",
        value: "Hãy giải thích những dấu hiệu rủi ro quan trọng nhất.",
        icon: Sparkles,
    },
];

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
        <PrewiseShell>
            <main id="main-content" className={styles.page}>
                <header className={styles.pageHeader}>
                    <div>
                        <p className={styles.eyebrow}><i /> AI / RISK COPILOT</p>
                        <h1>Trợ lý phân tích</h1>
                        <p>Kiểm tra tín hiệu đáng ngờ và hỏi tiếp trên cùng một ngữ cảnh.</p>
                    </div>
                    <div className={styles.headerStatus}>
                        <span><LockKeyhole aria-hidden /> Kết nối mã hóa</span>
                        <span><ShieldCheck aria-hidden /> Bằng chứng có giải thích</span>
                    </div>
                </header>

                <div className={styles.workspace}>
                    <section className={styles.conversation} aria-label="Hội thoại phân tích">
                        <div className={styles.conversationBar}>
                            <div>
                                <span className={styles.liveDot} />
                                <strong>Phiên phân tích mới</strong>
                            </div>
                            <small>{legalMode ? "LEGAL CONTEXT" : "RISK CONTEXT"} · STREAMING</small>
                        </div>

                        <div ref={scrollRef} className={styles.messages} aria-live="polite">
                            {showWelcome && (
                                <section className={styles.welcome} aria-label="Bắt đầu phiên phân tích">
                                    <div className={styles.welcomeIcon}><ShieldCheck aria-hidden /></div>
                                    <p className={styles.welcomeKicker}>PREWISE ASSISTANT</p>
                                    <h2>Bạn muốn kiểm tra điều gì?</h2>
                                    <p>{WELCOME_TEXT}</p>
                                    <div className={styles.quickStarts}>
                                        {QUICK_STARTS.map(({ label, detail, value, icon: Icon }) => (
                                            <button key={label} type="button" onClick={() => setInput(value)}>
                                                <Icon aria-hidden />
                                                <span><strong>{label}</strong><small>{detail}</small></span>
                                                <ArrowUpRight aria-hidden />
                                            </button>
                                        ))}
                                    </div>
                                </section>
                            )}

                            {messages.map((message) => (
                                <ChatMessage
                                    key={message.id}
                                    message={message}
                                    isStreaming={isStreaming && message.id === lastAssistantId}
                                />
                            ))}

                            {hasAssessment && (
                                <div className={styles.extensionCta}>
                                    <Sparkles aria-hidden />
                                    <span>Muốn được bảo vệ tự động khi duyệt web?</span>
                                    <Link href="/downloads">Cài Extension <ArrowUpRight aria-hidden /></Link>
                                </div>
                            )}
                        </div>

                        <div className={styles.composerZone}>
                            {error && (
                                <div role="alert" className={`${styles.notice} ${styles.errorNotice}`}>
                                    <span>{error}</span>
                                    <button type="button" onClick={() => void retryLast()}>
                                        <RefreshCw aria-hidden /> Thử lại
                                    </button>
                                </div>
                            )}

                            {quotaBlocked && (
                                <div role="alert" className={`${styles.notice} ${styles.quotaNotice}`}>
                                    <span>{QUOTA_EXCEEDED_TEXT}</span>
                                    <Link href="/pricing">Xem gói nâng cấp</Link>
                                </div>
                            )}

                            <div className={styles.modeSwitch} role="group" aria-label="Chế độ trợ lý">
                                <button
                                    type="button"
                                    className={!legalMode ? styles.activeMode : ""}
                                    aria-pressed={!legalMode}
                                    onClick={() => setLegalMode(false)}
                                >
                                    <ScanSearch aria-hidden /> Phân tích rủi ro
                                </button>
                                <button
                                    type="button"
                                    className={legalMode ? styles.activeMode : ""}
                                    aria-pressed={legalMode}
                                    onClick={() => setLegalMode(true)}
                                >
                                    <Scale aria-hidden /> Hỏi pháp luật
                                </button>
                            </div>

                            {legalMode && (
                                <div className={styles.legalFields}>
                                    <label>Quốc gia
                                        <input value={legalContext.jurisdiction} aria-label="Quốc gia"
                                            onChange={(e) => setLegalContext({ ...legalContext, jurisdiction: e.target.value })}
                                            placeholder="VN" />
                                    </label>
                                    <label>Ngày áp dụng
                                        <input type="date" value={legalContext.as_of_date} aria-label="Ngày áp dụng"
                                            onChange={(e) => setLegalContext({ ...legalContext, as_of_date: e.target.value })} />
                                    </label>
                                    <label>Chủ thể
                                        <input value={legalContext.actor} aria-label="Chủ thể"
                                            onChange={(e) => setLegalContext({ ...legalContext, actor: e.target.value })}
                                            placeholder="Ví dụ: doanh nghiệp" />
                                    </label>
                                    <label>Hành động
                                        <input value={legalContext.action} aria-label="Hành động"
                                            onChange={(e) => setLegalContext({ ...legalContext, action: e.target.value })}
                                            placeholder="Hành động cần đánh giá" />
                                    </label>
                                    <label className={styles.wideField}>Dữ liệu hoặc tài sản
                                        <input value={legalContext.data_or_asset} aria-label="Dữ liệu hoặc tài sản"
                                            onChange={(e) => setLegalContext({ ...legalContext, data_or_asset: e.target.value })}
                                            placeholder="Thông tin, tài sản hoặc dữ liệu liên quan" />
                                    </label>
                                </div>
                            )}

                            <div className={styles.composer}>
                                <textarea
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                    onKeyDown={handleKeyDown}
                                    rows={3}
                                    placeholder={legalMode ? "Mô tả tình huống pháp lý cần làm rõ…" : "Dán URL, email hoặc tin nhắn đáng ngờ…"}
                                    aria-label="Nội dung cần đánh giá"
                                />
                                <button
                                    type="button"
                                    onClick={() => void handleSend()}
                                    disabled={isStreaming || input.trim().length === 0}
                                    aria-label="Gửi nội dung"
                                >
                                    <Send aria-hidden /><span>Gửi</span>
                                </button>
                            </div>

                            <div className={styles.composerMeta}>
                                <input
                                    ref={emlInputRef}
                                    type="file"
                                    accept=".eml,message/rfc822"
                                    hidden
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
                                <button type="button" onClick={() => emlInputRef.current?.click()} aria-label="Tải file .eml">
                                    <Paperclip aria-hidden /> Đính kèm .eml
                                </button>
                                <span>Enter để gửi · Shift + Enter để xuống dòng</span>
                                <div title="Nội dung mới dùng 1 scan; AI Evaluate và AI Explain là hai lần gọi riêng.">
                                    <span>CORE <strong>{remainingLabel}</strong></span>
                                    <span>AI <strong>{aiRemainingLabel}</strong></span>
                                </div>
                            </div>
                        </div>
                    </section>

                    <aside className={styles.contextRail} aria-label="Thông tin phiên chat">
                        <section>
                            <p className={styles.railLabel}>PHẠM VI PHÂN TÍCH</p>
                            <h2>{legalMode ? "Ngữ cảnh pháp luật" : "Tín hiệu rủi ro"}</h2>
                            <p>{legalMode
                                ? "Trả lời dựa trên quốc gia, thời điểm và dữ kiện bạn cung cấp."
                                : "Đối chiếu URL, nội dung và hành vi đáng ngờ trong cùng một phiên."}</p>
                            <ul>
                                <li><i>01</i><span><strong>Nhận diện</strong><small>Loại tín hiệu và mục đích</small></span></li>
                                <li><i>02</i><span><strong>Đánh giá</strong><small>Điểm rủi ro và bằng chứng</small></span></li>
                                <li><i>03</i><span><strong>Giải thích</strong><small>Hướng xử lý an toàn</small></span></li>
                            </ul>
                        </section>
                        <section className={styles.privacyCard}>
                            <LockKeyhole aria-hidden />
                            <div><strong>Không tự mở liên kết</strong><p>Nội dung được hiển thị dạng trơ. Bạn quyết định mọi hành động tiếp theo.</p></div>
                        </section>
                        <section className={styles.quotaCard}>
                            <p className={styles.railLabel}>HẠN MỨC HÔM NAY</p>
                            <div><span>Core scans</span><strong>{remainingLabel}</strong></div>
                            <div><span>AI credits</span><strong>{aiRemainingLabel}</strong></div>
                            <Link href="/account/billing">Quản lý gói <ArrowUpRight aria-hidden /></Link>
                        </section>
                    </aside>
                </div>
            </main>
        </PrewiseShell>
    );
}
