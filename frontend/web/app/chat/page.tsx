"use client";

import Link from "next/link";
import {
    ArrowUpRight,
    Bot,
    CircleHelp,
    Clock3,
    Link2,
    LockKeyhole,
    MessageCircleQuestion,
    Send,
    ShieldCheck,
    Sparkles,
    X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import ChatMessage from "@/components/ChatMessage";
import { PrewiseShell } from "@/components/PrewiseUI";
import { useAuth } from "@/context/AuthContext";
import { useChatSession } from "@/hooks/useChatSession";
import { getApiClient } from "@/lib/api";
import type { ScanRecord } from "@/lib/types";

import styles from "./chat.module.css";

const CONTEXT_TOKEN = /@([A-Za-z0-9]+(?:-[A-Za-z0-9]+){1,})/g;

const QUICK_QUESTIONS = [
    {
        title: "Xử lý sau khi bấm nhầm",
        detail: "Các bước cần làm ngay để giảm rủi ro.",
        question: "Tôi vừa bấm vào một liên kết đáng ngờ. Tôi nên làm gì ngay bây giờ?",
        icon: ShieldCheck,
    },
    {
        title: "Nhận biết email giả mạo",
        detail: "Dấu hiệu phổ biến và cách tự kiểm tra.",
        question: "Những dấu hiệu phổ biến của email giả mạo là gì?",
        icon: CircleHelp,
    },
    {
        title: "Bảo vệ lại tài khoản",
        detail: "Khi nào nên đổi mật khẩu và thu hồi phiên.",
        question: "Khi nào tôi nên đổi mật khẩu và thu hồi các phiên đăng nhập?",
        icon: LockKeyhole,
    },
] as const;

function shortId(id: string): string {
    return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

function findReferencedId(value: string, records: ScanRecord[]): string | null {
    const matches = Array.from(value.matchAll(CONTEXT_TOKEN));
    const token = matches.at(-1)?.[1];
    if (!token) return null;

    const exact = records.find((record) => record.id.toLowerCase() === token.toLowerCase());
    if (exact) return exact.id;

    const prefixMatches = records.filter((record) =>
        record.id.toLowerCase().startsWith(token.toLowerCase()),
    );
    if (prefixMatches.length === 1) return prefixMatches[0].id;

    // Full request ids can be pasted before the history list has finished loading.
    return token.split("-").length >= 3 ? token : null;
}

function stripContextTokens(value: string): string {
    return value.replace(CONTEXT_TOKEN, " ").replace(/\s+/g, " ").trim();
}

export default function ChatPage(): JSX.Element {
    const { messages, sendMessage, isStreaming, error, retryLast } = useChatSession();
    const { quotaInfo, refreshQuota } = useAuth();
    const [input, setInput] = useState("");
    const [records, setRecords] = useState<ScanRecord[]>([]);
    const [historyLoading, setHistoryLoading] = useState(true);
    const [historyError, setHistoryError] = useState("");
    const [attachedId, setAttachedId] = useState<string | null>(null);
    const messagesEndRef = useRef<HTMLDivElement | null>(null);

    useEffect(() => {
        let active = true;
        setHistoryLoading(true);
        void getApiClient().getScanHistory()
            .then((items) => {
                if (!active) return;
                setRecords(items);
                setHistoryError("");
            })
            .catch((reason) => {
                if (!active) return;
                setRecords([]);
                setHistoryError(
                    reason instanceof Error ? reason.message : "Không thể tải lịch sử.",
                );
            })
            .finally(() => {
                if (active) setHistoryLoading(false);
            });
        return () => {
            active = false;
        };
    }, []);

    useEffect(() => {
        const scrollIntoView = messagesEndRef.current?.scrollIntoView;
        if (typeof scrollIntoView === "function") {
            scrollIntoView.call(messagesEndRef.current, { behavior: "smooth", block: "end" });
        }
    }, [messages, isStreaming]);

    const attachedRecord = useMemo(
        () => records.find((record) => record.id === attachedId) ?? null,
        [attachedId, records],
    );
    const recentRecords = records.slice(0, 6);
    const hasAssessment = messages.some((message) => Boolean(message.assessment));

    function updateInput(value: string): void {
        setInput(value);
        const referencedId = findReferencedId(value, records);
        if (referencedId) setAttachedId(referencedId);
    }

    function attachRecord(record: ScanRecord): void {
        setAttachedId(record.id);
        setInput((current) => {
            const question = stripContextTokens(current);
            return `@${record.id}${question ? ` ${question}` : " "}`;
        });
    }

    function removeContext(): void {
        setAttachedId(null);
        setInput((current) => stripContextTokens(current));
    }

    async function handleSend(): Promise<void> {
        const question = stripContextTokens(input);
        if (!question || isStreaming) return;

        setInput("");
        await sendMessage(
            question,
            attachedId
                ? {
                    content: "",
                    modality: "text",
                    analysis_id: attachedId,
                }
                : undefined,
        );
        await refreshQuota();
    }

    return (
        <PrewiseShell>
            <main className={styles.page}>
                <header className={styles.pageHeader}>
                    <div>
                        <p className={styles.eyebrow}><i />CHAT / SECURITY ASSISTANT</p>
                        <h1>Trợ lý an toàn số</h1>
                        <p>Hỏi đáp và giải thích kết quả cũ — không chạy lại Analyze.</p>
                    </div>
                    <div className={styles.headerStatus} aria-label="Trạng thái trợ lý">
                        <span><span className={styles.liveDot} /> Trợ lý sẵn sàng</span>
                        <span><LockKeyhole /> Ngữ cảnh riêng tư</span>
                    </div>
                </header>

                <div className={styles.workspace}>
                    <section className={styles.conversation} aria-label="Cuộc trò chuyện">
                        <div className={styles.conversationBar}>
                            <div>
                                <Bot aria-hidden="true" />
                                <strong>PREWISE ASSISTANT</strong>
                            </div>
                            <small>
                                {attachedId ? `ACTIVE CONTEXT · @${shortId(attachedId)}` : "NO ACTIVE CONTEXT"}
                            </small>
                        </div>

                        <div className={styles.messages} aria-live="polite">
                            {messages.length === 0 ? (
                                <div className={styles.welcome}>
                                    <span className={styles.welcomeIcon}><MessageCircleQuestion /></span>
                                    <p className={styles.welcomeKicker}>ASK, UNDERSTAND, ACT</p>
                                    <h2>Bạn muốn hỏi điều gì?</h2>
                                    <p>
                                        Hỏi về an toàn số, cách xử lý sự cố hoặc gắn một kết quả
                                        trong lịch sử bằng <strong>@ID</strong> để được giải thích.
                                    </p>
                                    <div className={styles.quickStarts}>
                                        {QUICK_QUESTIONS.map((item) => {
                                            const Icon = item.icon;
                                            return (
                                                <button
                                                    key={item.title}
                                                    type="button"
                                                    onClick={() => setInput(item.question)}
                                                    aria-label={item.title}
                                                >
                                                    <Icon />
                                                    <span>
                                                        <strong>{item.title}</strong>
                                                        <small>{item.detail}</small>
                                                    </span>
                                                    <ArrowUpRight />
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>
                            ) : (
                                messages.map((message, index) => (
                                    <ChatMessage
                                        key={message.id}
                                        message={message}
                                        isStreaming={isStreaming && index === messages.length - 1}
                                    />
                                ))
                            )}
                            <div ref={messagesEndRef} />
                        </div>

                        <div className={styles.composerZone}>
                            {error && (
                                <div className={`${styles.notice} ${styles.errorNotice}`} role="alert">
                                    <span>{error}</span>
                                    <button type="button" onClick={() => void retryLast()}>
                                        Thử lại
                                    </button>
                                </div>
                            )}

                            {attachedId && (
                                <div className={styles.contextChip} role="status">
                                    <Link2 />
                                    <span>
                                        <small>NGỮ CẢNH ĐÃ GẮN</small>
                                        <strong>
                                            @{shortId(attachedId)}
                                            {attachedRecord
                                                ? ` · ${attachedRecord.type} · ${attachedRecord.score}/100`
                                                : ""}
                                        </strong>
                                    </span>
                                    <button type="button" onClick={removeContext} aria-label="Bỏ ngữ cảnh">
                                        <X />
                                    </button>
                                </div>
                            )}

                            <div className={styles.composer}>
                                <textarea
                                    aria-label="Câu hỏi cho trợ lý"
                                    value={input}
                                    onChange={(event) => updateInput(event.target.value)}
                                    onKeyDown={(event) => {
                                        if (event.key === "Enter" && !event.shiftKey) {
                                            event.preventDefault();
                                            void handleSend();
                                        }
                                    }}
                                    placeholder="Hỏi điều bạn cần biết… Có thể thêm @ID từ lịch sử để làm ngữ cảnh."
                                />
                                <button
                                    type="button"
                                    disabled={!stripContextTokens(input) || isStreaming}
                                    onClick={() => void handleSend()}
                                    aria-label="Gửi câu hỏi"
                                >
                                    <Send />
                                    <span>{isStreaming ? "Đang trả lời" : "Gửi"}</span>
                                </button>
                            </div>

                            <div className={styles.composerMeta}>
                                <span>ENTER để gửi · SHIFT + ENTER để xuống dòng</span>
                                <span className={styles.composerHint}>
                                    <Sparkles /> Chat không dùng lượt Analyze
                                </span>
                                <div>
                                    <span>AI CREDITS</span>
                                    <strong>
                                        {quotaInfo
                                            ? `${quotaInfo.aiRemaining}/${quotaInfo.aiCreditDailyLimit}`
                                            : "—"}
                                    </strong>
                                </div>
                            </div>

                            {hasAssessment && (
                                <div className={styles.extensionCta}>
                                    <ShieldCheck />
                                    <span>Muốn kiểm tra nội dung mới? Hãy dùng đúng công cụ Analyze.</span>
                                    <Link href="/analyze">Mở Analyze <ArrowUpRight /></Link>
                                </div>
                            )}
                        </div>
                    </section>

                    <aside className={styles.contextRail} aria-label="Ngữ cảnh từ lịch sử">
                        <section>
                            <p className={styles.railLabel}>NGỮ CẢNH TỪ LỊCH SỬ</p>
                            <h2>Gắn kết quả bằng @ID</h2>
                            <p>Chọn một kết quả đã phân tích để trợ lý giải thích hoặc trả lời tiếp.</p>

                            {historyLoading ? (
                                <p className={styles.historyEmpty}>Đang tải lịch sử…</p>
                            ) : historyError ? (
                                <p className={styles.historyEmpty}>{historyError}</p>
                            ) : recentRecords.length === 0 ? (
                                <div className={styles.historyEmpty}>
                                    <span>Chưa có kết quả nào.</span>
                                    <Link href="/analyze">Phân tích nội dung đầu tiên →</Link>
                                </div>
                            ) : (
                                <div className={styles.historyList}>
                                    {recentRecords.map((record) => (
                                        <button
                                            key={record.id}
                                            type="button"
                                            className={`${styles.historyItem} ${
                                                attachedId === record.id ? styles.historyItemActive : ""
                                            }`}
                                            onClick={() => attachRecord(record)}
                                            aria-label={`Gắn kết quả @${record.id}`}
                                        >
                                            <span className={styles.historyBadge}>{record.type}</span>
                                            <span>
                                                <strong>{record.target || "Nội dung đã được ẩn"}</strong>
                                                <small>@{shortId(record.id)} · {record.timestamp}</small>
                                            </span>
                                            <b>{record.score}</b>
                                        </button>
                                    ))}
                                </div>
                            )}
                            <Link className={styles.historyLink} href="/account/history">
                                <Clock3 /> Xem toàn bộ lịch sử <ArrowUpRight />
                            </Link>
                        </section>

                        <section className={styles.privacyCard}>
                            <LockKeyhole />
                            <div>
                                <strong>Không quét lại dữ liệu</strong>
                                <p>
                                    Chat chỉ đọc kết quả đã lưu, kiểm tra quyền sở hữu tài khoản
                                    và không trừ lượt Analyze.
                                </p>
                            </div>
                        </section>

                        <section className={styles.quotaCard}>
                            <p className={styles.railLabel}>CHAT USAGE</p>
                            <div>
                                <span>AI credits còn lại</span>
                                <strong>
                                    {quotaInfo
                                        ? `${quotaInfo.aiRemaining}/${quotaInfo.aiCreditDailyLimit}`
                                        : "—"}
                                </strong>
                            </div>
                            <Link href="/account/plan">Xem gói tài khoản <ArrowUpRight /></Link>
                        </section>
                    </aside>
                </div>
            </main>
        </PrewiseShell>
    );
}
