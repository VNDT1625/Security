"use client";

import Link from "next/link";
import {
    ArrowUpRight,
    Bot,
    CircleHelp,
    Clock3,
    History,
    Link2,
    LockKeyhole,
    MessageCircleQuestion,
    Scale,
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
import type { LegalContext, ScanRecord } from "@/lib/types";

import styles from "./chat.module.css";

const CONTEXT_TOKEN = /@([A-Za-z0-9]+(?:-[A-Za-z0-9]+){1,})/g;
const LEGAL_JURISDICTIONS = [{ code: "VN", label: "Việt Nam" }] as const;

const QUICK_QUESTIONS = [
    {
        title: "Thông báo sự cố dữ liệu",
        detail: "Nghĩa vụ khi phát hiện rò rỉ dữ liệu cá nhân.",
        question: "Doanh nghiệp tại Việt Nam cần làm gì khi phát hiện sự cố rò rỉ dữ liệu cá nhân?",
        icon: ShieldCheck,
    },
    {
        title: "Chuyển dữ liệu ra nước ngoài",
        detail: "Điều kiện và hồ sơ cần chuẩn bị.",
        question: "Doanh nghiệp có được chuyển dữ liệu cá nhân của khách hàng ra nước ngoài không?",
        icon: CircleHelp,
    },
    {
        title: "Thu thập log truy cập",
        detail: "Căn cứ, thông báo và thời hạn lưu trữ.",
        question: "Khi thu thập log truy cập của người dùng, doanh nghiệp cần thông báo và xin đồng ý thế nào?",
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

function todayInVietnam(): string {
    return new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Ho_Chi_Minh",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
    }).format(new Date());
}

export default function ChatPage(): JSX.Element {
    const { messages, sendMessage, isStreaming, error, retryLast } = useChatSession();
    const { quotaInfo, refreshQuota } = useAuth();
    const [input, setInput] = useState("");
    const [records, setRecords] = useState<ScanRecord[]>([]);
    const [historyLoading, setHistoryLoading] = useState(true);
    const [historyError, setHistoryError] = useState("");
    const [attachedId, setAttachedId] = useState<string | null>(null);
    const [mentionOpen, setMentionOpen] = useState(false);
    const [mode, setMode] = useState<"legal" | "history">("legal");
    const [legalContext, setLegalContext] = useState<LegalContext>(() => ({
        jurisdiction: "VN",
        as_of_date: todayInVietnam(),
        actor: "",
        action: "",
        data_or_asset: "",
    }));
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
    const mentionQuery = input.match(/(?:^|\s)@([A-Za-z0-9-]*)$/)?.[1]?.toLowerCase() ?? "";
    const mentionMatches = records.filter((record) => {
        if (!mentionQuery) return true;
        return `${record.id} ${record.type} ${record.target ?? ""}`
            .toLowerCase()
            .includes(mentionQuery);
    });
    const hasAssessment = messages.some((message) => Boolean(message.assessment));

    function updateInput(value: string): void {
        setInput(value);
        const hasMentionTrigger = /(?:^|\s)@[A-Za-z0-9-]*$/.test(value);
        if (hasMentionTrigger) {
            setMode("history");
            setMentionOpen(true);
        } else {
            setMentionOpen(false);
        }
        const referencedId = findReferencedId(value, records);
        if (referencedId) {
            setAttachedId(referencedId);
            setMode("history");
            setMentionOpen(false);
        }
    }

    function attachRecord(record: ScanRecord): void {
        setAttachedId(record.id);
        setMode("history");
        setMentionOpen(false);
        setInput((current) => {
            const withoutPendingMention = current.replace(
                /(?:^|\s)@[A-Za-z0-9-]*$/,
                " ",
            );
            const question = stripContextTokens(withoutPendingMention);
            return `@${record.id}${question ? ` ${question}` : " "}`;
        });
    }

    function removeContext(): void {
        setAttachedId(null);
        setMentionOpen(false);
        setInput((current) => stripContextTokens(current));
    }

    function selectMode(nextMode: "legal" | "history"): void {
        setMode(nextMode);
        if (nextMode === "legal") {
            removeContext();
        }
    }

    async function handleSend(): Promise<void> {
        const question = stripContextTokens(input);
        if (!question || isStreaming || (mode === "history" && !attachedId)) return;

        setInput("");
        await sendMessage(
            question,
            mode === "history" && attachedId
                ? {
                    content: "",
                    modality: "text",
                    analysis_id: attachedId,
                }
                : undefined,
            mode === "legal" ? legalContext : undefined,
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
                        <p>Hỏi pháp luật an ninh mạng hoặc giải thích kết quả cũ bằng @ID.</p>
                    </div>
                    <div className={styles.headerStatus} aria-label="Trạng thái trợ lý">
                        <span><span className={styles.liveDot} /> Trợ lý sẵn sàng</span>
                        <span><Scale /> RAG + nguồn Chính phủ</span>
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
                                {mode === "legal"
                                    ? "LEGAL ADAPTER ACTIVE"
                                    : attachedId
                                        ? `HISTORY CONTEXT · @${shortId(attachedId)}`
                                        : "SELECT HISTORY CONTEXT"}
                            </small>
                        </div>

                        <div className={styles.messages} aria-live="polite">
                            {messages.length === 0 ? (
                                <div className={styles.welcome}>
                                    <span className={styles.welcomeIcon}><MessageCircleQuestion /></span>
                                    <p className={styles.welcomeKicker}>TWO PURPOSES, ONE ASSISTANT</p>
                                    <h2>
                                        {mode === "legal"
                                            ? "Hỏi pháp luật an ninh mạng"
                                            : "Hỏi theo kết quả đã phân tích"}
                                    </h2>
                                    {mode === "legal" ? (
                                        <>
                                            <p>
                                                AI tự phân tích bối cảnh, đối chiếu Legal RAG và
                                                truy xuất nguồn Chính phủ kèm liên kết gốc.
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
                                        </>
                                    ) : (
                                        <p>
                                            Chọn một kết quả ở cột lịch sử hoặc dán
                                            <strong> @ID</strong>, sau đó đặt câu hỏi cần giải thích.
                                        </p>
                                    )}
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
                            <div className={styles.modeSwitch} role="tablist" aria-label="Công dụng Chat">
                                <button
                                    type="button"
                                    role="tab"
                                    aria-selected={mode === "legal"}
                                    className={mode === "legal" ? styles.activeMode : ""}
                                    onClick={() => selectMode("legal")}
                                >
                                    <Scale /> Pháp luật an ninh mạng
                                </button>
                                <button
                                    type="button"
                                    role="tab"
                                    aria-selected={mode === "history"}
                                    className={mode === "history" ? styles.activeMode : ""}
                                    onClick={() => selectMode("history")}
                                >
                                    <History /> Hỏi theo @ID lịch sử
                                </button>
                            </div>

                            {error && (
                                <div className={`${styles.notice} ${styles.errorNotice}`} role="alert">
                                    <span>{error}</span>
                                    <button type="button" onClick={() => void retryLast()}>
                                        Thử lại
                                    </button>
                                </div>
                            )}

                            {mode === "legal" && (
                                <div className={styles.legalContextBar} aria-label="Bối cảnh pháp luật">
                                    <label>
                                        Quốc gia
                                        <select
                                            aria-label="Quốc gia"
                                            value={legalContext.jurisdiction}
                                            onChange={(event) => setLegalContext((current) => ({
                                                ...current,
                                                jurisdiction: event.target.value,
                                            }))}
                                        >
                                            {LEGAL_JURISDICTIONS.map((item) => (
                                                <option key={item.code} value={item.code}>
                                                    {item.label}
                                                </option>
                                            ))}
                                        </select>
                                    </label>
                                    <div className={styles.legalSourceInfo}>
                                        <strong>LEGAL RAG + WEB CHÍNH PHỦ</strong>
                                        <span>
                                            AI tự xác định chủ thể, hành động và dữ liệu từ câu hỏi.
                                            Nguồn dùng để trả lời sẽ có liên kết để đối chiếu.
                                        </span>
                                    </div>
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

                            <div className={styles.composerWrap}>
                                {mentionOpen && (
                                    <div
                                        className={styles.mentionPicker}
                                        role="listbox"
                                        aria-label="Gợi ý lịch sử"
                                    >
                                        <div className={styles.mentionHeader}>
                                            <span>LỊCH SỬ · MỚI NHẤT TRƯỚC</span>
                                            <small>{mentionMatches.length} kết quả</small>
                                        </div>
                                        <div className={styles.mentionList}>
                                            {historyLoading ? (
                                                <p>Đang tải lịch sử…</p>
                                            ) : mentionMatches.length === 0 ? (
                                                <p>Không tìm thấy kết quả phù hợp.</p>
                                            ) : mentionMatches.map((record) => (
                                                <button
                                                    key={record.id}
                                                    type="button"
                                                    role="option"
                                                    aria-selected={attachedId === record.id}
                                                    aria-label={`Chọn lịch sử @${record.id}`}
                                                    onClick={() => attachRecord(record)}
                                                >
                                                    <span className={styles.historyBadge}>
                                                        {record.type}
                                                    </span>
                                                    <span>
                                                        <strong>
                                                            {record.target || "Nội dung đã được ẩn"}
                                                        </strong>
                                                        <small>
                                                            @{record.id} · {record.timestamp}
                                                        </small>
                                                    </span>
                                                    <b>{record.score}</b>
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                <div className={styles.composer}>
                                    <textarea
                                        aria-label="Câu hỏi cho trợ lý"
                                        value={input}
                                        onChange={(event) => updateInput(event.target.value)}
                                        onKeyDown={(event) => {
                                            if (event.key === "Escape") {
                                                setMentionOpen(false);
                                                return;
                                            }
                                            if (event.key === "Enter" && !event.shiftKey) {
                                                event.preventDefault();
                                                void handleSend();
                                            }
                                        }}
                                        placeholder={
                                            mode === "legal"
                                                ? "Đặt câu hỏi pháp luật hoặc an ninh mạng…"
                                                : "Gõ @ để chọn lịch sử, rồi đặt câu hỏi cần giải thích…"
                                        }
                                    />
                                    <button
                                        type="button"
                                        disabled={
                                            !stripContextTokens(input)
                                            || isStreaming
                                            || (mode === "history" && !attachedId)
                                        }
                                        onClick={() => void handleSend()}
                                        aria-label="Gửi câu hỏi"
                                    >
                                        <Send />
                                        <span>{isStreaming ? "Đang trả lời" : "Gửi"}</span>
                                    </button>
                                </div>
                            </div>

                            <div className={styles.composerMeta}>
                                <span>ENTER để gửi · SHIFT + ENTER để xuống dòng</span>
                                <span className={styles.composerHint}>
                                    {mode === "legal"
                                        ? <><Scale /> RAG + nguồn Chính phủ</>
                                        : <><Sparkles /> Không quét lại Analyze</>}
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
