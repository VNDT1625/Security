"use client";

import Link from "next/link";
import { FormEvent, Suspense, useEffect, useRef, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import { PrewiseShell, RiskDial, demoFindings } from "@/components/PrewiseUI";
import { ExportReportButton } from "@/components/ExportReportButton";
import {
  ReportSiteButton,
  ShareReportButton,
} from "@/components/ReportResultActions";
import {
  displayValue,
  extractScanChecks,
  mapRiskResult,
  type RiskCoreRecord,
} from "@/lib/risk-core";
import { loadResultRecord } from "@/lib/result-storage";
import { getApiClient } from "@/lib/api";
import type { ChatMessageModel } from "@/lib/types";
import { getRiskLevelForContext } from "@/lib/risk";
import styles from "./result-pro-ai.module.css";
import mobileStyles from "../../mobile-pages.module.css";

type Finding = {
  title: string;
  detail: string;
  evidence: string;
  severity: "high" | "medium" | "low";
};
type ScoreLayer = {
  layer?: string;
  score?: number;
  status?: "completed" | "skipped" | "unavailable";
  summary?: string;
  signals?: number;
  details?: CriterionDetail[];
};
type CriterionDetail = {
  criterion?: string;
  value?: string;
  triggered?: boolean;
  contribution?: number;
  reason?: string;
};
type SandboxReport = {
  analysis_mode?: "http" | "browser" | "browser_http";
  behaviors?: unknown[];
  redirects?: unknown[];
  scripts_executed?: string[];
  network_calls?: string[];
  dom_modifications?: unknown[];
  analysis_time_ms?: number;
  error?: string | null;
};
type DangerousCriterion = {
  criterion_id?: number;
  name?: string;
  contribution?: number;
  max_weight?: number;
  reason?: string;
};
type AccessAnalysis = {
  performed?: boolean;
  analysis_mode?: string;
  verdict?: string;
  warning?: string;
  causes?: string[];
  observed_effects?: string[];
  final_url?: string;
};
type IntelligenceSource = {
  source?: string;
  status?: "completed" | "not_configured" | "unavailable" | "redacted";
  detail?: string;
};
type URLIntelligence = {
  domain?: string;
  ip_addresses?: string[];
  primary_ip?: string | null;
  ip_location?: string | null;
  asn?: string | null;
  provider?: string | null;
  registrar?: string | null;
  registrant?: string | null;
  registered_at?: string | null;
  expires_at?: string | null;
  nameservers?: string[];
  collected_at?: string;
  sources?: IntelligenceSource[];
};
type StoredRecord = {
  id?: string;
  score?: number;
  content?: string;
  type?: "url" | "email" | "sms";
  sender?: string;
  subject?: string;
  emailFilename?: string;
  gmailMessageId?: string;
  phoneNumber?: string;
  phoneIntelligence?: {
    provider?: string;
    provider_status?: string;
    reputation?: string | null;
    metadata?: Record<string, unknown>;
  };
  isDemo?: boolean;
  dataSource?: string;
  analysisDepth?: "quick" | "balanced" | "deep" | "pro";
  llmContext?: string;
  result?: {
    request_id?: string;
    risk_score?: number;
    confidence?: number;
    analysis_time_ms?: number;
    cache_hit?: boolean;
    cache_status?: "hit" | "miss" | "bypassed" | "refresh";
    threat_level?: string;
    deep_analysis_recommended?: boolean;
    warning_required?: boolean;
    auto_deep_analysis?: boolean;
    dangerous_criteria?: DangerousCriterion[];
    access_analysis?: AccessAnalysis;
    score_layers?: ScoreLayer[];
    sandbox_report?: SandboxReport | null;
    ai_detection?: {
      detected?: boolean;
      confidence?: number;
      model_version?: string;
    };
    evidence?: Array<{
      source?: string;
      feature?: string;
      message?: string;
      severity?: string;
      contribution?: number;
    }>;
    risk_core?: Record<string, unknown>;
    url_intelligence?: URLIntelligence | null;
    risk_level?: string;
    decision?: string;
    reasons?: string[];
    analysis_coverage?: Record<string, string>;
    message_metadata?: Record<string, unknown>;
    embedded_url_assessments?: Array<Record<string, unknown>>;
    contextual_analysis?: {
      status?: string;
      adapter_id?: string;
      scoring_mode?: string;
      confidence?: number | null;
      error?: string;
    };
  };
};

type AIScore = { score: number; weight: number; effectiveWeight?: number };

function readAIScore(result?: StoredRecord["result"]): AIScore | null {
  const core = result?.risk_core;
  if (!core) return null;
  const weight = Number(core.ai_context_weight_percent ?? 0);
  const score = Number(core.ai_context_score);
  if (!Number.isFinite(weight) || weight <= 0 || !Number.isFinite(score))
    return null;
  const effectiveWeight = Number(core.ai_context_effective_weight_percent);
  return {
    score: Math.max(0, Math.min(100, score)),
    weight: Math.max(0, Math.min(40, weight)),
    effectiveWeight: Number.isFinite(effectiveWeight)
      ? Math.max(0, Math.min(40, effectiveWeight))
      : undefined,
  };
}

function AIScoreCard({ value }: { value: AIScore }) {
  const level = getRiskLevelForContext(undefined, undefined, value.score);
  return (
    <div
      className={styles.aiScore}
      aria-label={`AI hỗ trợ kết luận ${level.label}`}
    >
      <span>AI HỖ TRỢ ĐÁNH GIÁ</span>
      <strong>{level.label}</strong>
      <p>
        Đã tham gia đối chiếu tín hiệu; quyết định cuối vẫn do lõi chính sách
        đưa ra.
      </p>
    </div>
  );
}

function ProAIContextPanel({ record }: { record: StoredRecord }) {
  const [advice, setAdvice] = useState("");
  const [messages, setMessages] = useState<ChatMessageModel[]>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const started = useRef(false);
  const contextContent = [
    record.content,
    record.sender && `Người gửi: ${record.sender}`,
    record.subject && `Chủ đề: ${record.subject}`,
    `Kết quả Risk Core: ${JSON.stringify(record.result ?? {})}`,
  ]
    .filter(Boolean)
    .join("\n")
    .slice(0, 12000);
  const modality =
    record.type === "url" || record.type === "email" || record.type === "sms"
      ? record.type
      : "text";

  async function streamAnswer(
    prompt: string,
    history: ChatMessageModel[],
    onDelta: (text: string) => void,
  ) {
    let full = "";
    const stream = getApiClient().openChatStream({
      question: prompt,
      context: {
        content: contextContent,
        modality,
        operator_context: record.llmContext,
        analysis_id: record.id,
      },
      history,
    });
    while (true) {
      const next = await stream.next();
      if (next.done) return { text: full, id: next.value.messageId };
      full += next.value.delta;
      onDelta(full);
    }
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    setBusy(true);
    void streamAnswer(
      "Dựa trên toàn bộ kết quả vừa phân tích, hãy đưa ra lời khuyên cuối ngắn gọn, thực tế bằng tiếng Việt: người dùng nên làm gì ngay, điều gì tuyệt đối không làm, và khi nào cần báo cáo hoặc nhờ chuyên gia.",
      [],
      setAdvice,
    )
      .then(({ text, id }) =>
        setMessages([{ id, role: "assistant", text, createdAt: Date.now() }]),
      )
      .catch((reason) =>
        setError(
          reason instanceof Error
            ? reason.message
            : "Không thể lấy lời khuyên từ AI.",
        ),
      )
      .finally(() => setBusy(false));
    // This panel is mounted for one immutable analysis record.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function ask(event: FormEvent) {
    event.preventDefault();
    const prompt = question.trim();
    if (!prompt || busy) return;
    setQuestion("");
    setError("");
    setBusy(true);
    const user: ChatMessageModel = {
      id: crypto.randomUUID(),
      role: "user",
      text: prompt,
      createdAt: Date.now(),
    };
    const pendingId = crypto.randomUUID();
    const history = [...messages, user];
    setMessages([
      ...history,
      { id: pendingId, role: "assistant", text: "", createdAt: Date.now() },
    ]);
    try {
      const answer = await streamAnswer(prompt, history, (text) =>
        setMessages((items) =>
          items.map((item) =>
            item.id === pendingId ? { ...item, text } : item,
          ),
        ),
      );
      setMessages((items) =>
        items.map((item) =>
          item.id === pendingId
            ? { ...item, id: answer.id, text: answer.text }
            : item,
        ),
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Không thể nhận phản hồi từ AI.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={styles.proPanel} aria-labelledby="pro-ai-title">
      <header>
        <div>
          <span>PRO AI · CONTEXT</span>
          <h2 id="pro-ai-title">Lời khuyên cuối từ AI</h2>
        </div>
        <em>AI dùng ngữ cảnh của lần phân tích này</em>
      </header>
      <div className={styles.finalAdvice}>
        {advice ? (
          <p>{advice}</p>
        ) : busy ? (
          <p>AI đang tổng hợp lời khuyên cuối…</p>
        ) : (
          <p>Chưa có lời khuyên.</p>
        )}
      </div>
      <div className={styles.chatLog}>
        {messages.slice(1).map((message) => (
          <article
            className={
              message.role === "user" ? styles.userMessage : styles.aiMessage
            }
            key={message.id}
          >
            <b>{message.role === "user" ? "Bạn" : "Pro AI"}</b>
            <p>{message.text || "Đang trả lời…"}</p>
          </article>
        ))}
      </div>
      <form className={styles.chatForm} onSubmit={ask}>
        <label htmlFor="pro-ai-question">Hỏi thêm về kết quả này</label>
        <div>
          <input
            id="pro-ai-question"
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            disabled={busy}
            placeholder="Ví dụ: Tôi đã bấm vào link rồi thì cần làm gì?"
          />
          <button type="submit" disabled={busy || !question.trim()}>
            {busy ? "Đang xử lý…" : "Gửi câu hỏi"}
          </button>
        </div>
      </form>
      {error && (
        <p className={styles.aiError} role="alert">
          {error}
        </p>
      )}
      <small>
        AI hỗ trợ quyết định; không thay thế xác minh hoặc tư vấn chuyên môn.
      </small>
    </section>
  );
}

function MessageReport({
  record,
  fallbackScore,
  type,
}: {
  record: StoredRecord | null;
  fallbackScore: number;
  type: "email" | "sms";
}) {
  const result = record?.result;
  const rawScore = result?.risk_score ?? record?.score ?? fallbackScore;
  const score = Math.round(rawScore <= 1 ? rawScore * 100 : rawScore);
  const confidenceRaw = result?.confidence ?? 0;
  const confidence = Math.round(
    confidenceRaw <= 1 ? confidenceRaw * 100 : confidenceRaw,
  );
  const evidence = result?.evidence ?? [];
  const coverage = result?.analysis_coverage ?? {};
  const reasons =
    result?.reasons ??
    evidence
      .filter(
        (item) => item.severity === "critical" || item.severity === "high",
      )
      .slice(0, 3)
      .map((item) => item.message || "Tín hiệu cần kiểm tra");
  const displayLevel = getRiskLevelForContext(
    result?.decision,
    result?.risk_level,
    score,
  );
  const verdict =
    displayLevel.key === "danger"
      ? "Nguy hiểm — không làm theo"
      : displayLevel.key === "warn"
        ? "Đáng ngờ — cần xác minh"
        : "Chưa thấy rủi ro rõ";
  const groupDefinitions =
    type === "email"
      ? ([
          ["Danh tính người gửi", ["E-ID"]],
          ["Link & website", ["E-WEB", "embedded_url"]],
          ["Ý đồ nội dung", ["E-BEC", "email_", "payment_"]],
          ["Tệp & QR", ["E-FILE"]],
          ["Ngữ cảnh", ["context", "history"]],
        ] as const)
      : ([
          ["Số gửi & danh tính", ["S-ID", "phone"]],
          ["Link & website", ["S-WEB", "embedded_url"]],
          ["Ý đồ hành động", ["S-CONT", "sms_"]],
          ["Chuỗi hội thoại", ["S-CONV"]],
          ["Chiến dịch", ["campaign", "community"]],
        ] as const);
  const groupCount = (keys: readonly string[]) =>
    evidence.filter((item) =>
      keys.some((key) =>
        `${item.feature || ""} ${item.source || ""}`.includes(key),
      ),
    ).length;
  const phoneUnavailable =
    type === "sms" &&
    record?.phoneNumber &&
    record.phoneIntelligence?.provider_status !== "completed";
  const headerUnavailable =
    type === "email" && !record?.sender && !record?.subject;
  const contextualAI = result?.contextual_analysis;
  const aiScore = readAIScore(result);

  return (
    <PrewiseShell>
      <main id="main-content" className={`report ${mobileStyles.report}`}>
        <div className="report-title">
          <div>
            <p className="eyebrow">
              <i /> ANALYSIS REPORT · {type.toUpperCase()}
            </p>
            <span className="demo-badge">KẾT QUẢ BACKEND THẬT</span>
            <h1>Đánh giá {type === "email" ? "email" : "tin nhắn"} hoàn tất</h1>
            <p>
              Kết luận dựa trên bằng chứng, mức nguy hiểm và chính sách bảo vệ;
              điểm kỹ thuật được giữ nội bộ.
            </p>
          </div>
          <div className="report-actions">
            <ExportReportButton reportId={record?.id} reportType={type} />
          </div>
        </div>
        <section className="report-overview" aria-label="Tổng quan kết quả">
          <RiskDial
            score={score}
            decision={result?.decision}
            riskLevel={result?.risk_level}
          />
          <div className="verdict">
            <span>KHUYẾN NGHỊ</span>
            <h2>{verdict}</h2>
            <p>
              {reasons[0] ||
                "Không có tín hiệu nghiêm trọng trong phần dữ liệu đã kiểm tra."}
            </p>
            <div>
              <b>Độ tin cậy của kết quả</b>
              <strong>{confidence}%</strong>
              <i aria-hidden>
                <em style={{ width: `${confidence}%` }} />
              </i>
            </div>
          </div>
          {aiScore ? (
            <AIScoreCard value={aiScore} />
          ) : (
            <div className="signal-visual" aria-hidden>
              <div className="report-core" />
              <small>{evidence.length} TÍN HIỆU</small>
            </div>
          )}
        </section>
        <section className="message-identity" aria-label="Thông tin đầu vào">
          {type === "email" ? (
            <>
              <div>
                <span>Người gửi</span>
                <strong>{record?.sender || "Không được cung cấp"}</strong>
              </div>
              <div>
                <span>Chủ đề</span>
                <strong>{record?.subject || "Không được cung cấp"}</strong>
              </div>
              <div>
                <span>Nguồn</span>
                <strong>
                  {record?.gmailMessageId
                    ? "Gmail · thư được chọn"
                    : record?.emailFilename
                      ? `Tệp .eml · ${record.emailFilename}`
                      : "Dán nội dung"}
                </strong>
              </div>
            </>
          ) : (
            <>
              <div>
                <span>Số gửi</span>
                <strong>{record?.phoneNumber || "Không được cung cấp"}</strong>
              </div>
              <div>
                <span>Uy tín số</span>
                <strong>
                  {record?.phoneIntelligence?.reputation || "Chưa có dữ liệu"}
                </strong>
              </div>
              <div>
                <span>Nguồn điều tra</span>
                <strong>
                  {record?.phoneIntelligence?.provider || "Chưa cấu hình"}
                </strong>
              </div>
            </>
          )}
        </section>
        {(phoneUnavailable || headerUnavailable) && (
          <div className="message-coverage" role="status">
            ⚠{" "}
            {phoneUnavailable
              ? "Nguồn điều tra số điện thoại chưa khả dụng; điểm hiện tại dựa trên nội dung và website, không coi số này là an toàn."
              : "Chưa có header kỹ thuật Email (From/Reply-To/Return-Path/SPF/DKIM/DMARC); kết quả hiện dựa trên nội dung và liên kết."}
          </div>
        )}
        {Object.keys(coverage).length > 0 && (
          <section
            className="message-coverage-matrix"
            aria-labelledby="coverage-title"
          >
            <div className="section-label">
              <span id="coverage-title">PHẠM VI KIỂM TRA THỰC TẾ</span>
              <b>
                {
                  Object.values(coverage).filter(
                    (value) => value === "completed",
                  ).length
                }
                /{Object.keys(coverage).length} hoàn tất
              </b>
            </div>
            <div>
              {Object.entries(coverage).map(([key, status]) => (
                <article className={status} key={key}>
                  <i aria-hidden>
                    {status === "completed"
                      ? "✓"
                      : status === "not_applicable"
                        ? "—"
                        : "!"}
                  </i>
                  <span>{key.replaceAll("_", " ")}</span>
                  <b>
                    {status === "completed"
                      ? "Đã kiểm tra"
                      : status === "not_applicable"
                        ? "Không áp dụng"
                        : status === "partial"
                          ? "Một phần"
                          : "Chưa khả dụng"}
                  </b>
                </article>
              ))}
            </div>
          </section>
        )}
        {contextualAI && (
          <section className="message-coverage" role="status">
            <b>AI Evaluate: {contextualAI.status || "không rõ"}</b> ·{" "}
            {contextualAI.scoring_mode === "shadow"
              ? "Shadow — quan sát ngữ cảnh nhưng không thay đổi điểm"
              : contextualAI.scoring_mode === "active"
                ? "Active — bằng chứng đã được Risk Core xem xét"
                : "Không tham gia chấm điểm"}
            {contextualAI.adapter_id ? ` · ${contextualAI.adapter_id}` : ""}
          </section>
        )}
        <div className="message-evidence-groups" aria-label="Năm nhóm tiêu chí">
          {groupDefinitions.map(([label, keys]) => (
            <div key={label}>
              <span>{label}</span>
              <b>{groupCount(keys)}</b>
              <small>tín hiệu</small>
            </div>
          ))}
        </div>
        <div className="report-grid">
          <section aria-labelledby="evidence-heading">
            <div className="section-label">
              <span id="evidence-heading">BẰNG CHỨNG ĐÃ PHÁT HIỆN</span>
              <b>{evidence.length} tín hiệu</b>
            </div>
            <div className="findings">
              {evidence.length ? (
                evidence.map((item, index) => {
                  const severity = ["critical", "high"].includes(
                    item.severity || "",
                  )
                    ? "high"
                    : ["low", "info"].includes(item.severity || "")
                      ? "low"
                      : "medium";
                  return (
                    <article key={`${item.feature}-${index}`}>
                      <span className={`severity ${severity}`}>
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <div>
                        <h3>{item.feature || item.source || "Tín hiệu"}</h3>
                        <p>{item.message || "Không có mô tả."}</p>
                        <code>
                          {item.source || "risk-core"}
                          {typeof item.contribution === "number"
                            ? ` · +${Math.round(item.contribution * 100)} điểm`
                            : ""}
                        </code>
                      </div>
                      <em>{item.severity?.toUpperCase() || "INFO"}</em>
                    </article>
                  );
                })
              ) : (
                <p>Không phát hiện tín hiệu rõ trong dữ liệu đã cung cấp.</p>
              )}
            </div>
          </section>
          <aside className="action-plan">
            <div className="section-label">
              <span>HÀNH ĐỘNG ĐỀ XUẤT</span>
            </div>
            <ol>
              <li>
                <b>Không bấm link hoặc trả lời vội</b>
                <p>Tự mở app/website chính thức để kiểm tra.</p>
              </li>
              <li>
                <b>Không gửi OTP, mật khẩu hay tiền</b>
                <p>Tổ chức hợp pháp không yêu cầu bạn đọc OTP cho nhân viên.</p>
              </li>
              <li>
                <b>Xác minh bằng kênh độc lập</b>
                <p>
                  Dùng số hoặc địa chỉ đã biết, không dùng thông tin trong tin
                  nhắn.
                </p>
              </li>
              <li>
                <b>Báo cáo và chặn khi rủi ro cao</b>
                <p>Lưu bằng chứng trước khi xóa.</p>
              </li>
            </ol>
          </aside>
        </div>
        <details className="result-guide">
          <summary>Nội dung đã kiểm tra</summary>
          <pre className="message-content-preview">
            {record?.content ||
              "Không đọc được nội dung từ bộ nhớ trình duyệt."}
          </pre>
        </details>
        {record?.analysisDepth === "pro" && (
          <ProAIContextPanel record={record} />
        )}
        <div className="report-foot">
          <Link href="/analyze">← Phân tích nội dung khác</Link>
          <span>
            Kết quả hỗ trợ quyết định; dữ liệu chưa kiểm tra được luôn được ghi
            rõ.
          </span>
        </div>
      </main>
    </PrewiseShell>
  );
}

function formatDomainDate(value?: string | null) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : new Intl.DateTimeFormat("vi-VN").format(parsed);
}

const STATUS_LABEL = {
  completed: "ĐÃ KIỂM TRA",
  skipped: "CHƯA CHẠY",
  unavailable: "KHÔNG KHẢ DỤNG",
} as const;
function localCriterionDetails(
  rawUrl: string | undefined,
  layerIndex: number,
): CriterionDetail[] {
  if (!rawUrl || layerIndex === 2) return [];
  try {
    const parsed = new URL(
      /^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`,
    );
    const host = parsed.hostname.toLowerCase();
    const labels = host.split(".").filter(Boolean);
    const multiSuffix = ["com.vn", "net.vn", "org.vn", "co.uk"].some((suffix) =>
      host.endsWith(`.${suffix}`),
    );
    const domain =
      labels.length < 2 ? host : labels.slice(multiSuffix ? -3 : -2).join(".");
    const subdomain =
      labels.slice(0, labels.length - (multiSuffix ? 3 : 2)).join(".") ||
      "(không có)";
    if (layerIndex === 0)
      return [
        {
          criterion: "Xác định hostname, domain thật và subdomain",
          value: `Hostname: ${host} · Domain đăng ký: ${domain} · Subdomain: ${subdomain}`,
          triggered: false,
          contribution: 0,
          reason:
            "Đã tách cấu trúc URL thành công. Bước này dùng làm đầu vào cho các luật giả mạo và không tự cộng điểm rủi ro.",
        },
        {
          criterion: "So khớp thương hiệu trên domain không chính chủ",
          value: `Domain được đối chiếu: ${domain}`,
          triggered: false,
          contribution: 0,
          reason:
            "Không có chi tiết kích hoạt riêng từ backend; xem phần Bằng chứng nếu core phát hiện brand_domain_mismatch.",
        },
        {
          criterion: "Phát hiện homoglyph, punycode và ký tự giả mạo",
          value: host.includes("xn--")
            ? "Có nhãn punycode xn--"
            : "Không thấy nhãn punycode",
          triggered: host.includes("xn--"),
          contribution: host.includes("xn--") ? 18 : 0,
          reason: host.includes("xn--")
            ? "Bộ phát hiện nhận diện tín hiệu giả mạo; lõi chính sách dùng bằng chứng này để đưa ra kết luận."
            : "Không phát hiện punycode ở hostname.",
        },
        {
          criterion: "Kiểm tra HTTPS, IP host, TLD rủi ro và shortlink",
          value: `Protocol: ${parsed.protocol.replace(":", "")} · TLD: ${labels.at(-1) || "—"}`,
          triggered: parsed.protocol !== "https:",
          contribution: parsed.protocol !== "https:" ? 10 : 0,
          reason:
            parsed.protocol === "https:"
              ? "URL sử dụng HTTPS; tiêu chí này không cộng mức tín hiệu."
              : "Bộ phát hiện ghi nhận kết nối không dùng HTTPS; lõi chính sách quyết định kết luận cuối.",
        },
      ];
    const decoded = decodeURIComponent(rawUrl).toLowerCase();
    const sensitive = [
      "password",
      "otp",
      "2fa",
      "mfa",
      "card",
      "cvv",
      "payment",
      "billing",
      "bank",
      "wallet",
      "token",
      "seed",
      "mnemonic",
    ].filter((word) => decoded.includes(word));
    return [
      {
        criterion: "Tìm từ khóa dữ liệu nhạy cảm",
        value: sensitive.length ? sensitive.join(", ") : "Không phát hiện",
        triggered: sensitive.length > 0,
        contribution: Math.min(26, 9 * sensitive.length),
        reason: sensitive.length
          ? `Phát hiện ${sensitive.length} từ khóa nhạy cảm.`
          : "Không có từ khóa mật khẩu, OTP, thẻ, ngân hàng, ví hoặc token.",
      },
      {
        criterion: "Phát hiện tham số chuyển hướng",
        value: parsed.search || "Không có query string",
        triggered:
          /(?:redirect|redirect_uri|return_url|continue|next|target|url)=/i.test(
            decoded,
          ),
        contribution:
          /(?:redirect|redirect_uri|return_url|continue|next|target|url)=/i.test(
            decoded,
          )
            ? 7
            : 0,
        reason: "Kiểm tra tham số có thể che giấu đích cuối.",
      },
      {
        criterion: "Kiểm tra @ và percent-encoding",
        value: `@: ${rawUrl.includes("@") ? "có" : "không"} · encoding %: ${rawUrl.includes("%") ? "có" : "không"}`,
        triggered: rawUrl.includes("@") || rawUrl.includes("%"),
        contribution: rawUrl.includes("@") ? 22 : rawUrl.includes("%") ? 12 : 0,
        reason: "Các ký tự này có thể được dùng để làm người đọc hiểu sai URL.",
      },
      {
        criterion: "Đếm query parameter",
        value: `${Array.from(parsed.searchParams.keys()).length} tham số`,
        triggered: Array.from(parsed.searchParams.keys()).length >= 5,
        contribution:
          Array.from(parsed.searchParams.keys()).length >= 5 ? 8 : 0,
        reason: "Nhiều tham số bất thường có thể là tín hiệu né tránh.",
      },
    ];
  } catch {
    return [];
  }
}
const LAYER_CRITERIA = [
  {
    scope: "Phân tích chuỗi URL · không mở website",
    steps: [
      "Xác định hostname, domain thật và subdomain",
      "So khớp thương hiệu trên domain không chính chủ",
      "Phát hiện homoglyph, punycode và ký tự giả mạo",
      "Kiểm tra IP host, TLD rủi ro, HTTPS và shortlink",
    ],
  },
  {
    scope: "Phân tích ý đồ và kỹ thuật che giấu · không mở website",
    steps: [
      "Tìm từ khóa password, OTP, thẻ, ngân hàng, ví và token",
      "Phát hiện URL lồng nhau và tham số redirect/next/target",
      "Kiểm tra ký tự @, percent-encoding và phân mảnh bất thường",
      "Đếm query parameter và nhận diện domain entropy cao",
    ],
  },
  {
    scope:
      "Quan sát website thật trong sandbox cô lập · HTTP/HTML ở Cân bằng, thêm browser ở Chuyên sâu",
    steps: [
      "Tải HTTP/HTML an toàn để kiểm tra chứng chỉ, redirect, form và chính sách",
      "Ở Chuyên sâu, mở URL bằng worker trình duyệt ở chế độ dry-run",
      "Theo dõi redirect, navigation và đích cuối",
      "Ghi nhận script, network request và hành vi đáng ngờ",
      "Quan sát DOM mutation; chặn submit và dữ liệu nhạy cảm thật",
    ],
  },
] as const;

function ResultContent() {
  const query = useSearchParams();
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [record, setRecord] = useState<StoredRecord | null>(null);
  const [selectedLayer, setSelectedLayer] = useState<number | null>(null);
  const queryDemo = query.get("demo");
  const isStoredBackend =
    record?.isDemo === false ||
    record?.dataSource === "backend" ||
    Boolean(record?.result);
  const isDemo = isStoredBackend ? false : queryDemo !== "0";
  const fallbackScore = Number(query.get("score") || 87);
  const type = query.get("type") || "url";

  useEffect(() => {
    if (!id) return;
    setRecord(loadResultRecord<StoredRecord>(id));
  }, [id]);

  useEffect(() => {
    if (selectedLayer == null) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSelectedLayer(null);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [selectedLayer]);

  if (type === "email" || type === "sms") {
    return (
      <MessageReport
        record={record}
        fallbackScore={fallbackScore}
        type={type}
      />
    );
  }

  const result = record?.result;
  const aiScore = readAIScore(result);
  const basic = result?.url_intelligence;
  const risk = mapRiskResult(result, record?.score ?? fallbackScore);
  const score = Math.round(risk.score);
  const displayLevel = getRiskLevelForContext(
    risk.decision,
    risk.level,
    score,
  );
  const v2Evidence = risk.evidence;
  const scanChecks = extractScanChecks(v2Evidence);
  const riskEvidence = v2Evidence.filter((item) => {
    const status = String(item.status ?? "").toLowerCase();
    const verdict = String(item.provider_verdict ?? "").toLowerCase();
    return (
      status === "suspicious" ||
      status === "malicious" ||
      verdict === "suspicious" ||
      verdict === "malicious"
    );
  });
  const evidence =
    risk.source === "risk_core_v2" ? riskEvidence : (result?.evidence ?? []);
  const findings: Finding[] = evidence.length
    ? evidence.slice(0, 8).map((item: RiskCoreRecord) => ({
        title: displayValue(
          item,
          ["feature", "category", "source"],
          "Tín hiệu rủi ro",
        ),
        detail: displayValue(
          item,
          ["message", "reason", "detail"],
          "Backend phát hiện tín hiệu cần xem xét.",
        ),
        evidence: displayValue(
          item,
          ["source", "adapter", "detector_family"],
          "risk-core",
        ),
        severity: (["critical", "high"].includes(
          displayValue(item, ["severity"]).toLowerCase(),
        )
          ? "high"
          : ["low", "info"].includes(
                displayValue(item, ["severity"]).toLowerCase(),
              )
            ? "low"
            : "medium") as Finding["severity"],
      }))
    : risk.source === "legacy" && isDemo
      ? demoFindings
      : [];
  const layers = result?.score_layers ?? [];
  const sandbox = result?.sandbox_report;
  const confidenceValue = risk.confidence;
  const confidenceNumber =
    typeof confidenceValue === "number" && Number.isFinite(confidenceValue)
      ? Math.max(0, Math.min(100, Math.round(confidenceValue)))
      : null;
  const confidence =
    confidenceNumber == null ? "Không được cung cấp" : `${confidenceNumber}%`;
  const verdict =
    risk.source === "risk_core_v2"
      ? risk.nextAction ||
        risk.decision ||
        "Chưa có hành động được policy cung cấp."
      : score >= 70
        ? "Không truy cập hoặc cung cấp thông tin."
        : score >= 40
          ? "Hãy xác minh thêm trước khi tiếp tục."
          : "Chưa thấy tín hiệu rủi ro nổi bật.";
  const description =
    risk.source === "risk_core_v2"
      ? `Mức ${risk.level || "chưa xác định"} · Quyết định ${risk.decision || "chưa được cung cấp"}. UI giữ nguyên kết luận của Risk Core v2.`
      : score >= 70
        ? "Trang đích có tín hiệu rủi ro cao. Không nhập mật khẩu, OTP, dữ liệu thẻ hoặc thông tin định danh."
        : score >= 40
          ? "Có một số tín hiệu cần xác minh qua kênh chính thức trước khi thao tác."
          : "Kết quả legacy: mức rủi ro và khuyến nghị được UI suy từ điểm do payload cũ chưa có policy v2.";
  const checkedLayers = layers.filter(
    (layer) => layer.status === "completed",
  ).length;
  const depthLabel = record?.analysisDepth
    ? (
        {
          quick: "Nhanh",
          balanced: "Cân bằng",
          deep: "Chuyên sâu",
          pro: "Pro AI",
        } as const
      )[record.analysisDepth]
    : "";
  const analysisKind = `${depthLabel ? `${depthLabel} · ` : ""}${
    sandbox?.analysis_mode === "http"
      ? "HTTP/HTML sandbox"
      : sandbox
        ? "browser sandbox"
        : "không tải nội dung website"
  }`;
  const dangerousCriteria = result?.dangerous_criteria ?? [];
  const accessAnalysis = result?.access_analysis;
  const warningRequired =
    result?.warning_required === true ||
    [
      "WARN",
      "ASK_USER_CONFIRMATION",
      "BLOCK",
      "require_review",
      "soft_block",
      "hard_block",
    ].includes(risk.decision || "");
  const contextAI = result?.contextual_analysis;
  const cacheHit = result?.cache_hit === true || result?.cache_status === "hit";
  const rescanHref = record?.content
    ? `/analyze?signal=${encodeURIComponent(record.content)}&force_rescan=1`
    : "/analyze";

  return (
    <PrewiseShell>
      <main id="main-content" className={`report ${mobileStyles.report}`}>
        <div className="report-title">
          <div>
            <p className="eyebrow">
              <i /> ANALYSIS REPORT · {type.toUpperCase()}
            </p>
            <span className="demo-badge">
              {isDemo ? "KẾT QUẢ MINH HỌA" : "KẾT QUẢ BACKEND THẬT"}
            </span>
            <h1>Đánh giá rủi ro hoàn tất</h1>
            <p>
              {isDemo
                ? "Prewise đã phát hiện nhiều tín hiệu cần được xem xét trước khi bạn tiếp tục."
                : "Báo cáo bên dưới cho biết chính xác những lớp nào đã chạy, tín hiệu nào được phát hiện và lớp nào chưa được thực hiện. Điểm kỹ thuật được giữ nội bộ."}
            </p>
          </div>
          <div className="report-actions" aria-label="Tác vụ báo cáo">
            <Link href={rescanHref} title="Bỏ qua cache và chạy lại URL này">
              ↻ Quét lại
            </Link>
            <ExportReportButton reportId={id} reportType="url" />
            <ShareReportButton
              score={score}
              decision={risk.decision}
              riskLevel={risk.level}
            />
          </div>
        </div>

        {cacheHit && (
          <p className="demo-disclosure" role="status">
            ⓘ Kết quả nhanh: dùng lại bản quét tương đương đã lưu, không trừ
            lượt quét. Chọn <Link href={rescanHref}>Quét lại</Link> để chạy mới.
          </p>
        )}

        {warningRequired && (
          <section
            className="danger-access-alert"
            role="alert"
            aria-labelledby="danger-access-title"
          >
            <header>
              <div>
                <span>
                  CẢNH BÁO TRUY CẬP ·{" "}
                  {result?.auto_deep_analysis
                    ? "ĐÃ TỰ ĐỘNG QUÉT SÂU"
                    : "RISK CORE"}
                </span>
                <h2 id="danger-access-title">
                  Nguy hiểm — nên cân nhắc trước khi truy cập
                </h2>
              </div>
              <strong>RỦI RO CAO</strong>
            </header>
            <p>
              {accessAnalysis?.warning ||
                "URL có đủ bằng chứng tổng hợp để đạt ngưỡng nguy hiểm. Không nhập mật khẩu, OTP, thông tin thẻ hoặc tải tệp."}
            </p>
            <div className="danger-access-grid">
              <section>
                <h3>Nguyên nhân kích hoạt</h3>
                {dangerousCriteria.length ? (
                  <ol>
                    {dangerousCriteria.map((item) => (
                      <li key={item.criterion_id}>
                        <b>{item.name || `Tiêu chí ${item.criterion_id}`}</b>
                        <span>
                          {item.reason ||
                            "Phát hiện nguy hiểm có độ tin cậy cao."}
                        </span>
                        <em>Bằng chứng đã kích hoạt cảnh báo</em>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p>
                    Nhiều bằng chứng độc lập đã cùng xác nhận mức nguy hiểm.
                  </p>
                )}
              </section>
              <section>
                <h3>Kết quả khi mở trong sandbox</h3>
                {accessAnalysis?.performed ? (
                  <>
                    <p>
                      Đích cuối:{" "}
                      <code>{accessAnalysis.final_url || record?.content}</code>
                    </p>
                    <ul>
                      {(accessAnalysis.observed_effects || []).map((effect) => (
                        <li key={effect}>{effect}</li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p>
                    Chưa thực hiện truy cập cô lập. Hệ thống khuyến nghị chạy
                    Chuyên sâu.
                  </p>
                )}
              </section>
            </div>
          </section>
        )}
        {contextAI && (
          <section className="scan-proof" aria-labelledby="context-ai-title">
            <div className="section-label">
              <span id="context-ai-title">AI EVALUATE · NGỮ CẢNH</span>
              <b>{contextAI.status || "không rõ"}</b>
            </div>
            <div className="scan-meta">
              <div>
                <span>Adapter</span>
                <strong>{contextAI.adapter_id || "Chưa cấu hình"}</strong>
              </div>
              <div>
                <span>Chế độ tính điểm</span>
                <strong>
                  {contextAI.scoring_mode === "shadow"
                    ? "Shadow · không đổi điểm"
                    : contextAI.scoring_mode || "none"}
                </strong>
              </div>
              <div>
                <span>Độ tin cậy AI</span>
                <strong>
                  {typeof contextAI.confidence === "number"
                    ? `${Math.round(contextAI.confidence * 100)}%`
                    : "—"}
                </strong>
              </div>
              <div>
                <span>Trạng thái</span>
                <strong>{contextAI.error || contextAI.status || "—"}</strong>
              </div>
            </div>
          </section>
        )}

        <section className="report-overview" aria-label="Tổng quan kết quả">
          <RiskDial
            score={score}
            decision={risk.decision}
            riskLevel={risk.level}
          />
          <div className="verdict">
            <span>KHUYẾN NGHỊ</span>
            <h2>{verdict}</h2>
            <p>{description}</p>
            <div>
              <b>Độ tin cậy của kết luận</b>
              <strong>{confidence}</strong>
              <i aria-hidden>
                <em style={{ width: `${confidenceNumber ?? 0}%` }} />
              </i>
            </div>
          </div>
          {aiScore ? (
            <AIScoreCard value={aiScore} />
          ) : (
            <div className="signal-visual" aria-hidden>
              <div className="report-core" />
              <small>{findings.length} TÍN HIỆU ĐƯỢC ĐỐI CHIẾU</small>
            </div>
          )}
        </section>

        {!isDemo &&
          type === "url" &&
          record?.content &&
          record.analysisDepth !== "pro" && (
            <section
              className="ai-deep-cta"
              aria-labelledby="ai-deep-cta-title"
            >
              <div>
                <span>PRO AI INVESTIGATION</span>
                <h2 id="ai-deep-cta-title">Nâng lên Pro AI</h2>
                <p>
                  Chạy browser sandbox đầy đủ rồi dùng AI Evaluate để đối chiếu
                  mục đích trang với bằng chứng kỹ thuật. Yêu cầu gói Pro và
                  dùng AI credit.
                </p>
              </div>
              <Link
                href={`/result/${id}/ai-analysis`}
                className="ai-deep-button"
              >
                Chạy Pro AI <span aria-hidden>→</span>
              </Link>
            </section>
          )}

        {basic && (
          <section className="url-basic-info" aria-labelledby="url-basic-title">
            <div className="section-label">
              <span id="url-basic-title">THÔNG TIN CĂN BẢN</span>
              <b>{basic.domain || "Tên miền chưa xác định"}</b>
            </div>
            <div className="url-basic-grid">
              <div>
                <span>Địa chỉ IP</span>
                <strong>
                  {basic.primary_ip || basic.ip_addresses?.join(", ") || "—"}
                </strong>
              </div>
              <div>
                <span>IP có vị trí</span>
                <strong>{basic.ip_location || "Không khả dụng"}</strong>
              </div>
              <div>
                <span>Nhà cung cấp</span>
                <strong>
                  {[basic.asn, basic.provider].filter(Boolean).join(" ") || "—"}
                </strong>
              </div>
              <div>
                <span>Nhà đăng ký</span>
                <strong>{basic.registrar || "—"}</strong>
              </div>
              <div>
                <span>Chủ sở hữu</span>
                <strong>
                  {basic.registrant || "Bị ẩn hoặc không công khai"}
                </strong>
              </div>
              <div>
                <span>Ngày đăng ký</span>
                <strong>{formatDomainDate(basic.registered_at)}</strong>
              </div>
              <div>
                <span>Ngày hết hạn</span>
                <strong>{formatDomainDate(basic.expires_at)}</strong>
              </div>
              <div className="url-basic-ns">
                <span>Nameservers</span>
                {basic.nameservers?.length ? (
                  basic.nameservers.map((name) => (
                    <code key={name}>{name}</code>
                  ))
                ) : (
                  <strong>—</strong>
                )}
              </div>
            </div>
            <div
              className="url-source-status"
              aria-label="Nguồn của thông tin căn bản"
            >
              {basic.sources?.map((source) => (
                <span
                  className={source.status || "unavailable"}
                  title={source.detail || ""}
                  key={source.source}
                >
                  <i aria-hidden>
                    {source.status === "completed"
                      ? "✓"
                      : source.status === "redacted"
                        ? "◐"
                        : "—"}
                  </i>
                  {source.source}
                </span>
              ))}
            </div>
          </section>
        )}

        {!isDemo && (
          <section className="scan-proof" aria-labelledby="scan-proof-title">
            <div className="section-label">
              <span id="scan-proof-title">PHẠM VI ĐÃ KIỂM TRA</span>
              <b>
                {checkedLayers}/{layers.length || 3} lớp hoàn tất
              </b>
            </div>
            <div className="scan-meta">
              <div>
                <span>URL được kiểm tra</span>
                <code title={record?.content}>
                  {record?.content || "Không đọc được từ bộ nhớ trình duyệt"}
                </code>
              </div>
              <div>
                <span>Kiểu phân tích</span>
                <strong>{analysisKind}</strong>
              </div>
              <div>
                <span>Thời gian backend</span>
                <strong>{result?.analysis_time_ms ?? "—"} ms</strong>
              </div>
              <div>
                <span>Core/model</span>
                <strong>
                  {result?.ai_detection?.model_version || "Không được cung cấp"}
                </strong>
              </div>
            </div>
            <div className="layer-grid">
              {layers.map((layer, index) => {
                const status = layer.status || "completed";
                const layerScore = Math.round(layer.score || 0);
                return (
                  <article
                    role="button"
                    tabIndex={0}
                    aria-label={`Mở chi tiết ${layer.layer || `lớp ${index + 1}`}`}
                    onClick={() => setSelectedLayer(index)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedLayer(index);
                      }
                    }}
                    className={`layer-card layer-card-clickable ${status}`}
                    key={`${layer.layer}-${index}`}
                  >
                    <header>
                      <span>L{index + 1}</span>
                      <em>{STATUS_LABEL[status]}</em>
                    </header>
                    <h3>{layer.layer || `Lớp kiểm tra ${index + 1}`}</h3>
                    <p>{layer.summary || "Không có mô tả."}</p>
                    <div>
                      <span>Trạng thái <b>{STATUS_LABEL[status]}</b></span>
                      <span>{layer.signals || 0} phát hiện</span>
                    </div>
                    <i aria-hidden>
                      <em style={{ width: `${layerScore}%` }} />
                    </i>
                    <button type="button" tabIndex={-1} aria-hidden>
                      Chi tiết tiêu chí ↗
                    </button>
                  </article>
                );
              })}
            </div>
            <div className="criteria-table-wrap">
              <table className="criteria-table layer-criteria-table">
                <thead>
                  <tr>
                    <th>Lớp</th>
                    <th>Phạm vi thực tế</th>
                    <th>Các bước / tiêu chí xét</th>
                    <th>Kết quả lần quét này</th>
                  </tr>
                </thead>
                <tbody>
                  {LAYER_CRITERIA.map((criteria, index) => {
                    const layer = layers[index];
                    const status =
                      layer?.status || (index < 2 ? "completed" : "skipped");
                    return (
                      <tr key={`criteria-${index}`} className={status}>
                        <td>
                          <strong>L{index + 1}</strong>
                          <span>
                            {index === 0
                              ? "Danh tính URL"
                              : index === 1
                                ? "Ý đồ & né tránh"
                                : "Browser sandbox"}
                          </span>
                        </td>
                        <td>{criteria.scope}</td>
                        <td>
                          <ol>
                            {criteria.steps.map((step, stepIndex) => (
                              <li key={step}>
                                <i>{stepIndex + 1}</i>
                                {step}
                              </li>
                            ))}
                          </ol>
                        </td>
                        <td>
                          <em>{STATUS_LABEL[status]}</em>
                          <span>
                            {layer
                              ? `${layer.signals || 0} tín hiệu`
                              : "Không có dữ liệu lớp"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {!sandbox && (
              <div className="coverage-warning">
                <b>⚠ Chưa mở nội dung website</b>
                <p>
                  Kết quả nhanh vì chế độ này chạy model ONNX và luật trên cấu
                  trúc URL ngay trong bộ nhớ; không tải HTML, không theo
                  redirect live và không chạy JavaScript. Chọn <b>Chuyên sâu</b>{" "}
                  ở trang Analyze nếu muốn chạy browser sandbox.
                </p>
                {result?.deep_analysis_recommended && (
                  <strong>
                    Core khuyến nghị chạy phân tích chuyên sâu cho URL này.
                  </strong>
                )}
              </div>
            )}
            {sandbox && (
              <div className="sandbox-summary">
                <b>
                  {sandbox.analysis_mode === "http"
                    ? "HTTP/HTML sandbox đã chạy"
                    : "Browser sandbox đã chạy"}
                </b>
                <span>{sandbox.behaviors?.length || 0} hành vi</span>
                <span>
                  {sandbox.redirects?.length || 0} redirect/navigation
                </span>
                <span>{sandbox.scripts_executed?.length || 0} script</span>
                <span>
                  {sandbox.network_calls?.length || 0} network request
                </span>
                <span>
                  {sandbox.dom_modifications?.length || 0} DOM mutation
                </span>
                <span>{sandbox.analysis_time_ms ?? "—"} ms</span>
                {sandbox.error && <p>Sandbox báo lỗi: {sandbox.error}</p>}
              </div>
            )}
          </section>
        )}

        {selectedLayer != null &&
          (() => {
            const criteria = LAYER_CRITERIA[selectedLayer];
            const layer = layers[selectedLayer];
            const status =
              layer?.status || (selectedLayer < 2 ? "completed" : "skipped");
            return (
              <div
                className="layer-modal-backdrop"
                role="presentation"
                onMouseDown={(event) => {
                  if (event.target === event.currentTarget)
                    setSelectedLayer(null);
                }}
              >
                <section
                  className="layer-modal"
                  role="dialog"
                  aria-modal="true"
                  aria-labelledby="layer-modal-title"
                >
                  <header>
                    <div>
                      <span>CHI TIẾT KIỂM TRA · L{selectedLayer + 1}</span>
                      <h2 id="layer-modal-title">
                        {layer?.layer ||
                          (selectedLayer === 0
                            ? "Danh tính URL"
                            : selectedLayer === 1
                              ? "Ý đồ & né tránh"
                              : "Browser sandbox")}
                      </h2>
                    </div>
                    <button
                      type="button"
                      autoFocus
                      onClick={() => setSelectedLayer(null)}
                      aria-label="Đóng cửa sổ"
                    >
                      ×
                    </button>
                  </header>
                  <div className="layer-modal-status">
                    <em className={status}>{STATUS_LABEL[status]}</em>
                    <span>
                      Tín hiệu: <b>{layer?.signals || 0}</b>
                    </span>
                  </div>
                  <div className="layer-modal-scope">
                    <b>Phạm vi thực tế</b>
                    <p>{criteria.scope}</p>
                  </div>
                  <div className="criteria-checklist">
                    <h3>Các tiêu chí hệ thống xét ở lớp này</h3>
                    {((layer?.details?.length
                      ? layer.details
                      : localCriterionDetails(record?.content, selectedLayer)
                    ).length
                      ? layer?.details?.length
                        ? layer.details
                        : localCriterionDetails(record?.content, selectedLayer)
                      : criteria.steps.map(
                          (criterion): CriterionDetail => ({
                            criterion,
                            triggered: status === "completed",
                            contribution: 0,
                          }),
                        )
                    ).map((detail, index) => (
                      <article key={`${detail.criterion}-${index}`}>
                        <i aria-hidden>
                          {status !== "completed"
                            ? status === "unavailable"
                              ? "!"
                              : "—"
                            : detail.triggered
                              ? "✕"
                              : "✓"}
                        </i>
                        <div>
                          <b>
                            {String(index + 1).padStart(2, "0")}.{" "}
                            {detail.criterion}
                          </b>
                          {detail.value && (
                            <code className="criterion-value">
                              {detail.value}
                            </code>
                          )}
                          <p>
                            {detail.reason ||
                              (status === "completed"
                                ? "Đã xét tiêu chí; không có tín hiệu rủi ro riêng được kích hoạt."
                                : status === "unavailable"
                                  ? "Không thể hoàn tất tiêu chí do lớp phân tích không khả dụng."
                                  : "Tiêu chí chưa được chạy trong lần phân tích này.")}
                          </p>
                          {status === "completed" && (
                            <span
                              className={`criterion-score ${detail.triggered ? "risk" : "safe"}`}
                            >
                              {detail.triggered
                                ? "Đã kích hoạt cảnh báo"
                                : "Không phát hiện"}
                            </span>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                  {selectedLayer === 2 && (
                    <div className="layer-modal-sandbox">
                      <b>Dữ liệu sandbox ghi nhận</b>
                      <div>
                        <span>
                          {sandbox?.redirects?.length || 0}
                          <small>Redirect</small>
                        </span>
                        <span>
                          {sandbox?.scripts_executed?.length || 0}
                          <small>Script</small>
                        </span>
                        <span>
                          {sandbox?.network_calls?.length || 0}
                          <small>Network</small>
                        </span>
                        <span>
                          {sandbox?.dom_modifications?.length || 0}
                          <small>DOM</small>
                        </span>
                      </div>
                      {!sandbox && (
                        <p>
                          Chọn mức <b>Chuyên sâu</b> ở trang Analyze để thực sự
                          chạy L3.
                        </p>
                      )}
                    </div>
                  )}
                  <footer>
                    <span>
                      {layer?.summary || "Không có dữ liệu tóm tắt từ backend."}
                    </span>
                    <button
                      type="button"
                      onClick={() => setSelectedLayer(null)}
                    >
                      Đã hiểu
                    </button>
                  </footer>
                </section>
              </div>
            );
          })()}

        {risk.source === "risk_core_v2" && scanChecks.length > 0 && (
          <section
            className="scan-proof source-checks"
            aria-labelledby="source-checks-title"
          >
            <div className="section-label">
              <span id="source-checks-title">CÁC HẠNG MỤC / NGUỒN ĐÃ QUÉT</span>
              <b>
                {scanChecks.filter((check) => check.status === "safe").length}{" "}
                đạt ·{" "}
                {scanChecks.filter((check) => check.status === "danger").length}{" "}
                nguy hiểm
              </b>
            </div>
            <p className="source-check-note">
              Dấu ✓ nghĩa là phép kiểm tra đã hoàn tất và không thấy chỉ báo
              trong nguồn đó; không phải bảo đảm tuyệt đối rằng URL an toàn.
            </p>
            <div className="source-check-grid">
              {scanChecks.map((check) => (
                <article className={check.status} key={check.id}>
                  <i aria-hidden>
                    {check.status === "danger"
                      ? "✕"
                      : check.status === "safe"
                        ? "✓"
                        : check.status === "review"
                          ? "!"
                          : "—"}
                  </i>
                  <div>
                    <b>{check.label}</b>
                    <p>{check.detail}</p>
                    <small>{check.source}</small>
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        {risk.source === "risk_core_v2" && (
          <section className="scan-proof" aria-labelledby="risk-core-details">
            <div className="section-label">
              <span id="risk-core-details">
                RISK CORE V2 · CHI TIẾT QUYẾT ĐỊNH
              </span>
              <b>
                Schema {risk.schemaVersion || "2"} ·{" "}
                {risk.scoringVersion || "scoring version —"}
              </b>
            </div>
            <div className="scan-meta">
              <div>
                <span>Kết luận hiển thị</span>
                <strong>{displayLevel.label}</strong>
              </div>
              <div>
                <span>Chính sách bảo vệ</span>
                <strong>{risk.decision || "Chưa được cung cấp"}</strong>
              </div>
              <div>
                <span>Độ tin cậy</span>
                <strong>{confidence}</strong>
              </div>
            </div>
            {risk.effectiveOverride && (
              <div className="coverage-warning">
                <b>Override đang có hiệu lực</b>
                <p>
                  {displayValue(
                    risk.effectiveOverride,
                    ["reason", "description", "rule"],
                    "Backend không cung cấp lý do override.",
                  )}
                </p>
              </div>
            )}
            <div className="criteria-table-wrap">
              <table className="criteria-table risk-criteria-table">
                <thead>
                  <tr>
                    <th>Tiêu chí</th>
                    <th>Trạng thái</th>
                    <th>Lý do</th>
                  </tr>
                </thead>
                <tbody>
                  {risk.criteria.length ? (
                    risk.criteria.map((item, index) => (
                      <tr
                        key={displayValue(
                          item,
                          ["id", "criterion_id", "name"],
                          String(index),
                        )}
                      >
                        <td>
                          <strong>
                            {displayValue(
                              item,
                              ["name", "criterion", "criterion_id", "id"],
                              `Tiêu chí ${index + 1}`,
                            )}
                          </strong>
                        </td>
                        <td>
                          {displayValue(item, [
                            "status",
                            "result",
                            "triggered",
                          ])}
                        </td>
                        <td>
                          {displayValue(item, [
                            "reason",
                            "message",
                            "description",
                          ])}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={3}>
                        Không có chi tiết tiêu chí trong payload.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {(risk.unavailableChecks.length > 0 ||
              risk.notCheckedChecks.length > 0) && (
              <div className="coverage-warning">
                <b>Phạm vi chưa hoàn tất</b>
                <p>
                  Không khả dụng: {risk.unavailableChecks.join(", ") || "không"}
                </p>
                <p>
                  Chưa kiểm tra: {risk.notCheckedChecks.join(", ") || "không"}
                </p>
              </div>
            )}
            <div className="report-grid">
              <section>
                <div className="section-label">
                  <span>MITIGATION</span>
                  <b>{risk.mitigations.length}</b>
                </div>
                {risk.mitigations.map((item, index) => (
                  <p key={index}>
                    <b>
                      {displayValue(
                        item,
                        ["title", "action", "name"],
                        `Biện pháp ${index + 1}`,
                      )}
                      :
                    </b>{" "}
                    {displayValue(item, ["description", "reason", "detail"])}
                  </p>
                ))}
              </section>
              <aside className="action-plan">
                <div className="section-label">
                  <span>REASONING / OVERRIDE / CAPS</span>
                </div>
                {risk.reasoning.length ? (
                  <ol>
                    {risk.reasoning.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ol>
                ) : (
                  <p>Không có reasoning.</p>
                )}
                <p>
                  Overrides: {risk.overrides.length} · Caps: {risk.caps.length}{" "}
                  · Conflicts: {risk.conflicts.length}
                </p>
              </aside>
            </div>
          </section>
        )}
        {risk.source === "legacy" && (
          <p className="demo-disclosure" role="status">
            ⚠ Chế độ tương thích legacy: payload không có{" "}
            <code>risk_core</code>. Điểm có thể được chuẩn hóa từ thang 0..1;
            level/khuyến nghị cục bộ không phải quyết định policy v2.
          </p>
        )}

        <details className="result-guide">
          <summary>Cách đọc và giới hạn của kết quả</summary>
          <p>
            <b>Kết luận rủi ro</b> được tạo từ mô hình nhận diện và các luật phát
            hiện giả mạo, ý đồ đánh cắp thông tin, kỹ thuật che giấu. Mức Nhanh không tải nội
            dung website; Cân bằng chỉ đọc HTTP/HTML trong sandbox;{" "}
            <b>Chuyên sâu và Pro AI</b> mới mở trang trong browser sandbox để
            quan sát redirect, script, network và DOM. Pro AI bổ sung đánh giá
            ngữ cảnh có cấu trúc.
          </p>
        </details>
        {record?.analysisDepth === "pro" && (
          <ProAIContextPanel record={record} />
        )}
        {isDemo ? (
          <p className="demo-disclosure" role="status">
            ⓘ Đây là luồng demo dùng điểm số và bằng chứng cố định để minh họa
            giao diện.
          </p>
        ) : (
          <p className="demo-disclosure" role="status">
            ⓘ Phản hồi backend thật · {analysisKind} · Latency{" "}
            {result?.analysis_time_ms ?? "—"} ms · Threat level:{" "}
            {result?.threat_level || "—"}.
          </p>
        )}

        <div className="report-grid">
          <section aria-labelledby="evidence-heading">
            <div className="section-label">
              <span id="evidence-heading">BẰNG CHỨNG CORE TRẢ VỀ</span>
              <b>{findings.length} tín hiệu</b>
            </div>
            <div className="findings">
              {findings.map((finding, index) => (
                <article key={`${finding.title}-${index}`}>
                  <span
                    className={`severity ${finding.severity}`}
                    aria-label={`Tín hiệu ${index + 1}`}
                  >
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <div>
                    <h3>{finding.title}</h3>
                    <p>{finding.detail}</p>
                    <code>{finding.evidence}</code>
                  </div>
                  <em>
                    {finding.severity === "high"
                      ? "CAO"
                      : finding.severity === "low"
                        ? "THẤP/INFO"
                        : "VỪA"}
                  </em>
                </article>
              ))}
            </div>
          </section>
          <aside className="action-plan" aria-labelledby="actions-heading">
            <div className="section-label">
              <span id="actions-heading">HÀNH ĐỘNG ĐỀ XUẤT</span>
            </div>
            <ol>
              <li>
                <b>Không mở liên kết hoặc biểu mẫu</b>
                <p>Đóng trang nếu bạn đã truy cập.</p>
              </li>
              <li>
                <b>Không chia sẻ thông tin</b>
                <p>Không nhập mật khẩu, OTP hay dữ liệu thẻ.</p>
              </li>
              <li>
                <b>Xác minh qua kênh chính thức</b>
                <p>Tự nhập tên miền hoặc gọi số đã xác thực.</p>
              </li>
              <li>
                <b>Chạy Chuyên sâu khi còn nghi ngờ</b>
                <p>
                  Browser sandbox kiểm tra thêm redirect, script và network.
                </p>
              </li>
            </ol>
            <ReportSiteButton
              requestId={!isDemo ? result?.request_id : undefined}
            />
          </aside>
        </div>
        <div className="report-foot">
          <Link href="/analyze">← Phân tích nội dung khác</Link>
          <span>
            Kết quả hỗ trợ quyết định, không thay thế xác minh hoặc đánh giá
            chuyên môn.
          </span>
        </div>
      </main>
    </PrewiseShell>
  );
}

export default function ResultPage() {
  return (
    <Suspense
      fallback={
        <PrewiseShell>
          <main id="main-content" className="analysis-loading" aria-busy="true">
            <p>Đang chuẩn bị báo cáo…</p>
          </main>
        </PrewiseShell>
      }
    >
      <ResultContent />
    </Suspense>
  );
}
