"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { PrewiseShell } from "@/components/PrewiseUI";
import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";
import { canUseProAI } from "@/lib/entitlements";
import { persistResultRecord } from "@/lib/result-storage";
import { fetchWithAnonymousSessionFallback } from "@/lib/auth-session";
import type { GmailMessagePreview, GmailMessageSummary, GmailStatus } from "@/lib/types";
import mobileStyles from "../mobile-pages.module.css";

type Mode = "url" | "email" | "sms";
type Depth = "quick" | "balanced" | "deep" | "pro";
type ApiEvidence = { source: string; message: string; severity: string; feature?: string };
type UrlResponse = { risk_score: number; threat_level: string; analysis_time_ms: number; evidence: ApiEvidence[]; ai_detection: { model_version: string }; score_layers?: unknown[]; deep_analysis_recommended?: boolean; cache_hit?: boolean; cache_status?: "hit" | "miss" | "bypassed" | "refresh" };
const STEPS = ["Chuẩn hóa URL", "Phân tích tên miền và giả mạo", "Đánh giá rủi ro", "Tổng hợp bằng chứng"];
const DEPTH_OPTIONS: Array<{ key: Depth; label: string; badge: string }> = [
  { key: "quick", label: "Nhanh", badge: "Không mở trang" },
  { key: "balanced", label: "Cân bằng", badge: "HTTP sandbox" },
  { key: "deep", label: "Chuyên sâu", badge: "Browser sandbox" },
  { key: "pro", label: "Pro AI", badge: "Browser + AI" },
];

function depthDescription(depth: Depth, mode: Mode): { title: string; detail: string; facts: string[] } {
  if (mode === "url") {
    return {
      quick: { title: "Kiểm tra cấu trúc và nguồn đối chứng", detail: "Không tải HTML và không chạy JavaScript của website.", facts: ["URL, domain, DNS/IP", "Model + Risk Core", "Nhanh nhất"] },
      balanced: { title: "Đọc HTTP/HTML trong tiến trình cô lập", detail: "Kiểm tra redirect, form, nội dung, thanh toán và chính sách; không thực thi JavaScript.", facts: ["Toàn bộ mức Nhanh", "HTTP/HTML sandbox", "Không chạy JS"] },
      deep: { title: "Quan sát website bằng browser sandbox", detail: "Theo dõi JavaScript, network, DOM và hành vi điều hướng với dữ liệu canary; chặn submit thật.", facts: ["Toàn bộ mức Cân bằng", "Browser sandbox", "JS, network, DOM"] },
      pro: { title: "Chuyên sâu kèm AI ngữ cảnh", detail: "Thêm AI có cấu trúc để đối chiếu mục đích trang và ngữ cảnh bạn cung cấp. Yêu cầu gói Pro và dùng AI credit.", facts: ["Toàn bộ mức Chuyên sâu", "AI Evaluate", "Ô ngữ cảnh có hiệu lực"] },
    }[depth];
  }
  return {
    quick: { title: "Chấm nội dung cốt lõi", detail: "Kiểm tra danh tính, ý đồ và tối đa một liên kết nhúng.", facts: ["Risk Core", "1 liên kết", "Nhanh nhất"] },
    balanced: { title: "Mở rộng liên kết và bằng chứng", detail: "Phân tích đầy đủ tối đa hai liên kết nhúng và các trường metadata hiện có.", facts: ["Risk Core", "2 liên kết", "Metadata"] },
    deep: { title: "Điều tra nhiều tín hiệu hơn", detail: "Phân tích đầy đủ tối đa ba liên kết nhúng và tăng phạm vi tệp/metadata nếu có.", facts: ["3 liên kết", "Tệp + metadata", "Không dùng AI context"] },
    pro: { title: "Chuyên sâu kèm AI ngữ cảnh", detail: "AI phân tích ý đồ toàn cục cùng ngữ cảnh bạn cung cấp. Yêu cầu gói Pro và dùng AI credit.", facts: ["Toàn bộ mức Chuyên sâu", "AI Evaluate", "Ô ngữ cảnh có hiệu lực"] },
  }[depth];
}

function gmailSenderQuery(value: string): string {
  const search = value.trim();
  if (!search) return "";
  if (/(?:^|\s)(?:from|to|subject|is|label|in):/i.test(search)) return search;
  return search.includes("@")
    ? `from:${search}`
    : `from:"${search.replace(/["\\]/g, " ")}"`;
}

function AnalyzeContent() {
  const query = useSearchParams();
  const router = useRouter();
  const { plan } = useAuth();
  const [mode, setMode] = useState<Mode>("url");
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [emailFile, setEmailFile] = useState<File | null>(null);
  const [gmailStatus, setGmailStatus] = useState<GmailStatus | null>(null);
  const [gmailMessages, setGmailMessages] = useState<GmailMessageSummary[]>([]);
  const [gmailSelected, setGmailSelected] = useState<GmailMessageSummary | null>(null);
  const [gmailPreview, setGmailPreview] = useState<GmailMessagePreview | null>(null);
  const [gmailPickerOpen, setGmailPickerOpen] = useState(false);
  const [gmailDemoNoticeOpen, setGmailDemoNoticeOpen] = useState(false);
  const [gmailBusy, setGmailBusy] = useState(false);
  const [gmailQuery, setGmailQuery] = useState("");
  const [llmContext, setLlmContext] = useState("");
  const [depth, setDepth] = useState<Depth>("balanced");
  const [scopes, setScopes] = useState({ spoofing: true, sensitive: true, manipulation: true });
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    const signal = query.get("signal");
    if (!signal) return;
    setText(signal);
    if (!/^https?:\/\//i.test(signal) && !/^www\./i.test(signal)) setMode(signal.length <= 180 ? "sms" : "email");
  }, [query]);
  useEffect(() => {
    if (query.get("gmail") !== "connected") return;
    setMode("email");
    void openGmailPicker();
  // OAuth callback marker is stable for the lifetime of this page.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);
  useEffect(() => {
    if (!loading) return;
    const interval = window.setInterval(() => setStep((current) => Math.min(current + 1, STEPS.length - 1)), 650);
    return () => window.clearInterval(interval);
  }, [loading]);
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); void analyze(); }
    };
    addEventListener("keydown", key);
    return () => removeEventListener("keydown", key);
  });

  async function analyze() {
    if (depth === "pro" && !canUseProAI(plan?.tier)) {
      setError("Chế độ Pro AI yêu cầu gói Pro hoặc cao hơn.");
      return;
    }
    const value = text.trim();
    if (!value && !(mode === "email" && (emailFile || gmailSelected))) { setError("Hãy dán nội dung, chọn thư Gmail hoặc tải tệp Email .eml cần kiểm tra."); return; }
    setError(""); setLoading(true); setStep(0);
    try {
      if (mode !== "url") {
        const api = getApiClient();
        const messageMetadata = {
          modality: mode,
          analysis_depth: depth,
          operator_context: depth === "pro" ? llmContext.trim() || undefined : undefined,
          scopes: { spoofing: true, sensitive: true, manipulation: true },
          ...(mode === "email" ? { sender: sender.trim(), subject: subject.trim() } : {}),
        } as const;
        const phoneResult = mode === "sms" && phoneNumber.trim()
          ? await api.assessPhone(phoneNumber.trim(), value, "VN", messageMetadata)
          : null;
        const assessment = mode === "email" && gmailSelected
          ? await api.assessGmailMessage(gmailSelected.id, messageMetadata)
          : mode === "email" && emailFile
          ? await api.assessEmailFile(emailFile, messageMetadata)
          : phoneResult?.assessment ?? await api.assessText(value, messageMetadata);
        const parsedSender = String(assessment.messageMetadata?.sender || assessment.messageMetadata?.from || sender.trim() || "");
        const parsedSubject = String(assessment.messageMetadata?.subject || subject.trim() || "");
        const record = {
          id: crypto.randomUUID(), type: mode, content: value || (gmailSelected ? `Gmail: ${gmailSelected.subject}` : `Email file: ${emailFile?.name}`),
          analysisDepth: depth,
          llmContext: depth === "pro" ? llmContext.trim() || undefined : undefined,
          sender: parsedSender || undefined, subject: parsedSubject || undefined,
          emailFilename: emailFile?.name,
          gmailMessageId: gmailSelected?.id,
          phoneNumber: phoneNumber.trim() || undefined,
          phoneIntelligence: phoneResult ? {
            provider: phoneResult.provider,
            provider_status: phoneResult.providerStatus,
            reputation: phoneResult.reputation,
            metadata: phoneResult.metadata,
          } : undefined,
          score: assessment.score, date: new Date().toISOString(), findings: assessment.evidence,
          isDemo: false, dataSource: "backend",
          result: {
            risk_score: assessment.score / 100,
            risk_level: assessment.riskLevel,
            confidence: assessment.confidence,
            reasons: assessment.reasons,
            evidence: assessment.evidence,
            model_version: assessment.modelVersion,
            latency_ms: assessment.latencyMs,
            request_id: assessment.requestId,
            analysis_coverage: assessment.analysisCoverage,
            message_metadata: assessment.messageMetadata,
            embedded_url_assessments: assessment.embeddedUrlAssessments,
            contextual_analysis: assessment.contextualAnalysis,
            risk_core: assessment.riskCore,
          },
        };
        persistResultRecord(record.id, record);
        router.push(`/result/${record.id}?score=${record.score}&type=${mode}&demo=0`);
        return;
      }
      const forceRescan = query.get("force_rescan") === "1";
      const response = await fetchWithAnonymousSessionFallback("/api/demo/url/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: value, deep_analysis: depth !== "quick", advanced_analysis: depth === "deep" || depth === "pro", llm_context: depth === "pro" ? llmContext.trim() || undefined : undefined, ai_context: depth === "pro" ? "on" : "off", force_rescan: forceRescan }),
      });
      const data = await response.json() as UrlResponse & { detail?: string };
      if (!response.ok) throw new Error(data.detail || "Máy chủ không thể phân tích URL này.");
      const normalizedScore = data.risk_score <= 1 ? data.risk_score * 100 : data.risk_score;
      const record = { id: crypto.randomUUID(), type: "url", content: value, analysisDepth: depth, llmContext: depth === "pro" ? llmContext.trim() || undefined : undefined, score: Math.round(normalizedScore), date: new Date().toISOString(), findings: data.evidence, isDemo: false, dataSource: "backend", result: data };
      persistResultRecord(record.id, record);
      router.push(`/result/${record.id}?score=${record.score}&type=url&demo=0`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không thể kết nối dịch vụ phân tích."); }
    finally { setLoading(false); }
  }

  async function openGmailPicker(search = "", demoAccessConfirmed = false) {
    setGmailBusy(true); setError("");
    try {
      const api = getApiClient();
      const status = await api.getGmailStatus();
      setGmailStatus(status);
      if (!status.configured) { setError("Gmail OAuth chưa được cấu hình trên máy chủ."); return; }
      if (!status.connected) {
        if (!demoAccessConfirmed) {
          setGmailDemoNoticeOpen(true);
          return;
        }
        const { authUrl } = await api.connectGmail();
        window.location.assign(authUrl);
        return;
      }
      setGmailDemoNoticeOpen(false);
      setGmailMessages(await api.listGmailMessages(gmailSenderQuery(search)));
      setGmailPickerOpen(true);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không thể mở Gmail."); }
    finally { setGmailBusy(false); }
  }

  async function selectGmailMessage(message: GmailMessageSummary) {
    setGmailBusy(true); setError("");
    try {
      const preview = await getApiClient().getGmailMessagePreview(message.id);
      setGmailSelected(message);
      setGmailPreview(preview);
      setEmailFile(null);
      setSender(preview.from);
      setSubject(preview.subject);
      setText(preview.body);
      setGmailPickerOpen(false);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không thể tải nội dung thư Gmail."); }
    finally { setGmailBusy(false); }
  }

  async function disconnectGmail() {
    setGmailBusy(true); setError("");
    try {
      await getApiClient().disconnectGmail();
      setGmailStatus({ configured: true, connected: false, address: "", status: "not_connected" });
      setGmailMessages([]); setGmailSelected(null); setGmailPreview(null); setGmailPickerOpen(false);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không thể ngắt Gmail."); }
    finally { setGmailBusy(false); }
  }

  const depthInfo = depthDescription(depth, mode);

  return <PrewiseShell><main id="main-content" className={`workspace ${mobileStyles.analyze}`}>
    <section className="editor-pane" aria-labelledby="analysis-title">
      <div className="pane-head"><div><span className="crumb">WORKSPACE / NEW ANALYSIS</span><h1 id="analysis-title">Phân tích tín hiệu</h1></div><span className="saved">● BACKEND · Phân tích thật</span></div>
      <div className="mode-tabs" role="tablist" aria-label="Loại nội dung">{(["url", "email", "sms"] as Mode[]).map((item) => <button type="button" role="tab" aria-selected={mode === item} onClick={() => { setMode(item); setText(""); setEmailFile(null); setGmailSelected(null); setGmailPreview(null); setError(""); }} className={mode === item ? "active" : ""} key={item}>{item === "url" ? "Website / URL" : item === "email" ? "Email" : "SMS / Tin nhắn"}</button>)}</div>
      {mode === "email" && <><div className="message-meta email-meta" aria-label="Thông tin email"><button type="button" onClick={() => void openGmailPicker()} disabled={gmailBusy}>{gmailBusy ? "Đang tải Gmail…" : gmailStatus?.connected ? `Gmail · ${gmailStatus.address}` : "Chọn từ Gmail"}</button><label className="eml-picker">Tải Email .eml<input type="file" accept=".eml,.rfc822,message/rfc822" onChange={(event) => { setEmailFile(event.target.files?.[0] || null); setGmailSelected(null); setGmailPreview(null); setError(""); }} /><span>{emailFile ? emailFile.name : "Chọn tệp RFC822/MIME"}</span></label><label>Người gửi<input value={gmailSelected?.from || sender} disabled={Boolean(gmailSelected)} onChange={(event) => setSender(event.target.value)} placeholder="Ví dụ: Ngân hàng <alert@example.com>" /></label><label>Chủ đề<input value={gmailSelected?.subject || subject} disabled={Boolean(gmailSelected)} onChange={(event) => setSubject(event.target.value)} placeholder="Chủ đề email" /></label></div>{gmailDemoNoticeOpen && !gmailStatus?.connected && <section className="demo-disclosure" role="dialog" aria-labelledby="gmail-demo-title" aria-describedby="gmail-demo-description"><span className="demo-badge">GMAIL · DEMO</span><p><b id="gmail-demo-title">Gmail của bạn cần thuộc danh sách người dùng thử nghiệm</b></p><p id="gmail-demo-description">Dự án đang ở giai đoạn demo nên Google chỉ cho phép những địa chỉ Gmail đã được nhóm phát triển phê duyệt trước. Nếu tài khoản chưa có trong danh sách, Google sẽ chặn kết nối; đây không phải lỗi tài khoản hay lỗi hệ thống.</p><p>Hãy liên hệ nhóm demo để được thêm Gmail, hoặc tiếp tục nếu bạn đã được xác nhận quyền thử nghiệm.</p><div className="account-actions"><button type="button" className="secondary" onClick={() => setGmailDemoNoticeOpen(false)}>Đóng</button><button type="button" onClick={() => { setGmailDemoNoticeOpen(false); void openGmailPicker("", true); }}>Tôi đã được cấp quyền — tiếp tục</button></div></section>}{gmailPreview && <div className="gmail-preview-note"><b>Đang xem thư Gmail thật ở chế độ an toàn</b><span>{gmailPreview.linksRemoved ? `${gmailPreview.linksRemoved} liên kết đã bị vô hiệu hóa` : "Không có liên kết cần vô hiệu hóa"} · {gmailPreview.attachments.length} tệp đính kèm</span></div>}{gmailPickerOpen && <section className="gmail-picker" aria-label="Chọn thư Gmail"><header><div><b>{gmailQuery.trim() ? `${gmailMessages.length} kết quả theo người gửi` : `${gmailMessages.length}/30 email gần nhất`}</b><span>{gmailStatus?.address}</span></div><span className="gmail-picker-actions"><button type="button" onClick={() => { setGmailQuery(""); void openGmailPicker(""); }} disabled={gmailBusy}>30 thư gần nhất</button><button type="button" onClick={() => void disconnectGmail()} disabled={gmailBusy}>Ngắt Gmail</button><button type="button" onClick={() => setGmailPickerOpen(false)} aria-label="Đóng">×</button></span></header><form onSubmit={(event) => { event.preventDefault(); void openGmailPicker(gmailQuery); }}><input value={gmailQuery} onChange={(event) => setGmailQuery(event.target.value)} placeholder="Tên hoặc địa chỉ người gửi, ví dụ an@gmail.com" /><button type="submit" disabled={gmailBusy}>Tìm người gửi</button></form><div>{gmailMessages.length ? gmailMessages.map((message) => <button type="button" className={gmailSelected?.id === message.id ? "selected" : ""} onClick={() => void selectGmailMessage(message)} disabled={gmailBusy} key={message.id}><b>{message.subject || "(Không có chủ đề)"}</b><span>{message.from}</span><p>{message.snippet}</p><small>{message.date ? new Date(message.date).toLocaleString("vi-VN") : message.labelIds.join(" · ")}</small></button>) : <p>Không tìm thấy thư từ người gửi này.</p>}</div></section>}</>}
      {mode === "sms" && <div className="message-meta sms-meta" aria-label="Thông tin số gửi"><label>Số điện thoại gửi (không bắt buộc)<input inputMode="tel" autoComplete="tel" value={phoneNumber} onChange={(event) => setPhoneNumber(event.target.value)} placeholder="Ví dụ: +84 912 345 678" /></label><p>Nếu nhập số, hệ thống sẽ kiểm tra thêm nhà mạng, loại số và uy tín khi nguồn dữ liệu được cấu hình.</p></div>}
      <div className="editor-area"><div className="line-nos" aria-hidden>01<br />02<br />03<br />04<br />05<br />06</div><div className="input-stack"><label htmlFor="analysis-input">Nội dung cần kiểm tra</label><textarea id="analysis-input" autoFocus value={text} disabled={loading} onChange={(event) => { setText(event.target.value); setError(""); }} placeholder={mode === "url" ? "Ví dụ: https://example.com/verify" : mode === "email" ? "Dán toàn bộ nội dung hoặc mã HTML của email…" : "Dán một tin hoặc cả chuỗi hội thoại SMS…"} aria-describedby={`input-safety input-processing${error ? " input-error" : ""}`} aria-invalid={Boolean(error)} /><p id="input-safety" className="input-safety"><b>Không dán mật khẩu, mã OTP, mã khôi phục hoặc dữ liệu tài chính bí mật.</b></p><details id="input-processing" className="data-processing"><summary>Cách Prewise xử lý dữ liệu</summary><p>{mode === "url" ? "URL được gửi đến Security Gateway để phân tích thật; chế độ Chuyên sâu có thể dùng sandbox cô lập." : "Nội dung được chấm bằng bộ tiêu chí riêng; mọi liên kết nhìn thấy hoặc ẩn trong HTML đều được đưa qua bộ kiểm tra website. Nguồn không khả dụng sẽ được ghi rõ, không được coi là an toàn."}</p></details>{error && <p id="input-error" className="form-error" role="alert">⚠ {error}</p>}</div></div>
      <div className="editor-status"><span>{text.length} ký tự</span><span>UTF-8 &nbsp; • &nbsp; Tiếng Việt / English</span></div>{loading && <div className="editor-status" aria-live="polite"><span>Đang kiểm tra: {STEPS[step]}</span><span>{step + 1}/{STEPS.length} · {Math.round(((step + 1) / STEPS.length) * 100)}%</span></div>}
    </section>
    <aside className="inspector"><div className="inspector-head"><span>CẤU HÌNH ĐÁNH GIÁ</span><b aria-hidden>⌁</b></div>
      <div className="config-group"><span className="group-label">Phạm vi phân tích</span><div className="check-row"><span><label className="check-box locked" aria-label="Dấu hiệu lừa đảo"><input type="checkbox" checked disabled /><i aria-hidden>✓</i></label>Dấu hiệu lừa đảo</span></div>{([ ["spoofing", "Độ tin cậy & giả mạo"], ["sensitive", "Dữ liệu nhạy cảm"], ["manipulation", "Thao túng & thúc ép"] ] as const).map(([key, label]) => { const locked = mode !== "url"; const checked = locked || scopes[key]; return <div className="check-row" key={key}><span><label className={`check-box ${locked ? "locked" : ""}`} aria-label={`${locked ? "Luôn bật" : "Bật hoặc tắt"} ${label}`}><input type="checkbox" checked={checked} disabled={locked} onChange={(event) => setScopes({ ...scopes, [key]: event.target.checked })} /><i aria-hidden>{checked ? "✓" : ""}</i></label>{label}</span></div>; })}{mode !== "url" && <p>Ba lớp an toàn luôn bật cho Email/SMS để không bỏ sót tín hiệu nghiêm trọng.</p>}</div>
      <fieldset className="config-group depth-config"><legend>Mức độ phân tích</legend><div className="segments">{DEPTH_OPTIONS.map((option) => { const locked = option.key === "pro" && !canUseProAI(plan?.tier); return <button type="button" aria-pressed={depth === option.key} className={depth === option.key ? "active" : ""} disabled={locked} onClick={() => setDepth(option.key)} title={locked ? "Yêu cầu gói Pro hoặc cao hơn" : option.badge} key={option.key}><span>{option.label}</span><small>{locked ? "Cần gói Pro" : option.badge}</small></button>; })}</div>{!canUseProAI(plan?.tier) && <p>Pro AI dành cho gói trả phí. <Link href="/account/billing">Xem các gói →</Link></p>}<div className="depth-explainer" aria-live="polite"><b>{depthInfo.title}</b><p>{depthInfo.detail}</p><div>{depthInfo.facts.map((fact) => <span key={fact}>✓ {fact}</span>)}</div></div></fieldset>
      {depth === "pro" && <div className="llm-context"><div className="llm-context-head"><label htmlFor="llm-context">Ngữ cảnh cho Pro AI</label><span>Chỉ dùng ở Pro AI</span></div><textarea id="llm-context" value={llmContext} disabled={loading} maxLength={2000} onChange={(event) => setLlmContext(event.target.value)} placeholder={mode === "url" ? "Ví dụ: Trang này được gửi để đăng ký giải đấu và yêu cầu chuyển khoản…" : "Ví dụ: Đây là đối tác mới; người gửi nói đã gọi xác nhận…"} aria-describedby="llm-context-help" /><p id="llm-context-help">AI dùng thông tin này như dữ liệu tham khảo, không coi đó là chỉ dẫn và không được phép tự thay đổi quyết định của Risk Core.</p></div>}
      <div className="analyze-action"><button type="button" disabled={(!text.trim() && !(mode === "email" && (emailFile || gmailSelected))) || loading} onClick={() => void analyze()} aria-describedby="scan-shortcut">{loading ? <><span className="spinner" aria-hidden />{STEPS[step]}…</> : <>Phân tích nội dung <span aria-hidden>→</span></>}</button><small id="scan-shortcut">Ctrl/⌘ + Enter</small>{mode === "url" && query.get("force_rescan") === "1" && <small role="status">Quét lại được bật: bỏ qua kết quả cache cho lần này.</small>}<span className="sr-only" role="status" aria-live="polite">{loading ? `Đang phân tích: ${STEPS[step]}` : ""}</span></div>
    </aside>
  </main></PrewiseShell>;
}

export default function AnalyzePage() {
  return <Suspense fallback={<PrewiseShell><main id="main-content" className="analysis-loading" aria-busy="true"><p>Đang mở không gian phân tích…</p></main></PrewiseShell>}><AnalyzeContent /></Suspense>;
}
