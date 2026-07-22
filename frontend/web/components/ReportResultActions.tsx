"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { getApiClient } from "@/lib/api";
import { loadResultRecord } from "@/lib/result-storage";
import type { FeedbackReason, ReportShareExpiry } from "@/lib/types";
import styles from "./ReportResultActions.module.css";

type ShareReportButtonProps = {
  score: number;
  requestId?: string;
};

export function safeSharePayload(score: number, url: string) {
  return {
    title: "Báo cáo an toàn Prewise",
    text: `Prewise ghi nhận mức rủi ro ${Math.round(score)}/100. Liên kết chỉ mở bản tóm tắt đã che dữ liệu nhạy cảm.`,
    url,
  };
}

async function copyToClipboard(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Clipboard unavailable");
}

export function ShareReportButton({ score, requestId }: ShareReportButtonProps) {
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [expiry, setExpiry] = useState<ReportShareExpiry>("24h");
  const [activeShare, setActiveShare] = useState<{ id: string; url: string } | null>(null);
  const storedId = typeof window === "undefined" ? undefined : decodeURIComponent(window.location.pathname.split("/").filter(Boolean).at(-1) || "");
  const storedRequestId = storedId ? loadResultRecord<{ result?: { request_id?: string } }>(storedId)?.result?.request_id : undefined;
  const effectiveRequestId = requestId || storedRequestId;

  async function share() {
    if (busy || !effectiveRequestId) return;
    setBusy(true);
    setStatus("");
    try {
      let portable = activeShare;
      if (!portable) {
        const created = await getApiClient().createReportShare({ requestId: effectiveRequestId, expiresIn: expiry });
        portable = { id: created.id, url: `${window.location.origin}/shared-report/${encodeURIComponent(created.shareToken)}` };
        setActiveShare(portable);
        setStatus("Đã tạo liên kết báo cáo đã che. Bạn có thể chia sẻ hoặc thu hồi liên kết này.");
      }
      const payload = safeSharePayload(score, portable.url);
      if (navigator.share) {
        try {
          await navigator.share(payload);
          setStatus("Đã mở trình chia sẻ an toàn.");
          return;
        } catch (reason) {
          if (reason instanceof DOMException && reason.name === "AbortError") return;
        }
      }
      await copyToClipboard(`${payload.text}\n${payload.url}`);
      setStatus("Đã sao chép liên kết báo cáo đã che.");
    } catch {
      setStatus("Không thể chia sẻ tự động. Liên kết đã tạo vẫn có thể được chia sẻ lại hoặc thu hồi.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (!activeShare || busy) return;
    setBusy(true);
    try {
      await getApiClient().revokeReportShare(activeShare.id);
      setActiveShare(null);
      setStatus("Đã thu hồi liên kết. Người nhận không thể mở liên kết cũ nữa.");
    } catch (failure) {
      setStatus(failure instanceof Error ? failure.message : "Không thể thu hồi liên kết lúc này.");
    } finally {
      setBusy(false);
    }
  }

  return <span className={styles.shareAction}>
    <label className={styles.expiryLabel}>Hết hạn
      <select value={expiry} disabled={busy || Boolean(activeShare)} onChange={(event) => setExpiry(event.target.value as ReportShareExpiry)} aria-label="Thời hạn liên kết chia sẻ">
        <option value="1h">1 giờ</option><option value="24h">24 giờ</option><option value="7d">7 ngày</option>
      </select>
    </label>
    <button type="button" onClick={share} disabled={busy || !effectiveRequestId} aria-describedby={!effectiveRequestId ? "share-report-unavailable" : "share-report-status"} title={!effectiveRequestId ? "Chỉ chia sẻ được kết quả thật có mã từ backend" : undefined}>
      {busy ? "Đang xử lý…" : activeShare ? "↗ Chia sẻ lại" : "↗ Tạo link chia sẻ"}
    </button>
    {activeShare && <button className={styles.revoke} type="button" onClick={revoke} disabled={busy}>Thu hồi</button>}
    <span id="share-report-status" className={styles.srOnly} role="status" aria-live="polite">{status}</span>
    {!effectiveRequestId && <span id="share-report-unavailable" className={styles.srOnly}>Không thể chia sẻ kết quả minh họa hoặc kết quả không có mã lần quét từ backend.</span>}
  </span>;
}

const REASONS: Array<{ value: FeedbackReason; label: string }> = [
  { value: "suspicious_site", label: "Website có dấu hiệu lừa đảo hoặc nguy hiểm" },
  { value: "incorrect_evidence", label: "Bằng chứng hiển thị chưa chính xác" },
  { value: "other", label: "Lý do khác" },
];

export function ReportSiteButton({ requestId }: { requestId?: string }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<FeedbackReason>("suspicious_site");
  const [details, setDetails] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const firstReasonRef = useRef<HTMLInputElement>(null);
  const idempotencyKey = useRef("");

  function close() {
    if (busy) return;
    setOpen(false);
    window.setTimeout(() => triggerRef.current?.focus(), 0);
  }

  function show() {
    if (!requestId) return;
    idempotencyKey.current = globalThis.crypto?.randomUUID?.() ?? `feedback-${requestId}-${Date.now()}`;
    setReason("suspicious_site");
    setDetails("");
    setError("");
    setSubmitted(false);
    setOpen(true);
  }

  useEffect(() => {
    if (!open) return;
    firstReasonRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  // close is intentionally scoped to the current modal state.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, busy]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      if (!requestId) throw new Error("Báo cáo này không có mã lần quét từ backend.");
      await getApiClient().submitFeedback({
        requestId,
        feedbackType: "report_site",
        reason,
        details: details.trim() || undefined,
        idempotencyKey: idempotencyKey.current,
      });
      setSubmitted(true);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Không thể gửi báo cáo lúc này.");
    } finally {
      setBusy(false);
    }
  }

  return <>
    <button ref={triggerRef} type="button" onClick={show} disabled={!requestId} aria-describedby={!requestId ? "report-site-unavailable" : undefined} title={!requestId ? "Chỉ báo cáo được kết quả quét thật có mã từ backend" : undefined}>Báo cáo website ↗</button>
    {!requestId && <span id="report-site-unavailable" className={styles.srOnly}>Không thể báo cáo kết quả minh họa hoặc kết quả không có mã lần quét từ backend.</span>}
    {open && <div className={styles.backdrop} role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}>
      <section className={styles.dialog} role="dialog" aria-modal="true" aria-labelledby="report-site-title" aria-describedby="report-site-description">
        <header>
          <div><span>PHẢN HỒI CỘNG ĐỒNG</span><h2 id="report-site-title">Báo cáo website</h2></div>
          <button type="button" onClick={close} disabled={busy} aria-label="Đóng cửa sổ">×</button>
        </header>
        {submitted ? <div className={styles.success} role="status">
          <strong>Đã nhận báo cáo của bạn</strong>
          <p>Prewise sẽ dùng phản hồi này để xem xét kết quả. Nội dung website không được tự động gửi lại từ trình duyệt.</p>
          <button type="button" onClick={close}>Hoàn tất</button>
        </div> : <form onSubmit={submit}>
          <p id="report-site-description">Chỉ mã lần quét, lý do và phần mô tả bạn chủ động nhập được gửi. Không gửi mật khẩu, OTP hoặc dữ liệu cá nhân.</p>
          <fieldset>
            <legend>Lý do báo cáo</legend>
            {REASONS.map((option, index) => <label key={option.value}>
              <input ref={index === 0 ? firstReasonRef : undefined} type="radio" name="report-reason" value={option.value} checked={reason === option.value} onChange={() => setReason(option.value)} />
              <span>{option.label}</span>
            </label>)}
          </fieldset>
          <label className={styles.details} htmlFor="report-site-details">Mô tả thêm <span>(không bắt buộc)</span></label>
          <textarea id="report-site-details" value={details} onChange={(event) => setDetails(event.target.value.slice(0, 1000))} maxLength={1000} rows={4} placeholder="Mô tả dấu hiệu bạn nhận thấy; không dán dữ liệu nhạy cảm." />
          <small>{details.length}/1000 ký tự</small>
          {error && <p className={styles.error} role="alert">{error}</p>}
          <footer><button type="button" onClick={close} disabled={busy}>Hủy</button><button type="submit" disabled={busy}>{busy ? "Đang gửi…" : "Gửi báo cáo"}</button></footer>
        </form>}
      </section>
    </div>}
  </>;
}
