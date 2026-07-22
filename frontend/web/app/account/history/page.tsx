"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import RiskBadge from "@/components/RiskBadge";
import { getApiClient } from "@/lib/api";
import { persistResultRecord } from "@/lib/result-storage";
import type { ScanRecord, ScanRecordDetail } from "@/lib/types";

type Filter = "all" | "URL" | "Email" | "SMS";

export default function AccountHistoryPage(): JSX.Element {
  const router = useRouter();
  const [records, setRecords] = useState<ScanRecord[] | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  function load() {
    setRecords(null);
    setError("");
    void getApiClient().getScanHistory()
      .then(setRecords)
      .catch((reason) => {
        setRecords([]);
        setError(reason instanceof Error ? reason.message : "Không thể tải lịch sử tài khoản.");
      });
  }

  useEffect(load, []);

  async function fetchDetail(record: ScanRecord): Promise<ScanRecordDetail> {
    setBusy(record.id);
    setError("");
    setNotice("");
    try {
      return await getApiClient().getScanHistoryDetail(record.id);
    } finally {
      setBusy(null);
    }
  }

  async function reopen(record: ScanRecord) {
    try {
      const detail = await fetchDetail(record);
      const localId = `server-${detail.id}`;
      const evidence = detail.evidence ?? [];
      persistResultRecord(localId, {
        id: localId,
        type: detail.modality === "text" ? "email" : detail.modality,
        content: detail.target || "Nội dung đã được che",
        score: detail.score,
        date: detail.createdAt,
        findings: evidence,
        isDemo: false,
        dataSource: "account-history",
        result: {
          request_id: detail.id,
          risk_score: detail.score / 100,
          risk_level: detail.riskLevel,
          decision: detail.decision,
          confidence: (detail.confidence ?? 0) / 100,
          reasons: detail.reasons,
          evidence,
          model_version: detail.modelVersion,
          latency_ms: detail.latencyMs,
          schema_version: detail.schemaVersion,
          scoring_version: detail.scoringVersion,
          risk_core: detail.riskCore,
        },
      });
      router.push(`/result/${encodeURIComponent(localId)}?score=${detail.score}&type=${detail.modality}&demo=0`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể mở lại báo cáo.");
    }
  }

  async function exportJson(record: ScanRecord) {
    try {
      const detail = await fetchDetail(record);
      const blob = new Blob([JSON.stringify(detail, null, 2)], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `prewise-report-${detail.id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setNotice("Đã xuất báo cáo JSON an toàn.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể xuất báo cáo.");
    }
  }

  async function remove(record: ScanRecord) {
    if (!window.confirm(`Xóa vĩnh viễn lượt quét ${record.id}?`)) return;
    setBusy(record.id);
    setError("");
    try {
      await getApiClient().deleteScanHistory(record.id);
      setRecords((current) => current?.filter((item) => item.id !== record.id) ?? []);
      setExpanded((current) => current === record.id ? null : current);
      setNotice("Đã xóa lượt quét khỏi tài khoản.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể xóa lượt quét.");
    } finally {
      setBusy(null);
    }
  }

  async function clearAll() {
    if (!records?.length || !window.confirm("Xóa vĩnh viễn toàn bộ lịch sử tài khoản? Thao tác này không thể hoàn tác.")) return;
    setBusy("all");
    setError("");
    try {
      const result = await getApiClient().clearScanHistory();
      setRecords([]);
      setExpanded(null);
      setNotice(`Đã xóa ${result.deleted} lượt quét khỏi tài khoản.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể xóa lịch sử tài khoản.");
    } finally {
      setBusy(null);
    }
  }

  const shown = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase("vi");
    return (records ?? []).filter((record) => {
      if (filter !== "all" && record.type !== filter) return false;
      if (!needle) return true;
      return `${record.id} ${record.target ?? ""} ${record.type} ${record.decision ?? ""}`
        .toLocaleLowerCase("vi").includes(needle);
    });
  }, [filter, query, records]);

  return <div className="account-page account-history-page">
    <header><span>ACCOUNT / SCAN HISTORY</span><h1>Lịch sử tài khoản</h1><p>Các lần quét đã đồng bộ từ máy chủ, kèm quyết định và bằng chứng an toàn để tra cứu.</p></header>
    <div className="filter-row">
      <div className="search">⌕ <input aria-label="Tìm lịch sử" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Tìm đích, mã yêu cầu hoặc quyết định…" /></div>
      {(["all", "URL", "Email", "SMS"] as Filter[]).map((value) => <button type="button" className={filter === value ? "active" : ""} onClick={() => setFilter(value)} key={value}>{value === "all" ? "Tất cả" : value}</button>)}
      <button type="button" disabled={!records?.length || busy !== null} onClick={() => void clearAll()}>Xóa toàn bộ</button>
    </div>
    {error && <div className="form-error" role="alert"><b>Không tải được lịch sử.</b> {error} <button type="button" onClick={load}>Thử lại</button></div>}
    {notice && <div className="form-success" role="status">{notice}</div>}
    {records === null ? <div className="key-skeleton">Đang tải lịch sử…</div> : !error && shown.length === 0 ? <div className="empty-state"><div className="empty-radar">⌁</div><h2>{records.length ? "Không tìm thấy kết quả" : "Chưa có lịch sử scan"}</h2><p>{records.length ? "Hãy thử từ khóa hoặc bộ lọc khác." : "Các lần phân tích bằng tài khoản này sẽ xuất hiện tại đây."}</p><Link className="primary" href="/analyze">Bắt đầu phân tích →</Link></div> : <div className="account-history-list">
      {shown.map((record) => {
        const open = expanded === record.id;
        return <article key={record.id} className={open ? "expanded" : ""}>
          <button type="button" className="account-history-summary" aria-expanded={open} onClick={() => setExpanded(open ? null : record.id)}>
            <span className="history-icon">{record.type === "URL" ? "↗" : record.type === "Email" ? "✉" : "▤"}</span>
            <span><b>{record.target || "Nội dung đã được ẩn"}</b><small>{record.timestamp} · {record.type} · {record.id}</small></span>
            <RiskBadge score={record.score} showScore />
            <em>{open ? "Thu gọn" : "Chi tiết"}</em>
          </button>
          {open && <div className="account-history-detail">
            <div className="scan-meta"><div><span>Quyết định</span><strong>{record.decision || record.riskLevel}</strong></div><div><span>Độ tin cậy</span><strong>{record.confidence ?? "—"}%</strong></div><div><span>Model</span><strong>{record.modelVersion || "—"}</strong></div><div><span>Bằng chứng</span><strong>{record.evidence?.length ?? 0}</strong></div></div>
            <div className="account-history-actions">
              <button type="button" disabled={busy === record.id} onClick={() => void reopen(record)}>{busy === record.id ? "Đang xử lý…" : "Mở báo cáo đầy đủ"}</button>
              <button type="button" disabled={busy === record.id} onClick={() => void exportJson(record)}>Xuất JSON</button>
              <button type="button" disabled={busy === record.id} onClick={() => void remove(record)}>Xóa bản ghi</button>
            </div>
            <div className="findings">{record.evidence?.length ? record.evidence.map((item, index) => <article key={`${item.source}-${index}`}><span className={`severity ${["critical", "high"].includes(item.severity) ? "high" : ["low", "info"].includes(item.severity) ? "low" : "medium"}`}>{String(index + 1).padStart(2, "0")}</span><div><h3>{item.feature || item.source}</h3><p>{item.message}</p><code>{item.source}</code></div><em>{item.severity.toUpperCase()}</em></article>) : <p>Không có bằng chứng rủi ro được lưu cho lần quét này.</p>}</div>
          </div>}
        </article>;
      })}
    </div>}
  </div>;
}
