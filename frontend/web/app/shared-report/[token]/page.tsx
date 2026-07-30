"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PrewiseShell } from "@/components/PrewiseUI";
import { getApiClient } from "@/lib/api";
import { getRiskLevelForContext } from "@/lib/risk";
import type { PublicReportShare } from "@/lib/types";
import styles from "./shared-report.module.css";

function expiryLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Không xác định" : new Intl.DateTimeFormat("vi-VN", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export default function SharedReportPage() {
  const { token } = useParams<{ token: string }>();
  const [share, setShare] = useState<PublicReportShare | null>(null);
  const [error, setError] = useState("");
  const displayLevel = getRiskLevelForContext(
    share?.snapshot.decision,
    share?.snapshot.riskLevel,
    share?.snapshot.score ?? 0,
  );

  useEffect(() => {
    if (!token) return;
    let active = true;
    getApiClient().getPublicReportShare(token)
      .then((value) => { if (active) setShare(value); })
      .catch((failure) => { if (active) setError(failure instanceof Error && failure.message.includes("410") ? "Liên kết báo cáo đã hết hạn." : "Liên kết không tồn tại, đã hết hạn hoặc đã bị thu hồi."); });
    return () => { active = false; };
  }, [token]);

  return <PrewiseShell><main id="main-content" className={styles.page}>
    <header><span>PREWISE · SHARED SAFETY REPORT</span><h1>Bản tóm tắt báo cáo đã che</h1><p>Trang công khai này chỉ chứa kết luận và bằng chứng đã được lọc. Nội dung gốc, URL đích, danh tính người gửi và thông tin bí mật không được công khai.</p></header>
    {!share && !error && <section className={styles.state} aria-busy="true"><p>Đang kiểm tra liên kết chia sẻ…</p></section>}
    {error && <section className={styles.state} role="alert"><h2>Không thể mở báo cáo</h2><p>{error}</p></section>}
    {share && <>
      <section className={styles.overview} aria-label="Tổng quan báo cáo">
        <div><span>MỨC RỦI RO</span><strong>{displayLevel.icon} {displayLevel.label}</strong></div>
        <div><span>KẾT LUẬN</span><h2>{displayLevel.label}</h2><p>Độ tin cậy {share.snapshot.confidence}% · Loại {share.snapshot.type.toUpperCase()}</p></div>
      </section>
      <section className={styles.evidence} aria-labelledby="shared-evidence-title"><div><span id="shared-evidence-title">BẰNG CHỨNG ĐÃ LỌC</span><b>{share.snapshot.evidence.length} tín hiệu</b></div>{share.snapshot.evidence.length ? share.snapshot.evidence.map((item, index) => <article key={`${item.source}-${index}`}><i>{String(index + 1).padStart(2, "0")}</i><div><h3>{item.feature || item.source}</h3><p>{item.message}</p><small>{item.source} · {item.severity}</small></div></article>) : <p>Không có bằng chứng công khai trong bản tóm tắt này.</p>}</section>
      <footer><span>Liên kết tự hết hạn: {expiryLabel(share.expiresAt)}</span><b>Không dùng báo cáo này thay cho xác minh chuyên môn.</b></footer>
    </>}
  </main></PrewiseShell>;
}
