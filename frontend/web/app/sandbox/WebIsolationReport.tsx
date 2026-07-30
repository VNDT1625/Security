import type { BrowserSandboxResult } from "@/lib/types";

import styles from "./WebIsolationReport.module.css";
import { summarizeWebIsolation } from "./web-isolation-report";

export interface WebIsolationReportProps {
    result: BrowserSandboxResult & { risk_core?: Record<string, unknown> | null };
}

export function WebIsolationReport({ result }: WebIsolationReportProps) {
    const report = summarizeWebIsolation(result);

    return (
        <section className={styles.report} data-tone={report.tone} aria-label="Kết quả Web Isolation">
            <header className={styles.header}>
                <div>
                    <span className={styles.eyebrow}>KẾT LUẬN</span>
                    <strong>{report.conclusion}</strong>
                    <p>{report.target}</p>
                </div>
                <div className={styles.score} aria-label={report.riskScore == null ? "Backend chưa trả điểm rủi ro" : `Điểm rủi ro ${report.riskScore} trên 100`}>
                    <span>Điểm rủi ro</span>
                    <b>{report.riskScore == null ? "—" : `${report.riskScore}/100`}</b>
                    {report.confidence != null && <small>Tin cậy {report.confidence}%</small>}
                </div>
            </header>

            <div
                className={styles.identity}
                data-first-party={report.identity.firstParty ? "true" : "false"}
            >
                <span>{report.identity.label}</span>
                <p>{report.identity.detail}</p>
            </div>

            <dl className={styles.metrics} aria-label="Thông tin lần kiểm tra">
                <div>
                    <dt>HTTP</dt>
                    <dd>{report.statusCode ?? "—"}</dd>
                </div>
                <div>
                    <dt>Thời gian</dt>
                    <dd>{report.elapsedMs > 0 ? `${report.elapsedMs} ms` : "—"}</dd>
                </div>
                <div>
                    <dt>Phạm vi</dt>
                    <dd>Browser cô lập + Risk Core</dd>
                </div>
            </dl>

            <div className={styles.section}>
                <h3>Bằng chứng chính</h3>
                {report.evidence.length > 0 ? (
                    <ul className={styles.evidence}>
                        {report.evidence.map((item) => (
                            <li key={item.id} data-severity={item.severity}>
                                <span>{item.channel}</span>
                                <div><b>{item.title}</b><small>{item.detail}</small></div>
                            </li>
                        ))}
                    </ul>
                ) : <p>Backend chưa trả bằng chứng quan sát được.</p>}
            </div>

            <div className={styles.columns}>
                <div className={styles.section}>
                    <h3>Kênh còn thiếu</h3>
                    <ul>{report.missingChannels.map((item) => <li key={item}>{item}</li>)}</ul>
                </div>
                <div className={styles.section}>
                    <h3>Hành động đề xuất</h3>
                    <ol>{report.actions.map((item) => <li key={item}>{item}</li>)}</ol>
                </div>
            </div>
        </section>
    );
}
