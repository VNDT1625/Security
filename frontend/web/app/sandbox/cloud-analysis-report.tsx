export type CloudEvidenceChannel = {
    id: "process" | "file" | "registry" | "network" | string;
    status: "observed" | "no_activity" | "unavailable" | "available" | "unknown" | "pending" | string;
    eventCount: number;
};

export type CloudAnalysis = {
    schemaVersion: string;
    outcome:
        | "dangerous"
        | "suspicious"
        | "no_obvious_behavior"
        | "inconclusive"
        | "failed"
        | "pending"
        | string;
    verdict: string;
    riskScore: number | null;
    confidence: number | null;
    confidenceBasis: string | null;
    isConclusive: boolean;
    safetyClaim: string;
    evidenceChannels: CloudEvidenceChannel[];
    missingChannels: string[];
    riskSignals: unknown[];
    recommendedAction: { code: string; label: string };
    cleanup: {
        state: string;
        vmDestroyed: boolean;
        remoteAccessRevoked: boolean;
    };
};

type CloudAnalysisReportProps = {
    analysis?: CloudAnalysis | null;
    phase: string;
    sampleStatus: string;
    summary?: unknown;
};

const OUTCOME_LABELS: Record<string, string> = {
    dangerous: "NGUY HIỂM",
    suspicious: "ĐÁNG NGỜ",
    no_obvious_behavior: "CHƯA GHI NHẬN HÀNH VI RÕ",
    inconclusive: "CHƯA ĐỦ BẰNG CHỨNG",
    failed: "PHÂN TÍCH THẤT BẠI",
    pending: "ĐANG PHÂN TÍCH",
};

const CHANNEL_LABELS: Record<string, string> = {
    process: "Process tree",
    file: "File system",
    registry: "Registry",
    network: "Network",
};

export function cloudOutcomeLabel(outcome?: string | null): string {
    return OUTCOME_LABELS[outcome || "pending"] || "CHƯA ĐỦ BẰNG CHỨNG";
}

export function cloudSafetyExplanation(analysis?: CloudAnalysis | null): string {
    switch (analysis?.outcome) {
        case "dangerous":
            return "Telemetry ghi nhận hành vi nguy hiểm. Không mở hoặc chạy lại mẫu ngoài môi trường cô lập.";
        case "suspicious":
            return "Telemetry ghi nhận hành vi đáng ngờ; cần điều tra thêm trước khi cho phép sử dụng.";
        case "no_obvious_behavior":
            return "Trong cửa sổ quan sát này chưa ghi nhận hành vi rõ; đây không phải chứng nhận file an toàn.";
        case "failed":
            return "Phân tích không hoàn tất. Không được suy ra file an toàn từ một lần chạy thất bại.";
        case "inconclusive":
            return "Bằng chứng chưa đủ hoặc có kênh telemetry không khả dụng; chưa thể kết luận file an toàn.";
        default:
            return "Agent đang thu thập bằng chứng trong Windows VM cô lập.";
    }
}

export function cloudChannelStatus(channel: CloudEvidenceChannel): string {
    if (channel.status === "observed") return `${channel.eventCount} sự kiện`;
    if (channel.status === "no_activity") return "Đã quan sát · không có sự kiện";
    if (channel.status === "unavailable") return "Không khả dụng";
    if (channel.status === "available") return "Đang quan sát";
    if (channel.status === "unknown") return "Không xác định";
    return "Đang chờ";
}

function defaultChannels(sampleStatus: string): CloudEvidenceChannel[] {
    return Object.keys(CHANNEL_LABELS).map((id) => ({
        id,
        status: ["completed", "failed"].includes(sampleStatus) ? "unknown" : "pending",
        eventCount: 0,
    }));
}

export function CloudAnalysisReport({ analysis, phase, sampleStatus, summary }: CloudAnalysisReportProps) {
    const channels = analysis?.evidenceChannels?.length
        ? analysis.evidenceChannels
        : defaultChannels(sampleStatus);
    const action = analysis?.recommendedAction?.label;
    const cleanup = analysis?.cleanup;
    const confidence = typeof analysis?.confidence === "number"
        ? `${Math.round(analysis.confidence * 100)}%`
        : "—";

    return (
        <>
            <div className="auto-report-metrics" aria-label="Kết quả phân tích Windows Cloud">
                <span>
                    <small>KẾT LUẬN</small>
                    <b>{cloudOutcomeLabel(analysis?.outcome)}</b>
                </span>
                <span>
                    <small>ĐIỂM RỦI RO</small>
                    <b>{typeof analysis?.riskScore === "number" ? `${analysis.riskScore}/100` : "—"}</b>
                </span>
                <span>
                    <small>ĐỘ TIN CẬY</small>
                    <b>{confidence}</b>
                </span>
                <span>
                    <small>KÊNH THIẾU</small>
                    <b>{analysis?.missingChannels?.length ?? 0}</b>
                </span>
                <span>
                    <small>DỌN PHIÊN</small>
                    <b>{cleanup?.vmDestroyed ? "VM ĐÃ HỦY" : cleanup?.state?.replaceAll("_", " ") || "ĐANG CHỜ"}</b>
                </span>
            </div>

            <div className="auto-console-body">
                <section className={`auto-state phase-${phase}`}>
                    <span>
                        <small>CURRENT PHASE</small>
                        <h3>{phase.replaceAll("_", " ")}</h3>
                        <p>{cloudSafetyExplanation(analysis)}</p>
                        {action && <strong className="auto-recommended-action">Hành động: {action}</strong>}
                        {!analysis && summary != null && <em className="auto-legacy-summary">{String(summary)}</em>}
                    </span>
                </section>

                <aside className="auto-evidence-status">
                    <small>EVIDENCE CHANNELS</small>
                    {channels.map((channel) => (
                        <span
                            className={channel.status === "observed" ? "observed" : channel.status}
                            key={channel.id}
                        >
                            <i />
                            <b>{CHANNEL_LABELS[channel.id] || channel.id}</b>
                            <em>{cloudChannelStatus(channel)}</em>
                        </span>
                    ))}
                    {cleanup?.remoteAccessRevoked && (
                        <small className="auto-cleanup-proof">Remote access đã thu hồi</small>
                    )}
                </aside>
            </div>
        </>
    );
}
