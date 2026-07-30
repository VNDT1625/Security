import type { ExeProviderResult, ExeSandboxResult } from "@/lib/types";

export type QuickExeSelectionReset = {
    file: File | null;
    result: null;
    shareWithProvider: false;
    providerPolling: false;
};

/**
 * A provider upload consent is bound to one exact file selection. Selecting a
 * different file must fail closed instead of inheriting consent or stale data.
 */
export function resetQuickExeSelection(file?: File | null): QuickExeSelectionReset {
    return {
        file: file ?? null,
        result: null,
        shareWithProvider: false,
        providerPolling: false,
    };
}

export function quickExeVerdictLabel(verdict: ExeSandboxResult["verdict"]): string {
    if (verdict === "dangerous") return "NGUY HIỂM";
    if (verdict === "suspicious") return "ĐÁNG NGỜ";
    if (verdict === "no_obvious_theft_detected") {
        return "CHƯA PHÁT HIỆN DẤU HIỆU RÕ";
    }
    return "CHƯA ĐỦ DỮ LIỆU";
}

export function quickExeProviderLabel(provider?: ExeProviderResult): string {
    if (!provider?.configured || provider.status === "disabled") {
        return "Chưa cấu hình · chỉ có kết quả cục bộ";
    }
    if (provider.status === "not_found") return "Hash chưa có trong dữ liệu provider";
    if (provider.status === "queued") return `Đang quét ${provider.progress}%`;
    if (provider.status === "failed") return "Provider không trả được kết quả";
    if (provider.total_engines > 0) {
        return `${provider.detected_engines}/${provider.total_engines} engine phát hiện`;
    }
    return "Đã nhận báo cáo provider";
}

export function quickExeEvidence(result: ExeSandboxResult): string[] {
    const candidates = [
        ...result.issues,
        ...(result.local_analysis?.anomalies ?? []),
    ];
    return [...new Set(candidates.map((item) => item.trim()).filter(Boolean))].slice(0, 6);
}

export function ExeQuickReport({
    result,
    polling,
    onShare,
    onRefresh,
    onOpenAuto,
    onOpenInteractive,
}: {
    result: ExeSandboxResult;
    polling: boolean;
    onShare?: () => void;
    onRefresh?: () => void;
    onOpenAuto?: () => void;
    onOpenInteractive?: () => void;
}) {
    const provider = result.provider;
    const local = result.local_analysis;
    const evidence = quickExeEvidence(result);

    return (
        <div className={`exe-quick-report verdict-${result.verdict}`}>
            <div className="exe-report-head">
                <span>{quickExeVerdictLabel(result.verdict)}</span>
                <strong aria-label={`Kết luận: ${quickExeVerdictLabel(result.verdict)}`}>{
                    result.verdict === "dangerous" ? "⛔" : result.verdict === "suspicious" ? "⚠" : "✓"
                }</strong>
            </div>

            <p className="exe-report-file">{result.filename}</p>
            <code title={result.sha256}>SHA-256 · {result.sha256}</code>

            {local && (
                <div className="exe-report-metrics">
                    <span>
                        <small>PE</small>
                        <b>{local.valid ? `${local.format} · ${local.architecture}` : "Không hợp lệ"}</b>
                    </span>
                    <span>
                        <small>SECTION</small>
                        <b>{local.section_count}</b>
                    </span>
                    <span>
                        <small>CHỮ KÝ</small>
                        <b>{local.signature_present ? "Có · chưa xác minh" : "Không có"}</b>
                    </span>
                    <span>
                        <small>OVERLAY</small>
                        <b>{local.overlay_bytes.toLocaleString("vi-VN")} B</b>
                    </span>
                </div>
            )}

            <div className="exe-provider-row">
                <span>
                    <small>PROVIDER</small>
                    <b>{quickExeProviderLabel(provider)}</b>
                </span>
                {polling && <i>Đang chờ báo cáo…</i>}
            </div>

            {provider?.error && <p className="exe-provider-error">{provider.error}</p>}
            {onRefresh && provider?.data_id && !polling && provider.status === "queued" && (
                <button className="exe-refresh-button" type="button" onClick={onRefresh}>
                    Cập nhật báo cáo provider
                </button>
            )}

            {result.upload_consent_required && onShare && (
                <button className="exe-share-button" type="button" onClick={onShare}>
                    Đồng ý gửi đúng mẫu này để kiểm tra sâu
                </button>
            )}

            <small className="exe-report-disclaimer">
                Giới hạn: Test nhanh chỉ phân tích tĩnh và không thực thi file. Điểm thấp chỉ có
                nghĩa là chưa thấy chỉ báo rõ trong dữ liệu hiện có, không xác nhận file vô hại.
            </small>

            {evidence.length > 0 ? (
                <ul className="exe-issue-list" aria-label="Bằng chứng tĩnh">
                    {evidence.map((item) => (
                        <li key={item}>{item}</li>
                    ))}
                </ul>
            ) : (
                <small className="exe-report-disclaimer">
                    Bằng chứng tĩnh: Chưa có chỉ báo nổi bật trong các kênh đã kiểm tra.
                </small>
            )}

            {provider?.detections && provider.detections.length > 0 && (
                <div className="exe-detections" aria-label="Phát hiện từ provider">
                    {provider.detections.slice(0, 5).map((item) => (
                        <span key={`${item.engine}-${item.threat}`}>
                            <b>{item.engine}</b>
                            <small>{item.threat}</small>
                        </span>
                    ))}
                </div>
            )}

            {(onOpenAuto || onOpenInteractive) && (
                <div className="local-shield-handoff">
                    <span>
                        <b>HÀNH ĐỘNG ĐỀ XUẤT</b>
                        <small>Chạy trong Windows VM để quan sát process, file, registry và network.</small>
                    </span>
                    {onOpenAuto && (
                        <button type="button" onClick={onOpenAuto}>
                            Phân tích tự động
                        </button>
                    )}
                    {onOpenInteractive && (
                        <button type="button" onClick={onOpenInteractive}>
                            Điều tra tương tác
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}
