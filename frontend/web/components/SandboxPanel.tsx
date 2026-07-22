import type { SandboxResult, SandboxScanStep, Severity } from "@/lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
    info: "border-neutral-200 bg-neutral-50 text-neutral-700",
    low: "border-blue-200 bg-blue-50 text-blue-900",
    medium: "border-amber-200 bg-amber-50 text-amber-900",
    high: "border-red-200 bg-red-50 text-red-900",
    critical: "border-red-300 bg-red-100 text-red-950",
};

function displayValue(value: unknown): string {
    if (Array.isArray(value)) return value.join(", ");
    if (typeof value === "number") return value.toString();
    if (typeof value === "string") return value;
    return "";
}

function StepIcon({ status }: { status: SandboxScanStep["status"] }) {
    const passed = status === "passed";
    const failed = status === "failed";
    return (
        <span
            className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[11px] font-bold ${
                passed
                    ? "border-emerald-600 bg-emerald-600 text-white"
                    : failed
                      ? "border-red-600 bg-red-600 text-white"
                      : "border-neutral-300 bg-neutral-100 text-neutral-500"
            }`}
            aria-hidden="true"
        >
            {passed ? "✓" : failed ? "×" : "-"}
        </span>
    );
}

function ScanSteps({ steps }: { steps: SandboxScanStep[] }) {
    if (steps.length === 0) return null;
    return (
        <div className="mt-4 border border-neutral-200 bg-neutral-50 p-3">
            <h4 className="text-xs font-semibold uppercase text-neutral-500">
                Quy trinh quet
            </h4>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
                {steps.map((step) => (
                    <div key={step.key} className="flex gap-2 text-sm">
                        <StepIcon status={step.status} />
                        <div className="min-w-0">
                            <p className="font-medium text-neutral-900">{step.label}</p>
                            {step.detail && (
                                <p className="mt-0.5 break-all text-xs text-neutral-500">
                                    {step.detail}
                                </p>
                            )}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default function SandboxPanel({
    result,
    loading,
}: {
    result: SandboxResult | null;
    loading: boolean;
}) {
    if (!loading && result === null) return null;

    return (
        <div className="min-w-0 max-w-full overflow-hidden border border-neutral-200 bg-white p-4 sm:p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                    <h3 className="text-base font-semibold text-neutral-900">
                        Sandbox trực tiếp
                    </h3>
                    <p className="mt-1 text-xs text-neutral-500">
                        Tiến trình cô lập, chặn mạng nội bộ, giới hạn thời gian và dữ liệu
                    </p>
                </div>
                {loading ? (
                    <span className="text-sm font-medium text-blue-700">Đang mở trang...</span>
                ) : (
                    <span
                        className={`text-sm font-semibold ${result?.ok ? "text-emerald-700" : "text-red-700"}`}
                    >
                        {result?.ok ? "Đã chạy xong" : "Không thể chạy"}
                    </span>
                )}
            </div>

            {!loading && result && (
                <>
                    <dl className="mt-4 grid min-w-0 gap-x-6 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">HTTP</dt>
                            <dd className="mt-0.5 font-medium text-neutral-900">
                                {result.status_code ?? "Không có phản hồi"} {result.http_reason}
                            </dd>
                        </div>
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">IP đã kết nối</dt>
                            <dd className="mt-0.5 break-all font-medium text-neutral-900">
                                {result.resolved_ip || "-"}
                            </dd>
                        </div>
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">Dữ liệu đọc</dt>
                            <dd className="mt-0.5 font-medium text-neutral-900">
                                {result.bytes_read.toLocaleString("vi-VN")} byte
                            </dd>
                        </div>
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">Thời gian</dt>
                            <dd className="mt-0.5 font-medium text-neutral-900">
                                {Math.round(result.elapsed_ms)} ms
                            </dd>
                        </div>
                    </dl>

                    {(result.page_title || result.final_url) && (
                        <div className="mt-4 border-t border-neutral-100 pt-4 text-sm">
                            {result.page_title && (
                                <p className="font-medium text-neutral-900">{result.page_title}</p>
                            )}
                            {result.final_url && (
                                <p className="mt-1 break-all text-xs text-neutral-500">
                                    URL cuối: {result.final_url}
                                </p>
                            )}
                        </div>
                    )}

                    <ScanSteps steps={result.scan_steps ?? []} />

                    {Object.keys(result.page_signals).length > 0 && (
                        <div className="mt-4 flex flex-wrap gap-2">
                            {Object.entries(result.page_signals).map(([key, value]) => {
                                const displayed = displayValue(value);
                                if (!displayed || displayed === "0") return null;
                                return (
                                    <span
                                        key={key}
                                        className="max-w-full break-all border border-neutral-200 bg-neutral-50 px-2.5 py-1 text-xs text-neutral-700"
                                    >
                                        {key}: {displayed}
                                    </span>
                                );
                            })}
                        </div>
                    )}

                    <div className="mt-4 space-y-2">
                        {result.issues.length === 0 ? (
                            <p className="border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
                                Không phát hiện lỗi HTTP, TLS hoặc dấu hiệu nội dung nổi bật.
                            </p>
                        ) : (
                            result.issues.map((issue, index) => (
                                <div
                                    key={`${issue.code}-${index}`}
                                    className={`border p-3 text-sm ${SEVERITY_STYLES[issue.severity]}`}
                                >
                                    <div className="flex min-w-0 flex-col gap-1 sm:flex-row sm:flex-wrap sm:items-baseline sm:justify-between sm:gap-2">
                                        <p className="min-w-0 break-words font-medium">{issue.message}</p>
                                        <code className="break-all text-xs">{issue.code}</code>
                                    </div>
                                    {issue.detail && (
                                        <p className="mt-1 break-all text-xs opacity-80">{issue.detail}</p>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </>
            )}
        </div>
    );
}
