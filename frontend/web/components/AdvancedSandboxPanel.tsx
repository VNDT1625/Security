import type { BrowserSandboxResult, SandboxScanStep, Severity } from "@/lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
    info: "border-neutral-200 bg-neutral-50 text-neutral-700",
    low: "border-blue-200 bg-blue-50 text-blue-900",
    medium: "border-amber-200 bg-amber-50 text-amber-900",
    high: "border-red-200 bg-red-50 text-red-900",
    critical: "border-red-300 bg-red-100 text-red-950",
};

function displayRecord(record: Record<string, unknown>): string {
    return Object.entries(record)
        .filter(([, value]) => value !== null && value !== undefined && value !== "" && value !== 0)
        .map(([key, value]) => `${key}: ${String(value)}`)
        .join(", ");
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
                Quy trinh browser sandbox
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

export default function AdvancedSandboxPanel({
    result,
    loading,
}: {
    result: BrowserSandboxResult | null;
    loading: boolean;
}) {
    if (!loading && result === null) return null;

    const blockedEvents = result?.network_events.filter((event) => event.blocked) ?? [];
    const fieldSummary = result ? displayRecord(result.canary.field_types) : "";

    return (
        <div className="min-w-0 max-w-full overflow-hidden border border-neutral-200 bg-white p-4 sm:p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                    <h3 className="text-base font-semibold text-neutral-900">
                        Browser sandbox nang cao
                    </h3>
                    <p className="mt-1 text-xs text-neutral-500">
                        Chrome co lap, profile tam, chan mang noi bo, dung clone/canary gia.
                    </p>
                </div>
                {loading ? (
                    <span className="text-sm font-medium text-blue-700">Dang chay browser...</span>
                ) : (
                    <span
                        className={`text-sm font-semibold ${result?.ok ? "text-emerald-700" : "text-red-700"}`}
                    >
                        {result?.ok ? "Da co lap xong" : "Chua chay duoc"}
                    </span>
                )}
            </div>

            {!loading && result && (
                <>
                    <dl className="mt-4 grid min-w-0 gap-x-6 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">Trang</dt>
                            <dd className="mt-0.5 font-medium text-neutral-900">
                                {result.status_code ?? "Khong co HTTP"} {result.page_title}
                            </dd>
                        </div>
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">Canary clone</dt>
                            <dd className="mt-0.5 break-all font-medium text-neutral-900">
                                {result.canary.clone_email || "Chua tao"}
                            </dd>
                        </div>
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">Field da bom gia</dt>
                            <dd className="mt-0.5 font-medium text-neutral-900">
                                {result.canary.fields_filled}
                                {fieldSummary ? ` (${fieldSummary})` : ""}
                            </dd>
                        </div>
                        <div className="min-w-0">
                            <dt className="text-xs text-neutral-500">Request bi chan</dt>
                            <dd className="mt-0.5 font-medium text-neutral-900">
                                {blockedEvents.length}
                            </dd>
                        </div>
                    </dl>

                    {result.final_url && (
                        <p className="mt-4 break-all border-t border-neutral-100 pt-4 text-xs text-neutral-500">
                            URL cuoi: {result.final_url}
                        </p>
                    )}

                    <ScanSteps steps={result.scan_steps ?? []} />

                    <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                        <div className="border border-neutral-200 bg-neutral-50 p-3">
                            <p className="font-medium text-neutral-900">Co lap</p>
                            <p className="mt-1 break-words text-xs text-neutral-600">
                                {displayRecord(result.isolation) || "Khong co du lieu"}
                            </p>
                        </div>
                        <div className="border border-neutral-200 bg-neutral-50 p-3">
                            <p className="font-medium text-neutral-900">Canary</p>
                            <p className="mt-1 text-xs text-neutral-600">
                                {result.canary.exfiltration_blocked
                                    ? "Da chan du lieu clone truoc khi roi sandbox."
                                    : "Khong thay du lieu clone bi gui ra ngoai."}
                            </p>
                            {result.canary.form_submissions_blocked > 0 && (
                                <p className="mt-1 break-words text-xs text-neutral-600">
                                    Da chan {result.canary.form_submissions_blocked} lan submit form.
                                </p>
                            )}
                        </div>
                    </div>

                    {blockedEvents.length > 0 && (
                        <div className="mt-4">
                            <h4 className="mb-2 text-xs font-semibold uppercase text-neutral-500">
                                Duong truyen bi chan
                            </h4>
                            <div className="space-y-2">
                                {blockedEvents.slice(0, 5).map((event, index) => (
                                    <div
                                        key={`${event.reason}-${index}`}
                                        className="border border-red-200 bg-red-50 p-3 text-xs text-red-950"
                                    >
                                        <div className="font-medium">{event.reason || "blocked"}</div>
                                        <div className="mt-1 break-all opacity-80">{event.method} {event.url}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <div className="mt-4 space-y-2">
                        {result.issues.length === 0 ? (
                            <p className="border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
                                Khong thay dau hieu OTP/password/exfiltration trong browser sandbox.
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
