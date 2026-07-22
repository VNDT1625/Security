"use client";

import Image from "next/image";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import {
    Activity,
    CheckCircle2,
    Clock3,
    Cloud,
    FileWarning,
    Globe2,
    Maximize2,
    Minimize2,
    MonitorPlay,
    MousePointer2,
    RotateCcw,
    ShieldCheck,
    Timer,
    X,
    Zap,
} from "lucide-react";

import { PrewiseShell } from "@/components/PrewiseUI";
import { getApiClient } from "@/lib/api";
import { readStoredAccessToken } from "@/lib/auth-session";
import type {
    BrowserSandboxResult,
    ExeProviderResult,
    ExeSandboxResult,
} from "@/lib/types";
import {
    REMOTE_IFRAME_SANDBOX_POLICY,
    buildSessionCreatePayload,
    formatLeaseCountdown,
    labActionState,
    leaseDeadline,
    remainingLeaseSeconds,
    resolveSandboxMode,
    resolveSandboxPhase,
    safeRemoteConnectUrl,
    selectDisplayedSession,
    timelineState,
} from "./session-ui";
import type { SandboxLeaseMinutes, SandboxMode } from "./session-ui";

type View = "lab" | "sandbox";
type Tier = "free" | "pro" | "max";
type CloudSession = {
    id: string;
    tier: Tier;
    status: string;
    remoteUrl: string | null;
    expiresAt: string;
    mode?: SandboxMode | null;
    phase?: string | null;
    leaseMinutes?: SandboxLeaseMinutes | number | null;
    readyAt?: string | null;
    leaseExpiresAt?: string | null;
    remoteAccessExpiresAt?: string | null;
    interactiveAvailable?: boolean | null;
    remoteAvailable?: boolean | null;
    remoteStatus?: string | null;
    remoteUnavailableReason?: string | null;
    cleanupState?: string | null;
    error: string | null;
    sample: {
        filename: string | null;
        sha256: string | null;
        size: number | null;
        status: string;
        report: Record<string, unknown>;
    };
};
type SandboxPayment = {
    orderId: string;
    reference: string;
    amountVnd: number;
    credits: number;
    expiresAt: string | null;
    bankAccount: string;
    bankName: string;
    accountName: string;
    transferContent: string;
    qrUrl: string;
    status: "pending" | "paid" | "expired" | string;
};

type FreeBrowserEvent = {
    id: string;
    type:
        | "input_substituted"
        | "form_submission_attempt"
        | "canary_submission"
        | "download_blocked"
        | "private_network_blocked";
    severity: "info" | "medium" | "high";
    title: string;
    message: string;
    destination?: string | null;
    filename?: string;
    replacement?: string;
    blocked?: boolean;
};
type FreeBrowser = {
    url: string;
    title: string;
    image: string;
    width: number;
    height: number;
    protection: {
        canaryEnabled: boolean;
        realInputSent: boolean;
        downloadBlockingEnabled: boolean;
        submissionsObserved: number;
        downloadsBlocked: number;
    };
    events: FreeBrowserEvent[];
    lastEvent: FreeBrowserEvent | null;
};
type CloudStatus = {
    accountTier: Tier;
    credits: number;
    availableTiers: Array<{
        tier: Tier;
        web: boolean;
        exe: boolean;
        gpu: boolean;
        minutes: number;
        provider: string;
        creditCost: number;
        allowed: boolean;
        configured: boolean;
    }>;
    cloudConfigured: boolean;
    freeConfigured: boolean;
    session: CloudSession | null;
    recentSession?: CloudSession | null;
};

type RemoteAccess = {
    connectUrl?: string | null;
    remoteUrl?: string | null;
    accessToken?: string | null;
    tokenExpiresAt?: string | null;
    leaseExpiresAt?: string | null;
};

type TimelineItem = {
    id: string;
    label: string;
    detail: string;
};

const API = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000").replace(
    /\/$/,
    "",
);

const AUTO_TIMELINE: TimelineItem[] = [
    {
        id: "provisioning",
        label: "Khởi tạo VM",
        detail: "Tạo Windows VM dùng một lần và cô lập mạng.",
    },
    {
        id: "ready",
        label: "Agent sẵn sàng",
        detail: "Máy đã sẵn sàng nhận đúng một mẫu kiểm tra.",
    },
    {
        id: "sample_staged",
        label: "Đưa mẫu vào vùng cách ly",
        detail: "Xác thực file và chuyển mẫu bằng kênh phiên tạm thời.",
    },
    {
        id: "running",
        label: "Quan sát hành vi",
        detail: "Theo dõi process, file, registry và network có sẵn.",
    },
    {
        id: "completed",
        label: "Tổng hợp bằng chứng",
        detail: "Đưa telemetry về Risk Core và chuẩn bị hủy VM.",
    },
];

const INTERACTIVE_TIMELINE: TimelineItem[] = [
    {
        id: "provisioning",
        label: "Khởi tạo VM",
        detail: "Cấp Windows VM riêng và chính sách egress giới hạn.",
    },
    {
        id: "ready",
        label: "Desktop sẵn sàng",
        detail: "Lease chỉ bắt đầu sau khi backend xác nhận trạng thái ready.",
    },
    {
        id: "sample_staged",
        label: "Đưa mẫu vào vùng cách ly",
        detail: "File được đặt trong VM, chưa chạy trên thiết bị của bạn.",
    },
    {
        id: "interactive",
        label: "Điều tra trực tiếp",
        detail: "Điều khiển desktop qua gateway phiên tạm thời.",
    },
    {
        id: "completed",
        label: "Thu bằng chứng & hủy",
        detail: "Khóa input, lưu báo cáo rồi tiêu hủy môi trường.",
    },
];

function phaseTimelineIndex(
    phase: string,
    mode: SandboxMode,
    remoteConnected: boolean,
): number {
    if ([
        "destroying",
        "destroyed",
        "termination_requested",
        "terminating",
        "terminated",
        "expired",
        "completed",
        "cleanup_failed",
    ].includes(phase)) {
        return 4;
    }
    if (["collecting"].includes(phase)) return 4;
    if (["running", "executing"].includes(phase)) return 3;
    if (["sample_staged", "queued", "delivered", "staged"].includes(phase)) return 2;
    if (mode === "interactive" && remoteConnected) return 3;
    if (phase === "ready") return 1;
    return 0;
}

function reportArrayLength(report: Record<string, unknown>, keys: string[]): number {
    for (const key of keys) {
        const value = report[key];
        if (Array.isArray(value)) return value.length;
    }
    return 0;
}

function remoteUnavailableLabel(reason?: string | null): string {
    if (!reason) return "Gateway điều khiển chưa trả về một URL phiên hợp lệ.";
    if (reason === "auto_mode_agent_only") {
        return "Auto Analyze là phiên agent-only và không mở desktop điều khiển.";
    }
    if (reason === "remote_broker_not_configured") {
        return "Remote broker chưa được quản trị viên cấu hình.";
    }
    if (reason === "interactive_mode_disabled") {
        return "Chế độ Interactive đang bị tắt trên hạ tầng hiện tại.";
    }
    return reason.replaceAll("_", " ");
}

async function cloudRequest<T>(path: string, init?: RequestInit): Promise<T> {
    const token = readStoredAccessToken();
    let response: Response;
    try {
        response = await fetch(`${API}/v1/sandbox-cloud${path}`, {
            ...init,
            headers: {
                "Content-Type": "application/json",
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
        });
    } catch {
        throw new Error(
            "Mất kết nối tới Sandbox backend. Hãy kiểm tra backend cổng 8000 rồi thử lại.",
        );
    }
    if (!response.ok) {
        throw new Error(
            (await response.json().catch(() => null))?.detail ||
                `Lỗi Sandbox ${response.status}`,
        );
    }
    return response.json() as Promise<T>;
}

function wait(milliseconds: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function formatMoney(amount: number): string {
    return `${new Intl.NumberFormat("vi-VN").format(amount)}đ`;
}

function verdictForScore(score: number): ExeSandboxResult["verdict"] {
    if (score >= 75) return "dangerous";
    if (score >= 35) return "suspicious";
    return "no_obvious_theft_detected";
}

function verdictLabel(verdict: ExeSandboxResult["verdict"]): string {
    if (verdict === "dangerous") return "NGUY HIỂM";
    if (verdict === "suspicious") return "ĐÁNG NGỜ";
    if (verdict === "no_obvious_theft_detected") return "CHƯA THẤY DẤU HIỆU RÕ";
    return "CHƯA XÁC ĐỊNH";
}

function providerStatusLabel(provider?: ExeProviderResult): string {
    if (!provider?.configured || provider.status === "disabled") {
        return "Chưa cấu hình · chỉ phân tích cục bộ";
    }
    if (provider.status === "not_found") return "Hash chưa có kết quả";
    if (provider.status === "queued") return `Đang quét ${provider.progress}%`;
    if (provider.status === "failed") return "Không lấy được kết quả";
    if (provider.total_engines > 0) {
        return `${provider.detected_engines}/${provider.total_engines} engine phát hiện`;
    }
    return "Đã nhận báo cáo provider";
}

function mergeProviderResult(
    current: ExeSandboxResult,
    provider: ExeProviderResult,
): ExeSandboxResult {
    const localScore = current.local_analysis?.risk_score ?? current.risk_score;
    const score = Math.max(localScore, provider.risk_score);
    const providerIssue =
        provider.detected_engines > 0
            ? `${provider.detected_engines}/${provider.total_engines || "?"} engine phát hiện tệp.`
            : null;
    const mergedProvider = {
        ...provider,
        sample_shared: Boolean(current.provider?.sample_shared || provider.sample_shared),
    };
    return {
        ...current,
        provider: mergedProvider,
        execution_status: provider.status === "queued" ? "queued" : "completed",
        risk_score: score,
        verdict: current.ok ? verdictForScore(score) : "unknown",
        issues:
            providerIssue && !current.issues.includes(providerIssue)
                ? [...current.issues, providerIssue]
                : current.issues,
    };
}

export default function SandboxPage() {
    const [view, setView] = useState<View>("lab");
    const [url, setUrl] = useState("https://example.com");
    const [busy, setBusy] = useState(false);
    const [webBusy, setWebBusy] = useState(false);
    const [exeBusy, setExeBusy] = useState(false);
    const [error, setError] = useState("");
    const [web, setWeb] = useState<BrowserSandboxResult | null>(null);
    const [exe, setExe] = useState<ExeSandboxResult | null>(null);
    const [exeFile, setExeFile] = useState<File | null>(null);
    const [shareExe, setShareExe] = useState(false);
    const [providerPolling, setProviderPolling] = useState(false);
    const [cloud, setCloud] = useState<CloudStatus | null>(null);
    const [payment, setPayment] = useState<SandboxPayment | null>(null);
    const [paymentCredits, setPaymentCredits] = useState(1);
    const [paymentBusy, setPaymentBusy] = useState(false);
    const [selected, setSelected] = useState<Tier>("free");
    const [labMode, setLabMode] = useState<SandboxMode>("auto");
    const [leaseMinutes, setLeaseMinutes] = useState<SandboxLeaseMinutes>(5);
    const [remoteAccess, setRemoteAccess] = useState<RemoteAccess | null>(null);
    const [remoteBusy, setRemoteBusy] = useState(false);
    const [remoteError, setRemoteError] = useState("");
    const [clockNow, setClockNow] = useState(() => Date.now());
    const [freeBrowser, setFreeBrowser] = useState<FreeBrowser | null>(null);
    const [freeUrl, setFreeUrl] = useState("https://example.com");
    const [sandboxText, setSandboxText] = useState("");
    const [expanded, setExpanded] = useState(false);
    const [cloudExeFile, setCloudExeFile] = useState<File | null>(null);
    const [cloudExeConsent, setCloudExeConsent] = useState(false);
    const [cloudExeUploading, setCloudExeUploading] = useState(false);
    const typingBuffer = useRef("");
    const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    const typingPromise = useRef<Promise<void> | null>(null);
    const actionQueue = useRef<Promise<void>>(Promise.resolve());
    const providerPollGeneration = useRef(0);

    async function refresh() {
        try {
            const value = await cloudRequest<CloudStatus>("/status");
            setCloud(value);
            if (value.session) {
                setSelected(value.session.tier);
                setLabMode(resolveSandboxMode(value.session));
                if (value.session.leaseMinutes === 5 || value.session.leaseMinutes === 10) {
                    setLeaseMinutes(value.session.leaseMinutes);
                }
            }
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        }
    }

    useEffect(() => {
        if (view === "sandbox") void refresh();
    }, [view]);

    const provisioning = cloud?.session?.status === "provisioning";
    useEffect(() => {
        if (!provisioning) return;
        const timer = setInterval(() => void refresh(), 3000);
        return () => clearInterval(timer);
    }, [provisioning]);

    const sampleProcessing = ["queued", "delivered", "staging", "running", "collecting"].includes(
        cloud?.session?.sample.status ?? "",
    );
    useEffect(() => {
        if (!sampleProcessing) return;
        const timer = setInterval(() => void refresh(), 2000);
        return () => clearInterval(timer);
    }, [sampleProcessing]);

    const cleanupPending = ["termination_requested", "terminating"].includes(
        cloud?.session?.status ?? "",
    );
    useEffect(() => {
        if (!cleanupPending) return;
        const timer = setInterval(() => void refresh(), 2000);
        return () => clearInterval(timer);
    }, [cleanupPending]);

    const paymentOrderId = payment?.orderId;
    const paymentStatus = payment?.status;
    useEffect(() => {
        if (!paymentOrderId || paymentStatus !== "pending") return;
        const timer = setInterval(async () => {
            try {
                const next = await cloudRequest<SandboxPayment>(`/payments/${paymentOrderId}`);
                setPayment(next);
                if (next.status === "paid") await refresh();
            } catch {
                // Giữ QR hiện tại; người dùng vẫn có thể hoàn tất chuyển khoản.
            }
        }, 4000);
        return () => clearInterval(timer);
    }, [paymentOrderId, paymentStatus]);

    async function createCreditPayment() {
        setPaymentBusy(true);
        setError("");
        try {
            setPayment(
                await cloudRequest<SandboxPayment>("/payments", {
                    method: "POST",
                    body: JSON.stringify({ credits: paymentCredits }),
                }),
            );
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setPaymentBusy(false);
        }
    }

    async function startSession() {
        if (cloud?.session) return;
        setBusy(true);
        setError("");
        try {
            const created = await cloudRequest<CloudSession>("/sessions", {
                method: "POST",
                body: JSON.stringify(
                    buildSessionCreatePayload(selected, labMode, leaseMinutes),
                ),
            });
            await refresh();
            if (created.tier === "free") {
                setFreeBrowser(
                    await cloudRequest<FreeBrowser>(`/sessions/${created.id}/browser`),
                );
            }
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setBusy(false);
        }
    }

    const activeSession = cloud?.session ?? null;
    const recentSession = cloud?.recentSession ?? null;
    const session = selectDisplayedSession(activeSession, recentSession);
    const showingRecentSession = !activeSession && Boolean(recentSession);
    const sessionMode = resolveSandboxMode(session);
    const sessionPhase = resolveSandboxPhase(session);
    const sessionReady = activeSession?.status === "ready";
    // A remote desktop URL is trusted only when it comes from the explicit,
    // one-time access request triggered by the user's connect button. Never
    // auto-open a legacy URL embedded in a session/status response.
    const remoteCandidate = remoteAccess?.connectUrl || remoteAccess?.remoteUrl || null;
    const remoteUrl =
        sessionReady && sessionMode === "interactive"
            ? safeRemoteConnectUrl(
                  remoteCandidate,
                  typeof window === "undefined" ? "https://prewise.local" : window.location.origin,
              )
            : null;
    const effectiveLeaseDeadline =
        remoteAccess?.leaseExpiresAt || leaseDeadline(activeSession);
    const leaseSeconds = remainingLeaseSeconds(effectiveLeaseDeadline, clockNow);
    const remoteTokenSeconds = remainingLeaseSeconds(remoteAccess?.tokenExpiresAt, clockNow);
    const remoteWaitingForSample = Boolean(
        activeSession &&
            sessionMode === "interactive" &&
            (activeSession.remoteStatus === "staging" ||
                ["sample_required", "sample_staging"].includes(
                    activeSession.remoteUnavailableReason || "",
                )),
    );
    const remoteExplicitlyUnavailable = Boolean(
        activeSession &&
            sessionMode === "interactive" &&
            !remoteWaitingForSample &&
            (activeSession.remoteAvailable === false ||
                activeSession.interactiveAvailable === false ||
                ["failed", "unavailable", "disabled"].includes(
                    activeSession.remoteStatus || "",
                )),
    );
    const timeline = sessionMode === "interactive" ? INTERACTIVE_TIMELINE : AUTO_TIMELINE;
    const timelineIndex = phaseTimelineIndex(sessionPhase, sessionMode, Boolean(remoteUrl));
    const selectedTierInfo = cloud?.availableTiers.find((item) => item.tier === selected);
    const selectedCreditCost = selectedTierInfo?.creditCost ?? 0;
    const lacksCredits = selected !== "free" && (cloud?.credits ?? 0) < selectedCreditCost;
    const sampleVerdict = session?.sample.report.verdict;
    const sampleAlreadySubmitted = Boolean(
        activeSession &&
            activeSession.tier !== "free" &&
            activeSession.sample.status !== "none",
    );
    const report = session?.sample.report ?? {};
    const reportMetrics = {
        processes: reportArrayLength(report, ["process_tree", "processes"]),
        files: reportArrayLength(report, ["file_events", "files"]),
        registry: reportArrayLength(report, ["registry_events", "registry"]),
        network: reportArrayLength(report, ["network_events", "network_connections"]),
    };
    const labActions = labActionState(webBusy, exeBusy);

    useEffect(() => {
        setRemoteAccess(null);
        setRemoteError("");
    }, [activeSession?.id]);

    useEffect(() => {
        if (!sessionReady || !effectiveLeaseDeadline) return;
        setClockNow(Date.now());
        const timer = setInterval(() => setClockNow(Date.now()), 1000);
        return () => clearInterval(timer);
    }, [sessionReady, effectiveLeaseDeadline]);

    const remotePending = Boolean(
        sessionReady &&
            activeSession &&
            sessionMode === "interactive" &&
            !remoteUrl &&
            activeSession.remoteStatus &&
            ["pending", "provisioning", "starting", "staging"].includes(
                activeSession.remoteStatus,
            ) &&
            (activeSession.remoteStatus !== "staging" ||
                activeSession.sample.status !== "none"),
    );
    useEffect(() => {
        if (!remotePending) return;
        const timer = setInterval(() => void refresh(), 2000);
        return () => clearInterval(timer);
    }, [remotePending]);

    function freeAction(path: string, body: object): Promise<void> {
        if (!activeSession) return Promise.resolve();
        const run = async () => {
            setBusy(true);
            setError("");
            try {
                setFreeBrowser(
                    await cloudRequest<FreeBrowser>(
                        `/sessions/${activeSession.id}/browser/${path}`,
                        { method: "POST", body: JSON.stringify(body) },
                    ),
                );
            } catch (caught) {
                setError(caught instanceof Error ? caught.message : String(caught));
            } finally {
                setBusy(false);
            }
        };
        const pending = actionQueue.current.then(run, run);
        actionQueue.current = pending.catch(() => undefined);
        return pending;
    }

    async function stopSession() {
        if (!cloud?.session) return;
        setBusy(true);
        try {
            await cloudRequest(`/sessions/${cloud.session.id}`, { method: "DELETE" });
            setExpanded(false);
            setFreeBrowser(null);
            setRemoteAccess(null);
            setRemoteError("");
            await refresh();
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setBusy(false);
        }
    }

    async function openRemoteDesktop() {
        if (!activeSession || sessionMode !== "interactive" || !sessionReady) return;
        setRemoteBusy(true);
        setRemoteError("");
        try {
            const access = await cloudRequest<RemoteAccess>(
                `/sessions/${activeSession.id}/remote-access`,
                { method: "POST", body: "{}" },
            );
            const candidate = access.connectUrl || access.remoteUrl;
            const checked = safeRemoteConnectUrl(candidate, window.location.origin);
            if (!checked) {
                throw new Error(
                    "Remote gateway không trả về HTTPS URL hợp lệ; desktop không được mở.",
                );
            }
            setRemoteAccess({ ...access, connectUrl: checked });
        } catch (caught) {
            setRemoteError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setRemoteBusy(false);
        }
    }

    async function uploadCloudExecutable() {
        if (!activeSession || !cloudExeFile || !cloudExeConsent || sampleAlreadySubmitted) {
            return;
        }
        const token = readStoredAccessToken();
        const form = new FormData();
        form.set("file", cloudExeFile);
        form.set("consent", "true");
        setCloudExeUploading(true);
        setError("");
        try {
            const response = await fetch(`${API}/v1/sandbox-cloud/sessions/${activeSession.id}/exe`, {
                method: "POST",
                headers: token ? { Authorization: `Bearer ${token}` } : {},
                body: form,
            });
            if (!response.ok) throw new Error((await response.json().catch(() => null))?.detail || "Không thể gửi mẫu vào Cloud Sandbox");
            await refresh();
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setCloudExeUploading(false);
        }
    }

    async function scanUrl() {
        setWebBusy(true);
        setError("");
        setWeb(null);
        try {
            setWeb(await getApiClient().browserSandboxUrl(url));
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setWebBusy(false);
        }
    }

    async function pollExeProvider(dataId: string) {
        const generation = ++providerPollGeneration.current;
        const delays = [10_000, 20_000, 30_000, 30_000, 30_000, 30_000];
        setProviderPolling(true);
        try {
            for (const delay of delays) {
                await wait(delay);
                if (generation !== providerPollGeneration.current) return;
                const provider = await getApiClient().getExecutableProviderReport(dataId);
                if (generation !== providerPollGeneration.current) return;
                setExe((current) => (current ? mergeProviderResult(current, provider) : current));
                if (provider.status !== "queued") return;
            }
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            if (generation === providerPollGeneration.current) setProviderPolling(false);
        }
    }

    async function refreshExeProvider(dataId: string) {
        providerPollGeneration.current += 1;
        setProviderPolling(true);
        setError("");
        let continuePolling = false;
        try {
            const provider = await getApiClient().getExecutableProviderReport(dataId);
            setExe((current) => (current ? mergeProviderResult(current, provider) : current));
            continuePolling = provider.status === "queued";
            if (continuePolling) void pollExeProvider(dataId);
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            if (!continuePolling) setProviderPolling(false);
        }
    }

    async function scanExe(file?: File, shareWithProvider = shareExe) {
        if (!file) return;
        providerPollGeneration.current += 1;
        setProviderPolling(false);
        setExeFile(file);
        setExe(null);
        setExeBusy(true);
        setError("");
        try {
            const result = await getApiClient().sandboxExecutable(file, shareWithProvider);
            setExe(result);
            if (result.provider?.status === "queued" && result.provider.data_id) {
                void pollExeProvider(result.provider.data_id);
            }
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
            setExeBusy(false);
        }
    }

    function flushSandboxTyping(): Promise<void> {
        if (typingTimer.current) {
            clearTimeout(typingTimer.current);
            typingTimer.current = null;
        }
        if (typingPromise.current) return typingPromise.current;
        const hasText = typingBuffer.current.length > 0;
        typingBuffer.current = "";
        if (!hasText) return Promise.resolve();
        const pending = freeAction("type", { text: "*" }).finally(() => {
            typingPromise.current = null;
            typingBuffer.current = "";
        });
        typingPromise.current = pending;
        return pending;
    }

    function queueSandboxTyping(text: string) {
        typingBuffer.current += text;
        if (typingPromise.current || typingTimer.current) return;
        typingTimer.current = setTimeout(() => {
            typingTimer.current = null;
            void flushSandboxTyping();
        }, 60);
    }

    function handleSandboxKey(event: ReactKeyboardEvent<HTMLDivElement>) {
        if (event.ctrlKey || event.metaKey || event.altKey) return;
        if (event.key.length === 1) {
            event.preventDefault();
            queueSandboxTyping(event.key);
            return;
        }
        if (event.key === "Backspace" && typingBuffer.current) {
            event.preventDefault();
            typingBuffer.current = typingBuffer.current.slice(0, -1);
            return;
        }
        const allowed = [
            "Enter",
            "Escape",
            "Tab",
            "Backspace",
            "ArrowUp",
            "ArrowDown",
            "ArrowLeft",
            "ArrowRight",
            "PageUp",
            "PageDown",
        ];
        if (allowed.includes(event.key)) {
            event.preventDefault();
            void flushSandboxTyping().then(() => freeAction("key", { key: event.key }));
        }
    }

    useEffect(() => {
        if (
            activeSession?.tier === "free" &&
            activeSession.status === "ready" &&
            !freeBrowser
        ) {
            cloudRequest<FreeBrowser>(`/sessions/${activeSession.id}/browser`)
                .then(setFreeBrowser)
                .catch(() => undefined);
        }
    }, [activeSession?.id, activeSession?.status, activeSession?.tier, freeBrowser]);

    useEffect(() => {
        if (!expanded) return;
        const collapse = (event: KeyboardEvent) => {
            if (event.key === "Escape") setExpanded(false);
        };
        window.addEventListener("keydown", collapse);
        return () => window.removeEventListener("keydown", collapse);
    }, [expanded]);

    useEffect(
        () => () => {
            if (typingTimer.current) clearTimeout(typingTimer.current);
            providerPollGeneration.current += 1;
        },
        [],
    );

    return (
        <PrewiseShell>
            <main
                id="main-content"
                className={`sandbox-page ${freeBrowser ? "sandbox-page-live" : ""}`}
            >
                <header className="sandbox-toolbar">
                    <div>
                        <span>ISOLATED ENVIRONMENT</span>
                        <b>
                            {view === "lab"
                                ? "Quick Scan & Browser Lab"
                                : "Windows Cloud Lab · Auto + Interactive"}
                        </b>
                    </div>
                    <div className="sandbox-status">
                        <i />
                        {cloud
                            ? `${cloud.accountTier.toUpperCase()} · ${cloud.credits} lượt`
                            : "Phiên cô lập"}
                    </div>
                    <button
                        onClick={() => {
                            setWeb(null);
                            setExe(null);
                            setError("");
                            void refresh();
                        }}
                    >
                        <RotateCcw />Làm mới
                    </button>
                </header>

                <nav className="sandbox-subtabs">
                    <button
                        className={view === "lab" ? "active" : ""}
                        onClick={() => setView("lab")}
                    >
                        <ShieldCheck />1. Lab<small>Tự động kiểm tra</small>
                    </button>
                    <button
                        className={view === "sandbox" ? "active" : ""}
                        onClick={() => setView("sandbox")}
                    >
                        <MonitorPlay />2. Windows Cloud<small>Tự động + điều khiển có thời hạn</small>
                    </button>
                </nav>

                {view === "lab" ? (
                    <section className="live-sandbox-grid">
                        <article className="live-sandbox-card">
                            <Globe2 />
                            <h2>Mở website thật</h2>
                            <form
                                onSubmit={(event) => {
                                    event.preventDefault();
                                    void scanUrl();
                                }}
                            >
                                <input value={url} onChange={(event) => setUrl(event.target.value)} />
                                <button disabled={labActions.web.disabled}>
                                    {labActions.web.label}
                                </button>
                            </form>
                            {web && (
                                <div className="sandbox-report">
                                    <strong>
                                        {web.canary.exfiltration_blocked
                                            ? "PHÁT HIỆN RÒ RỈ"
                                            : "HOÀN TẤT"}
                                    </strong>
                                    <p>{web.page_title || web.final_url}</p>
                                </div>
                            )}
                        </article>

                        <article className="live-sandbox-card exe-lab-card">
                            <FileWarning />
                            <h2>Test nhanh EXE</h2>
                            <p className="exe-lab-intro">
                                Phân tích cấu trúc PE và hash mà không chạy tệp. Provider bên ngoài
                                chỉ nhận mẫu khi bạn chủ động đồng ý.
                            </p>
                            <label className="exe-picker">
                                <input
                                    type="file"
                                    accept=".exe,application/vnd.microsoft.portable-executable"
                                    disabled={labActions.exe.disabled}
                                    onClick={(event) => {
                                        event.currentTarget.value = "";
                                    }}
                                    onChange={(event) => void scanExe(event.target.files?.[0])}
                                />
                                {labActions.exe.label}
                            </label>
                            <label className="exe-provider-consent">
                                <input
                                    type="checkbox"
                                    checked={shareExe}
                                    onChange={(event) => setShareExe(event.target.checked)}
                                />
                                <span>
                                    Cho phép gửi mẫu tới MetaDefender nếu hash chưa có kết quả.
                                </span>
                            </label>
                            <small className="exe-privacy-note">
                                Mặc định tắt. Không bật với file nội bộ, riêng tư hoặc chưa công bố.
                            </small>
                            {exe && (
                                <ExeQuickReport
                                    result={exe}
                                    polling={providerPolling}
                                    onShare={
                                        exeFile
                                            ? () => {
                                                  setShareExe(true);
                                                  void scanExe(exeFile, true);
                                              }
                                            : undefined
                                    }
                                    onRefresh={
                                        exe.provider?.data_id
                                            ? () =>
                                                  void refreshExeProvider(
                                                      exe.provider?.data_id as string,
                                                  )
                                            : undefined
                                    }
                                />
                            )}
                            <div className="local-shield-handoff">
                                <Cloud />
                                <span>
                                    <b>LOCAL SHIELD → CLOUD LAB</b>
                                    <small>
                                        Local Shield sàng lọc file trên máy trước. Khi còn nghi ngờ,
                                        gửi chính mẫu đó vào Windows VM dùng một lần để Auto Analyze
                                        hoặc điều tra tương tác.
                                    </small>
                                </span>
                                <button
                                    type="button"
                                    onClick={() => {
                                        if (exeFile) {
                                            setCloudExeFile(exeFile);
                                            setCloudExeConsent(false);
                                        }
                                        setSelected("pro");
                                        setLabMode("auto");
                                        setView("sandbox");
                                    }}
                                >
                                    {exeFile ? "Chuyển file sang Cloud Lab" : "Mở Windows Cloud Lab"}
                                </button>
                            </div>
                        </article>
                    </section>
                ) : (
                    <>
                        {!activeSession && (
                            <section className="cloud-lab-command" id="cloud-lab-setup">
                                <header>
                                    <div>
                                        <small>WINDOWS CLOUD LAB / DUAL MODE</small>
                                        <h1>Chọn cách điều tra file đáng ngờ</h1>
                                        <p>
                                            Cùng một Windows VM dùng một lần, cùng Risk Core và cùng
                                            báo cáo bằng chứng. Chỉ khác ai điều khiển phiên phân tích.
                                        </p>
                                    </div>
                                    <div className="cloud-lab-safety">
                                        <ShieldCheck />
                                        <span>
                                            <b>Không chạy trên máy của bạn</b>
                                            <small>VM bị hủy khi hoàn tất hoặc hết lease.</small>
                                        </span>
                                    </div>
                                </header>
                                <div className="lab-mode-grid" role="radiogroup" aria-label="Chế độ Windows Cloud Lab">
                                    <button
                                        type="button"
                                        role="radio"
                                        aria-checked={labMode === "auto"}
                                        className={labMode === "auto" ? "selected" : ""}
                                        onClick={() => setLabMode("auto")}
                                    >
                                        <Zap />
                                        <span>
                                            <small>AUTO / AGENT-DRIVEN</small>
                                            <strong>Auto Analyze</strong>
                                            <p>
                                                Agent tự đưa mẫu vào VM, chạy có giám sát, thu telemetry
                                                và trả báo cáo nhanh.
                                            </p>
                                        </span>
                                        <em>Mặc định</em>
                                    </button>
                                    <button
                                        type="button"
                                        role="radio"
                                        aria-checked={labMode === "interactive"}
                                        className={labMode === "interactive" ? "selected" : ""}
                                        onClick={() => {
                                            setLabMode("interactive");
                                            if (selected === "free") setSelected("pro");
                                        }}
                                    >
                                        <MousePointer2 />
                                        <span>
                                            <small>INTERACTIVE / HUMAN-IN-THE-LOOP</small>
                                            <strong>Interactive Investigate</strong>
                                            <p>
                                                Điều khiển desktop cô lập qua remote gateway trong đúng
                                                lượt 5 hoặc 10 phút.
                                            </p>
                                        </span>
                                        <em>PRO / MAX</em>
                                    </button>
                                </div>
                                {labMode === "interactive" && (
                                    <div className="lease-control">
                                        <span>
                                            <Timer />
                                            <b>Thời lượng điều khiển</b>
                                            <small>Đồng hồ chỉ bắt đầu khi desktop báo ready.</small>
                                        </span>
                                        <div role="radiogroup" aria-label="Thời lượng phiên tương tác">
                                            {([5, 10] as SandboxLeaseMinutes[]).map((minutes) => (
                                                <button
                                                    type="button"
                                                    role="radio"
                                                    aria-checked={leaseMinutes === minutes}
                                                    className={leaseMinutes === minutes ? "selected" : ""}
                                                    onClick={() => setLeaseMinutes(minutes)}
                                                    key={minutes}
                                                >
                                                    {minutes} phút
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </section>
                        )}

                        {!activeSession && cloud && (
                            <section className="sandbox-wallet-panel">
                                <div>
                                    <small>VÍ SANDBOX</small>
                                    <strong>{cloud.credits} credit</strong>
                                    <span>PRO và MAX dùng credit theo từng phiên cloud.</span>
                                </div>
                                <div className="sandbox-wallet-actions">
                                    <select
                                        value={paymentCredits}
                                        onChange={(event) =>
                                            setPaymentCredits(Number(event.target.value))
                                        }
                                        aria-label="Số credit Sandbox cần mua"
                                    >
                                        <option value={1}>1 credit</option>
                                        <option value={5}>5 credit</option>
                                        <option value={10}>10 credit</option>
                                    </select>
                                    <button
                                        type="button"
                                        disabled={paymentBusy || payment?.status === "pending"}
                                        onClick={() => void createCreditPayment()}
                                    >
                                        {paymentBusy ? "Đang tạo QR…" : "Mua bằng SePay"}
                                    </button>
                                    {cloud.accountTier === "free" && (
                                        <Link href="/account/checkout?plan=pro&period=monthly">
                                            Nâng PRO
                                        </Link>
                                    )}
                                    {cloud.accountTier === "pro" && (
                                        <Link href="/account/checkout?plan=team&period=monthly">
                                            Mở MAX
                                        </Link>
                                    )}
                                </div>
                            </section>
                        )}

                        {!activeSession && payment && (
                            <section className={`sandbox-payment-card status-${payment.status}`}>
                                <div className="sandbox-payment-qr">
                                    {payment.qrUrl ? (
                                        <Image
                                            src={payment.qrUrl}
                                            unoptimized
                                            width={220}
                                            height={220}
                                            alt={`QR mua ${payment.credits} credit Sandbox`}
                                        />
                                    ) : (
                                        <strong>QR chưa được cấu hình</strong>
                                    )}
                                </div>
                                <div>
                                    <small>THANH TOÁN SANDBOX / SEPAY</small>
                                    <h2>
                                        {payment.status === "paid"
                                            ? "Đã cộng credit"
                                            : payment.status === "expired"
                                              ? "Đơn đã hết hạn"
                                              : `Mua ${payment.credits} credit`}
                                    </h2>
                                    <b>{formatMoney(payment.amountVnd)}</b>
                                    <dl>
                                        <div><dt>Ngân hàng</dt><dd>{payment.bankName}</dd></div>
                                        <div><dt>Số tài khoản</dt><dd>{payment.bankAccount}</dd></div>
                                        <div><dt>Nội dung</dt><dd><code>{payment.transferContent}</code></dd></div>
                                    </dl>
                                    <p>
                                        {payment.status === "paid"
                                            ? "SePay đã xác nhận. Ví Sandbox đã được cập nhật."
                                            : payment.status === "expired"
                                              ? "Tạo đơn mới để tiếp tục."
                                              : "Giữ nguyên số tiền và nội dung. Hệ thống kiểm tra tự động mỗi 4 giây."}
                                    </p>
                                    <button type="button" onClick={() => setPayment(null)}>
                                        {payment.status === "pending" ? "Ẩn QR" : "Đóng"}
                                    </button>
                                </div>
                            </section>
                        )}

                        {!activeSession && (
                            <section className="sandbox-tier-grid">
                                {cloud?.availableTiers.map((item) => (
                                    <button
                                        key={item.tier}
                                        disabled={!item.allowed || !item.configured}
                                        className={`${selected === item.tier ? "selected" : ""} ${
                                            !item.allowed || !item.configured ? "locked" : ""
                                        }`}
                                        onClick={() => {
                                            setSelected(item.tier);
                                            if (item.tier === "free") setLabMode("auto");
                                        }}
                                    >
                                        <b>{item.tier.toUpperCase()}</b>
                                        <strong>
                                            {item.tier === "free"
                                                ? "Browser tương tác"
                                                : item.tier === "pro"
                                                  ? labMode === "interactive"
                                                      ? "Windows desktop"
                                                      : "EXE chuyên dụng"
                                                  : labMode === "interactive"
                                                    ? "Desktop GPU"
                                                    : "Ứng dụng / GPU"}
                                        </strong>
                                        <span>
                                            {item.minutes} phút ·{` `}
                                            {item.provider === "local" ? "Local" : "Cloud"}
                                            {item.creditCost > 0 ? ` · ${item.creditCost} credit` : ""}
                                        </span>
                                        <ul>
                                            <li>✓ VM/session dùng một lần</li>
                                            <li>{item.exe ? "✓" : "—"} Phân tích file Windows</li>
                                            <li>{item.gpu ? "✓" : "—"} GPU/ứng dụng nặng</li>
                                        </ul>
                                        {!item.allowed && <em>Cần nâng gói</em>}
                                        {item.allowed && !item.configured && <em>Cloud chưa cấu hình</em>}
                                    </button>
                                ))}
                            </section>
                        )}

                        {showingRecentSession && (
                            <section className="lab-restart-panel">
                                <span>
                                    <Zap />
                                    <span>
                                        <b>TẠO MỘT VM ĐỘC LẬP MỚI</b>
                                        <small>
                                            Báo cáo lượt trước vẫn giữ ở phía dưới; file và môi trường
                                            cũ không được tái sử dụng.
                                        </small>
                                    </span>
                                </span>
                                <button
                                    type="button"
                                    disabled={
                                        busy ||
                                        !selectedTierInfo?.allowed ||
                                        !selectedTierInfo.configured ||
                                        lacksCredits
                                    }
                                    onClick={() => void startSession()}
                                >
                                    {busy
                                        ? "Đang tạo phiên…"
                                        : labMode === "interactive"
                                          ? `Tạo desktop ${leaseMinutes} phút`
                                          : `Bắt đầu Auto Analyze ${selected.toUpperCase()}`}
                                </button>
                            </section>
                        )}

                        {activeSession && activeSession.tier !== "free" && (
                            <section className={`cloud-sample-panel mode-${sessionMode}`}>
                                <header>
                                    <span>
                                        {sessionMode === "auto" ? <Activity /> : <MousePointer2 />}
                                        <span>
                                            <small>
                                                {sessionMode === "auto"
                                                    ? "AUTO ANALYZE / AGENT-DRIVEN"
                                                    : "INTERACTIVE INVESTIGATE / HUMAN-IN-THE-LOOP"}
                                            </small>
                                            <h2>
                                                {sessionMode === "auto"
                                                    ? "Gửi file để hệ thống tự phân tích"
                                                    : "Đưa file vào desktop cô lập"}
                                            </h2>
                                        </span>
                                    </span>
                                    <em>{activeSession.tier.toUpperCase()} · 1 FILE / SESSION</em>
                                </header>
                                <p>
                                    {sessionMode === "auto"
                                        ? "Agent tự thực thi mẫu, thu bằng chứng có sẵn và trả báo cáo. Bạn không cần mở desktop."
                                        : "Mẫu được đặt trong VM dùng một lần; bạn điều tra qua remote gateway trong lease đã chọn."}
                                </p>
                                <div className="cloud-file-row">
                                    <label>
                                        <FileWarning />
                                        <span>
                                            <b>{cloudExeFile?.name || "Chưa chọn file Windows"}</b>
                                            <small>
                                                EXE, MSI, BAT, CMD, COM, SCR hoặc PS1 · không chạy local
                                            </small>
                                        </span>
                                        <input
                                            type="file"
                                            accept=".exe,.msi,.bat,.cmd,.com,.scr,.ps1"
                                            disabled={
                                                cloudExeUploading ||
                                                activeSession.status !== "ready" ||
                                                sampleAlreadySubmitted
                                            }
                                            onClick={(event) => {
                                                event.currentTarget.value = "";
                                            }}
                                            onChange={(event) => {
                                                setCloudExeFile(event.target.files?.[0] || null);
                                                setCloudExeConsent(false);
                                            }}
                                        />
                                    </label>
                                    <button
                                        type="button"
                                        disabled={
                                            !cloudExeFile ||
                                            !cloudExeConsent ||
                                            cloudExeUploading ||
                                            activeSession.status !== "ready" ||
                                            sampleAlreadySubmitted
                                        }
                                        onClick={() => void uploadCloudExecutable()}
                                    >
                                        {sampleAlreadySubmitted
                                            ? "Mẫu đã được khóa vào phiên"
                                            : cloudExeUploading
                                              ? "Đang chuyển vào VM…"
                                              : sessionMode === "auto"
                                                ? "Bắt đầu Auto Analyze"
                                                : "Đưa file vào desktop"}
                                    </button>
                                </div>
                                <label className="cloud-sample-consent">
                                    <input
                                        type="checkbox"
                                        checked={cloudExeConsent}
                                        disabled={sampleAlreadySubmitted}
                                        onChange={(event) =>
                                            setCloudExeConsent(event.target.checked)
                                        }
                                    />
                                    <span>
                                        Tôi có quyền gửi file này và đồng ý xử lý trong Windows VM tạm
                                        thời. Không gửi dữ liệu mật hoặc file chưa được phép chia sẻ.
                                    </span>
                                </label>
                                {activeSession.sample?.filename && (
                                    <div className="cloud-sample-status" role="status">
                                        <CheckCircle2 />
                                        <span>
                                            <b>{activeSession.sample.filename}</b>
                                            <small>
                                                {activeSession.sample.status}
                                                {activeSession.sample.sha256
                                                    ? ` · SHA-256 ${activeSession.sample.sha256.slice(0, 16)}…`
                                                    : ""}
                                            </small>
                                        </span>
                                    </div>
                                )}
                                {sampleAlreadySubmitted && (
                                    <small className="cloud-one-file-note">
                                        File đã gắn với phiên này. Hãy kết thúc và tạo VM mới để phân
                                        tích file khác, tránh lây nhiễm chéo.
                                    </small>
                                )}
                            </section>
                        )}

                        {session && (
                            <section className={`session-command-center mode-${sessionMode}`}>
                                <header>
                                    <div>
                                        <small>
                                            {showingRecentSession ? "RECENT RESULT" : "LIVE SESSION"} /{` `}
                                            {session.id.slice(0, 8)}
                                        </small>
                                        <h2>
                                            {showingRecentSession
                                                ? "Kết quả lượt phân tích gần nhất"
                                                : sessionMode === "auto"
                                                ? "Automated investigation pipeline"
                                                : "Interactive investigation lease"}
                                        </h2>
                                    </div>
                                    <div className="session-kpis">
                                        <span>
                                            <small>PHASE</small>
                                            <b>{sessionPhase.replaceAll("_", " ")}</b>
                                        </span>
                                        <span className={
                                            sessionMode === "interactive" &&
                                            leaseSeconds !== null &&
                                            leaseSeconds <= 60
                                                ? "urgent"
                                                : ""
                                        }>
                                            <small>
                                                {showingRecentSession
                                                    ? "TRẠNG THÁI PHIÊN"
                                                    : sessionMode === "auto"
                                                      ? "CHẾ ĐỘ PHÂN TÍCH"
                                                    : cleanupPending
                                                      ? "TRẠNG THÁI LEASE"
                                                    : sessionReady
                                                      ? "THỜI GIAN CÒN LẠI"
                                                      : "LEASE CHƯA BẮT ĐẦU"}
                                            </small>
                                            <b>
                                                {showingRecentSession
                                                    ? "ĐÃ KẾT THÚC"
                                                    : sessionMode === "auto"
                                                      ? "TỰ ĐỘNG"
                                                    : cleanupPending
                                                      ? "ĐANG THU HỒI"
                                                    : sessionReady
                                                    ? formatLeaseCountdown(leaseSeconds)
                                                    : "CHỜ READY"}
                                            </b>
                                        </span>
                                        {activeSession ? (
                                            <button
                                                type="button"
                                                className="kill-session-button"
                                                disabled={busy || cleanupPending}
                                                onClick={() => void stopSession()}
                                            >
                                                <X />
                                                {cleanupPending ? "Đang hủy VM…" : "Dừng & hủy VM"}
                                            </button>
                                        ) : (
                                            <button
                                                type="button"
                                                className="new-session-button"
                                                onClick={() => {
                                                    setSelected(session.tier);
                                                    setLabMode(sessionMode);
                                                    document
                                                        .getElementById("cloud-lab-setup")
                                                        ?.scrollIntoView({ behavior: "smooth" });
                                                }}
                                            >
                                                <Zap /> Tạo lượt mới
                                            </button>
                                        )}
                                    </div>
                                </header>
                                <div className="session-timeline" aria-label="Tiến trình phiên Windows Cloud Lab">
                                    {timeline.map((item, index) => {
                                        const state = timelineState(index, timelineIndex, sessionPhase);
                                        return (
                                            <article className={state} key={item.id}>
                                                <i>
                                                    {state === "done" ? (
                                                        <CheckCircle2 />
                                                    ) : state === "failed" ? (
                                                        <X />
                                                    ) : (
                                                        String(index + 1).padStart(2, "0")
                                                    )}
                                                </i>
                                                <span>
                                                    <b>{item.label}</b>
                                                    <small>{item.detail}</small>
                                                </span>
                                            </article>
                                        );
                                    })}
                                </div>
                                {activeSession?.status === "provisioning" && (
                                    <p className="lease-waiting-note">
                                        <Clock3 /> Provisioning không trừ thời gian điều khiển. Đồng hồ
                                        chỉ chạy sau khi backend ghi nhận <code>readyAt</code> và
                                        <code>leaseExpiresAt</code>.
                                    </p>
                                )}
                                {showingRecentSession && (
                                    <p className="lease-waiting-note recent-result-note">
                                        <ShieldCheck /> Báo cáo được giữ lại sau cleanup; desktop và URL
                                        điều khiển của lượt này không còn hiệu lực.
                                    </p>
                                )}
                                {activeSession && sessionReady && sessionMode === "interactive" && leaseSeconds === null && (
                                    <p className="lease-waiting-note warning" role="alert">
                                        <Clock3 /> Backend chưa trả deadline lease sau trạng thái ready.
                                        UI sẽ không tự đoán thời gian; hãy kiểm tra cấu hình phiên.
                                    </p>
                                )}
                            </section>
                        )}

                        <section
                            className={`interactive-sandbox ${
                                freeBrowser || remoteUrl ? "session-live" : ""
                            } ${expanded ? "is-expanded" : ""}`}
                        >
                            <header>
                                <div>
                                    <MonitorPlay />
                                    <span>
                                        <b>
                                            {session?.tier === "free"
                                                ? "SAFE BROWSER SESSION"
                                                : showingRecentSession
                                                  ? "RECENT SANDBOX REPORT"
                                                : (session ? sessionMode : labMode) === "interactive"
                                                  ? "INTERACTIVE WINDOWS DESKTOP"
                                                  : "AUTO ANALYZE CONSOLE"}
                                        </b>
                                        <small className={freeBrowser || remoteUrl ? "session-running" : ""}>
                                            {(freeBrowser || remoteUrl) && <i />}
                                            {freeBrowser
                                                ? "Browser cô lập đang hoạt động"
                                                : remoteUrl
                                                  ? `Desktop đã kết nối · ${formatLeaseCountdown(leaseSeconds)}`
                                                  : session
                                                    ? `${session.status} · ${sessionPhase.replaceAll("_", " ")}`
                                                    : "Chọn môi trường phù hợp rồi bắt đầu"}
                                        </small>
                                    </span>
                                </div>
                                <div className="sandbox-window-actions">
                                    {(freeBrowser || remoteUrl) && (
                                        <button
                                            type="button"
                                            onClick={() => setExpanded((value) => !value)}
                                            aria-label={
                                                expanded
                                                    ? "Thu gọn màn hình sandbox"
                                                    : "Phóng to màn hình sandbox"
                                            }
                                        >
                                            {expanded ? <Minimize2 /> : <Maximize2 />}
                                            {expanded ? "Thu gọn" : "Phóng to"}
                                        </button>
                                    )}
                                </div>
                            </header>

                            {activeSession?.tier === "free" && freeBrowser ? (
                                <div className="free-browser">
                                    <form
                                        className="sandbox-address-bar"
                                        onSubmit={(event) => {
                                            event.preventDefault();
                                            void freeAction("navigate", { url: freeUrl });
                                        }}
                                    >
                                        <span className="sandbox-address-security">
                                            <ShieldCheck />HTTPS
                                        </span>
                                        <input
                                            value={freeUrl}
                                            onChange={(event) => setFreeUrl(event.target.value)}
                                            aria-label="Địa chỉ website trong sandbox"
                                        />
                                        <button disabled={busy}>Truy cập</button>
                                    </form>
                                    <div
                                        className="free-browser-screen"
                                        tabIndex={0}
                                        onKeyDown={handleSandboxKey}
                                    >
                                        {/* Data URL là ảnh chụp phiên Playwright thay đổi sau mỗi thao tác. */}
                                        {/* eslint-disable-next-line @next/next/no-img-element */}
                                        <img
                                            src={freeBrowser.image}
                                            alt={`Trang ${freeBrowser.title}`}
                                            onClick={(event) => {
                                                event.currentTarget.parentElement?.focus();
                                                const rect =
                                                    event.currentTarget.getBoundingClientRect();
                                                const scale = Math.min(
                                                    rect.width / 1280,
                                                    rect.height / 720,
                                                );
                                                const contentWidth = 1280 * scale;
                                                const contentHeight = 720 * scale;
                                                const offsetX = (rect.width - contentWidth) / 2;
                                                const offsetY = (rect.height - contentHeight) / 2;
                                                const x =
                                                    event.clientX - rect.left - offsetX;
                                                const y =
                                                    event.clientY - rect.top - offsetY;
                                                if (
                                                    x < 0 ||
                                                    y < 0 ||
                                                    x > contentWidth ||
                                                    y > contentHeight
                                                ) {
                                                    return;
                                                }
                                                void flushSandboxTyping().then(() =>
                                                    freeAction("click", {
                                                        x: x / scale,
                                                        y: y / scale,
                                                    }),
                                                );
                                            }}
                                        />
                                        {freeBrowser.lastEvent && (
                                            <div
                                                className={`sandbox-live-alert ${freeBrowser.lastEvent.severity}`}
                                                role="status"
                                            >
                                                {freeBrowser.lastEvent.type ===
                                                "download_blocked" ? (
                                                    <FileWarning />
                                                ) : (
                                                    <ShieldCheck />
                                                )}
                                                <span>
                                                    <b>{freeBrowser.lastEvent.title}</b>
                                                    <small>{freeBrowser.lastEvent.message}</small>
                                                </span>
                                            </div>
                                        )}
                                    </div>
                                    <footer className="free-browser-footer">
                                        <div className="sandbox-safety">
                                            <ShieldCheck />
                                            <span>
                                                <b>Canary đang bảo vệ dữ liệu nhập</b>
                                                <small>
                                                    {
                                                        freeBrowser.protection
                                                            .submissionsObserved
                                                    }{" "}
                                                    lượt gửi đã quan sát ·{` `}
                                                    {freeBrowser.protection.downloadsBlocked} tải
                                                    tệp bị chặn
                                                </small>
                                            </span>
                                        </div>
                                        <form
                                            className="sandbox-type-form"
                                            onSubmit={(event) => {
                                                event.preventDefault();
                                                if (!sandboxText.trim()) return;
                                                void freeAction("type", { text: "*" }).then(() =>
                                                    setSandboxText(""),
                                                );
                                            }}
                                        >
                                            <input
                                                value={sandboxText}
                                                onChange={(event) =>
                                                    setSandboxText(event.target.value)
                                                }
                                                maxLength={500}
                                                placeholder="Nhập nội dung; hệ thống sẽ thay bằng canary…"
                                            />
                                            <button
                                                type="submit"
                                                disabled={busy || !sandboxText.trim()}
                                            >
                                                Gửi
                                            </button>
                                        </form>
                                        <button
                                            className="end-session-button"
                                            type="button"
                                            disabled={busy}
                                            onClick={() => void stopSession()}
                                        >
                                            Kết thúc
                                        </button>
                                    </footer>
                                </div>
                            ) : session &&
                              session.tier !== "free" &&
                              (showingRecentSession || sessionMode === "auto") ? (
                                <div className="auto-analysis-workspace">
                                    <header>
                                        <span>
                                            <Activity />
                                            <span>
                                                <small>
                                                    {showingRecentSession
                                                        ? "PERSISTED REPORT / VM DESTROYED"
                                                        : "AGENT-ONLY WINDOWS VM"}
                                                </small>
                                                <h2>
                                                    {showingRecentSession
                                                        ? "Báo cáo lượt phân tích gần nhất"
                                                        : session.sample.status === "completed"
                                                        ? "Báo cáo phân tích tự động"
                                                        : session.sample.status === "failed"
                                                          ? "Phiên phân tích gặp lỗi"
                                                          : ["queued", "delivered", "running"].includes(
                                                                  session.sample.status,
                                                              )
                                                            ? "Agent đang quan sát hành vi"
                                                            : "VM sẵn sàng nhận mẫu"}
                                                </h2>
                                            </span>
                                        </span>
                                        <em>
                                            {showingRecentSession
                                                ? "Chỉ đọc · remote access đã bị thu hồi"
                                                : "Không mở remote desktop trong Auto Analyze"}
                                        </em>
                                    </header>
                                    <div className="auto-report-metrics">
                                        <span><small>VERDICT</small><b>{sampleVerdict ? String(sampleVerdict) : "CHƯA CÓ"}</b></span>
                                        <span><small>PROCESS</small><b>{reportMetrics.processes}</b></span>
                                        <span><small>FILE EVENT</small><b>{reportMetrics.files}</b></span>
                                        <span><small>REGISTRY</small><b>{reportMetrics.registry}</b></span>
                                        <span><small>NETWORK</small><b>{reportMetrics.network}</b></span>
                                    </div>
                                    <div className="auto-console-body">
                                        <section className={`auto-state phase-${sessionPhase}`}>
                                            <div className="auto-state-radar" aria-hidden><i /><Activity /></div>
                                            <span>
                                                <small>CURRENT PHASE</small>
                                                <h3>{sessionPhase.replaceAll("_", " ")}</h3>
                                                <p>
                                                    {session.sample.status === "none"
                                                        ? "Chọn file ở phía trên để agent bắt đầu. VM hiện chưa thực thi mẫu nào."
                                                        : String(
                                                              session.sample.report.summary ||
                                                                  (session.sample.status === "completed"
                                                                      ? "Agent đã hoàn tất và gửi bằng chứng về Risk Core."
                                                                      : session.sample.status === "failed"
                                                                        ? "Agent đã dừng; xem lỗi và không coi mẫu là an toàn."
                                                                        : "Mẫu đang được xử lý trong Windows VM cô lập."),
                                                          )}
                                                </p>
                                            </span>
                                        </section>
                                        <aside className="auto-evidence-status">
                                            <small>EVIDENCE CHANNELS</small>
                                            {[
                                                ["Process tree", reportMetrics.processes],
                                                ["File system", reportMetrics.files],
                                                ["Registry", reportMetrics.registry],
                                                ["Network", reportMetrics.network],
                                            ].map(([label, count]) => (
                                                <span className={Number(count) > 0 ? "observed" : "empty"} key={String(label)}>
                                                    <i /><b>{label}</b>
                                                    <em>{Number(count) > 0 ? `${count} sự kiện` : session.sample.status === "completed" ? "Không ghi nhận" : "Đang chờ"}</em>
                                                </span>
                                            ))}
                                        </aside>
                                    </div>
                                    {Object.keys(report).length > 0 && (
                                        <details className="raw-sandbox-report">
                                            <summary>Xem payload bằng chứng máy đọc được</summary>
                                            <pre>{JSON.stringify(report, null, 2)}</pre>
                                        </details>
                                    )}
                                </div>
                            ) : activeSession &&
                              activeSession.tier !== "free" &&
                              sessionMode === "interactive" ? (
                                remoteUrl ? (
                                    <div className="remote-desktop-stage">
                                        <iframe
                                            src={remoteUrl}
                                            title="Desktop Windows cô lập — phiên điều tra tương tác"
                                            allow="fullscreen"
                                            sandbox={REMOTE_IFRAME_SANDBOX_POLICY}
                                            referrerPolicy="no-referrer"
                                        />
                                        <footer>
                                            <span><ShieldCheck /> Gateway phiên tạm · không công khai RDP</span>
                                            <span>Token truy cập: {formatLeaseCountdown(remoteTokenSeconds)}</span>
                                            <b className={leaseSeconds !== null && leaseSeconds <= 60 ? "urgent" : ""}>Lease {formatLeaseCountdown(leaseSeconds)}</b>
                                        </footer>
                                    </div>
                                ) : (
                                    <div className="remote-access-gate">
                                        <div className="remote-gate-visual"><MonitorPlay /><i /></div>
                                        <small>INTERACTIVE REMOTE GATEWAY</small>
                                        <h2>
                                            {!sessionReady
                                                ? "Đang chuẩn bị Windows desktop…"
                                                : leaseSeconds === 0
                                                  ? "Lease điều khiển đã kết thúc"
                                                  : remoteWaitingForSample
                                                    ? activeSession.sample.status === "none"
                                                        ? "Hãy đưa file vào desktop trước"
                                                        : "Đang staging file trong VM…"
                                                  : remoteExplicitlyUnavailable
                                                    ? "Không thể cấp desktop tương tác"
                                                    : "Desktop đã sẵn sàng để kết nối"}
                                        </h2>
                                        <p>
                                            {!sessionReady
                                                ? "Bạn chưa bị trừ thời gian. Backend đang tạo VM, policy mạng và tài khoản phiên tạm."
                                                : leaseSeconds === 0
                                                  ? "Input đã bị khóa. Backend đang thu báo cáo và hủy VM; không thể dùng lại URL cũ."
                                                  : remoteWaitingForSample
                                                    ? activeSession.sample.status === "none"
                                                        ? "Chọn file ở khu vực phía trên và xác nhận quyền gửi. Remote gateway chỉ được cấp sau khi mẫu đã được staging an toàn."
                                                        : "Mẫu đang được chuyển vào workspace cô lập. Nút kết nối sẽ xuất hiện khi backend xác nhận trạng thái staged hoặc running."
                                                  : remoteExplicitlyUnavailable
                                                    ? remoteUnavailableLabel(
                                                          activeSession.remoteUnavailableReason ||
                                                              activeSession.remoteStatus,
                                                      )
                                                    : "Prewise chỉ mở desktop sau khi nhận URL HTTPS từ remote broker. Không có URL thì UI không giả lập RDP hoặc màn hình điều khiển."}
                                        </p>
                                        <div className="remote-security-facts">
                                            <span><ShieldCheck /> Token phiên ngắn hạn</span>
                                            <span><Timer /> Lease {activeSession.leaseMinutes || leaseMinutes} phút</span>
                                            <span><X /> Hủy VM khi kết thúc</span>
                                        </div>
                                        {remoteError && <p className="remote-access-error" role="alert">{remoteError}</p>}
                                        {sessionReady &&
                                            leaseSeconds !== 0 &&
                                            !remoteWaitingForSample &&
                                            !remoteExplicitlyUnavailable &&
                                            activeSession.remoteAvailable !== false && (
                                            <button type="button" disabled={remoteBusy} onClick={() => void openRemoteDesktop()}>
                                                {remoteBusy ? "Đang xin token một lần…" : remoteError ? "Thử kết nối lại" : "Kết nối desktop an toàn"}
                                            </button>
                                        )}
                                        {remoteExplicitlyUnavailable && (
                                            <small className="remote-fallback-note">Kết thúc phiên này và chọn Auto Analyze để agent tự kiểm tra file mà không cần remote gateway.</small>
                                        )}
                                    </div>
                                )
                            ) : (
                                <div className="sandbox-unavailable">
                                    <MonitorPlay />
                                    <h2>
                                        {selected === "free" ? "Safe Browser tương tác" : labMode === "interactive" ? "Interactive Investigate" : "Auto Analyze"}
                                    </h2>
                                    <p>
                                        {selected === "free"
                                            ? `Môi trường local chỉ mở web, tối đa ${selectedTierInfo?.minutes ?? 10} phút mỗi phiên.`
                                            : labMode === "interactive"
                                              ? `Windows desktop điều khiển trong ${leaseMinutes} phút sau khi ready. Chỉ khả dụng khi remote broker được cấu hình.`
                                              : "Windows VM agent-only tự chạy mẫu, thu telemetry và trả báo cáo mà không cần remote desktop."}
                                    </p>
                                    {!selectedTierInfo?.allowed && selected === "pro" && (
                                        <Link href="/account/checkout?plan=pro&period=monthly">
                                            Nâng cấp PRO bằng SePay
                                        </Link>
                                    )}
                                    {!selectedTierInfo?.allowed && selected === "max" && (
                                        <Link href="/account/checkout?plan=team&period=monthly">
                                            Nâng cấp TEAM / MAX bằng SePay
                                        </Link>
                                    )}
                                    {selectedTierInfo?.allowed && lacksCredits && (
                                        <button type="button" onClick={() => void createCreditPayment()}>
                                            Mua {paymentCredits} credit bằng SePay
                                        </button>
                                    )}
                                    {selectedTierInfo?.allowed && !selectedTierInfo.configured && (
                                        <small>Máy cloud cho tier này chưa được quản trị viên cấu hình.</small>
                                    )}
                                    {!activeSession ? (
                                        <button
                                            disabled={
                                                busy ||
                                                !selectedTierInfo?.allowed ||
                                                !selectedTierInfo.configured ||
                                                lacksCredits
                                            }
                                            onClick={() => void startSession()}
                                        >
                                            {labMode === "interactive" ? `Tạo desktop ${leaseMinutes} phút` : `Bắt đầu Auto Analyze ${selected.toUpperCase()}`}
                                        </button>
                                    ) : null}
                                </div>
                            )}
                        </section>
                    </>
                )}

                {error && (
                    <div className="sandbox-global-error" role="alert">
                        <span>{error}</span>
                        <button
                            type="button"
                            onClick={() => setError("")}
                            aria-label="Đóng thông báo"
                        >
                            <X />
                        </button>
                    </div>
                )}
            </main>
        </PrewiseShell>
    );
}

function ExeQuickReport({
    result,
    polling,
    onShare,
    onRefresh,
}: {
    result: ExeSandboxResult;
    polling: boolean;
    onShare?: () => void;
    onRefresh?: () => void;
}) {
    const provider = result.provider;
    const local = result.local_analysis;
    return (
        <div className={`exe-quick-report verdict-${result.verdict}`}>
            <div className="exe-report-head">
                <span>{verdictLabel(result.verdict)}</span>
                <strong>{result.risk_score}/100</strong>
            </div>
            <p className="exe-report-file">{result.filename}</p>
            <code title={result.sha256}>{result.sha256.slice(0, 24)}…</code>

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
                    <b>{providerStatusLabel(provider)}</b>
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
                    Đồng ý gửi mẫu để kiểm tra sâu
                </button>
            )}

            {result.issues.length > 0 && (
                <ul className="exe-issue-list">
                    {result.issues.slice(0, 6).map((issue) => (
                        <li key={issue}>{issue}</li>
                    ))}
                </ul>
            )}

            {provider?.detections && provider.detections.length > 0 && (
                <div className="exe-detections">
                    {provider.detections.slice(0, 5).map((item) => (
                        <span key={`${item.engine}-${item.threat}`}>
                            <b>{item.engine}</b>
                            <small>{item.threat}</small>
                        </span>
                    ))}
                </div>
            )}

            <small className="exe-report-disclaimer">
                Test nhanh không thực thi file. Kết quả tĩnh hoặc AV không bảo đảm file an toàn tuyệt
                đối; phân tích hành vi đầy đủ thuộc Sandbox Pro.
            </small>
        </div>
    );
}
