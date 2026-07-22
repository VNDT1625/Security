export type SandboxMode = "auto" | "interactive";
export type SandboxLeaseMinutes = 5 | 10;
export type SandboxTier = "free" | "pro" | "max";

export const REMOTE_IFRAME_SANDBOX_POLICY =
    "allow-scripts allow-forms allow-same-origin allow-pointer-lock";

export type SandboxSessionUiShape = {
    status: string;
    mode?: SandboxMode | null;
    phase?: string | null;
    readyAt?: string | null;
    leaseExpiresAt?: string | null;
    remoteAccessExpiresAt?: string | null;
    expiresAt?: string | null;
    sample?: {
        status?: string | null;
    } | null;
};

export type SandboxTimelineState = "done" | "active" | "pending" | "failed";

export function labActionState(webBusy: boolean, exeBusy: boolean) {
    return {
        web: {
            disabled: webBusy,
            label: webBusy ? "Đang kiểm thử…" : "Kiểm thử",
        },
        exe: {
            disabled: exeBusy,
            label: exeBusy ? "Đang phân tích…" : "Chọn EXE",
        },
    } as const;
}

const KNOWN_PHASES = [
    "created",
    "provisioning",
    "ready",
    "sample_staged",
    "running",
    "collecting",
    "completed",
    "failed",
    "expired",
    "destroying",
    "destroyed",
] as const;

export function resolveSandboxMode(session?: SandboxSessionUiShape | null): SandboxMode {
    return session?.mode === "interactive" ? "interactive" : "auto";
}

export function buildSessionCreatePayload(
    tier: SandboxTier,
    mode: SandboxMode,
    leaseMinutes: SandboxLeaseMinutes,
): {
    tier: SandboxTier;
    mode: SandboxMode;
    leaseMinutes?: SandboxLeaseMinutes;
} {
    const effectiveMode: SandboxMode = tier === "free" ? "auto" : mode;
    return {
        tier,
        mode: effectiveMode,
        ...(effectiveMode === "interactive" ? { leaseMinutes } : {}),
    };
}

export function selectDisplayedSession<T>(
    activeSession: T | null | undefined,
    recentSession: T | null | undefined,
): T | null {
    return activeSession ?? recentSession ?? null;
}

export function resolveSandboxPhase(session?: SandboxSessionUiShape | null): string {
    if (!session) return "created";
    const explicit = String(session.phase || "").trim().toLowerCase();
    const status = String(session.status || "").trim().toLowerCase();
    const terminalPhase = [explicit, status].find((value) =>
        [
            "termination_requested",
            "terminating",
            "terminated",
            "destroying",
            "destroyed",
            "expired",
            "cleanup_failed",
        ].includes(value),
    );
    if (terminalPhase) return terminalPhase;

    const sampleStatus = String(session.sample?.status || "").trim().toLowerCase();
    if (sampleStatus === "completed") return "completed";
    if (sampleStatus === "failed") return "failed";
    if (["running", "executing"].includes(sampleStatus)) return "running";
    if (["collecting", "reporting"].includes(sampleStatus)) return "collecting";
    if (["queued", "delivered", "staged"].includes(sampleStatus)) return "sample_staged";

    if (explicit) return explicit;
    if (status === "ready") return "ready";
    if (KNOWN_PHASES.includes(status as (typeof KNOWN_PHASES)[number])) return status;
    return status || "created";
}

export function leaseDeadline(session?: SandboxSessionUiShape | null): string | null {
    if (!session || session.status !== "ready") return null;
    if (session.leaseExpiresAt) return session.leaseExpiresAt;
    if (session.remoteAccessExpiresAt) return session.remoteAccessExpiresAt;

    // expiresAt của contract cũ bắt đầu từ lúc provisioning, vì vậy không dùng nó
    // làm đồng hồ phiên tương tác. Backend mới phải trả leaseExpiresAt/readyAt.
    if (session.readyAt && session.expiresAt) return session.expiresAt;
    return null;
}

export function remainingLeaseSeconds(
    deadline: string | null | undefined,
    nowMilliseconds: number,
): number | null {
    if (!deadline) return null;
    const deadlineMilliseconds = Date.parse(deadline);
    if (!Number.isFinite(deadlineMilliseconds)) return null;
    return Math.max(0, Math.ceil((deadlineMilliseconds - nowMilliseconds) / 1000));
}

export function formatLeaseCountdown(seconds: number | null): string {
    if (seconds === null) return "--:--";
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
}

export function safeRemoteConnectUrl(
    value: string | null | undefined,
    baseUrl = "https://prewise.local",
): string | null {
    if (!value) return null;
    try {
        const url = new URL(value, baseUrl);
        const localDevelopment =
            url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
        if (url.protocol !== "https:" && !localDevelopment) return null;
        if (["javascript:", "data:", "file:"].includes(url.protocol)) return null;
        return url.toString();
    } catch {
        return null;
    }
}

export function timelineState(
    stepIndex: number,
    activeIndex: number,
    phase: string,
): SandboxTimelineState {
    if (phase.includes("failed") && stepIndex === activeIndex) return "failed";
    if (
        ["completed", "terminated", "destroyed", "expired"].includes(phase) &&
        stepIndex <= activeIndex
    ) {
        return "done";
    }
    if (stepIndex < activeIndex) return "done";
    if (stepIndex === activeIndex) return "active";
    return "pending";
}
