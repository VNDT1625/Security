import { describe, expect, it } from "vitest";

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

describe("sandbox session UI contract", () => {
    it("keeps website and EXE quick-scan busy states independent", () => {
        expect(labActionState(true, false)).toEqual({
            web: { disabled: true, label: "Đang kiểm thử…" },
            exe: { disabled: false, label: "Chọn EXE" },
        });
        expect(labActionState(false, true)).toEqual({
            web: { disabled: false, label: "Kiểm thử" },
            exe: { disabled: true, label: "Đang phân tích…" },
        });
    });

    it("keeps the remote iframe policy intentionally narrow", () => {
        expect(REMOTE_IFRAME_SANDBOX_POLICY.split(" ").sort()).toEqual(
            ["allow-forms", "allow-pointer-lock", "allow-same-origin", "allow-scripts"].sort(),
        );
        expect(REMOTE_IFRAME_SANDBOX_POLICY).not.toContain("allow-top-navigation");
        expect(REMOTE_IFRAME_SANDBOX_POLICY).not.toContain("allow-popups");
        expect(REMOTE_IFRAME_SANDBOX_POLICY).not.toContain("allow-downloads");
    });

    it("only sends leaseMinutes for an interactive cloud session", () => {
        expect(buildSessionCreatePayload("pro", "auto", 10)).toEqual({
            tier: "pro",
            mode: "auto",
        });
        expect(buildSessionCreatePayload("pro", "interactive", 10)).toEqual({
            tier: "pro",
            mode: "interactive",
            leaseMinutes: 10,
        });
        expect(buildSessionCreatePayload("free", "interactive", 10)).toEqual({
            tier: "free",
            mode: "auto",
        });
    });

    it("shows an active session first and falls back to the recent terminal report", () => {
        const active = { id: "active" };
        const recent = { id: "recent" };
        expect(selectDisplayedSession(active, recent)).toBe(active);
        expect(selectDisplayedSession(null, recent)).toBe(recent);
        expect(selectDisplayedSession(undefined, undefined)).toBeNull();
    });

    it("treats a legacy session without a mode as automated analysis", () => {
        expect(resolveSandboxMode({ status: "ready" })).toBe("auto");
        expect(resolveSandboxMode({ status: "ready", mode: "interactive" })).toBe(
            "interactive",
        );
    });

    it("derives useful phases from legacy sample states", () => {
        expect(
            resolveSandboxPhase({ status: "ready", sample: { status: "delivered" } }),
        ).toBe("sample_staged");
        expect(
            resolveSandboxPhase({ status: "ready", sample: { status: "completed" } }),
        ).toBe("completed");
    });

    it("prefers real sample progress over a generic ready phase", () => {
        expect(
            resolveSandboxPhase({
                status: "ready",
                phase: "ready",
                sample: { status: "completed" },
            }),
        ).toBe("completed");
        expect(
            resolveSandboxPhase({
                status: "termination_requested",
                phase: "termination_requested",
                sample: { status: "completed" },
            }),
        ).toBe("termination_requested");
    });

    it("does not start an interactive countdown while provisioning", () => {
        const session = {
            status: "provisioning",
            leaseExpiresAt: "2026-07-22T10:10:00.000Z",
        };
        expect(leaseDeadline(session)).toBeNull();
    });

    it("does not reuse a legacy provisioning deadline as a ready-time lease", () => {
        expect(
            leaseDeadline({
                status: "ready",
                expiresAt: "2026-07-22T10:10:00.000Z",
            }),
        ).toBeNull();
    });

    it("formats and clamps a server-owned lease countdown", () => {
        const deadline = "2026-07-22T10:10:00.000Z";
        const now = Date.parse("2026-07-22T10:04:59.100Z");
        expect(remainingLeaseSeconds(deadline, now)).toBe(301);
        expect(formatLeaseCountdown(301)).toBe("05:01");
        expect(remainingLeaseSeconds(deadline, Date.parse("2026-07-22T10:11:00Z"))).toBe(0);
        expect(formatLeaseCountdown(null)).toBe("--:--");
    });

    it("marks the active failed timeline step visibly", () => {
        expect(timelineState(1, 1, "failed")).toBe("failed");
        expect(timelineState(1, 1, "cleanup_failed")).toBe("failed");
        expect(timelineState(0, 1, "failed")).toBe("done");
        expect(timelineState(2, 1, "failed")).toBe("pending");
    });

    it("marks a terminal successful timeline as fully complete", () => {
        expect(timelineState(4, 4, "completed")).toBe("done");
        expect(timelineState(4, 4, "terminated")).toBe("done");
    });

    it("accepts HTTPS/relative remote endpoints and rejects unsafe schemes", () => {
        expect(safeRemoteConnectUrl("https://broker.example/session/1")).toBe(
            "https://broker.example/session/1",
        );
        expect(safeRemoteConnectUrl("/remote/session/1", "https://prewise.test/app")).toBe(
            "https://prewise.test/remote/session/1",
        );
        expect(safeRemoteConnectUrl("javascript:alert(1)")).toBeNull();
        expect(safeRemoteConnectUrl("http://public.example/session/1")).toBeNull();
        expect(safeRemoteConnectUrl("http://localhost:8443/session/1")).toBe(
            "http://localhost:8443/session/1",
        );
    });
});
