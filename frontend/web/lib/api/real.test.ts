import { beforeEach, describe, expect, it, vi } from "vitest";

import { SESSION_STORAGE_KEY } from "@/lib/auth-session";
import { RealApiClient, resolveApiBase, resolveWsBase } from "@/lib/api/real";


describe("RealApiClient authentication", () => {
    beforeEach(() => {
        window.localStorage.clear();
        vi.restoreAllMocks();
    });

    it("sends the stored Bearer token to protected account endpoints", async () => {
        window.localStorage.setItem(
            SESSION_STORAGE_KEY,
            JSON.stringify({ token: "session-token" }),
        );
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ key: "sk-dev-test", createdAt: "06/07 15:00" }),
        });
        vi.stubGlobal("fetch", fetchMock);

        await new RealApiClient().getApiKey();

        expect(fetchMock).toHaveBeenCalledWith(
            "http://localhost:8000/v1/account/api-key",
            expect.objectContaining({
                headers: expect.objectContaining({
                    Authorization: "Bearer session-token",
                }),
            }),
        );
    });

    it("reads the server-authoritative account quota", async () => {
        window.localStorage.setItem(
            SESSION_STORAGE_KEY,
            JSON.stringify({ token: "session-token" }),
        );
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ remaining: 997, dailyScanLimit: 1000 }),
        });
        vi.stubGlobal("fetch", fetchMock);

        const quota = await new RealApiClient().getQuota();

        expect(quota.remaining).toBe(997);
        expect(fetchMock).toHaveBeenCalledWith(
            "http://localhost:8000/v1/account/quota",
            expect.objectContaining({
                method: "GET",
                headers: expect.objectContaining({ Authorization: "Bearer session-token" }),
            }),
        );
    });

    it("submits structured feedback to the authenticated feedback endpoint", async () => {
        window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ token: "session-token" }));
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ id: "feedback-1", status: "received" }),
        });
        vi.stubGlobal("fetch", fetchMock);

        await new RealApiClient().submitFeedback({
            requestId: "scan-123",
            feedbackType: "report_site",
            reason: "suspicious_site",
            details: "Trang giả mạo",
            idempotencyKey: "once-123",
        });

        expect(fetchMock).toHaveBeenCalledWith(
            "http://localhost:8000/v1/feedback",
            expect.objectContaining({
                method: "POST",
                body: JSON.stringify({
                    requestId: "scan-123",
                    feedbackType: "report_site",
                    reason: "suspicious_site",
                    details: "Trang giả mạo",
                    idempotencyKey: "once-123",
                }),
                headers: expect.objectContaining({ Authorization: "Bearer session-token" }),
            }),
        );
    });

    it("creates, reads, and revokes portable report shares", async () => {
        window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ token: "session-token" }));
        const fetchMock = vi.fn()
            .mockResolvedValueOnce({ ok: true, json: async () => ({ id: "share-1", shareToken: "token", expiresAt: "2026-07-23T00:00:00Z" }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ id: "share-1", snapshot: {}, expiresAt: "2026-07-23T00:00:00Z" }) })
            .mockResolvedValueOnce({ ok: true, status: 204 });
        vi.stubGlobal("fetch", fetchMock);
        const api = new RealApiClient();

        await api.createReportShare({ requestId: "scan-123", expiresIn: "7d" });
        await api.getPublicReportShare("public_token");
        await api.revokeReportShare("share-1");

        expect(fetchMock.mock.calls[0][0]).toBe("http://localhost:8000/v1/report-shares");
        expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({
            method: "POST", body: JSON.stringify({ requestId: "scan-123", expiresIn: "7d" }),
            headers: expect.objectContaining({ Authorization: "Bearer session-token" }),
        }));
        expect(fetchMock.mock.calls[1][0]).toBe("http://localhost:8000/v1/report-shares/public/public_token");
        expect(fetchMock.mock.calls[1][1].headers).not.toHaveProperty("Authorization");
        expect(fetchMock.mock.calls[2][0]).toBe("http://localhost:8000/v1/report-shares/share-1");
        expect(fetchMock.mock.calls[2][1].headers).toEqual(expect.objectContaining({ Authorization: "Bearer session-token" }));
    });

    it("keeps login public", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ token: "new-token", user: {}, plan: {} }),
        });
        vi.stubGlobal("fetch", fetchMock);

        await new RealApiClient().login({
            email: "demo@aisec.local",
            password: "Demo@123456",
        });

        const request = fetchMock.mock.calls[0][1] as RequestInit;
        expect(request.headers).not.toHaveProperty("Authorization");
    });

    it("shows only the server-provided login message instead of technical HTTP details", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: false,
            status: 401,
            statusText: "Unauthorized",
            text: async () => '{"detail":"Email hoặc mật khẩu không đúng."}',
        });
        vi.stubGlobal("fetch", fetchMock);

        await expect(new RealApiClient().login({
            email: "demo@aisec.local",
            password: "wrong-password",
        })).rejects.toThrow("Email hoặc mật khẩu không đúng.");
    });

    it("does not expose an HTML gateway error in the user interface", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: false,
            status: 502,
            statusText: "Bad Gateway",
            text: async () => "<html><body>upstream connect error</body></html>",
        });
        vi.stubGlobal("fetch", fetchMock);

        await expect(new RealApiClient().login({
            email: "demo@aisec.local",
            password: "Demo@123456",
        })).rejects.toThrow("Hệ thống đang tạm thời gián đoạn. Vui lòng thử lại sau.");
    });

    it("sends EXE bytes only with the explicit provider consent flag", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ ok: true }),
        });
        vi.stubGlobal("fetch", fetchMock);
        const file = new File([new Uint8Array([0x4d, 0x5a])], "sample.exe", {
            type: "application/octet-stream",
        });

        await new RealApiClient().sandboxExecutable(file, true);

        const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toBe("http://localhost:8000/v1/assess/file/exe-quick-scan");
        expect(request.method).toBe("POST");
        const form = request.body as FormData;
        expect(form.get("file")).toBe(file);
        expect(form.get("share_with_provider")).toBe("true");
    });

    it("retries Browser Lab anonymously when a stale session causes 401", async () => {
        window.localStorage.setItem(
            SESSION_STORAGE_KEY,
            JSON.stringify({ token: "expired-session" }),
        );
        const fetchMock = vi
            .fn()
            .mockResolvedValueOnce({
                ok: false,
                status: 401,
                statusText: "Unauthorized",
                text: async () => '{"detail":"expired"}',
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({ final_url: "https://example.com", canary: {} }),
            });
        vi.stubGlobal("fetch", fetchMock);

        await new RealApiClient().browserSandboxUrl("https://example.com");

        expect(fetchMock).toHaveBeenCalledTimes(2);
        expect(new Headers(fetchMock.mock.calls[0][1].headers).get("Authorization"))
            .toBe("Bearer expired-session");
        expect(new Headers(fetchMock.mock.calls[1][1].headers).get("Authorization"))
            .toBeNull();
        expect(window.localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    });

    it("keeps the EXE quick-scan form intact on the anonymous stale-session retry", async () => {
        window.localStorage.setItem(
            SESSION_STORAGE_KEY,
            JSON.stringify({ token: "expired-session" }),
        );
        const fetchMock = vi
            .fn()
            .mockResolvedValueOnce({ ok: false, status: 401, text: async () => "expired" })
            .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ ok: true }) });
        vi.stubGlobal("fetch", fetchMock);
        const file = new File([new Uint8Array([0x4d, 0x5a])], "sample.exe");

        await new RealApiClient().sandboxExecutable(file, false);

        expect(fetchMock).toHaveBeenCalledTimes(2);
        const first = fetchMock.mock.calls[0][1] as RequestInit;
        const second = fetchMock.mock.calls[1][1] as RequestInit;
        expect(first.body).toBe(second.body);
        expect((second.body as FormData).get("file")).toBe(file);
        expect((second.body as FormData).get("share_with_provider")).toBe("false");
        expect(new Headers(second.headers).get("Authorization")).toBeNull();
    });

    it("polls the provider report through the encoded data id endpoint", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ status: "completed", data_id: "job=1" }),
        });
        vi.stubGlobal("fetch", fetchMock);

        await new RealApiClient().getExecutableProviderReport("job=1");

        expect(fetchMock).toHaveBeenCalledWith(
            "http://localhost:8000/v1/assess/file/exe-quick-scan/provider/job%3D1",
            expect.objectContaining({ method: "GET" }),
        );
    });
});

describe("production API base resolution", () => {
    it("never falls back to localhost on the public Prewise domains", () => {
        expect(resolveApiBase(undefined, "www.prewise.site")).toBe("https://api.prewise.site");
        expect(resolveApiBase("", "prewise.site")).toBe("https://api.prewise.site");
        expect(resolveWsBase(undefined, "www.prewise.site")).toBe("wss://api.prewise.site");
    });

    it("keeps localhost defaults for local development and honors explicit overrides", () => {
        expect(resolveApiBase(undefined, "localhost")).toBe("http://localhost:8000");
        expect(resolveWsBase(undefined, "127.0.0.1")).toBe("ws://localhost:8000");
        expect(resolveApiBase("https://gateway.example/v1/", "www.prewise.site"))
            .toBe("https://gateway.example/v1");
    });
});
