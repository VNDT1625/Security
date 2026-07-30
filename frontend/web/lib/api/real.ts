/**
 * RealApiClient — hiện thực gọi REST `/v1/assess/*` và WebSocket `/v1/chat`.
 *
 * Đây là khung (scaffold) type-safe hiện thực đầy đủ interface `ApiClient`
 * bằng `fetch` (REST) + `WebSocket` (chat streaming). Nó KHÔNG phụ thuộc vào
 * một backend đang chạy để biên dịch; khi Security Gateway sẵn sàng và
 * `NEXT_PUBLIC_API_MODE=real`, UI dùng client này mà không cần sửa mã.
 *
 * Base URL đọc từ biến môi trường (có mặc định cho môi trường phát triển):
 *   - `NEXT_PUBLIC_API_BASE_URL` (mặc định `http://localhost:8000`)
 *   - `NEXT_PUBLIC_WS_BASE_URL`  (mặc định `ws://localhost:8000`)
 *
 * Ánh xạ contract backend (§7 API Contract của design.md + mcp-tool-schema):
 *   AssessResponse{ risk_level, confidence, reasons, evidence, model_version,
 *   latency_ms, risk_score(0..1), request_id } → AssessResult{ score(0..100),
 *   riskLevel, confidence, reasons, evidence, ... }.
 *
 * Nguyên tắc nhất quán: `riskLevel` LUÔN được tính lại từ `score` bằng
 * `getRiskLevel(score).key` (nguồn duy nhất), bất kể backend trả `risk_level`
 * dạng gì — bảo đảm bất biến `riskLevel === getRiskLevel(score).key`.
 *
 * _Requirements: 16.2, 16.3_
 */

import type { ApiClient } from "@/lib/api/client";
import {
    fetchWithAnonymousSessionFallback,
    readStoredAccessToken,
} from "@/lib/auth-session";
import { getRiskLevel } from "@/lib/risk";
import type {
    ApiKeyInfo,
    AssessMetadata,
    AssessResult,
    BrowserSandboxResult,
    ExeSandboxResult,

    ExeProviderResult,
    FeedbackInput,
    FeedbackReceipt,
    ChatChunk,
    ChatFinal,
    ChatRequest,
    CreateReportShareInput,
    CreatedReportShare,
    ContextualAnalysis,
    Credentials,
    Evidence,
    PlanInfo,
    QuotaInfo,
    PublicReportShare,
    PhoneAssessResult,
    GmailMessagePreview,
    GmailMessageSummary,
    GmailStatus,
    PasswordChangeInput,
    PasswordResetRequestResult,
    RegisterInput,
    SandboxResult,
    ScanRecord,
    ScanRecordDetail,
    Session,
    Severity,
    UserProfile,
    UserAISettings,
    UserAISettingsInput,
} from "@/lib/types";
import { trustedPopularResult } from "@/lib/trusted-popular-domains";

// ---------------------------------------------------------------------------
// Cấu hình base URL
// ---------------------------------------------------------------------------

const DEFAULT_API_BASE = "http://localhost:8000";
const DEFAULT_WS_BASE = "ws://localhost:8000";
const PRODUCTION_API_BASE = "https://api.prewise.site";
const PRODUCTION_WS_BASE = "wss://api.prewise.site";
const PRODUCTION_WEB_HOSTS = new Set(["prewise.site", "www.prewise.site"]);

/** Bỏ dấu `/` thừa ở cuối để nối path an toàn. */
function trimTrailingSlash(url: string): string {
    return url.replace(/\/+$/, "");
}

export function resolveApiBase(configured: string | undefined, hostname: string): string {
    const fallback = PRODUCTION_WEB_HOSTS.has(hostname.toLowerCase())
        ? PRODUCTION_API_BASE
        : DEFAULT_API_BASE;
    return trimTrailingSlash(configured?.trim() || fallback);
}

export function resolveWsBase(configured: string | undefined, hostname: string): string {
    const fallback = PRODUCTION_WEB_HOSTS.has(hostname.toLowerCase())
        ? PRODUCTION_WS_BASE
        : DEFAULT_WS_BASE;
    return trimTrailingSlash(configured?.trim() || fallback);
}

function browserHostname(): string {
    return typeof window === "undefined" ? "" : window.location.hostname;
}

function getApiBase(): string {
    return resolveApiBase(process.env.NEXT_PUBLIC_API_BASE_URL, browserHostname());
}

function getWsBase(): string {
    return resolveWsBase(process.env.NEXT_PUBLIC_WS_BASE_URL, browserHostname());
}

// ---------------------------------------------------------------------------
// Kiểu response phía backend (khớp §7 API Contract + mcp-tool-schema)
// ---------------------------------------------------------------------------

/** Mức rủi ro backend trả về (5 mức), khác với 3 mức của frontend. */
type BackendRiskLevel = "safe" | "low" | "medium" | "high" | "critical";

/** Evidence dạng backend (severity gồm cả "info"). */
interface BackendEvidence {
    source: string;
    message: string;
    severity: string;
    feature?: string | null;
    contribution?: number | null;
}

/**
 * Hình dạng phản hồi đánh giá của backend. Một số trường là tùy chọn để
 * dung nạp cả `AssessResponse` (design.md §7) lẫn schema MCP (`risk_score`
 * 0..1, `request_id`).
 */
interface BackendAssessResponse {
    /** Điểm rủi ro chuẩn hóa 0..1 (schema MCP). */
    risk_score?: number;
    /** Mức rủi ro 5 bậc (design.md §7). */
    risk_level?: BackendRiskLevel | string;
    confidence?: number;
    reasons?: string[];
    evidence?: BackendEvidence[];
    explanation?: string;
    model_version?: string;
    latency_ms?: number;
    request_id?: string;
    analysis_coverage?: Record<string, string>;
    message_metadata?: Record<string, unknown>;
    embedded_url_assessments?: Array<Record<string, unknown>>;
    contextual_analysis?: ContextualAnalysis;
    risk_core?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Helpers ánh xạ backend → frontend
// ---------------------------------------------------------------------------

const VALID_SEVERITIES: readonly Severity[] = [
    "info",
    "low",
    "medium",
    "high",
    "critical",
];

/** Chuẩn hóa severity backend → Severity frontend (mặc định "info"). */
function normalizeSeverity(severity: string | undefined): Severity {
    if (severity && (VALID_SEVERITIES as string[]).includes(severity)) {
        return severity as Severity;
    }
    return "info";
}

/** Map một BackendEvidence → Evidence frontend, loại bỏ null. */
function mapEvidence(raw: BackendEvidence): Evidence {
    const evidence: Evidence = {
        source: raw.source ?? "unknown",
        message: raw.message ?? "",
        severity: normalizeSeverity(raw.severity),
    };
    if (raw.feature != null) {
        evidence.feature = raw.feature;
    }
    if (typeof raw.contribution === "number" && Number.isFinite(raw.contribution)) {
        evidence.contribution = raw.contribution;
    }
    return evidence;
}

/**
 * Điểm đại diện khi backend chỉ trả `risk_level` (không có `risk_score`).
 * Chọn giá trị nằm giữa khoảng của mỗi mức theo thang frontend.
 */
function scoreFromRiskLevel(level: string | undefined): number {
    switch (level) {
        case "safe":
            return 10; // 0..39 → safe
        case "low":
            return 30; // vẫn thuộc safe theo thang 3 bậc frontend
        case "medium":
            return 55; // 40..69 → warn
        case "high":
            return 80; // 70..100 → danger
        case "critical":
            return 95; // danger
        default:
            return 0;
    }
}

/** Kẹp một số về khoảng [min, max]. */
function clamp(value: number, min: number, max: number): number {
    return Math.min(max, Math.max(min, value));
}

/**
 * Ánh xạ phản hồi backend → `AssessResult` của frontend.
 *
 * - `score`: ưu tiên `risk_score`(0..1)×100; nếu thiếu, suy ra từ `risk_level`.
 * - `riskLevel`: LUÔN tính lại bằng `getRiskLevel(score).key` để giữ bất biến
 *   `riskLevel === getRiskLevel(score).key`.
 * - `confidence`: kẹp về [0,1].
 */
function mapAssessResponse(
    raw: BackendAssessResponse,
    modality: "url" | "email" | "sms" | "text",
): AssessResult {
    const rawScore =
        typeof raw.risk_score === "number" && Number.isFinite(raw.risk_score)
            ? raw.risk_score * 100
            : scoreFromRiskLevel(raw.risk_level);

    const score = clamp(Math.round(rawScore), 0, 100);
    const riskLevel = getRiskLevel(score).key;

    const confidence =
        typeof raw.confidence === "number" && Number.isFinite(raw.confidence)
            ? clamp(raw.confidence, 0, 1)
            : 0;

    const result: AssessResult = {
        score,
        riskLevel,
        confidence,
        reasons: Array.isArray(raw.reasons) ? raw.reasons : [],
        evidence: Array.isArray(raw.evidence) ? raw.evidence.map(mapEvidence) : [],
        modality,
        requestId: raw.request_id ?? generateRequestId(),
    };

    if (typeof raw.explanation === "string") {
        result.explanation = raw.explanation;
    }
    if (typeof raw.model_version === "string") {
        result.modelVersion = raw.model_version;
    }
    if (typeof raw.latency_ms === "number") {
        result.latencyMs = raw.latency_ms;
    }
    if (raw.analysis_coverage) result.analysisCoverage = raw.analysis_coverage;
    if (raw.message_metadata) result.messageMetadata = raw.message_metadata;
    if (raw.embedded_url_assessments) result.embeddedUrlAssessments = raw.embedded_url_assessments;
    if (raw.contextual_analysis) result.contextualAnalysis = raw.contextual_analysis;
    if (raw.risk_core) result.riskCore = raw.risk_core;

    return result;
}

/** Sinh request id dự phòng khi backend không trả (crypto khi có sẵn). */
function generateRequestId(): string {
    const g = globalThis as { crypto?: { randomUUID?: () => string } };
    if (g.crypto?.randomUUID) {
        return g.crypto.randomUUID();
    }
    return `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

function apiErrorFallback(status: number): string {
    if (status === 429) {
        return "Bạn thao tác quá nhanh. Vui lòng thử lại sau.";
    }
    if (status >= 500) {
        return "Hệ thống đang tạm thời gián đoạn. Vui lòng thử lại sau.";
    }
    return "Không thể hoàn tất yêu cầu. Vui lòng kiểm tra thông tin và thử lại.";
}

function apiErrorMessage(rawBody: string, status: number): string {
    const body = rawBody.trim();
    if (body) {
        try {
            const payload = JSON.parse(body) as { detail?: unknown; message?: unknown };
            if (typeof payload.detail === "string" && payload.detail.trim()) {
                return payload.detail.trim();
            }
            if (typeof payload.message === "string" && payload.message.trim()) {
                return payload.message.trim();
            }
        } catch {
            // Chỉ hiển thị body dạng text ngắn; không đưa HTML/proxy dump ra UI.
            if (!body.startsWith("<") && body.length <= 300) {
                return body;
            }
        }
    }
    return apiErrorFallback(status);
}

async function throwApiError(response: Response): Promise<never> {
    const body = await response.text().catch(() => "");
    throw new Error(apiErrorMessage(body, response.status));
}

/**
 * Gửi một yêu cầu JSON và trả về body đã parse.
 *
 * @throws {Error} khi phản hồi không thành công (status ngoài 2xx).
 */
async function requestJson<TResponse>(
    path: string,
    init: RequestInit,
): Promise<TResponse> {
    const url = `${getApiBase()}${path}`;
    const response = await fetch(url, {
        ...init,
        headers: {
            "Content-Type": "application/json",
            ...(init.headers ?? {}),
        },
    });

    if (!response.ok) {
        return throwApiError(response);
    }

    return (await response.json()) as TResponse;
}

async function requestAnonymousAssessmentJson<TResponse>(
    path: string,
    init: RequestInit,
): Promise<TResponse> {
    const response = await fetchWithAnonymousSessionFallback(`${getApiBase()}${path}`, {
        ...init,
        headers: {
            "Content-Type": "application/json",
            ...(init.headers ?? {}),
        },
    });
    if (!response.ok) {
        return throwApiError(response);
    }
    return response.json() as Promise<TResponse>;
}

function withAuthentication(init: RequestInit): RequestInit {
    const token = readStoredAccessToken();
    if (!token) return init;

    return {
        ...init,
        headers: {
            ...(init.headers ?? {}),
            Authorization: `Bearer ${token}`,
        },
    };
}

// ---------------------------------------------------------------------------
// WebSocket message shapes cho `/v1/chat`
// ---------------------------------------------------------------------------

/**
 * Thông điệp phía server gửi qua WS chat. Mỗi message có `type` để phân biệt
 * đoạn delta (token) với thông điệp kết thúc (kèm assessment tùy chọn).
 */
interface WsChatMessage {
    type: "delta" | "final" | "error";
    delta?: string;
    message_id?: string;
    assessment?: BackendAssessResponse;
    legal_answer?: import("@/lib/types").LegalAnswerResult;
    modality?: "url" | "email" | "sms" | "text" | "legal";
    error?: string;
}

// ---------------------------------------------------------------------------
// RealApiClient
// ---------------------------------------------------------------------------

export class RealApiClient implements ApiClient {
    /** Đánh giá rủi ro cho một URL qua REST `POST /v1/assess/url`.
     *  Khớp contract gateway: body `{ url, context }`. */
    async assessUrl(url: string): Promise<AssessResult> {
        const trusted = trustedPopularResult(url);
        if (trusted) return trusted;
        const raw = await requestJson<BackendAssessResponse>("/v1/assess/url", {
            ...withAuthentication({ method: "POST" }),
            body: JSON.stringify({ url, context: "" }),
        });
        return mapAssessResponse(raw, "url");
    }

    async sandboxUrl(url: string): Promise<SandboxResult> {
        return requestJson<SandboxResult>(
            "/v1/assess/url/sandbox",
            withAuthentication({
                method: "POST",
                body: JSON.stringify({ url }),
            }),
        );
    }

    /** Đánh giá rủi ro cho văn bản/email qua REST `POST /v1/assess/text`.
     *  Khớp contract gateway: body `{ text, modality, metadata }`. */
    async browserSandboxUrl(url: string): Promise<BrowserSandboxResult> {
        return requestAnonymousAssessmentJson<BrowserSandboxResult>(
            "/v1/assess/url/browser-sandbox",
            {
                method: "POST",
                body: JSON.stringify({ url, canary_mode: "dry_run" }),
            },
        );
    }

    async sandboxExecutable(file: File, shareWithProvider = false): Promise<ExeSandboxResult> {
        const form = new FormData();
        form.append("file", file);
        form.append("share_with_provider", shareWithProvider ? "true" : "false");
        const response = await fetchWithAnonymousSessionFallback(
            `${getApiBase()}/v1/assess/file/exe-quick-scan`,
            { method: "POST", body: form },
        );
        if (!response.ok) throw new Error(`Kiểm thử EXE thất bại: ${response.status} — ${await response.text()}`);
        return response.json() as Promise<ExeSandboxResult>;
    }
    async getExecutableProviderReport(dataId: string): Promise<ExeProviderResult> {
        return requestAnonymousAssessmentJson<ExeProviderResult>(
            `/v1/assess/file/exe-quick-scan/provider/${encodeURIComponent(dataId)}`,
            { method: "GET" },
        );
    }



    async assessText(
        text: string,
        metadata?: AssessMetadata,
    ): Promise<AssessResult> {
        const rawModality: "url" | "email" | "sms" | "text" = metadata?.modality ?? "email";
        // Gateway chỉ nhận modality "email" | "text" | "sms" cho endpoint text.
        const modality: "email" | "sms" | "text" = rawModality === "url" ? "text" : rawModality;
        const raw = await requestJson<BackendAssessResponse>("/v1/assess/text", {
            ...withAuthentication({ method: "POST" }),
            body: JSON.stringify({
                text,
                modality,
                metadata: metadata ?? null,
                ai_context: metadata?.analysis_depth === "pro" ? "on" : "auto",
            }),
        });
        return mapAssessResponse(raw, modality);
    }

    async assessEmailFile(file: File, metadata: AssessMetadata = {}): Promise<AssessResult> {
        const form = new FormData();
        form.append("file", file);
        form.append("analysis_depth", String(metadata.analysis_depth || "balanced"));
        form.append("operator_context", String(metadata.operator_context || ""));
        form.append("ai_context", metadata.analysis_depth === "pro" ? "on" : "auto");
        const response = await fetch(
            `${getApiBase()}/v1/assess/email-file`,
            withAuthentication({ method: "POST", body: form }),
        );
        if (!response.ok) {
            throw new Error(`Phân tích Email thất bại: ${response.status} — ${await response.text()}`);
        }
        return mapAssessResponse(await response.json() as BackendAssessResponse, "email");
    }

    async assessPhone(
        phoneNumber: string,
        sms: string,
        countryHint = "VN",
        metadata: AssessMetadata = {},
    ): Promise<PhoneAssessResult> {
        const raw = await requestJson<{
            provider?: string;
            provider_status?: PhoneAssessResult["providerStatus"];
            reputation?: PhoneAssessResult["reputation"];
            metadata?: Record<string, unknown>;
            assessment?: BackendAssessResponse | null;
        }>("/v1/assess/phone", {
            ...withAuthentication({ method: "POST" }),
            body: JSON.stringify({
                phone_number: phoneNumber,
                country_hint: countryHint,
                sms,
                transcript: "",
                metadata: { ...metadata, modality: "sms" },
                ai_context: metadata.analysis_depth === "pro" ? "on" : "auto",
            }),
        });
        return {
            provider: raw.provider ?? "",
            providerStatus: raw.provider_status ?? "unavailable",
            reputation: raw.reputation ?? null,
            metadata: raw.metadata ?? {},
            assessment: raw.assessment ? mapAssessResponse(raw.assessment, "sms") : null,
        };
    }

    async getGmailStatus(): Promise<GmailStatus> {
        return requestJson<GmailStatus>(
            "/v1/integrations/gmail/status",
            withAuthentication({ method: "GET" }),
        );
    }

    async connectGmail(): Promise<{authUrl: string}> {
        return requestJson<{authUrl: string}>(
            "/v1/integrations/gmail/connect",
            withAuthentication({ method: "POST" }),
        );
    }

    async listGmailMessages(query = "", label = ""): Promise<GmailMessageSummary[]> {
        const params = new URLSearchParams();
        params.set("limit", "30");
        if (query.trim()) params.set("q", query.trim());
        if (label) params.set("label", label);
        const raw = await requestJson<{messages: GmailMessageSummary[]}>(
            `/v1/integrations/gmail/messages?${params.toString()}`,
            withAuthentication({ method: "GET" }),
        );
        return raw.messages;
    }

    async getGmailMessagePreview(messageId: string): Promise<GmailMessagePreview> {
        return requestJson<GmailMessagePreview>(
            `/v1/integrations/gmail/messages/${encodeURIComponent(messageId)}/preview`,
            withAuthentication({ method: "GET" }),
        );
    }

    async assessGmailMessage(messageId: string, metadata: AssessMetadata = {}): Promise<AssessResult> {
        const raw = await requestJson<BackendAssessResponse>(
            `/v1/integrations/gmail/messages/${encodeURIComponent(messageId)}/assess`,
            {
                ...withAuthentication({ method: "POST" }),
                body: JSON.stringify({
                    analysis_depth: metadata.analysis_depth || "balanced",
                    operator_context: metadata.operator_context || "",
                }),
            },
        );
        return mapAssessResponse(raw, "email");
    }

    async disconnectGmail(): Promise<void> {
        await requestJson<{disconnected: boolean}>(
            "/v1/integrations/gmail/connection",
            withAuthentication({ method: "DELETE" }),
        );
    }

    /**
     * Mở luồng chat qua WebSocket `${wsBase}/v1/chat`.
     *
     * - Kết nối WS, gửi `payload` một lần khi mở.
     * - Yield từng `ChatChunk` (delta) khi message tới.
     * - Trả về `ChatFinal` (kèm assessment nếu có) khi nhận message `final`
     *   hoặc khi kết nối đóng bình thường.
     * - Ném lỗi khi kết nối lỗi/đóng bất thường để hook hiển thị "mất kết nối".
     */
    async *openChatStream(
        payload: ChatRequest,
    ): AsyncGenerator<ChatChunk, ChatFinal, void> {
        const wsUrl = `${getWsBase()}/v1/chat`;
        const socket = new WebSocket(wsUrl);

        // Hàng đợi delta + cơ chế đánh thức generator khi có sự kiện mới.
        const queue: ChatChunk[] = [];
        let finalResult: ChatFinal | null = null;
        let streamError: Error | null = null;
        let closed = false;
        let notify: (() => void) | null = null;

        const wake = (): void => {
            if (notify) {
                const fn = notify;
                notify = null;
                fn();
            }
        };

        const waitForEvent = (): Promise<void> =>
            new Promise<void>((resolve) => {
                notify = resolve;
            });

        socket.onopen = () => {
            try {
                const accessToken = readStoredAccessToken();
                socket.send(JSON.stringify({
                    ...payload,
                    ...(accessToken ? { access_token: accessToken } : {}),
                }));
            } catch (err) {
                streamError = err instanceof Error ? err : new Error(String(err));
                wake();
            }
        };

        socket.onmessage = (event: MessageEvent) => {
            try {
                const msg = JSON.parse(String(event.data)) as WsChatMessage;
                if (msg.type === "delta" && typeof msg.delta === "string") {
                    queue.push({ delta: msg.delta });
                } else if (msg.type === "final") {
                    finalResult = {
                        messageId: msg.message_id ?? generateRequestId(),
                        ...(msg.assessment
                            ? {
                                assessment: mapAssessResponse(
                                    msg.assessment,
                                    msg.modality === "legal" ? "text" : (msg.modality ?? "text"),
                                ),
                            }
                            : {}),
                        ...(msg.legal_answer ? { legalAnswer: msg.legal_answer } : {}),
                    };
                } else if (msg.type === "error") {
                    streamError = new Error(
                        msg.error ?? "Lỗi luồng chat từ máy chủ",
                    );
                }
            } catch (err) {
                streamError = err instanceof Error ? err : new Error(String(err));
            }
            wake();
        };

        socket.onerror = () => {
            streamError = new Error("Mất kết nối tới máy chủ chat (WebSocket error)");
            wake();
        };

        socket.onclose = (event: CloseEvent) => {
            closed = true;
            if (!event.wasClean && finalResult === null && streamError === null) {
                streamError = new Error(
                    `Kết nối chat bị đóng bất thường (mã ${event.code})`,
                );
            }
            wake();
        };

        try {
            // Vòng lặp tiêu thụ: phát delta, dừng khi có final/error/close.
            // eslint-disable-next-line no-constant-condition
            while (true) {
                while (queue.length > 0) {
                    yield queue.shift() as ChatChunk;
                }

                if (streamError !== null) {
                    throw streamError;
                }
                if (finalResult !== null && queue.length === 0) {
                    return finalResult;
                }
                if (closed) {
                    // Đóng sạch mà không có final rõ ràng → trả final rỗng.
                    return finalResult ?? { messageId: generateRequestId() };
                }

                await waitForEvent();
            }
        } finally {
            if (
                socket.readyState === WebSocket.OPEN ||
                socket.readyState === WebSocket.CONNECTING
            ) {
                socket.close();
            }
        }
    }

    /** Đăng nhập qua REST `POST /v1/auth/login`. */
    async login(cred: Credentials): Promise<Session> {
        return requestJson<Session>("/v1/auth/login", {
            method: "POST",
            body: JSON.stringify(cred),
        });
    }

    /** Đăng ký qua REST `POST /v1/auth/register`. */
    async register(cred: RegisterInput): Promise<Session> {
        return requestJson<Session>("/v1/auth/register", {
            method: "POST",
            body: JSON.stringify(cred),
        });
    }

    async requestPasswordReset(email: string): Promise<PasswordResetRequestResult> {
        return requestJson<PasswordResetRequestResult>("/v1/auth/password/forgot", {method: "POST", body: JSON.stringify({email})});
    }

    async resetPassword(token: string, newPassword: string): Promise<void> {
        await requestJson<unknown>("/v1/auth/password/reset", {method: "POST", body: JSON.stringify({token,newPassword})});
    }

    /** Đăng xuất qua REST `POST /v1/auth/logout`. */
    async logout(): Promise<void> {
        await requestJson<unknown>(
            "/v1/auth/logout",
            withAuthentication({ method: "POST" }),
        );
    }

    /** Lấy thông tin gói qua REST `GET /v1/account/plan`. */
    async getPlan(): Promise<PlanInfo> {
        return requestJson<PlanInfo>(
            "/v1/account/plan",
            withAuthentication({ method: "GET" }),
        );
    }

    /** Lấy lịch sử quét qua REST `GET /v1/account/history`. */
    async getScanHistory(): Promise<ScanRecord[]> {
        return requestJson<ScanRecord[]>(
            "/v1/account/history",
            withAuthentication({ method: "GET" }),
        );
    }

    /** Lấy API/MCP key qua REST `GET /v1/account/api-key`. */
    async getApiKey(): Promise<ApiKeyInfo> {
        return requestJson<ApiKeyInfo>(
            "/v1/account/api-key",
            withAuthentication({ method: "GET" }),
        );
    }

    /** Tạo lại API/MCP key qua REST `POST /v1/account/api-key/rotate`. */
    async rotateApiKey(): Promise<ApiKeyInfo> {
        return requestJson<ApiKeyInfo>(
            "/v1/account/api-key/rotate",
            withAuthentication({ method: "POST" }),
        );
    }

    async cancelSubscription(): Promise<PlanInfo> {
        return requestJson<PlanInfo>(
            "/v1/account/subscription/cancel",
            withAuthentication({ method: "POST" }),
        );
    }

    async updateProfile(displayName: string): Promise<UserProfile> {
        return requestJson<UserProfile>(
            "/v1/account/profile",
            withAuthentication({
                method: "PATCH",
                body: JSON.stringify({ displayName }),
            }),
        );
    }

    async changePassword(input: PasswordChangeInput): Promise<void> {
        await requestJson<unknown>(
            "/v1/account/password",
            withAuthentication({ method: "POST", body: JSON.stringify(input) }),
        );
    }

    async getQuota(): Promise<QuotaInfo> {
        return requestJson<QuotaInfo>(
            "/v1/account/quota",
            withAuthentication({ method: "GET" }),
        );
    }

    async getScanHistoryDetail(requestId: string): Promise<ScanRecordDetail> {
        return requestJson<ScanRecordDetail>(
            `/v1/account/history/${encodeURIComponent(requestId)}`,
            withAuthentication({ method: "GET" }),
        );
    }

    async deleteScanHistory(requestId: string): Promise<{deleted: number}> {
        return requestJson<{deleted: number}>(
            `/v1/account/history/${encodeURIComponent(requestId)}`,
            withAuthentication({ method: "DELETE" }),
        );
    }

    async clearScanHistory(): Promise<{deleted: number}> {
        return requestJson<{deleted: number}>(
            "/v1/account/history",
            withAuthentication({ method: "DELETE" }),
        );
    }

    async submitFeedback(input: FeedbackInput): Promise<FeedbackReceipt> {
        return requestJson<FeedbackReceipt>(
            "/v1/feedback",
            withAuthentication({ method: "POST", body: JSON.stringify(input) }),
        );
    }

    async createReportShare(input: CreateReportShareInput): Promise<CreatedReportShare> {
        return requestJson<CreatedReportShare>(
            "/v1/report-shares",
            withAuthentication({ method: "POST", body: JSON.stringify(input) }),
        );
    }

    async getPublicReportShare(token: string): Promise<PublicReportShare> {
        return requestJson<PublicReportShare>(
            `/v1/report-shares/public/${encodeURIComponent(token)}`,
            { method: "GET" },
        );
    }

    async revokeReportShare(shareId: string): Promise<void> {
        const path = `/v1/report-shares/${encodeURIComponent(shareId)}`;
        const init = withAuthentication({ method: "DELETE" });
        const response = await fetch(`${getApiBase()}${path}`, {
            ...init,
            headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
        });
        if (!response.ok) throw new Error(`Yêu cầu ${path} thất bại: ${response.status} ${response.statusText}`);
    }

    async getAISettings(): Promise<UserAISettings> {
        return requestJson<UserAISettings>(
            "/v1/account/ai-settings",
            withAuthentication({ method: "GET" }),
        );
    }

    async updateAISettings(input: UserAISettingsInput): Promise<UserAISettings> {
        return requestJson<UserAISettings>(
            "/v1/account/ai-settings",
            withAuthentication({ method: "PUT", body: JSON.stringify(input) }),
        );
    }

    async testAISettings(): Promise<{ok: boolean; modelAvailable: boolean; modelsCount: number}> {
        return requestJson<{ok: boolean; modelAvailable: boolean; modelsCount: number}>(
            "/v1/account/ai-settings/test",
            withAuthentication({ method: "POST" }),
        );
    }
}
