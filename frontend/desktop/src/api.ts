export type RiskLevel = "safe" | "warn" | "danger";
export type AnalysisDepth = "quick" | "balanced" | "deep" | "pro";
export interface Evidence {
  source: string;
  message: string;
  severity: string;
  feature?: string;
  contribution?: number;
}
export interface ScoreLayer {
  layer: string;
  score: number;
  status: "completed" | "skipped" | "unavailable";
  summary: string;
  signals: number;
}
export interface DangerousCriterion {
  criterionId: number;
  name: string;
  contribution: number;
  reason: string;
}
export interface AccessAnalysis {
  performed: boolean;
  analysisMode: string;
  verdict: string;
  warning: string;
  causes: string[];
  observedEffects: string[];
  finalUrl: string;
}
export interface SandboxSummary {
  analysisMode: string;
  behaviors: number;
  redirects: number;
  scripts: number;
  networkCalls: number;
  domModifications: number;
  error?: string;
}
export interface SmsAssessment {
  assessment: Assessment;
  provider: string;
  providerStatus: string;
  reputation: string | null;
  phoneMetadata: Record<string, unknown>;
}
export interface Assessment {
  score: number;
  riskLevel: RiskLevel;
  decision?: string;
  confidence: number;
  reasons: string[];
  evidence: Evidence[];
  explanation?: string;
  requestId: string;
  latencyMs?: number;
  threatLevel?: string;
  cacheStatus?: string;
  deepAnalysisRecommended?: boolean;
  autoDeepAnalysis?: boolean;
  scoreLayers?: ScoreLayer[];
  dangerousCriteria?: DangerousCriterion[];
  accessAnalysis?: AccessAnalysis;
  sandbox?: SandboxSummary;
}
export interface MailItem {
  id: string;
  sender: string;
  email: string;
  subject: string;
  preview: string;
  content: string;
  date?: string;
  labelIds?: string[];
  attachments?: { filename: string; contentType: string; size: number }[];
  linksRemoved?: number;
  source?: "gmail" | "file";
  localFile?: File;
  score?: number;
  result?: Assessment;
}
export interface UserSession {
  token: string;
  user: { id: string; email: string; displayName: string; role?: string };
  plan: { tier: string; label: string; dailyScanLimit: number };
}
export interface UserProfile {
  id: string;
  email: string;
  displayName: string;
  avatarUrl?: string | null;
  role: string;
}
export type FeedbackType = "false_positive" | "false_negative" | "report_site";
export type FeedbackReason =
  | "incorrect_verdict"
  | "missed_threat"
  | "suspicious_site"
  | "incorrect_evidence"
  | "other";
export interface FeedbackInput {
  requestId: string;
  feedbackType: FeedbackType;
  reason: FeedbackReason;
  details?: string;
  idempotencyKey?: string;
}
export interface FeedbackReceipt {
  id: string;
  requestId: string;
  feedbackType: FeedbackType;
  reason: FeedbackReason;
  status: "received" | string;
  createdAt: string;
}
export interface AdminOverview {
  metrics: {
    usersTotal: number;
    activeUsers: number;
    scansTotal: number;
    dangerousScans: number;
    averageLatencyMs: number;
  };
  recentScans: {
    id: string;
    createdAt: string;
    modality: string;
    riskLevel: RiskLevel;
    score: number;
    target: string;
  }[];
  recentJobs: {
    id: string;
    type: string;
    status: string;
    progress: number;
    message?: string;
    createdAt: string;
  }[];
  models: {
    id: string;
    name: string;
    modality: string;
    status: string;
    f1?: number;
    accuracy?: number;
    createdAt: string;
  }[];
}
export interface AdminUser {
  id: string;
  displayName: string;
  email: string;
  role: string;
  status: "active" | "suspended";
  currentPlan: string;
  subscriptionStatus?: string | null;
  scansTotal: number;
  createdAt: string;
  lastLoginAt?: string | null;
}
export interface AdminFinance {
  summary: {
    totalRevenueVnd: number;
    revenueLast30DaysVnd: number;
    pendingAmountVnd: number;
    paidOrders: number;
    pendingOrders: number;
    activeSubscriptions: number;
  };
  planDistribution: Record<string, number>;
  monthlyRevenue: { month: string; amountVnd: number }[];
  plans: {
    tier: string;
    label: string;
    monthlyPriceVnd?: number | null;
    yearlyPriceVnd?: number | null;
  }[];
  recentOrders: {
    id: string;
    reference: string;
    email: string;
    amountVnd: number;
    planTier?: string | null;
    billingPeriod?: string | null;
    status: string;
    provider: string;
    paidAt?: string | null;
    createdAt: string;
  }[];
}
export interface AdminSpec {
  id: string;
  name: string;
  path: string;
  tasksTotal: number;
  tasksCompleted: number;
  tasksRemaining: number;
}
export interface AdminJobStatus {
  specId?: string;
  status: "idle" | "running" | "training" | "completed" | "error";
  currentTask?: string;
  currentModel?: string;
  progress: number;
  message?: string;
  results?: { model: string; f1_score?: number; accuracy?: number }[];
}
export interface AIWeightSettings {
  percent: number;
  minPercent: number;
  maxPercent: number;
  absoluteMaxPercent: number;
  mode: "shadow" | "weighted";
}
export interface LLMProviderSettings {
  provider: "auto" | "adapter" | "local" | "endpoint";
  baseUrl: string;
  model: string;
  apiKeyConfigured: boolean;
  configured: boolean;
  source: "environment" | "database";
  allowedProviders: Array<"adapter" | "local" | "endpoint">;
  allowedModels: string[];
}
export type UserAIProvider = "adapter" | "local" | "endpoint";
export interface UserAISettings {
  provider: "auto" | UserAIProvider;
  baseUrl: string;
  model: string;
  apiKeyConfigured: boolean;
  configured: boolean;
  source: "environment" | "database" | "account";
  allowedProviders: UserAIProvider[];
  allowedModels: string[];
  percent: number;
  minPercent: number;
  maxPercent: number;
  weightPercent: number;
  weightEligible: boolean;
  weightSource: "global" | "account";
}
export interface UserAISettingsInput {
  provider: UserAIProvider;
  baseUrl: string;
  model: string;
  apiKey?: string;
  clearApiKey?: boolean;
  weightPercent?: number;
}
export interface URLCacheSettings {
  enabled: boolean;
  ttlSeconds: number;
}
export interface OperationSettings {
  threatFeedSchedulerEnabled: boolean;
  openphishEnabled: boolean;
  operationalMaintenanceSchedulerEnabled: boolean;
}
export interface GmailStatus {
  configured: boolean;
  connected: boolean;
  address: string;
  status: string;
}
export interface GmailMessageSummary {
  id: string;
  threadId: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
  labelIds: string[];
}
export interface GmailMessagePreview {
  id: string;
  threadId: string;
  from: string;
  replyTo: string;
  subject: string;
  date: string;
  body: string;
  labelIds: string[];
  attachments: { filename: string; contentType: string; size: number }[];
  linksRemoved: number;
}
export type CloudSandboxMode = "auto" | "interactive";
export interface CloudSandboxSample {
  filename: string | null;
  sha256: string | null;
  size: number | null;
  status: string;
  report: Record<string, unknown>;
}
export interface CloudSandboxSession {
  id: string;
  tier: string;
  status: string;
  mode: CloudSandboxMode;
  phase: string;
  remoteUrl: string | null;
  remoteAvailable: boolean;
  remoteStatus: string;
  remoteUnavailableReason: string | null;
  expiresAt: string;
  readyAt: string | null;
  leaseMinutes?: number | null;
  leaseExpiresAt: string | null;
  cleanupState: string;
  terminationReason: string | null;
  error: string | null;
  sample: CloudSandboxSample;
}
export interface CloudSandboxStatus {
  session: CloudSandboxSession | null;
  recentSession?: CloudSandboxSession | null;
}
export interface CloudRemoteAccess {
  sessionId: string;
  mode: "interactive";
  remoteUrl: string;
  connectUrl: string;
  tokenExpiresAt: string;
  leaseExpiresAt: string;
  oneTime: true;
}

const PRODUCTION_API_BASE = "https://api.prewise.site";
const DEVELOPMENT_API_BASE = "http://localhost:8000";
const API_BASE = (
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? DEVELOPMENT_API_BASE : PRODUCTION_API_BASE)
).replace(/\/$/, "");
let sessionToken = "";
export const setSessionToken = (token: string | null) => {
  sessionToken = token || "";
};
export const apiBaseUrl = API_BASE;
const level = (score: number, decision: unknown = ""): RiskLevel => {
  const policy = String(decision || "").toUpperCase();
  if (["BLOCK", "SOFT_BLOCK", "HARD_BLOCK"].includes(policy)) return "danger";
  if (["WARN", "ASK_USER_CONFIRMATION", "REQUIRE_REVIEW"].includes(policy)) return "warn";
  if (policy === "ALLOW") return "safe";
  return score >= 70 ? "danger" : score >= 40 ? "warn" : "safe";
};

const normalize = (raw: Record<string, unknown>): Assessment => {
  const numeric = Number(raw.risk_score ?? raw.score ?? 0);
  const score = Math.max(0, Math.min(100, Math.round(numeric <= 1 ? numeric * 100 : numeric)));
  const decision = typeof raw.decision === "string" ? raw.decision : undefined;
  return {
    score,
    riskLevel: level(score, decision),
    decision,
    confidence: Number(raw.confidence ?? 0.85),
    reasons: Array.isArray(raw.reasons) ? (raw.reasons as string[]) : [],
    evidence: Array.isArray(raw.evidence) ? (raw.evidence as Evidence[]) : [],
    explanation: raw.explanation as string | undefined,
    requestId: (raw.request_id as string) || crypto.randomUUID(),
    latencyMs: raw.latency_ms as number | undefined,
  };
};

async function request<T>(
  path: string,
  body?: unknown,
  method = "POST",
  timeoutMs = 20_000,
): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError")
      throw new Error(`Core API không phản hồi sau ${Math.round(timeoutMs / 1000)} giây.`);
    throw new Error("Không thể kết nối Core API. Hãy kiểm tra backend đang chạy.");
  } finally {
    window.clearTimeout(timeout);
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const detail = Array.isArray(payload.detail)
      ? payload.detail
          .map((item: { msg?: string }) => item.msg || "Dữ liệu không hợp lệ")
          .join("; ")
      : payload.detail;
    throw new Error(detail || `Máy chủ phản hồi ${response.status}`);
  }
  const contentType = response.headers.get("content-type")?.toLowerCase() || "";
  if (!contentType.includes("application/json")) {
    throw new Error(
      "Core API trả về nội dung không hợp lệ. Hãy kiểm tra endpoint HTTPS hoặc quyền truy cập gateway.",
    );
  }
  return response.json() as Promise<T>;
}

export const login = (email: string, password: string) =>
  request<UserSession>("/v1/auth/login", { email, password });
export const register = (displayName: string, email: string, password: string) =>
  request<UserSession>("/v1/auth/register", { displayName, email, password });
export const logout = () => request<{ ok: boolean }>("/v1/auth/logout");
export const getProfile = () => request<UserProfile>("/v1/account/profile", undefined, "GET");
export const getUserAISettings = () =>
  request<UserAISettings>("/v1/account/ai-settings", undefined, "GET");
export const saveUserAISettings = (payload: UserAISettingsInput) =>
  request<UserAISettings>("/v1/account/ai-settings", payload, "PUT");
export const testUserAISettings = () =>
  request<{ ok: boolean; modelAvailable: boolean; modelsCount: number }>(
    "/v1/account/ai-settings/test",
    undefined,
    "POST",
    120_000,
  );
export const submitFeedback = (payload: FeedbackInput) =>
  request<FeedbackReceipt>("/v1/feedback", payload, "POST");
export const checkHealth = () => request<{ status: string }>("/v1/health", undefined, "GET");
const records = (value: unknown): Record<string, unknown>[] =>
  Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> => Boolean(item) && typeof item === "object",
      )
    : [];
const strings = (value: unknown): string[] => (Array.isArray(value) ? value.map(String) : []);
const text = (value: unknown, fallback = "") => (typeof value === "string" ? value : fallback);

function normalizeWebUrl(raw: Record<string, unknown>): Assessment {
  const numeric = Number(raw.risk_score ?? 0);
  const score = Math.max(0, Math.min(100, Math.round(numeric <= 1 ? numeric * 100 : numeric)));
  const decision = text(raw.decision);
  const riskLevel = level(score, decision);
  const ai =
    raw.ai_detection && typeof raw.ai_detection === "object"
      ? (raw.ai_detection as Record<string, unknown>)
      : {};
  const evidence = records(raw.evidence).map(
    (item): Evidence => ({
      source: text(item.source, "risk-core"),
      message: text(item.message ?? item.reason, "Backend phát hiện tín hiệu cần xem xét."),
      severity: text(item.severity, "medium"),
      feature: text(item.feature) || undefined,
      contribution: Number.isFinite(Number(item.contribution))
        ? Number(item.contribution)
        : undefined,
    }),
  );
  const accessRaw =
    raw.access_analysis && typeof raw.access_analysis === "object"
      ? (raw.access_analysis as Record<string, unknown>)
      : {};
  const accessAnalysis: AccessAnalysis = {
    performed: accessRaw.performed === true,
    analysisMode: text(accessRaw.analysis_mode, "not_run"),
    verdict: text(accessRaw.verdict, "unavailable"),
    warning: text(accessRaw.warning),
    causes: strings(accessRaw.causes),
    observedEffects: strings(accessRaw.observed_effects),
    finalUrl: text(accessRaw.final_url),
  };
  const sandboxRaw =
    raw.sandbox_report && typeof raw.sandbox_report === "object"
      ? (raw.sandbox_report as Record<string, unknown>)
      : null;
  const reasonsFromCore = strings(raw.reasons);
  const reasons = reasonsFromCore.length
    ? reasonsFromCore
    : evidence.map((item) => item.message);
  const defaultExplanation =
    riskLevel === "danger"
      ? "Không truy cập, không nhập mật khẩu, OTP hoặc thông tin thanh toán. Hãy xác minh qua kênh chính thức."
      : riskLevel === "warn"
        ? "Có tín hiệu cần xem xét. Hãy xác minh tên miền và nguồn gửi trước khi tiếp tục."
        : "Chưa thấy tín hiệu rủi ro nổi bật trong phạm vi các lớp đã kiểm tra.";
  return {
    score,
    riskLevel,
    decision: decision || undefined,
    confidence: Number(ai.confidence ?? 0.85),
    reasons,
    evidence,
    explanation: accessAnalysis.warning || defaultExplanation,
    requestId: text(raw.request_id) || crypto.randomUUID(),
    latencyMs: Number(raw.analysis_time_ms ?? 0),
    threatLevel: text(raw.threat_level),
    cacheStatus: text(raw.cache_status),
    deepAnalysisRecommended: raw.deep_analysis_recommended === true,
    autoDeepAnalysis: raw.auto_deep_analysis === true,
    scoreLayers: records(raw.score_layers).map(
      (item): ScoreLayer => ({
        layer: text(item.layer, "Lớp phân tích"),
        score: Number(item.score ?? 0),
        status: ["completed", "skipped", "unavailable"].includes(text(item.status))
          ? (text(item.status) as ScoreLayer["status"])
          : "completed",
        summary: text(item.summary),
        signals: Number(item.signals ?? 0),
      }),
    ),
    dangerousCriteria: records(raw.dangerous_criteria).map(
      (item): DangerousCriterion => ({
        criterionId: Number(item.criterion_id ?? 0),
        name: text(item.name, "Tiêu chí nguy hiểm"),
        contribution: Number(item.contribution ?? 0),
        reason: text(item.reason),
      }),
    ),
    accessAnalysis,
    sandbox: sandboxRaw
      ? {
          analysisMode: text(sandboxRaw.analysis_mode, "sandbox"),
          behaviors: records(sandboxRaw.behaviors).length,
          redirects: records(sandboxRaw.redirects).length,
          scripts: records(sandboxRaw.scripts_executed).length,
          networkCalls: records(sandboxRaw.network_calls).length,
          domModifications: records(sandboxRaw.dom_modifications).length,
          error: text(sandboxRaw.error) || undefined,
        }
      : undefined,
  };
}

/** Uses the same balanced URL-analysis contract as the web Analyze page. */
export const assessUrl = async (
  url: string,
  depth: AnalysisDepth = "balanced",
  operatorContext = "",
): Promise<Assessment> =>
  normalizeWebUrl(
    await request<Record<string, unknown>>(
      "/v1/demo/url/analyze",
      {
        url,
        deep_analysis: depth !== "quick",
        advanced_analysis: depth === "deep" || depth === "pro",
        llm_context: depth === "pro" ? operatorContext.trim() || undefined : undefined,
        ai_context: depth === "pro" ? "on" : "off",
        force_rescan: false,
      },
      "POST",
      120_000,
    ),
  );
export const assessEmail = async (
  content: string,
  depth: AnalysisDepth = "balanced",
  operatorContext = "",
): Promise<Assessment> =>
  normalize(
    await request<Record<string, unknown>>(
      "/v1/assess/text",
      {
        text: content,
        modality: "email",
        metadata: {
          source: "desktop_email_guard",
          locale: "vi",
          modality: "email",
          analysis_depth: depth,
          operator_context: depth === "pro" ? operatorContext.trim() || undefined : undefined,
          scopes: { spoofing: true, sensitive: true, manipulation: true },
        },
        ai_context: depth === "pro" ? "on" : "auto",
      },
      "POST",
      120_000,
    ),
  );
export async function assessSms(
  message: string,
  phoneNumber = "",
  depth: AnalysisDepth = "balanced",
  operatorContext = "",
): Promise<SmsAssessment> {
  const metadata = {
    source: "desktop_sms_guard",
    locale: "vi",
    modality: "sms",
    analysis_depth: depth,
    operator_context: depth === "pro" ? operatorContext.trim() || undefined : undefined,
    scopes: { spoofing: true, sensitive: true, manipulation: true },
  };
  const aiContext = depth === "pro" ? "on" : "auto";
  if (!phoneNumber.trim()) {
    const assessment = normalize(
      await request<Record<string, unknown>>(
        "/v1/assess/text",
        { text: message, modality: "sms", metadata, ai_context: aiContext },
        "POST",
        120_000,
      ),
    );
    return {
      assessment,
      provider: "",
      providerStatus: "not_requested",
      reputation: null,
      phoneMetadata: {},
    };
  }
  const raw = await request<Record<string, unknown>>(
    "/v1/assess/phone",
    {
      phone_number: phoneNumber.trim(),
      country_hint: "VN",
      sms: message,
      transcript: "",
      metadata,
      ai_context: aiContext,
    },
    "POST",
    120_000,
  );
  if (!raw.assessment || typeof raw.assessment !== "object")
    throw new Error("Backend không trả về kết quả đánh giá SMS.");
  return {
    assessment: normalize(raw.assessment as Record<string, unknown>),
    provider: text(raw.provider),
    providerStatus: text(raw.provider_status, "unavailable"),
    reputation: typeof raw.reputation === "string" ? raw.reputation : null,
    phoneMetadata:
      raw.metadata && typeof raw.metadata === "object"
        ? (raw.metadata as Record<string, unknown>)
        : {},
  };
}
export async function assessEmailFile(
  file: File,
  depth: AnalysisDepth = "balanced",
  operatorContext = "",
): Promise<Assessment> {
  const form = new FormData();
  form.append("file", file);
  form.append("analysis_depth", depth);
  form.append("operator_context", depth === "pro" ? operatorContext.trim() : "");
  form.append("ai_context", depth === "pro" ? "on" : "auto");
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 120_000);
  try {
    const response = await fetch(`${API_BASE}/v1/assess/email-file`, {
      method: "POST",
      signal: controller.signal,
      headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      body: form,
    });
    if (!response.ok) {
      const payload = (await response.json().catch(() => ({}))) as { detail?: string };
      throw new Error(payload.detail || `Phân tích Email thất bại: ${response.status}`);
    }
    return normalize((await response.json()) as Record<string, unknown>);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError")
      throw new Error("Core API không phản hồi sau 120 giây.");
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}
export const getGmailStatus = () =>
  request<GmailStatus>("/v1/integrations/gmail/status", undefined, "GET");
export const connectGmail = () => request<{ authUrl: string }>("/v1/integrations/gmail/connect");
export const listGmailMessages = async (query = "", label = "") => {
  const params = new URLSearchParams();
  if (query.trim()) params.set("q", query.trim());
  if (label) params.set("label", label);
  params.set("limit", "30");
  return (
    await request<{ messages: GmailMessageSummary[] }>(
      `/v1/integrations/gmail/messages?${params}`,
      undefined,
      "GET",
    )
  ).messages;
};
export const getGmailMessagePreview = (messageId: string) =>
  request<GmailMessagePreview>(
    `/v1/integrations/gmail/messages/${encodeURIComponent(messageId)}/preview`,
    undefined,
    "GET",
  );
export const assessGmailMessage = async (
  messageId: string,
  depth: AnalysisDepth = "balanced",
  operatorContext = "",
): Promise<Assessment> =>
  normalize(
    await request<Record<string, unknown>>(
      `/v1/integrations/gmail/messages/${encodeURIComponent(messageId)}/assess`,
      { analysis_depth: depth, operator_context: depth === "pro" ? operatorContext.trim() : "" },
      "POST",
      120_000,
    ),
  );
export const disconnectGmail = () =>
  request<{ disconnected: boolean }>("/v1/integrations/gmail/connection", undefined, "DELETE");
export const createCloudSandboxSession = (mode: CloudSandboxMode, leaseMinutes: 5 | 10) =>
  request<CloudSandboxSession>(
    "/v1/sandbox-cloud/sessions",
    {
      tier: "pro",
      mode,
      ...(mode === "interactive" ? { leaseMinutes } : {}),
    },
    "POST",
    30_000,
  );
export const getCloudSandboxSession = (sessionId: string) =>
  request<CloudSandboxSession>(
    `/v1/sandbox-cloud/sessions/${encodeURIComponent(sessionId)}`,
    undefined,
    "GET",
    30_000,
  );
export const getCloudSandboxStatus = () =>
  request<CloudSandboxStatus>("/v1/sandbox-cloud/status", undefined, "GET", 30_000);
export async function uploadCloudSandboxSample(
  sessionId: string,
  file: File,
): Promise<CloudSandboxSession> {
  const form = new FormData();
  form.append("file", file, file.name);
  form.append("consent", "true");
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 120_000);
  try {
    const response = await fetch(
      `${API_BASE}/v1/sandbox-cloud/sessions/${encodeURIComponent(sessionId)}/exe`,
      {
        method: "POST",
        signal: controller.signal,
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        body: form,
      },
    );
    if (!response.ok) {
      const payload = (await response.json().catch(() => ({}))) as { detail?: string };
      throw new Error(payload.detail || `Không thể gửi mẫu vào Cloud Lab (${response.status}).`);
    }
    return response.json() as Promise<CloudSandboxSession>;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("Cloud Lab không nhận xong tệp sau 120 giây.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}
export const stopCloudSandboxSession = (sessionId: string) =>
  request<{ ok: boolean; status: string; cleanupPending: boolean }>(
    `/v1/sandbox-cloud/sessions/${encodeURIComponent(sessionId)}`,
    undefined,
    "DELETE",
    30_000,
  );
export const issueCloudRemoteAccess = (sessionId: string) =>
  request<CloudRemoteAccess>(
    `/v1/sandbox-cloud/sessions/${encodeURIComponent(sessionId)}/remote-access`,
    undefined,
    "POST",
    30_000,
  );
export const getAdminOverview = () => request<AdminOverview>("/admin/overview", undefined, "GET");
export const getAdminUsers = () =>
  request<{ users: AdminUser[] }>("/admin/users", undefined, "GET");
export const getAdminFinance = () => request<AdminFinance>("/admin/finance", undefined, "GET");
export const setAdminUserStatus = (id: string, status: "active" | "suspended") =>
  request<{ id: string; status: string }>(`/admin/users/${id}/status`, { status }, "PATCH");
export const getAdminSpecs = () =>
  request<{ specs: AdminSpec[] }>("/admin/specs", undefined, "GET");
export const executeAdminSpec = (specId: string) =>
  request<{ jobId: string }>("/admin/specs/execute", { specId });
export const getAdminSpecStatus = (specId: string) =>
  request<AdminJobStatus>(`/admin/specs/${encodeURIComponent(specId)}/status`, undefined, "GET");
export const trainAdminModels = () =>
  request<{ jobId: string }>("/admin/models/train", {
    dataPath: "data/demo_text_training.csv",
    models: ["text"],
  });
export const getAdminTrainingStatus = () =>
  request<AdminJobStatus>("/admin/models/train/status", undefined, "GET");
export const getAIWeight = () =>
  request<AIWeightSettings>("/admin/settings/ai-context-weight", undefined, "GET");
export const saveAIWeight = (percent: number, minPercent?: number, maxPercent?: number) =>
  request<AIWeightSettings>("/admin/settings/ai-context-weight", { percent, minPercent, maxPercent }, "PUT");
export const getLLMProvider = () =>
  request<LLMProviderSettings>("/admin/settings/llm-provider", undefined, "GET");
export const saveLLMProvider = (payload: {
  provider: LLMProviderSettings["provider"];
  baseUrl: string;
  model: string;
  apiKey?: string;
  allowedProviders?: LLMProviderSettings["allowedProviders"];
  allowedModels?: string[];
}) => request<LLMProviderSettings>("/admin/settings/llm-provider", payload, "PUT");
export const testLLMProvider = () =>
  request<{ ok?: boolean; modelAvailable?: boolean; modelsCount?: number; completionOk?: boolean }>(
    "/admin/settings/llm-provider/test",
    undefined,
    "POST",
    120_000,
  );
export const getURLCache = () =>
  request<URLCacheSettings>("/admin/settings/url-assessment-cache", undefined, "GET");
export const saveURLCache = (enabled: boolean) =>
  request<URLCacheSettings>("/admin/settings/url-assessment-cache", { enabled }, "PUT");
export const purgeURLCache = () =>
  request<{ purged: number }>("/admin/settings/url-assessment-cache", undefined, "DELETE");
export const getOperationSettings = () =>
  request<OperationSettings>("/admin/settings/operations", undefined, "GET");
export const saveOperationSettings = (payload: OperationSettings) =>
  request<OperationSettings>("/admin/settings/operations", payload, "PUT");
export async function askContext(question: string, context: string): Promise<string> {
  const connect = (): Promise<string> =>
    new Promise((resolve, reject) => {
      const endpoint = API_BASE.replace(/^http/, "ws") + "/v1/chat";
      const socket = new WebSocket(endpoint);
      let answer = "";
      let settled = false;
      const finish = (callback: () => void) => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        callback();
      };
      const timeout = window.setTimeout(() => {
        socket.close();
        finish(() => reject(new Error("Core AI không phản hồi sau 120 giây.")));
      }, 120_000);
      socket.onopen = () =>
        socket.send(
          JSON.stringify({
            access_token: sessionToken,
            question,
            context: { content: context, modality: context.startsWith("http") ? "url" : "email" },
          }),
        );
      socket.onmessage = ({ data }) => {
        let event: { type: string; delta?: string; error?: string };
        try {
          event = JSON.parse(data as string);
        } catch {
          return;
        }
        if (event.type === "delta") answer += event.delta || "";
        if (event.type === "final") {
          socket.close();
          finish(() => resolve(answer || "Chưa có giải thích cho kết quả này."));
        }
        if (event.type === "error") {
          socket.close();
          finish(() => reject(new Error(event.error || "Không thể hỏi Core AI.")));
        }
      };
      socket.onerror = () => finish(() => reject(new Error("Không thể kết nối Core AI.")));
      socket.onclose = () => {
        if (!settled) finish(() => reject(new Error("CORE_AI_CONNECTION_CLOSED")));
      };
    });
  try {
    return await connect();
  } catch (error) {
    if (error instanceof Error && error.message === "CORE_AI_CONNECTION_CLOSED") {
      await new Promise((resolve) => window.setTimeout(resolve, 650));
      try {
        return await connect();
      } catch (retryError) {
        if (retryError instanceof Error && retryError.message === "CORE_AI_CONNECTION_CLOSED") {
          throw new Error("Kết nối Core AI bị gián đoạn. Hãy kiểm tra backend và thử lại.");
        }
        throw retryError;
      }
    }
    throw error;
  }
}
