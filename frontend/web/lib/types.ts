/**
 * Kiểu dữ liệu chung dùng toàn bộ Web App UI.
 *
 * Các interface ở đây khớp chính xác mục "Data Models" trong design.md
 * (thang màu rủi ro, kết quả đánh giá, chat protocol, session/gói, pricing)
 * cùng các kiểu phụ trợ tham chiếu bởi ApiClient và quickScan.
 *
 * _Requirements: 3.5, 9.1_
 */

// ---------------------------------------------------------------------------
// Model: RiskLevel & thang màu
// ---------------------------------------------------------------------------

export type RiskLevelKey = "safe" | "warn" | "danger";

export interface RiskLevel {
    key: RiskLevelKey;
    label: string; // "AN TOÀN" | "ĐÁNG NGỜ" | "RỦI RO CAO"
    color: string; // token màu Tailwind
    icon: string; // "✅" | "⚠" | "⛔"
    min: number; // ngưỡng dưới (0/40/70)
    max: number; // ngưỡng trên (39/69/100)
}

// ---------------------------------------------------------------------------
// Model: Evidence
// ---------------------------------------------------------------------------

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Evidence {
    source: string; // "url_adapter" | "text_adapter" | ...
    message: string; // tiếng Việt, mô tả bằng chứng
    severity: Severity;
    feature?: string; // vd "homoglyph_score"
    contribution?: number; // đóng góp SHAP (+0.38), tùy chọn
}

// ---------------------------------------------------------------------------
// Model: AssessResult
// ---------------------------------------------------------------------------

/** Metadata tùy chọn kèm theo lời gọi assessText. */
export interface AssessMetadata {
    modality?: "url" | "email" | "sms" | "text";
    locale?: string;
    [key: string]: unknown;
}

export interface AssessResult {
    score: number; // 0..100 (từ risk_score*100)
    riskLevel: RiskLevelKey;
    confidence: number; // 0..1
    reasons: string[]; // "Lý do chính" tiếng Việt
    evidence: Evidence[];
    explanation?: string; // giải thích ngôn ngữ tự nhiên (Layer 2)
    modality: "url" | "email" | "sms" | "text";
    modelVersion?: string;
    latencyMs?: number;
    requestId: string;
    analysisCoverage?: Record<string, string>;
    messageMetadata?: Record<string, unknown>;
    embeddedUrlAssessments?: Array<Record<string, unknown>>;
    contextualAnalysis?: ContextualAnalysis;
    riskCore?: Record<string, unknown>;
}

export interface ContextualAnalysis {
    task: string;
    adapter_id: string;
    status: "completed" | "not_configured" | "disabled" | "artifact_missing" | "incompatible" | "timeout" | "error" | "invalid_schema";
    scoring_mode: "none" | "shadow" | "active";
    confidence?: number | null;
    risk_signal?: number | null;
    latency_ms?: number;
    error?: string;
}

export interface PhoneAssessResult {
    provider: string;
    providerStatus: "completed" | "no_hit" | "unavailable";
    reputation: "malicious" | "suspicious" | "neutral" | "unknown" | null;
    metadata: Record<string, unknown>;
    assessment: AssessResult | null;
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
    attachments: Array<{
        filename: string;
        contentType: string;
        size: number;
    }>;
    linksRemoved: number;
}

export interface SandboxIssue {
    code: string;
    severity: Severity;
    category: string;
    message: string;
    detail?: string;
}

export interface SandboxScanStep {
    key: string;
    label: string;
    status: "passed" | "failed" | "skipped";
    detail?: string;
}

export interface SandboxRedirect {
    status_code: number;
    from_url: string;
    to_url: string;
}

export interface SandboxResult {
    ok: boolean;
    execution_status: "completed" | "failed";
    url: string;
    final_url: string;
    status_code: number | null;
    http_reason: string;
    content_type: string;
    bytes_read: number;
    resolved_ip: string;
    redirects: SandboxRedirect[];
    tls: Record<string, unknown>;
    page_title: string;
    page_signals: Record<string, unknown>;
    issues: SandboxIssue[];
    scan_steps: SandboxScanStep[];
    elapsed_ms: number;
}

export interface SandboxNetworkEvent {
    url: string;
    method: string;
    resource_type: string;
    status: number | null;
    blocked: boolean;
    reason: string;
    same_origin: boolean | null;
}

export interface SandboxCanaryReport {
    enabled: boolean;
    mode: "dry_run";
    clone_email: string;
    fields_filled: number;
    field_types: Record<string, number>;
    form_submissions_blocked: number;
    exfiltration_blocked: boolean;
    notes: string[];
}

export interface ExeQuickScanSection {
    name: string;
    virtual_size: number;
    raw_size: number;
    entropy: number;
    readable: boolean;
    writable: boolean;
    executable: boolean;
}

export interface ExeLocalAnalysis {
    valid: boolean;
    format: string;
    architecture: string;
    subsystem: string;
    entry_point_rva: number;
    section_count: number;
    sections: ExeQuickScanSection[];
    signature_present: boolean;
    overlay_bytes: number;
    compile_time: string | null;
    characteristics: number;
    anomalies: string[];
    risk_score: number;
}

export interface ExeProviderDetection {
    engine: string;
    threat: string;
}

export interface ExeProviderResult {
    name: string;
    configured: boolean;
    status: "disabled" | "not_found" | "known" | "queued" | "completed" | "failed";
    data_id: string | null;
    progress: number;
    detected_engines: number;
    total_engines: number;
    detections: ExeProviderDetection[];
    risk_score: number;
    sample_shared: boolean;
    error: string | null;
}

export interface ExeSandboxResult {
    ok: boolean;
    execution_status: "completed" | "queued" | "failed";
    filename: string;
    sha256: string;
    size_bytes: number;
    sandbox: string;
    network: string;
    verdict: "dangerous" | "suspicious" | "no_obvious_theft_detected" | "unknown";
    risk_score: number;
    issues: string[];
    processes: Record<string, unknown>[];
    files_created: Record<string, unknown>[];
    network_attempts: Record<string, unknown>[];
    signature_status?: string;
    signer?: string | null;
    defender_detections?: Record<string, unknown>[];
    analysis_mode?: "quick_scan" | "windows_sandbox";
    dynamic_execution?: boolean;
    local_analysis?: ExeLocalAnalysis;
    provider?: ExeProviderResult;
    provider_available?: boolean;
    upload_consent_required?: boolean;
    privacy_notice?: string;

    elapsed_ms: number;
}

export interface BrowserSandboxResult {
    ok: boolean;
    execution_status: "completed" | "failed";
    url: string;
    final_url: string;
    status_code: number | null;
    page_title: string;
    isolation: Record<string, unknown>;
    canary: SandboxCanaryReport;
    network_events: SandboxNetworkEvent[];
    browser_events: Record<string, unknown>[];
    console_errors: string[];
    issues: SandboxIssue[];
    scan_steps: SandboxScanStep[];
    elapsed_ms: number;
}

// ---------------------------------------------------------------------------
// Model: ChatMessageModel & Chat protocol
// ---------------------------------------------------------------------------

export interface ChatMessageModel {
    id: string;
    role: "user" | "assistant";
    text: string;
    createdAt: number;
    assessment?: AssessResult; // gắn khi assistant trả kết quả đánh giá
    legalAnswer?: LegalAnswerResult;
}

export interface LegalContext {
    jurisdiction: string;
    as_of_date: string;
    actor: string;
    action: string;
    data_or_asset: string;
}

export interface LegalCitation {
    chunk_id: string;
    title: string;
    document_number: string;
    section: string;
    page_start: number | null;
    page_end: number | null;
    status: string;
    effective_date: string;
    status_checked_at: string;
    source_page_url: string;
    authority?: string;
    source_kind?: "corpus" | "official_web";
    retrieval_channels?: string[];
}

export interface LegalAnswerResult {
    status: "answered" | "need_more_facts" | "insufficient_legal_basis" |
        "conflicting_sources" | "human_legal_review";
    jurisdiction: string;
    as_of_date: string;
    answer: string;
    legal_conclusions: Array<{ claim: string; citation_ids: string[] }>;
    citations: LegalCitation[];
    missing_facts: string[];
    uncertainties: string[];
    requires_human_review: boolean;
    disclaimer: string;
}

export interface ChatRequest {
    question: string;
    context?: {
        content: string;
        modality: "url" | "email" | "sms" | "text";
        operator_context?: string;
        analysis_id?: string;
    };
    legal_context?: LegalContext;
    history: ChatMessageModel[];
}

export interface ChatChunk {
    delta: string;
}

export interface ChatFinal {
    messageId: string;
    assessment?: AssessResult;
    legalAnswer?: LegalAnswerResult;
}

// ---------------------------------------------------------------------------
// Model: Session, PlanInfo, ScanRecord, ApiKeyInfo
// ---------------------------------------------------------------------------

export type PlanTier = "free" | "pro" | "team" | "enterprise";

export interface Session {
    token: string;
    user: UserProfile;
    plan: PlanInfo;
}

export interface UserProfile {
    id: string;
    email: string;
    displayName: string;
    avatarUrl?: string;
    role?: "user" | "admin";
}

export interface PasswordChangeInput {
    currentPassword: string;
    newPassword: string;
}

export interface PlanInfo {
    tier: PlanTier; // free | pro | team
    label: string; // "FREE" | "PRO" | "TEAM"
    renewsAt?: string; // "02/08/2026"
    dailyScanLimit: number; // 50 | Infinity
    aiCreditDailyLimit: number;
    deepScanDailyLimit: number;
    chatFollowupLimit: number;
    autoMessageContext: boolean;
    autoWebContext: boolean;
}

export interface ScanRecord {
    id: string;
    timestamp: string; // "02/07 18:32"
    type: "URL" | "Email" | "SMS";
    score: number; // 0..100
    riskLevel: RiskLevelKey;
    target?: string;
    decision?: string;
    confidence?: number;
    modelVersion?: string;
    evidence?: Array<{
        source: string;
        message: string;
        severity: string;
        feature?: string | null;
    }>;
}

/** Server-authoritative daily quota snapshot for the signed-in account. */
export interface QuotaInfo {
    usageDay: string;
    usedToday: number;
    dailyScanLimit: number;
    remaining: number;
    aiUsedToday: number;
    aiEvaluationUsedToday: number;
    aiExplanationUsedToday: number;
    aiCreditDailyLimit: number;
    aiRemaining: number;
    deepUsedToday: number;
    deepScanDailyLimit: number;
    deepRemaining: number;
}

export interface ScanRecordDetail extends ScanRecord {
    createdAt: string;
    modality: "url" | "email" | "sms" | "text";
    latencyMs: number;
    reasons: string[];
    schemaVersion?: string | null;
    scoringVersion?: string | null;
    riskCore?: Record<string, unknown> | null;
}

export interface ApiKeyInfo {
    key: string;
    createdAt: string;
    prefix: string;
    lastUsedAt?: string | null;
    scopes: string[];
    status: string;
    /** True only in the one-time response immediately after key rotation. */
    secretAvailable: boolean;
} // dùng cho Team/MCP

// ---------------------------------------------------------------------------
// Model: PricingTier (Pricing page)
// ---------------------------------------------------------------------------

export interface PricingTier {
    id: PlanTier;
    name: string; // "FREE" | "PRO" | "TEAM / API"
    priceMonthly: number | null; // null => "Liên hệ"
    priceYearly: number | null;
    highlighted: boolean; // PRO ★ Phổ biến
    features: PricingFeature[];
    ctaLabel: string; // "Bắt đầu" | "Dùng thử 7 ngày" | "Liên hệ"
}

export interface PricingFeature {
    label: string;
    included: boolean;
} // ✓ / ✗

// ---------------------------------------------------------------------------
// Auth inputs (dùng bởi ApiClient.login / register — design.md)
// ---------------------------------------------------------------------------

export interface Credentials {
    email: string;
    password: string;
}

export interface PasswordResetRequestResult {
    ok: boolean;
    message: string;
    resetToken?: string;
}

export interface RegisterInput {
    email: string;
    password: string;
    displayName: string;
}

// ---------------------------------------------------------------------------
// Error types (tham chiếu bởi quickScan trong pseudocode design.md)
// ---------------------------------------------------------------------------

/** Kiểu lỗi ứng dụng chung; có trường `error` để phân biệt với AssessResult. */
export interface AppError {
    error: string; // mã lỗi máy đọc, vd "validation" | "quota"
    message: string; // thông điệp tiếng Việt hiển thị cho người dùng
}

/** Lỗi khi đầu vào không hợp lệ (rỗng/chỉ khoảng trắng). */
export interface ValidationError extends AppError {
    error: "validation";
}

/** Lỗi khi đã hết lượt quét trong ngày. */
export interface QuotaError extends AppError {
    error: "quota";
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
    status: "received";
    createdAt: string;
}

export type ReportShareExpiry = "1h" | "24h" | "7d";

export interface ReportShareSnapshot {
    score: number;
    type: "url" | "email" | "sms" | "text";
    decision: string;
    riskLevel: string;
    confidence: number;
    evidence: Array<{
        source: string;
        message: string;
        severity: Severity;
        feature?: string | null;
    }>;
}

export interface CreateReportShareInput {
    requestId: string;
    expiresIn: ReportShareExpiry;
}

export interface CreatedReportShare {
    id: string;
    shareToken: string;
    expiresAt: string;
}

export interface PublicReportShare {
    id: string;
    snapshot: ReportShareSnapshot;
    expiresAt: string;
}

export type AIProvider = "auto" | "adapter" | "local" | "endpoint";
export type UserSelectableAIProvider = Exclude<AIProvider, "auto">;

export interface UserAISettings {
    provider: AIProvider;
    baseUrl: string;
    model: string;
    apiKeyConfigured: boolean;
    configured: boolean;
    source: "environment" | "database" | "account";
    percent: number;
    minPercent: number;
    maxPercent: number;
    weightPercent: number;
    weightEligible: boolean;
    weightSource: "global" | "account";
    allowedProviders: UserSelectableAIProvider[];
    allowedModels: string[];
}

export interface UserAISettingsInput {
    provider: AIProvider;
    baseUrl: string;
    model: string;
    apiKey?: string;
    clearApiKey?: boolean;
    weightPercent?: number;
}
