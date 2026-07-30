import type { BrowserSandboxResult, SandboxIssue } from "@/lib/types";
import { displayValue, mapRiskResult } from "@/lib/risk-core";

export type BrowserSandboxPayload = BrowserSandboxResult & {
    risk_core?: Record<string, unknown> | null;
};

export type WebIsolationTone = "danger" | "warning" | "neutral" | "low";

export interface WebIsolationEvidence {
    id: string;
    channel: "Tên miền" | "Chuyển hướng" | "Biểu mẫu" | "Tải tệp" | "Mạng" | "Phát hiện";
    title: string;
    detail: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface WebIsolationSummary {
    conclusion: string;
    tone: WebIsolationTone;
    riskScore: number | null;
    confidence: number | null;
    target: string;
    identity: {
        firstParty: boolean;
        label: string;
        detail: string;
    };
    statusCode: number | null;
    elapsedMs: number;
    evidence: WebIsolationEvidence[];
    missingChannels: string[];
    actions: string[];
}

const FIRST_PARTY_ASSETS: Record<string, string> = {
    "prewise.site": "Website chính thức Prewise",
    "www.prewise.site": "Website chính thức Prewise",
    "api.prewise.site": "API chính thức Prewise",
};

const ISSUE_LABELS: Record<string, string> = {
    otp_input_detected: "Trang yêu cầu mã OTP hoặc mã xác minh",
    password_input_detected: "Trang yêu cầu mật khẩu",
    cross_origin_form_action: "Biểu mẫu gửi dữ liệu sang tên miền khác",
    canary_exfiltration_blocked: "Đã chặn dữ liệu canary rời khỏi sandbox",
    form_submission_blocked: "Đã chặn thao tác gửi biểu mẫu thử nghiệm",
    private_network_request_blocked: "Đã chặn truy cập mạng riêng",
    websocket_request_blocked: "Đã chặn kết nối WebSocket",
    permission_request_blocked: "Đã từ chối quyền trình duyệt",
    deceptive_popup: "Trang cố mở cửa sổ bật lên",
    download_attempt_blocked: "Trang cố tải tệp xuống",
    malvertising_behavior: "Phát hiện hành vi quảng cáo độc hại",
    private_network_blocked: "Địa chỉ mạng riêng không được phép kiểm tra",
    browser_engine_unavailable: "Môi trường trình duyệt cô lập chưa sẵn sàng",
};

const NEXT_ACTIONS: Record<string, string> = {
    none: "Không thao tác với dữ liệu nhạy cảm nếu chưa tự xác minh tên miền.",
    deep_scan: "Thực hiện kiểm tra URL chuyên sâu trước khi tiếp tục.",
    sandbox: "Tiếp tục quan sát trong môi trường cô lập; không mở trên máy thật.",
    user_confirmation: "Xác minh website qua kênh chính thức trước khi nhập dữ liệu.",
    report: "Chặn và báo cáo website cho quản trị viên hoặc đơn vị phụ trách.",
    manual_investigation: "Chuyển kết quả cho chuyên gia điều tra thủ công.",
};

const DECISION_CONCLUSIONS: Record<string, { label: string; tone: WebIsolationTone }> = {
    hard_block: { label: "NGUY HIỂM", tone: "danger" },
    soft_block: { label: "RỦI RO CAO", tone: "danger" },
    require_review: { label: "CẦN XÁC MINH", tone: "warning" },
    warn: { label: "ĐÁNG NGỜ", tone: "warning" },
    allow: { label: "CHƯA PHÁT HIỆN DẤU HIỆU RÕ", tone: "low" },
};

const VERDICT_CONCLUSIONS: Record<string, { label: string; tone: WebIsolationTone }> = {
    critical: { label: "NGUY HIỂM", tone: "danger" },
    dangerous: { label: "NGUY HIỂM", tone: "danger" },
    high: { label: "RỦI RO CAO", tone: "danger" },
    medium: { label: "ĐÁNG NGỜ", tone: "warning" },
    suspicious: { label: "ĐÁNG NGỜ", tone: "warning" },
    low: { label: "CHƯA PHÁT HIỆN DẤU HIỆU RÕ", tone: "low" },
    minimal: { label: "CHƯA PHÁT HIỆN DẤU HIỆU RÕ", tone: "low" },
};

const SEVERITY_RANK: Record<WebIsolationEvidence["severity"], number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};

function asRecord(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : null;
}

function nonEmptyText(value: unknown): string | null {
    return typeof value === "string" && value.trim() ? value.trim() : null;
}

function hostOf(value: string): string | null {
    try {
        return new URL(value).hostname || null;
    } catch {
        return null;
    }
}

function identifyTarget(result: BrowserSandboxPayload): WebIsolationSummary["identity"] {
    const finalHost = hostOf(result.final_url) ?? hostOf(result.url);
    const asset = finalHost ? FIRST_PARTY_ASSETS[finalHost.toLowerCase()] : null;
    if (asset) {
        return {
            firstParty: true,
            label: "TÀI SẢN PREWISE ĐÃ NHẬN DIỆN",
            detail: `${asset} (${finalHost}). Danh tính nội bộ chỉ để nhận diện; điểm và kết luận vẫn lấy từ lần kiểm tra thực tế.`,
        };
    }
    return {
        firstParty: false,
        label: "WEBSITE BÊN NGOÀI",
        detail: finalHost
            ? `Đang đánh giá ${finalHost} theo dữ kiện quan sát được trong sandbox.`
            : "Không xác định được tên miền đích từ kết quả backend.",
    };
}

function normalizeSeverity(value: SandboxIssue["severity"]): WebIsolationEvidence["severity"] {
    return value === "critical" || value === "high" || value === "medium" || value === "low"
        ? value
        : "info";
}

function issueChannel(issue: SandboxIssue): WebIsolationEvidence["channel"] {
    const code = issue.code.toLowerCase();
    if (issue.category === "credential" || code.includes("form") || code.includes("password") || code.includes("otp")) {
        return "Biểu mẫu";
    }
    if (issue.category === "download" || code.includes("download")) return "Tải tệp";
    if (issue.category === "network" || code.includes("network") || code.includes("websocket")) return "Mạng";
    return "Phát hiện";
}

function browserRedirectEvidence(result: BrowserSandboxPayload): WebIsolationEvidence[] {
    const redirects: WebIsolationEvidence[] = [];
    for (const [index, rawEvent] of result.browser_events.entries()) {
        const event = asRecord(rawEvent);
        if (!event || !["redirect", "navigation"].includes(String(event.type ?? "").toLowerCase())) continue;
        const from = nonEmptyText(event.from_url) ?? nonEmptyText(event.from) ?? nonEmptyText(event.url);
        const to = nonEmptyText(event.to_url) ?? nonEmptyText(event.to) ?? nonEmptyText(event.destination);
        if (!from && !to) continue;
        redirects.push({
            id: `redirect-${index}`,
            channel: "Chuyển hướng",
            title: "Trình duyệt ghi nhận chuyển hướng",
            detail: [from, to].filter(Boolean).join(" → "),
            severity: "info",
        });
    }
    return redirects;
}

function buildEvidence(result: BrowserSandboxPayload): WebIsolationEvidence[] {
    const evidence: WebIsolationEvidence[] = [];
    const inputHost = hostOf(result.url);
    const finalHost = hostOf(result.final_url);

    if (finalHost) {
        evidence.push({
            id: "destination-domain",
            channel: "Tên miền",
            title: inputHost && inputHost !== finalHost ? "Tên miền đích đã thay đổi" : "Tên miền đích",
            detail: inputHost && inputHost !== finalHost ? `${inputHost} → ${finalHost}` : finalHost,
            severity: inputHost && inputHost !== finalHost ? "medium" : "info",
        });
    }

    const explicitRedirects = browserRedirectEvidence(result);
    evidence.push(...explicitRedirects);
    if (explicitRedirects.length === 0 && result.url && result.final_url && result.url !== result.final_url) {
        evidence.push({
            id: "final-url-changed",
            channel: "Chuyển hướng",
            title: "URL cuối khác URL ban đầu",
            detail: `${result.url} → ${result.final_url}`,
            severity: inputHost && finalHost && inputHost !== finalHost ? "medium" : "info",
        });
    }

    const fieldEntries = Object.entries(result.canary.field_types ?? {}).filter(([, count]) => Number(count) > 0);
    if (fieldEntries.length > 0) {
        evidence.push({
            id: "sensitive-fields",
            channel: "Biểu mẫu",
            title: "Đã quan sát trường nhập liệu",
            detail: fieldEntries.map(([kind, count]) => `${kind}: ${count}`).join(" · "),
            severity: fieldEntries.some(([kind]) => kind === "password" || kind === "otp") ? "high" : "info",
        });
    }

    for (const [index, issue] of result.issues.entries()) {
        evidence.push({
            id: `issue-${issue.code}-${index}`,
            channel: issueChannel(issue),
            title: ISSUE_LABELS[issue.code] ?? issue.message,
            detail: issue.detail?.trim() || issue.message,
            severity: normalizeSeverity(issue.severity),
        });
    }

    return evidence
        .filter((item, index, items) => items.findIndex((candidate) => candidate.title === item.title && candidate.detail === item.detail) === index)
        .sort((left, right) => SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity])
        .slice(0, 8);
}

function buildMissingChannels(result: BrowserSandboxPayload): string[] {
    const missing = new Set<string>();
    const risk = mapRiskResult(result);

    // The browser-sandbox response exposes the HTTPS URL but no certificate facts.
    // Do not turn the scheme into a fabricated TLS validation result.
    missing.add("Chứng chỉ/TLS chi tiết chưa được backend trả về");

    for (const step of result.scan_steps) {
        if (step.status === "failed") {
            missing.add(`${step.label}: kiểm tra gặp lỗi${step.detail ? ` (${step.detail})` : ""}`);
        } else if (step.status === "skipped") {
            missing.add(`${step.label}: chưa được kiểm tra`);
        }
    }
    if (risk.unavailableChecks.length > 0) {
        missing.add(`${risk.unavailableChecks.length} nguồn hoặc hạng mục Risk Core không khả dụng`);
    }
    if (risk.notCheckedChecks.length > 0) {
        missing.add(`${risk.notCheckedChecks.length} hạng mục Risk Core chưa được kiểm tra trong lượt này`);
    }

    return [...missing];
}

function conclusionFor(result: BrowserSandboxPayload): { label: string; tone: WebIsolationTone } {
    if (!result.ok || result.execution_status === "failed") {
        return { label: "PHÂN TÍCH THẤT BẠI", tone: "neutral" };
    }
    const risk = mapRiskResult(result);
    if (risk.source !== "risk_core_v2") return { label: "CHƯA ĐỦ DỮ LIỆU", tone: "neutral" };
    const decision = risk.decision?.toLowerCase();
    if (decision && decision !== "allow" && DECISION_CONCLUSIONS[decision]) {
        return DECISION_CONCLUSIONS[decision];
    }
    const verdict = risk.level?.toLowerCase();
    if (verdict && !["low", "minimal"].includes(verdict) && VERDICT_CONCLUSIONS[verdict]) {
        return VERDICT_CONCLUSIONS[verdict];
    }
    if (risk.confidence == null || risk.confidence < 50) {
        return { label: "CHƯA ĐỦ DỮ LIỆU", tone: "neutral" };
    }
    if (decision === "allow") return DECISION_CONCLUSIONS.allow;
    if (verdict && VERDICT_CONCLUSIONS[verdict]) return VERDICT_CONCLUSIONS[verdict];
    return { label: "CHƯA ĐỦ DỮ LIỆU", tone: "neutral" };
}

function buildActions(result: BrowserSandboxPayload, missingChannels: string[]): string[] {
    if (!result.ok || result.execution_status === "failed") {
        return ["Không coi website là an toàn; sửa lỗi môi trường rồi kiểm tra lại."];
    }
    const risk = mapRiskResult(result);
    const actions: string[] = [];
    if (risk.nextAction) actions.push(NEXT_ACTIONS[risk.nextAction.toLowerCase()] ?? risk.nextAction);
    for (const mitigation of risk.mitigations.slice(0, 2)) {
        const text = displayValue(mitigation, ["description", "action", "title", "name"], "");
        if (text) actions.push(text);
    }
    if (missingChannels.length > 0) actions.push("Xác minh bổ sung các kênh còn thiếu trước khi nhập mật khẩu, OTP hoặc tải tệp.");
    return [...new Set(actions)].slice(0, 3);
}

export function summarizeWebIsolation(result: BrowserSandboxPayload): WebIsolationSummary {
    const risk = mapRiskResult(result);
    const conclusion = conclusionFor(result);
    const missingChannels = buildMissingChannels(result);
    return {
        conclusion: conclusion.label,
        tone: conclusion.tone,
        riskScore: risk.source === "risk_core_v2" ? Math.round(risk.score) : null,
        confidence: risk.source === "risk_core_v2" && risk.confidence != null ? Math.round(risk.confidence) : null,
        target: result.page_title || result.final_url || result.url,
        identity: identifyTarget(result),
        statusCode: result.status_code,
        elapsedMs: Math.max(0, Math.round(result.elapsed_ms || 0)),
        evidence: buildEvidence(result),
        missingChannels,
        actions: buildActions(result, missingChannels),
    };
}
