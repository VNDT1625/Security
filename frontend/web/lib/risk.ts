/**
 * Module thang màu rủi ro — NGUỒN DUY NHẤT ánh xạ điểm → mức/màu/nhãn.
 *
 * Mọi component (RiskBadge, EvidencePanel, Lịch sử scan, Hero...) PHẢI gọi
 * `getRiskLevel(score)` thay vì tự tính ngưỡng riêng, để đảm bảo thang màu
 * nhất quán trên toàn ứng dụng (khớp wireframe & Extension badge):
 *
 *   - safe   (Xanh)  : điểm 0–39   → "AN TOÀN"    ✅
 *   - warn   (Vàng)  : điểm 40–69  → "ĐÁNG NGỜ"   ⚠
 *   - danger (Đỏ)    : điểm 70–100 → "RỦI RO CAO" ⛔
 *
 * Hàm thuần, tất định (cùng input → cùng output), không side-effect.
 *
 * _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_
 */

import type { RiskLevel, RiskLevelKey } from "./types";

// ---------------------------------------------------------------------------
// Bảng token màu Tailwind cho từng mức rủi ro
// ---------------------------------------------------------------------------

/** Bộ class/token màu Tailwind cho một mức rủi ro. */
export interface RiskColorToken {
    /** Tên nhóm token trong tailwind.config.ts (risk.safe / risk.warn / risk.danger). */
    token: string; // vd "risk-safe"
    /** Class chữ dùng token DEFAULT (vd nền đậm). */
    text: string; // vd "text-risk-safe"
    /** Class chữ tương phản trên nền nhạt (fg). */
    textFg: string; // vd "text-risk-safe-fg"
    /** Class nền nhạt (bg). */
    bg: string; // vd "bg-risk-safe-bg"
    /** Class nền đậm (DEFAULT) — vd cho badge đặc. */
    bgSolid: string; // vd "bg-risk-safe"
    /** Class viền (border). */
    border: string; // vd "border-risk-safe-border"
}

/**
 * Bảng token màu Tailwind theo mức rủi ro.
 *
 * Khớp chính xác các token khai báo trong `tailwind.config.ts`:
 *   risk.safe / risk.warn / risk.danger, mỗi nhóm có DEFAULT / fg / bg / border.
 * Component tái sử dụng bảng này để tô màu nhất quán mà không hard-code màu.
 */
export const RISK_COLOR_TOKENS: Record<RiskLevelKey, RiskColorToken> = {
    safe: {
        token: "risk-safe",
        text: "text-risk-safe",
        textFg: "text-risk-safe-fg",
        bg: "bg-risk-safe-bg",
        bgSolid: "bg-risk-safe",
        border: "border-risk-safe-border",
    },
    warn: {
        token: "risk-warn",
        text: "text-risk-warn",
        textFg: "text-risk-warn-fg",
        bg: "bg-risk-warn-bg",
        bgSolid: "bg-risk-warn",
        border: "border-risk-warn-border",
    },
    danger: {
        token: "risk-danger",
        text: "text-risk-danger",
        textFg: "text-risk-danger-fg",
        bg: "bg-risk-danger-bg",
        bgSolid: "bg-risk-danger",
        border: "border-risk-danger-border",
    },
};

// ---------------------------------------------------------------------------
// Định nghĩa các mức rủi ro (bất biến)
// ---------------------------------------------------------------------------

/**
 * Ngưỡng & thuộc tính cố định cho từng mức rủi ro.
 *
 * Các khoảng phủ kín và không chồng lấn toàn bộ [0, 100]:
 *   safe [0,39] · warn [40,69] · danger [70,100].
 */
export const RISK_LEVELS: Record<RiskLevelKey, RiskLevel> = {
    safe: {
        key: "safe",
        label: "AN TOÀN",
        color: RISK_COLOR_TOKENS.safe.token,
        icon: "✅",
        min: 0,
        max: 39,
    },
    warn: {
        key: "warn",
        label: "ĐÁNG NGỜ",
        color: RISK_COLOR_TOKENS.warn.token,
        icon: "⚠",
        min: 40,
        max: 69,
    },
    danger: {
        key: "danger",
        label: "RỦI RO CAO",
        color: RISK_COLOR_TOKENS.danger.token,
        icon: "⛔",
        min: 70,
        max: 100,
    },
};

// ---------------------------------------------------------------------------
// getRiskLevel — hàm thuần, tất định
// ---------------------------------------------------------------------------

/**
 * Ánh xạ một điểm rủi ro `score` (0..100) sang mức rủi ro tương ứng.
 *
 * Thang chuẩn (nguồn duy nhất):
 *   - [0, 39]   → safe   ("AN TOÀN",    ✅)
 *   - [40, 69]  → warn   ("ĐÁNG NGỜ",   ⚠)
 *   - [70, 100] → danger ("RỦI RO CAO", ⛔)
 *
 * **Preconditions**: `0 ≤ score ≤ 100` (và `score` là số hữu hạn).
 * **Postconditions**: trả đúng một mức; `result.min ≤ score ≤ result.max`;
 * hàm thuần, tất định (cùng `score` luôn cho cùng kết quả).
 *
 * @param score Điểm rủi ro trong khoảng [0, 100].
 * @returns Mức rủi ro (`RiskLevel`) kèm nhãn/icon/màu và biên min/max.
 * @throws {RangeError} khi `score` nằm ngoài [0, 100] hoặc không phải số hữu hạn
 *   (vi phạm tiền điều kiện — Requirement 1.6).
 */
export function getRiskLevel(score: number): RiskLevel {
    if (!Number.isFinite(score) || score < 0 || score > 100) {
        throw new RangeError(
            `Risk_Score không hợp lệ: ${score}. Yêu cầu 0 ≤ score ≤ 100.`,
        );
    }

    if (score <= 39) {
        return RISK_LEVELS.safe;
    }
    if (score <= 69) {
        return RISK_LEVELS.warn;
    }
    return RISK_LEVELS.danger;
}

/** Dùng quyết định máy chủ làm nguồn chính; điểm chỉ dành cho dữ liệu cũ. */
export function getRiskLevelForDecision(
    decision: string | undefined,
    score: number,
): RiskLevel {
    const policy = String(decision || "").toUpperCase();
    if (policy === "BLOCK" || policy === "SOFT_BLOCK" || policy === "HARD_BLOCK") {
        return RISK_LEVELS.danger;
    }
    if (
        policy === "WARN"
        || policy === "ASK_USER_CONFIRMATION"
        || policy === "REQUIRE_REVIEW"
    ) {
        return RISK_LEVELS.warn;
    }
    if (policy === "ALLOW") return RISK_LEVELS.safe;
    return getRiskLevel(score);
}

/**
 * Kết luận hiển thị ưu tiên quyết định và mức do máy chủ trả về.
 * Điểm chỉ là phương án tương thích cho dữ liệu cũ, không được hiển thị ra UI.
 */
export function getRiskLevelForContext(
    decision: string | undefined,
    riskLevel: string | undefined,
    score: number,
): RiskLevel {
    const policyLevel = getRiskLevelForDecision(decision, score);
    if (decision) return policyLevel;

    const normalized = String(riskLevel || "").toLowerCase();
    if (["critical", "dangerous", "danger", "high", "blocked"].includes(normalized)) {
        return RISK_LEVELS.danger;
    }
    if (["suspicious", "warn", "warning", "medium", "review", "unknown"].includes(normalized)) {
        return RISK_LEVELS.warn;
    }
    if (["safe", "low", "allow", "allowed"].includes(normalized)) {
        return RISK_LEVELS.safe;
    }
    return policyLevel;
}

/**
 * Tiện ích: lấy bảng token màu Tailwind cho một mức rủi ro theo `key`.
 *
 * @param key Khóa mức rủi ro (`safe` | `warn` | `danger`).
 * @returns Bộ class/token màu Tailwind tương ứng.
 */
export function getRiskColorToken(key: RiskLevelKey): RiskColorToken {
    return RISK_COLOR_TOKENS[key];
}
