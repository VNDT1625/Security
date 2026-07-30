// Shared risk-level mapping — mirrors web app lib/risk.ts and backend thresholds.
// Single source of truth for the extension's badge colors (0-100 display scale).

export const RISK_LEVELS = {
    safe: { key: "safe", label: "AN TOÀN", icon: "✅", color: "#16a34a", min: 0, max: 39 },
    warn: { key: "warn", label: "ĐÁNG NGỜ", icon: "⚠", color: "#d97706", min: 40, max: 69 },
    danger: { key: "danger", label: "RỦI RO CAO", icon: "⛔", color: "#dc2626", min: 70, max: 100 },
};

/** Map a 0..100 score to a risk level (clamps out-of-range for safety). */
export function getRiskLevel(score, decision = "") {
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
    const s = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
    if (s <= 39) return RISK_LEVELS.safe;
    if (s <= 69) return RISK_LEVELS.warn;
    return RISK_LEVELS.danger;
}

/** Backend returns risk_score 0..1; convert to the 0..100 display scale. */
export function toDisplayScore(riskScore01) {
    return Math.round(Math.max(0, Math.min(1, riskScore01)) * 100);
}
