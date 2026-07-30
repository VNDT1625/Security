/**
 * Component RiskBadge — huy hiệu rủi ro theo thang màu chuẩn.
 *
 * Hiển thị màu/icon/nhãn tương ứng với một Risk_Score, LẤY TRỰC TIẾP từ
 * `getRiskLevel(score)` trong `lib/risk.ts` (nguồn duy nhất). RiskBadge KHÔNG
 * tự tính ngưỡng riêng — mọi ánh xạ điểm → mức đều ủy quyền cho Risk_Module
 * và dùng bảng token màu Tailwind (`RISK_COLOR_TOKENS`) để tô màu nhất quán.
 *
 * Đây là component trình bày thuần (presentational): không dùng hook, không state,
 * nên render được ở cả Server lẫn Client Component.
 *
 * Robustness: `getRiskLevel` ném lỗi khi điểm ngoài [0, 100]. Để một điểm số
 * lạc (vd dữ liệu API bất thường) không làm sập cả trang, RiskBadge **kẹp
 * (clamp)** điểm về [0, 100] trước khi tra mức — vẫn giữ ánh xạ qua Risk_Module.
 *
 * _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
 */

import { getRiskColorToken, getRiskLevelForContext } from "@/lib/risk";

export interface RiskBadgeProps {
    /** Điểm rủi ro; kỳ vọng trong [0, 100], sẽ được kẹp về biên nếu lệch. */
    score: number;
    /** Kích thước hiển thị. Mặc định "md". */
    size?: "sm" | "md" | "lg";
    /** Tương thích cũ: bật nhãn kết luận, không hiển thị điểm số. */
    showScore?: boolean;
    /** Hiển thị nhãn mức rủi ro (vd "RỦI RO CAO"). */
    showLabel?: boolean;
    /** Quyết định máy chủ, được ưu tiên hơn điểm nội bộ. */
    decision?: string;
    /** Mức rủi ro máy chủ, dùng khi chưa có quyết định. */
    riskLevel?: string;
}

/** Class Tailwind theo kích thước badge. */
const SIZE_CLASSES: Record<NonNullable<RiskBadgeProps["size"]>, string> = {
    sm: "gap-1 rounded px-1.5 py-0.5 text-xs",
    md: "gap-1.5 rounded-md px-2.5 py-1 text-sm",
    lg: "gap-2 rounded-lg px-3.5 py-1.5 text-base",
};

/** Class cỡ icon theo kích thước badge. */
const ICON_SIZE_CLASSES: Record<NonNullable<RiskBadgeProps["size"]>, string> = {
    sm: "text-sm leading-none",
    md: "text-base leading-none",
    lg: "text-lg leading-none",
};

/** Kẹp điểm về [0, 100]; điểm không hữu hạn coi như 0 để hiển thị an toàn. */
function clampScore(score: number): number {
    if (!Number.isFinite(score)) {
        return 0;
    }
    if (score < 0) {
        return 0;
    }
    if (score > 100) {
        return 100;
    }
    return score;
}

/**
 * RiskBadge — hiển thị icon + (tùy chọn) điểm + (tùy chọn) nhãn với màu theo
 * mức rủi ro do `getRiskLevel` xác định.
 */
export default function RiskBadge({
    score,
    size = "md",
    showScore = false,
    showLabel = false,
    decision,
    riskLevel,
}: RiskBadgeProps) {
    const safeScore = clampScore(score);
    const level = getRiskLevelForContext(decision, riskLevel, safeScore);
    const colors = getRiskColorToken(level.key);
    // `showScore` được giữ để không phá API component cũ, nhưng UI công khai
    // chỉ hiển thị kết luận định tính. Điểm vẫn được dùng nội bộ.
    const shouldShowLabel = showLabel || showScore;

    const className = [
        "inline-flex items-center font-semibold",
        SIZE_CLASSES[size],
        colors.bg,
        colors.textFg,
        "border",
        colors.border,
    ].join(" ");

    return (
        <span
            className={className}
            role="status"
            aria-label={`Mức rủi ro: ${level.label}`}
        >
            <span className={ICON_SIZE_CLASSES[size]} aria-hidden="true">
                {level.icon}
            </span>
            {shouldShowLabel && <span>{level.label}</span>}
        </span>
    );
}
