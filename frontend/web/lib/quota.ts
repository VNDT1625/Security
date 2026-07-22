/**
 * Module quản lý quota quét — QuotaGuard.
 *
 * Quản lý "còn lại hôm nay: X/Y scan" theo gói dịch vụ (Plan_Tier):
 *   - free       : 1000 lượt/ngày → còn lại = max(0, 1000 - usedToday)
 *   - pro / team : vô hạn (Number.POSITIVE_INFINITY)
 *
 * Nguyên tắc:
 *   - `getScanQuotaRemaining(plan, usedToday)` là hàm THUẦN, tất định, KHÔNG
 *     side-effect: chỉ tính toán số còn lại từ tham số đầu vào.
 *   - `QuotaGuard` là lớp trạng thái: lưu số lượt đã dùng + ngày sử dụng, tự
 *     reset về 0 khi sang ngày mới (theo lịch, so sánh chuỗi YYYY-MM-DD local),
 *     và bền hóa (persist) vào `localStorage` khi chạy trong trình duyệt.
 *     Trên môi trường SSR (không có `window`), QuotaGuard vẫn hoạt động bằng
 *     trạng thái in-memory mà không đụng tới `localStorage`.
 *
 * _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
 */

import type { PlanTier } from "./types";

// ---------------------------------------------------------------------------
// Hằng số
// ---------------------------------------------------------------------------

/** Giới hạn quét hằng ngày của gói `free`. */
export const FREE_DAILY_SCAN_LIMIT = 1000;

/** Khóa lưu trạng thái quota trong localStorage. */
export const QUOTA_STORAGE_KEY = "aisec:quota";

// ---------------------------------------------------------------------------
// Hàm thuần: giới hạn theo gói & số lượt còn lại
// ---------------------------------------------------------------------------

/**
 * Trả về giới hạn quét hằng ngày cho một gói.
 *
 * **Postconditions**: `free` → 1000; `pro`/`team` → `Number.POSITIVE_INFINITY`;
 * kết quả luôn ≥ 0. Hàm thuần, tất định.
 *
 * @param plan Gói dịch vụ (`free` | `pro` | `team`).
 * @returns Giới hạn quét hằng ngày (số hữu hạn ≥ 0 hoặc vô hạn).
 */
export function getLimitForPlan(plan: PlanTier): number {
    return plan === "free" ? FREE_DAILY_SCAN_LIMIT : Number.POSITIVE_INFINITY;
}

/**
 * Tính số lượt quét còn lại hôm nay theo gói và số lượt đã dùng.
 *
 * Hàm THUẦN, tất định, KHÔNG side-effect (không đọc/ghi localStorage, không đọc
 * đồng hồ hệ thống): chỉ phụ thuộc vào tham số đầu vào.
 *
 * **Preconditions**: `usedToday ≥ 0`.
 * **Postconditions**:
 *   - `free`       → `max(0, 1000 - usedToday)`;
 *   - `pro`/`team` → `Number.POSITIVE_INFINITY`;
 *   - kết quả luôn KHÔNG âm.
 *
 * @param plan Gói dịch vụ (`free` | `pro` | `team`).
 * @param usedToday Số lượt đã dùng trong ngày (≥ 0).
 * @returns Số lượt còn lại (không âm), hoặc vô hạn với gói pro/team.
 */
export function getScanQuotaRemaining(
    plan: PlanTier,
    usedToday: number,
): number {
    const limit = getLimitForPlan(plan);
    if (limit === Number.POSITIVE_INFINITY) {
        return Number.POSITIVE_INFINITY;
    }
    // Phòng thủ: kẹp usedToday về [0, ∞) để kết quả luôn không âm dù đầu vào lệch.
    const used = Number.isFinite(usedToday) && usedToday > 0 ? usedToday : 0;
    return Math.max(0, limit - used);
}

// ---------------------------------------------------------------------------
// Tiện ích ngày & lưu trữ
// ---------------------------------------------------------------------------

/**
 * Khóa ngày theo lịch địa phương dạng `YYYY-MM-DD`.
 *
 * Dùng để phát hiện "sang ngày mới" nhằm reset số lượt đã dùng về 0.
 *
 * @param date Thời điểm cần lấy khóa ngày (mặc định: hiện tại).
 * @returns Chuỗi `YYYY-MM-DD` theo múi giờ địa phương.
 */
export function getDayKey(date: Date = new Date()): string {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, "0");
    const d = String(date.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
}

/** Trạng thái quota được bền hóa vào localStorage. */
interface QuotaState {
    /** Số lượt đã dùng trong ngày `day`. */
    used: number;
    /** Khóa ngày (YYYY-MM-DD) tương ứng với `used`. */
    day: string;
}

/** Kiểm tra có đang chạy trong trình duyệt (có localStorage) hay không. */
function hasBrowserStorage(): boolean {
    return (
        typeof window !== "undefined" &&
        typeof window.localStorage !== "undefined"
    );
}

/** Đọc trạng thái quota từ localStorage; trả về null nếu không có/không hợp lệ. */
function readStoredState(): QuotaState | null {
    if (!hasBrowserStorage()) {
        return null;
    }
    try {
        const raw = window.localStorage.getItem(QUOTA_STORAGE_KEY);
        if (!raw) {
            return null;
        }
        const parsed = JSON.parse(raw) as Partial<QuotaState>;
        if (
            typeof parsed.used === "number" &&
            Number.isFinite(parsed.used) &&
            typeof parsed.day === "string"
        ) {
            return { used: Math.max(0, parsed.used), day: parsed.day };
        }
        return null;
    } catch {
        // localStorage bị chặn hoặc dữ liệu hỏng → bỏ qua, dùng in-memory.
        return null;
    }
}

/** Ghi trạng thái quota vào localStorage (bỏ qua lỗi khi bị chặn). */
function writeStoredState(state: QuotaState): void {
    if (!hasBrowserStorage()) {
        return;
    }
    try {
        window.localStorage.setItem(QUOTA_STORAGE_KEY, JSON.stringify(state));
    } catch {
        // Quota storage đầy hoặc bị chặn → bỏ qua, vẫn giữ trạng thái in-memory.
    }
}

// ---------------------------------------------------------------------------
// QuotaGuard — lớp trạng thái quản lý số lượt còn lại theo ngày
// ---------------------------------------------------------------------------

/**
 * QuotaGuard: quản lý số lượt quét còn lại trong ngày cho một gói.
 *
 * - Bền hóa `used` + `day` vào localStorage khi ở trình duyệt; hoạt động
 *   bằng in-memory trên SSR (không đụng localStorage).
 * - Tự reset `used` về 0 khi phát hiện đã sang ngày mới (so khóa ngày local).
 *
 * @example
 * const guard = new QuotaGuard("free");
 * guard.getRemaining(); // 1000
 * guard.consume();
 * guard.getRemaining(); // 49
 */
export class QuotaGuard {
    private plan: PlanTier;
    private used: number;
    private day: string;

    /**
     * @param plan Gói dịch vụ hiện tại (`free` | `pro` | `team`).
     * @param now Thời điểm khởi tạo (mặc định hiện tại) — hữu ích cho test.
     */
    constructor(plan: PlanTier, now: Date = new Date()) {
        this.plan = plan;
        const today = getDayKey(now);
        const stored = readStoredState();
        if (stored && stored.day === today) {
            this.used = stored.used;
            this.day = stored.day;
        } else {
            // Không có trạng thái, hoặc trạng thái thuộc ngày cũ → bắt đầu mới.
            this.used = 0;
            this.day = today;
            if (stored) {
                // Chỉ ghi đè khi từng có dữ liệu cũ cần reset.
                this.persist();
            }
        }
    }

    /** Gói dịch vụ hiện tại. */
    getPlan(): PlanTier {
        return this.plan;
    }

    /**
     * Đổi gói dịch vụ (vd sau khi nâng cấp). Không reset số lượt đã dùng.
     * @param plan Gói mới.
     */
    setPlan(plan: PlanTier): void {
        this.plan = plan;
    }

    /**
     * Giới hạn quét hằng ngày của gói hiện tại.
     * @param plan Gói cần tra (mặc định: gói hiện tại).
     * @returns Free=1000, Pro/Team=∞.
     */
    getLimitForPlan(plan: PlanTier = this.plan): number {
        return getLimitForPlan(plan);
    }

    /**
     * Số lượt còn lại hôm nay. Tự reset khi sang ngày mới trước khi tính.
     *
     * **Postconditions**: kết quả không âm; free → `max(0, 1000 - used)`;
     * pro/team → `Number.POSITIVE_INFINITY`.
     */
    getRemaining(): number {
        this.rolloverIfNeeded();
        return getScanQuotaRemaining(this.plan, this.used);
    }

    /**
     * Cho biết còn lượt để quét hay không.
     *
     * **Postconditions**: trả `true` khi và chỉ khi `getRemaining() > 0`.
     */
    canScan(): boolean {
        return this.getRemaining() > 0;
    }

    /**
     * Tiêu thụ 1 lượt quét (tăng `used` thêm 1) và bền hóa trạng thái.
     * Tự reset trước khi tiêu thụ nếu đã sang ngày mới.
     *
     * Với gói pro/team (vô hạn), vẫn tăng `used` để thống kê nhưng không ảnh
     * hưởng tới số còn lại (luôn vô hạn).
     */
    consume(): void {
        this.rolloverIfNeeded();
        this.used += 1;
        this.persist();
    }

    /** Số lượt đã dùng hôm nay (sau khi cân nhắc reset theo ngày). */
    getUsedToday(): number {
        this.rolloverIfNeeded();
        return this.used;
    }

    /** Nếu đã sang ngày mới, đặt lại số lượt đã dùng về 0 và bền hóa. */
    private rolloverIfNeeded(): void {
        const today = getDayKey();
        if (today !== this.day) {
            this.day = today;
            this.used = 0;
            this.persist();
        }
    }

    /** Bền hóa trạng thái hiện tại vào localStorage (no-op trên SSR). */
    private persist(): void {
        writeStoredState({ used: this.used, day: this.day });
    }
}
