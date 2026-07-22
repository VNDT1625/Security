"use client";

/**
 * Component ScrollHero — Hero "Scroll-driven Product Reveal" của trang Home.
 *
 * Theo `landingpage.md.md`, Hero có 3 trạng thái, chỉ tiến theo một chiều
 * trong một phiên (Property 6 — không bao giờ lùi):
 *
 *   intro          → video full-screen loop, chưa gắn hiệu ứng scroll.
 *   scroll_driven  → scrub khung hình theo tiến độ cuộn (scrollProgress),
 *                    warp/dolly-out video theo progress để mô phỏng camera
 *                    kéo lùi; lộ dần slogan + callout.
 *   idle           → khi progress đạt 100%: giữ khung hình cuối, video +
 *                    hiệu ứng chạy độc lập (self-playing), không còn phụ
 *                    thuộc scroll.
 *
 * Video (Layer B) luôn chạy độc lập với clock riêng (autoplay/muted/loop);
 * scroll CHỈ điều khiển vị trí/warp của video, không điều khiển play/pause.
 *
 * Vì asset 3D thật (image-sequence + corner_pin.json) chưa tồn tại, component
 * hiện thực đầy đủ CƠ CHẾ (state machine, tính frameIndex, warp) nhưng hạ cấp
 * mượt mà (graceful degrade): dùng CSS transform trên chính thẻ <video> để mô
 * phỏng dolly-out/warp theo progress, và một hằng số `TOTAL_FRAMES` cho phần
 * toán chỉ số khung hình. Khi `reducedMotion` bật (hoặc prefers-reduced-motion),
 * bỏ toàn bộ hiệu ứng cuộn và render Hero tĩnh với ô quét nhanh + CTA hiển thị
 * ngay (Requirement 5.6).
 *
 * Logic thuần được tách ra (`nextHeroState`, `computeFrameIndex`) để tasks
 * 12.3/12.4 kiểm chứng Property 6 & 8 mà không cần dựng DOM.
 *
 * SSR-safe: mọi truy cập `window`/`document` đều nằm trong effect hoặc được
 * guard, không chạy khi render phía server.
 *
 * _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
 */

import {
    useCallback,
    useEffect,
    useMemo,
    useRef,
    useState,
    type CSSProperties,
} from "react";

// ---------------------------------------------------------------------------
// Kiểu & hằng số
// ---------------------------------------------------------------------------

/** Trạng thái của Hero, chỉ tiến theo thứ tự intro → scroll_driven → idle. */
export type HeroState = "intro" | "scroll_driven" | "idle";

/** Sự kiện điều khiển state machine của Hero. */
export type HeroEvent =
    | { type: "USER_SCROLLED" } // user bắt đầu cuộn (once) → rời intro
    | { type: "PROGRESS_COMPLETE" }; // scrollProgress đạt 1 → sang idle

/**
 * Số khung hình của image-sequence dùng cho phần toán chỉ số khung hình.
 *
 * Theo `landingpage.md.md` (mục tối ưu asset), khoảng 60–80 frame là đủ vì
 * trình duyệt nội suy giữa các frame. Dùng 60 làm mặc định ngay cả khi asset
 * thật chưa có, để cơ chế `computeFrameIndex` vẫn đúng đắn và test được.
 */
export const TOTAL_FRAMES = 60;

/** Ảnh fallback khi video demo thật chưa có trong `public/`. */
const FALLBACK_VISUAL_SRC = "/hero-demo-fallback.png";

/** Slogan chính (khớp wireframe §1.2). */
const SLOGAN =
    "AI có quyền hành động thay bạn thì AI cũng cần một lớp giáp trước khi hành động";

/** Phụ đề dưới slogan (khớp wireframe §1.2). */
const SUBTITLE = "Đánh giá độ tin cậy URL, Email — cho người và AI agent";

/** Placeholder ô quét nhanh (khớp wireframe §1.2). */
const QUICK_SCAN_PLACEHOLDER = "Dán URL hoặc nội dung email để thử ngay...";

// ---------------------------------------------------------------------------
// Logic thuần — testable (Property 6 & 8)
// ---------------------------------------------------------------------------

/**
 * Hàm chuyển trạng thái thuần của Hero.
 *
 * Chỉ cho phép tiến theo thứ tự `intro → scroll_driven → idle`; mọi chuyển
 * lùi hoặc chuyển không hợp lệ đều giữ nguyên trạng thái hiện tại (Property 6).
 *
 * - Từ `intro`: `USER_SCROLLED` → `scroll_driven`.
 * - Từ `scroll_driven`: `PROGRESS_COMPLETE` → `idle`.
 * - `idle` là trạng thái hấp thụ (absorbing) — không rời đi.
 *
 * @param current Trạng thái hiện tại.
 * @param event Sự kiện điều khiển.
 * @returns Trạng thái kế tiếp (không bao giờ lùi lại trạng thái trước).
 */
export function nextHeroState(current: HeroState, event: HeroEvent): HeroState {
    switch (current) {
        case "intro":
            return event.type === "USER_SCROLLED" ? "scroll_driven" : "intro";
        case "scroll_driven":
            return event.type === "PROGRESS_COMPLETE" ? "idle" : "scroll_driven";
        case "idle":
            return "idle";
        default:
            return current;
    }
}

/**
 * Tính chỉ số khung hình từ tiến độ cuộn, LUÔN kẹp vào [0, totalFrames-1]
 * (Property 8 — bất biến biên).
 *
 * `frameIndex = floor(progress * (totalFrames - 1))`, sau đó clamp để chống
 * các giá trị `progress` lệch biên (âm, > 1, hoặc NaN) làm chỉ số vượt khỏi
 * mảng khung hình.
 *
 * @param progress Tiến độ cuộn, kỳ vọng trong [0, 1].
 * @param totalFrames Tổng số khung hình (> 0). Mặc định `TOTAL_FRAMES`.
 * @returns Chỉ số khung hình nguyên trong [0, totalFrames-1].
 */
export function computeFrameIndex(
    progress: number,
    totalFrames: number = TOTAL_FRAMES,
): number {
    const maxIndex = Math.max(0, totalFrames - 1);
    if (!Number.isFinite(progress)) {
        return 0;
    }
    const raw = Math.floor(progress * maxIndex);
    if (raw < 0) {
        return 0;
    }
    if (raw > maxIndex) {
        return maxIndex;
    }
    return raw;
}

/** Kẹp một số về [0, 1]; giá trị không hữu hạn → 0. */
function clamp01(value: number): number {
    if (!Number.isFinite(value)) {
        return 0;
    }
    if (value < 0) {
        return 0;
    }
    if (value > 1) {
        return 1;
    }
    return value;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ScrollHeroProps {
    /** Video demo autoplay/loop (Layer B). Nếu thiếu, dùng ảnh fallback. */
    videoSrc?: string;
    /**
     * Đường dẫn image-sequence manifest (tùy chọn — asset thật chưa có).
     * Khi có thể dùng để preload khung hình; hiện tại chỉ là điểm mở rộng.
     */
    frameManifest?: string;
    /**
     * Đường dẫn corner_pin.json cho warp (tùy chọn — asset thật chưa có).
     * Khi có thể dùng để áp `matrix3d()` chính xác; hiện tại mô phỏng bằng
     * CSS transform theo progress.
     */
    cornerPinData?: string;
    /** Callback ô "Dán URL... [Quét]". */
    onQuickScan: (input: string) => void;
    /** Bật fallback tĩnh, bỏ hiệu ứng cuộn (Requirement 5.6). */
    reducedMotion?: boolean;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * ScrollHero — Hero cuộn tiết lộ sản phẩm với fallback tĩnh.
 */
export default function ScrollHero({
    videoSrc,
    frameManifest,
    cornerPinData,
    onQuickScan,
    reducedMotion = false,
}: ScrollHeroProps) {
    // Trạng thái state machine + tiến độ cuộn.
    const [heroState, setHeroState] = useState<HeroState>("intro");
    const [scrollProgress, setScrollProgress] = useState(0);

    // Phát hiện prefers-reduced-motion phía client (SSR-safe).
    const [systemReducedMotion, setSystemReducedMotion] = useState(false);
    const [mobileViewport, setMobileViewport] = useState(false);

    // Nội dung ô quét nhanh.
    const [quickScanInput, setQuickScanInput] = useState("");

    // Ref tới section Hero cao (300vh) để đo tiến độ cuộn.
    const sectionRef = useRef<HTMLElement | null>(null);
    // Ref lưu trạng thái hiện tại cho listener (tránh stale closure).
    const heroStateRef = useRef<HeroState>("intro");

    heroStateRef.current = heroState;

    // Chế độ giảm hiệu ứng hiệu lực = prop HOẶC cài đặt hệ thống.
    const effectiveReducedMotion = reducedMotion || systemReducedMotion || mobileViewport;

    // -------------------------------------------------------------------
    // Phát hiện prefers-reduced-motion (client-only, SSR-safe)
    // -------------------------------------------------------------------
    useEffect(() => {
        if (typeof window === "undefined" || !window.matchMedia) {
            return;
        }
        const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
        setSystemReducedMotion(mq.matches);

        const onChange = (e: MediaQueryListEvent) =>
            setSystemReducedMotion(e.matches);
        mq.addEventListener?.("change", onChange);
        return () => mq.removeEventListener?.("change", onChange);
    }, []);

    // Trên mobile dùng hero tĩnh: không gắn scroll listener và không autoplay video.
    useEffect(() => {
        if (typeof window === "undefined" || !window.matchMedia) {
            return;
        }
        const mq = window.matchMedia("(max-width: 800px)");
        const update = () => setMobileViewport(mq.matches);
        update();
        mq.addEventListener?.("change", update);
        return () => mq.removeEventListener?.("change", update);
    }, []);

    // -------------------------------------------------------------------
    // Gắn listener scroll khi ở chế độ hiệu ứng đầy đủ (SSR-safe)
    // -------------------------------------------------------------------
    useEffect(() => {
        // Fallback tĩnh: bỏ toàn bộ hiệu ứng cuộn (Requirement 5.6).
        if (effectiveReducedMotion) {
            return;
        }
        if (typeof window === "undefined") {
            return;
        }

        // Tính tiến độ cuộn [0,1] trên toàn chiều cao section Hero.
        const computeProgress = (): number => {
            const el = sectionRef.current;
            if (!el) {
                return 0;
            }
            const rect = el.getBoundingClientRect();
            // Tổng quãng cuộn khả dụng = chiều cao section - chiều cao viewport.
            const scrollable = el.offsetHeight - window.innerHeight;
            if (scrollable <= 0) {
                return 0;
            }
            // rect.top đi từ 0 (đầu section chạm đỉnh) → -scrollable (cuối).
            const scrolled = -rect.top;
            return clamp01(scrolled / scrollable);
        };

        const handleScroll = () => {
            // intro → scroll_driven ngay lần cuộn đầu tiên (once).
            if (heroStateRef.current === "intro") {
                setHeroState((prev) => nextHeroState(prev, { type: "USER_SCROLLED" }));
            }

            const progress = computeProgress();
            setScrollProgress(progress);

            // scroll_driven → idle khi đạt 100%.
            if (progress >= 1) {
                setHeroState((prev) =>
                    nextHeroState(prev, { type: "PROGRESS_COMPLETE" }),
                );
            }
        };

        window.addEventListener("scroll", handleScroll, { passive: true });
        // Tính ngay lần đầu (trường hợp trang tải giữa chừng section).
        handleScroll();
        return () => window.removeEventListener("scroll", handleScroll);
    }, [effectiveReducedMotion]);

    // -------------------------------------------------------------------
    // Dẫn xuất giá trị hiển thị từ progress
    // -------------------------------------------------------------------

    // Chỉ số khung hình hiện tại (kẹp trong biên — Property 8).
    const frameIndex = useMemo(
        () => computeFrameIndex(scrollProgress, TOTAL_FRAMES),
        [scrollProgress],
    );

    /**
     * Transform mô phỏng camera dolly-out + warp cho <video> (Layer B).
     *
     * Khi progress tăng: video co nhỏ dần (scale 1 → ~0.55) và hơi nghiêng
     * phối cảnh (perspective + rotateX/skew) để gợi ý khớp màn hình laptop.
     * Đây là bản thay thế CSS cho `matrix3d()` từ corner_pin.json chưa có.
     */
    const videoTransform = useMemo(() => {
        if (effectiveReducedMotion) {
            return undefined;
        }
        const p = clamp01(scrollProgress);
        const scale = 1 - 0.45 * p; // 1 → 0.55
        const translateY = -8 * p; // nhích lên nhẹ
        const rotateX = 6 * p; // nghiêng phối cảnh
        return `perspective(1200px) translateY(${translateY}%) rotateX(${rotateX}deg) scale(${scale})`;
    }, [effectiveReducedMotion, scrollProgress]);

    // Callout (slogan/subtitle) lộ dần khi progress > ~0.5 (mốc "tường sau").
    const calloutOpacity = useMemo(() => {
        if (effectiveReducedMotion) {
            return 1;
        }
        const p = clamp01(scrollProgress);
        // 0 tại p<=0.5, 1 tại p>=0.85.
        const start = 0.5;
        const end = 0.85;
        if (p <= start) return 0;
        if (p >= end) return 1;
        return (p - start) / (end - start);
    }, [effectiveReducedMotion, scrollProgress]);

    // -------------------------------------------------------------------
    // Handlers
    // -------------------------------------------------------------------

    const handleQuickScanSubmit = useCallback(
        (e: React.FormEvent) => {
            e.preventDefault();
            onQuickScan(quickScanInput);
        },
        [onQuickScan, quickScanInput],
    );

    const showFinalContent = heroState === "idle";

    // -------------------------------------------------------------------
    // Render — Fallback tĩnh (Requirement 5.6)
    // -------------------------------------------------------------------
    if (effectiveReducedMotion) {
        return (
            <section
                ref={sectionRef}
                data-hero-state="idle"
                data-reduced-motion="true"
                aria-label="Hero — chế độ giảm chuyển động"
                className="relative flex min-h-[100svh] w-full flex-col items-center justify-center gap-4 overflow-hidden bg-neutral-950 px-4 py-10 text-center text-white sm:gap-6 sm:px-6 sm:py-16"
            >
                <HeroMedia className="w-full max-w-2xl" />
                <HeroCallout opacity={1} compact />
                <QuickScanBox
                    value={quickScanInput}
                    onChange={setQuickScanInput}
                    onSubmit={handleQuickScanSubmit}
                />
                <HeroCtas />
            </section>
        );
    }

    // -------------------------------------------------------------------
    // Render — Hero cuộn đầy đủ (section cao 300vh)
    // -------------------------------------------------------------------
    return (
        <section
            ref={sectionRef}
            data-hero-state={heroState}
            data-frame-index={frameIndex}
            aria-label="Hero — cuộn để khám phá sản phẩm"
            className="relative w-full bg-neutral-950 text-white"
            style={{ height: "300vh" }}
        >
            {/* Lớp dính (sticky) giữ Hero trong viewport suốt quá trình cuộn */}
            <div className="sticky top-0 h-screen w-full overflow-hidden px-6">
                {showFinalContent ? (
                    <div className="mx-auto flex h-full max-w-5xl flex-col items-center justify-center gap-5 py-8 text-center">
                        <HeroMedia
                            className="w-full max-w-2xl"
                            videoSrc={videoSrc}
                        />
                        <HeroCallout opacity={1} compact />
                        <QuickScanBox
                            value={quickScanInput}
                            onChange={setQuickScanInput}
                            onSubmit={handleQuickScanSubmit}
                        />
                        <HeroCtas />
                    </div>
                ) : (
                    <div className="flex h-full w-full flex-col items-center justify-center">
                        {/* Layer B: video demo — warp theo progress (dolly-out mô phỏng) */}
                        <HeroMedia
                            className="w-full max-w-3xl will-change-transform"
                            style={{
                                transform: videoTransform,
                                transformOrigin: "center center",
                                transition: "transform 80ms linear",
                            }}
                            videoSrc={videoSrc}
                        />

                        {/* Layer 3: callout (slogan/subtitle) lộ dần theo scroll */}
                        <div
                            className="pointer-events-none absolute inset-x-0 bottom-24 px-6"
                            style={{ opacity: calloutOpacity }}
                        >
                            <HeroCallout opacity={calloutOpacity} />
                        </div>

                        {/* Chỉ báo tiến độ cuộn (Layer A scrub) */}
                        {heroState === "scroll_driven" && (
                            <div
                                className="absolute bottom-6 left-1/2 -translate-x-1/2 text-xs text-neutral-400"
                                aria-hidden="true"
                            >
                                Cuộn để khám phá · {Math.round(scrollProgress * 100)}%
                            </div>
                        )}
                    </div>
                )}
            </div>
        </section>
    );
}

// ---------------------------------------------------------------------------
// Presentational subcomponents
// ---------------------------------------------------------------------------

/** Slogan + phụ đề của Hero. */
function HeroCallout({
    opacity,
    compact = false,
}: {
    opacity: number;
    compact?: boolean;
}) {
    return (
        <div
            style={{ opacity }}
            className={compact ? "mx-auto max-w-3xl text-center" : "mx-auto max-w-2xl text-center"}
        >
            <h1
                className={
                    compact
                        ? "text-xl font-bold leading-snug sm:text-2xl md:text-3xl"
                        : "text-2xl font-bold leading-snug sm:text-3xl md:text-4xl"
                }
            >
                &ldquo;{SLOGAN}&rdquo;
            </h1>
            <p className={compact ? "mt-2 text-sm text-neutral-300 sm:text-base" : "mt-3 text-sm text-neutral-300 sm:text-base"}>
                {SUBTITLE}
            </p>
        </div>
    );
}

/** Media stage của Hero: phát video thật nếu có, nếu không hiển thị ảnh demo fallback. */
function HeroMedia({
    videoSrc,
    className = "",
    style,
}: {
    videoSrc?: string;
    className?: string;
    style?: CSSProperties;
}) {
    const [videoReady, setVideoReady] = useState(false);
    const [videoFailed, setVideoFailed] = useState(false);

    useEffect(() => {
        setVideoReady(false);
        setVideoFailed(false);
    }, [videoSrc]);

    const shouldRenderVideo = Boolean(videoSrc) && !videoFailed;

    return (
        <div
            className={`relative aspect-[16/9] overflow-hidden rounded-xl bg-neutral-900 shadow-2xl ring-1 ring-white/10 ${className}`}
            style={style}
            aria-label="Video demo sản phẩm"
        >
            <div
                className={`absolute inset-0 bg-cover bg-center transition-opacity duration-300 ${
                    videoReady && shouldRenderVideo ? "opacity-0" : "opacity-100"
                }`}
                style={{ backgroundImage: `url(${FALLBACK_VISUAL_SRC})` }}
                aria-hidden="true"
            />
            <div
                className="absolute inset-0 bg-gradient-to-t from-black/20 via-transparent to-white/5"
                aria-hidden="true"
            />
            {shouldRenderVideo && (
                <video
                    className={`absolute inset-0 h-full w-full object-cover transition-opacity duration-300 ${
                        videoReady ? "opacity-100" : "opacity-0"
                    }`}
                    src={videoSrc}
                    autoPlay
                    muted
                    loop
                    playsInline
                    onCanPlay={() => setVideoReady(true)}
                    onError={() => setVideoFailed(true)}
                    aria-label="Video demo sản phẩm"
                />
            )}
            {(!shouldRenderVideo || !videoReady) && (
                <div
                    className="absolute left-4 top-4 rounded-full bg-black/55 px-3 py-1 text-xs font-semibold text-white backdrop-blur"
                    aria-hidden="true"
                >
                    Product demo preview
                </div>
            )}
        </div>
    );
}

/** Ô quét nhanh: input + nút [Quét]. */
function QuickScanBox({
    value,
    onChange,
    onSubmit,
}: {
    value: string;
    onChange: (v: string) => void;
    onSubmit: (e: React.FormEvent) => void;
}) {
    return (
        <form
            onSubmit={onSubmit}
            className="pointer-events-auto flex w-full max-w-xl flex-col items-stretch gap-2 rounded-2xl bg-white/95 p-1.5 shadow-lg sm:flex-row sm:items-center sm:rounded-full"
        >
            <input
                type="text"
                value={value}
                onChange={(e) => onChange(e.target.value)}
                placeholder={QUICK_SCAN_PLACEHOLDER}
                aria-label="Dán URL hoặc nội dung email để thử ngay"
                className="min-w-0 flex-1 bg-transparent px-4 py-2 text-sm text-neutral-900 placeholder:text-neutral-400 focus:outline-none"
            />
            <button
                type="submit"
                className="min-h-11 w-full shrink-0 rounded-xl bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-700 sm:w-auto sm:rounded-full"
            >
                Quét
            </button>
        </form>
    );
}

/** Cụm CTA dẫn vào hai luồng demo chính của sản phẩm. */
function HeroCtas() {
    return (
        <div className="pointer-events-auto flex w-full max-w-xl flex-col items-stretch justify-center gap-3 sm:w-auto sm:flex-row sm:items-center">
            <a
                href="/analyze"
                className="min-h-11 rounded-full bg-white px-5 py-2.5 text-center text-sm font-semibold text-neutral-900 transition-colors hover:bg-neutral-200"
            >
                Mở demo trực tiếp
            </a>
            <a
                href="/about"
                className="min-h-11 rounded-full border border-white/40 px-5 py-2.5 text-center text-sm font-semibold text-white transition-colors hover:bg-white/10"
            >
                Tìm hiểu giải pháp
            </a>
        </div>
    );
}
