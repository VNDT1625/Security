import type { Config } from "tailwindcss";

/**
 * TailwindCSS config cho Web App UI — Prewise.
 *
 * Design token màu rủi ro theo thang chuẩn (khớp wireframe & Extension badge):
 *   - safe   (Xanh)  : điểm 0–39   → "AN TOÀN"
 *   - warn   (Vàng)  : điểm 40–69  → "ĐÁNG NGỜ"
 *   - danger (Đỏ)    : điểm 70–100 → "RỦI RO CAO"
 *
 * `lib/risk.ts` là nguồn duy nhất ánh xạ điểm → mức; các token này chỉ cung cấp
 * bảng màu để component tái sử dụng nhất quán.
 */
const config: Config = {
    content: [
        "./app/**/*.{ts,tsx}",
        "./components/**/*.{ts,tsx}",
        "./context/**/*.{ts,tsx}",
        "./hooks/**/*.{ts,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                risk: {
                    // AN TOÀN — Xanh
                    safe: {
                        DEFAULT: "#16a34a",
                        fg: "#052e16",
                        bg: "#dcfce7",
                        border: "#22c55e",
                    },
                    // ĐÁNG NGỜ — Vàng
                    warn: {
                        DEFAULT: "#d97706",
                        fg: "#451a03",
                        bg: "#fef3c7",
                        border: "#f59e0b",
                    },
                    // RỦI RO CAO — Đỏ
                    danger: {
                        DEFAULT: "#dc2626",
                        fg: "#450a0a",
                        bg: "#fee2e2",
                        border: "#ef4444",
                    },
                },
            },
        },
    },
    plugins: [],
};

export default config;
