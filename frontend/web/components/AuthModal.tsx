"use client";

/**
 * Component AuthModal — hộp thoại đăng nhập / đăng ký.
 *
 * Hỗ trợ hai chế độ trong cùng một modal: "login" và "register", có thể chuyển
 * qua lại. Theo Sequence Diagram 3 (design.md — "Đăng nhập & tải dữ liệu tài
 * khoản"):
 *   - Người dùng nhập email/mật khẩu → nhấn Đăng nhập.
 *   - Gọi `getApiClient().login(cred)` (hoặc `.register(cred)` cho đăng ký).
 *   - Nhận Session → `useAuth().setSession(session)` → đóng modal.
 *
 * Trước khi gọi API, modal LUÔN kiểm tra định dạng email phía client
 * (Requirement 11.4): nếu email không hợp lệ → hiển thị lỗi validation và
 * KHÔNG gọi login/register.
 *
 * Khả năng truy cập (accessibility):
 *   - `role="dialog"` + `aria-modal="true"` + gắn `aria-labelledby`.
 *   - Nhấn phím ESC để đóng; nhấp ra ngoài (backdrop) cũng đóng.
 *
 * _Requirements: 11.1, 11.4, 11.5_
 */

import {
    useCallback,
    useEffect,
    useId,
    useRef,
    useState,
    type FormEvent,
} from "react";

import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";
import type { Credentials, RegisterInput } from "@/lib/types";

/** Hai chế độ hiển thị của modal. */
export type AuthMode = "login" | "register";

export interface AuthModalProps {
    /** Có mở modal hay không. */
    open: boolean;
    /** Chế độ hiện tại: đăng nhập hay đăng ký. */
    mode: AuthMode;
    /** Gọi khi yêu cầu đóng modal (ESC, nhấp backdrop, nút ✕, hoặc thành công). */
    onClose: () => void;
    /** Gọi khi người dùng chuyển chế độ trong modal (login ⇄ register). */
    onModeChange?: (mode: AuthMode) => void;
}

/**
 * Regex kiểm tra định dạng email cơ bản: có phần trước @, một @, tên miền và
 * TLD. Cố ý giữ đơn giản nhưng đủ chặt để loại các chuỗi rõ ràng không hợp lệ
 * (thiếu @, thiếu miền, có khoảng trắng).
 */
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Kiểm tra định dạng email hợp lệ (client-side, trước khi gọi API). */
export function isValidEmail(email: string): boolean {
    return EMAIL_PATTERN.test(email.trim());
}

/** Nhãn tiếng Việt theo chế độ. */
const TITLE: Record<AuthMode, string> = {
    login: "Đăng nhập",
    register: "Đăng ký",
};

const SUBMIT_LABEL: Record<AuthMode, string> = {
    login: "Đăng nhập",
    register: "Đăng ký",
};

const INPUT_CLASS =
    "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 " +
    "placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 " +
    "focus:ring-indigo-500/30 disabled:cursor-not-allowed disabled:opacity-60";

/**
 * AuthModal — form đăng nhập/đăng ký với kiểm tra email trước khi gọi API.
 */
export default function AuthModal({
    open,
    mode,
    onClose,
    onModeChange,
}: AuthModalProps): JSX.Element | null {
    const { setSession } = useAuth();

    // Trường nhập liệu.
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [displayName, setDisplayName] = useState("");
    const [showPassword, setShowPassword] = useState(false);

    // Trạng thái lỗi & đang gửi.
    const [error, setError] = useState<string | null>(null);
    const [submitting, setSubmitting] = useState(false);

    // ID cho aria-labelledby (ổn định qua các render).
    const titleId = useId();

    // Tham chiếu input đầu tiên để auto-focus khi mở.
    const emailInputRef = useRef<HTMLInputElement>(null);

    // Reset form mỗi khi mở modal hoặc đổi chế độ.
    useEffect(() => {
        if (open) {
            setError(null);
            setSubmitting(false);
            setShowPassword(false);
        }
    }, [open, mode]);

    // Auto-focus vào ô email khi modal mở.
    useEffect(() => {
        if (open) {
            emailInputRef.current?.focus();
        }
    }, [open]);

    // Đóng modal khi nhấn ESC.
    useEffect(() => {
        if (!open) {
            return;
        }
        function handleKeyDown(event: KeyboardEvent): void {
            if (event.key === "Escape") {
                onClose();
            }
        }
        window.addEventListener("keydown", handleKeyDown);
        return () => window.removeEventListener("keydown", handleKeyDown);
    }, [open, onClose]);

    // Chuyển chế độ login ⇄ register.
    const switchMode = useCallback(
        (next: AuthMode): void => {
            setError(null);
            onModeChange?.(next);
        },
        [onModeChange],
    );

    const handleSubmit = useCallback(
        async (event: FormEvent<HTMLFormElement>): Promise<void> => {
            event.preventDefault();
            setError(null);

            const trimmedEmail = email.trim();

            // Requirement 11.4: validate định dạng email TRƯỚC khi gọi API.
            if (!isValidEmail(trimmedEmail)) {
                setError("Định dạng email không hợp lệ.");
                return;
            }

            if (password.length === 0) {
                setError("Vui lòng nhập mật khẩu.");
                return;
            }

            if (mode === "register" && displayName.trim().length === 0) {
                setError("Vui lòng nhập tên hiển thị.");
                return;
            }

            setSubmitting(true);
            try {
                const api = getApiClient();
                if (mode === "login") {
                    const cred: Credentials = {
                        email: trimmedEmail,
                        password,
                    };
                    const session = await api.login(cred);
                    setSession(session);
                } else {
                    const cred: RegisterInput = {
                        email: trimmedEmail,
                        password,
                        displayName: displayName.trim(),
                    };
                    const session = await api.register(cred);
                    setSession(session);
                }
                onClose();
            } catch (err) {
                const message =
                    err instanceof Error
                        ? err.message
                        : "Đã có lỗi xảy ra. Vui lòng thử lại.";
                setError(message);
            } finally {
                setSubmitting(false);
            }
        },
        [email, password, displayName, mode, setSession, onClose],
    );

    if (!open) {
        return null;
    }

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4"
            onClick={onClose}
        >
            <div
                role="dialog"
                aria-modal="true"
                aria-labelledby={titleId}
                className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl"
                onClick={(event) => event.stopPropagation()}
            >
                {/* Header: logo + tiêu đề + nút đóng */}
                <div className="relative mb-6 text-center">
                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Đóng"
                        className="absolute right-0 top-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
                    >
                        <span aria-hidden="true" className="text-lg leading-none">
                            ✕
                        </span>
                    </button>
                    <div className="text-2xl" aria-hidden="true">
                        🛡️
                    </div>
                    <div className="text-xs font-medium tracking-wide text-slate-400">
                        Prewise
                    </div>
                    <h2
                        id={titleId}
                        className="mt-2 text-xl font-bold text-slate-900"
                    >
                        {TITLE[mode]}
                    </h2>
                </div>

                {/* Thông báo lỗi */}
                {error !== null && (
                    <div
                        role="alert"
                        className="mb-4 rounded-lg border border-risk-danger-border bg-risk-danger-bg px-3 py-2 text-sm text-risk-danger"
                    >
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} noValidate className="space-y-4">
                    {/* Email */}
                    <div>
                        <label
                            htmlFor="auth-email"
                            className="mb-1 block text-sm font-medium text-slate-700"
                        >
                            Email
                        </label>
                        <input
                            id="auth-email"
                            ref={emailInputRef}
                            type="email"
                            name="email"
                            autoComplete="email"
                            placeholder="ban@example.com"
                            value={email}
                            disabled={submitting}
                            onChange={(e) => setEmail(e.target.value)}
                            className={INPUT_CLASS}
                        />
                    </div>

                    {/* Tên hiển thị (chỉ chế độ đăng ký) */}
                    {mode === "register" && (
                        <div>
                            <label
                                htmlFor="auth-display-name"
                                className="mb-1 block text-sm font-medium text-slate-700"
                            >
                                Tên hiển thị
                            </label>
                            <input
                                id="auth-display-name"
                                type="text"
                                name="displayName"
                                autoComplete="name"
                                placeholder="Nguyễn Văn A"
                                value={displayName}
                                disabled={submitting}
                                onChange={(e) => setDisplayName(e.target.value)}
                                className={INPUT_CLASS}
                            />
                        </div>
                    )}

                    {/* Mật khẩu + toggle hiện/ẩn */}
                    <div>
                        <label
                            htmlFor="auth-password"
                            className="mb-1 block text-sm font-medium text-slate-700"
                        >
                            Mật khẩu
                        </label>
                        <div className="relative">
                            <input
                                id="auth-password"
                                type={showPassword ? "text" : "password"}
                                name="password"
                                autoComplete={
                                    mode === "login"
                                        ? "current-password"
                                        : "new-password"
                                }
                                placeholder="••••••••"
                                value={password}
                                disabled={submitting}
                                onChange={(e) => setPassword(e.target.value)}
                                className={`${INPUT_CLASS} pr-10`}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword((v) => !v)}
                                aria-label={
                                    showPassword
                                        ? "Ẩn mật khẩu"
                                        : "Hiện mật khẩu"
                                }
                                aria-pressed={showPassword}
                                className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-400 hover:text-slate-600"
                            >
                                <span aria-hidden="true">
                                    {showPassword ? "🙈" : "👁"}
                                </span>
                            </button>
                        </div>
                    </div>

                    {/* Nút submit */}
                    <button
                        type="submit"
                        disabled={submitting}
                        className="w-full rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/40 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        {submitting ? "Đang xử lý…" : SUBMIT_LABEL[mode]}
                    </button>
                </form>

                {/* Login-only: Google (mock) + quên mật khẩu */}
                {mode === "login" && (
                    <>
                        <div className="my-4 flex items-center gap-3">
                            <span className="h-px flex-1 bg-slate-200" />
                            <span className="text-xs text-slate-400">hoặc</span>
                            <span className="h-px flex-1 bg-slate-200" />
                        </div>
                        <button
                            type="button"
                            disabled={submitting}
                            aria-label="Tiếp tục với Google"
                            className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                            <span aria-hidden="true" className="font-bold text-[#4285F4]">
                                G
                            </span>
                            Tiếp tục với Google
                        </button>
                        <div className="mt-4 text-center">
                            <button
                                type="button"
                                className="text-sm text-slate-500 hover:text-slate-700 hover:underline"
                            >
                                Quên mật khẩu?
                            </button>
                        </div>
                    </>
                )}

                {/* Link chuyển chế độ */}
                <div className="mt-4 text-center text-sm text-slate-600">
                    {mode === "login" ? (
                        <span>
                            Chưa có tài khoản?{" "}
                            <button
                                type="button"
                                onClick={() => switchMode("register")}
                                className="font-semibold text-indigo-600 hover:underline"
                            >
                                Đăng ký
                            </button>
                        </span>
                    ) : (
                        <span>
                            Đã có tài khoản?{" "}
                            <button
                                type="button"
                                onClick={() => switchMode("login")}
                                className="font-semibold text-indigo-600 hover:underline"
                            >
                                Đăng nhập
                            </button>
                        </span>
                    )}
                </div>
            </div>
        </div>
    );
}
