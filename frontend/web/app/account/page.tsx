"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type FormEvent } from "react";

import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";
import type { ProfileUpdateInput, UserProfile } from "@/lib/types";

const COUNTRIES = [
    ["VN", "Việt Nam"],
    ["SG", "Singapore"],
    ["JP", "Nhật Bản"],
    ["KR", "Hàn Quốc"],
    ["US", "Hoa Kỳ"],
    ["GB", "Vương quốc Anh"],
    ["AU", "Úc"],
    ["CA", "Canada"],
    ["DE", "Đức"],
    ["FR", "Pháp"],
] as const;

const TIMEZONES = [
    ["Asia/Ho_Chi_Minh", "TP. Hồ Chí Minh · UTC+7"],
    ["Asia/Singapore", "Singapore · UTC+8"],
    ["Asia/Tokyo", "Tokyo · UTC+9"],
    ["Asia/Seoul", "Seoul · UTC+9"],
    ["Europe/London", "London"],
    ["America/New_York", "New York"],
    ["UTC", "UTC"],
] as const;

const defaults = (profile: UserProfile): ProfileUpdateInput => ({
    displayName: profile.displayName,
    organizationName: profile.organizationName ?? null,
    jobTitle: profile.jobTitle ?? null,
    countryCode: profile.countryCode ?? "VN",
    locale: profile.locale ?? "vi",
    timezone: profile.timezone ?? "Asia/Ho_Chi_Minh",
});

const initials = (name: string, email: string) =>
    (name.trim() || email)
        .split(/\s+/)
        .slice(0, 2)
        .map((part) => part[0])
        .join("")
        .toUpperCase();

const formatDate = (value?: string | null) => {
    if (!value) return "Chưa có dữ liệu";
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? "Chưa có dữ liệu"
        : new Intl.DateTimeFormat("vi-VN", {
              dateStyle: "medium",
              timeStyle: "short",
          }).format(date);
};

export default function Account(): JSX.Element {
    const { session, isHydrated, setSession } = useAuth();
    const [profile, setProfile] = useState<UserProfile | null>(null);
    const [loadingError, setLoadingError] = useState("");

    useEffect(() => {
        if (!session) return;
        let cancelled = false;
        setProfile(null);
        setLoadingError("");
        void getApiClient()
            .getProfile()
            .then((fresh) => {
                if (cancelled) return;
                setProfile(fresh);
                setSession({ ...session, user: fresh });
            })
            .catch((error: unknown) => {
                if (cancelled) return;
                setProfile(session.user);
                setLoadingError(
                    error instanceof Error
                        ? error.message
                        : "Không thể tải hồ sơ mới nhất.",
                );
            });
        return () => {
            cancelled = true;
        };
    }, [session?.token]); // eslint-disable-line react-hooks/exhaustive-deps

    if (!isHydrated || (session && !profile)) {
        return (
            <div className="account-page">
                <div className="key-skeleton">Đang tải hồ sơ từ máy chủ…</div>
            </div>
        );
    }

    if (!session) {
        return (
            <div className="account-page">
                <header>
                    <span>PROFILE / IDENTITY</span>
                    <h1>Hồ sơ của bạn</h1>
                    <p>Đăng nhập để quản lý danh tính, bảo mật và tùy chọn tài khoản.</p>
                </header>
                <section className="account-callout">
                    <span>YÊU CẦU ĐĂNG NHẬP</span>
                    <p>Thông tin hồ sơ chỉ được đọc và lưu trong phiên xác thực của bạn.</p>
                    <Link href="/auth">Đăng nhập hoặc tạo tài khoản →</Link>
                </section>
            </div>
        );
    }

    return (
        <ProfileEditor
            profile={profile ?? session.user}
            planLabel={session.plan.label}
            loadingError={loadingError}
            onSaved={(fresh) => {
                setProfile(fresh);
                setSession({ ...session, user: fresh });
            }}
        />
    );
}

function ProfileEditor({
    profile,
    planLabel,
    loadingError,
    onSaved,
}: {
    profile: UserProfile;
    planLabel: string;
    loadingError: string;
    onSaved: (profile: UserProfile) => void;
}): JSX.Element {
    const initialForm = useMemo(() => defaults(profile), [profile]);
    const [form, setForm] = useState<ProfileUpdateInput>(initialForm);
    const [baseline, setBaseline] = useState<ProfileUpdateInput>(initialForm);
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState("");
    const [error, setError] = useState("");
    const [passwordOpen, setPasswordOpen] = useState(false);
    const [currentPassword, setCurrentPassword] = useState("");
    const [newPassword, setNewPassword] = useState("");

    useEffect(() => {
        setForm(initialForm);
        setBaseline(initialForm);
    }, [initialForm]);

    const dirty =
        form.displayName.trim().length > 0 &&
        JSON.stringify(form) !== JSON.stringify(baseline);

    const setField = <K extends keyof ProfileUpdateInput>(
        key: K,
        value: ProfileUpdateInput[K],
    ) => setForm((current) => ({ ...current, [key]: value }));

    async function save(event: FormEvent): Promise<void> {
        event.preventDefault();
        if (!dirty) return;
        setBusy(true);
        setError("");
        setNotice("");
        try {
            const payload: ProfileUpdateInput = {
                ...form,
                displayName: form.displayName.trim(),
                organizationName: form.organizationName?.trim() || null,
                jobTitle: form.jobTitle?.trim() || null,
            };
            const fresh = await getApiClient().updateProfile(payload);
            const next = defaults(fresh);
            setForm(next);
            setBaseline(next);
            onSaved(fresh);
            setNotice("Hồ sơ đã được lưu vào tài khoản.");
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Không thể lưu hồ sơ.");
        } finally {
            setBusy(false);
        }
    }

    async function changePassword(event: FormEvent): Promise<void> {
        event.preventDefault();
        setBusy(true);
        setError("");
        setNotice("");
        try {
            await getApiClient().changePassword({
                currentPassword,
                newPassword,
            });
            setCurrentPassword("");
            setNewPassword("");
            setPasswordOpen(false);
            setNotice("Mật khẩu đã được thay đổi.");
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Không thể đổi mật khẩu.");
        } finally {
            setBusy(false);
        }
    }

    return (
        <div className="account-page account-profile-page">
            <header>
                <span>PROFILE / IDENTITY</span>
                <h1>Tài khoản</h1>
                <p>Danh tính, thông tin nghề nghiệp, khu vực và bảo mật của bạn.</p>
            </header>

            <section className="identity-card account-identity-card">
                <div className="account-avatar">
                    {initials(form.displayName, profile.email)}
                </div>
                <div className="identity-primary">
                    <b>{form.displayName.trim() || "Chưa đặt tên"}</b>
                    <small>{profile.email}</small>
                    <span>{form.jobTitle || form.organizationName || "Hồ sơ cá nhân"}</span>
                </div>
                <i className={profile.emailVerified ? "verified" : "unverified"}>
                    {profile.emailVerified ? "EMAIL ĐÃ XÁC MINH" : "EMAIL CHƯA XÁC MINH"}
                </i>
            </section>

            <section className="account-facts" aria-label="Thông tin tài khoản">
                <div>
                    <span>GÓI HIỆN TẠI</span>
                    <strong>{planLabel}</strong>
                </div>
                <div>
                    <span>TRẠNG THÁI</span>
                    <strong>{profile.status === "active" ? "Đang hoạt động" : profile.status}</strong>
                </div>
                <div>
                    <span>THAM GIA</span>
                    <strong>{formatDate(profile.createdAt)}</strong>
                </div>
                <div>
                    <span>ĐĂNG NHẬP GẦN NHẤT</span>
                    <strong>{formatDate(profile.lastLoginAt)}</strong>
                </div>
            </section>

            {loadingError && (
                <p className="account-load-warning" role="alert">
                    Đang hiển thị dữ liệu phiên gần nhất: {loadingError}
                </p>
            )}

            <div className="account-profile-grid">
                <form className="account-form account-details-form" onSubmit={save}>
                    <div className="account-section-heading">
                        <span>01 / PROFILE</span>
                        <div>
                            <h2>Thông tin hồ sơ</h2>
                            <p>Dùng để cá nhân hóa nội dung và ngữ cảnh làm việc.</p>
                        </div>
                    </div>

                    <div className="account-field-grid">
                        <label>
                            Tên hiển thị
                            <input
                                value={form.displayName}
                                maxLength={200}
                                onChange={(event) => setField("displayName", event.target.value)}
                                placeholder="Tên của bạn"
                                required
                            />
                        </label>
                        <label>
                            Chức danh
                            <input
                                value={form.jobTitle ?? ""}
                                maxLength={160}
                                onChange={(event) => setField("jobTitle", event.target.value)}
                                placeholder="Ví dụ: Chuyên viên an ninh mạng"
                            />
                        </label>
                        <label className="account-field-wide">
                            Tổ chức / công ty
                            <input
                                value={form.organizationName ?? ""}
                                maxLength={200}
                                onChange={(event) =>
                                    setField("organizationName", event.target.value)
                                }
                                placeholder="Nơi bạn đang học tập hoặc làm việc"
                            />
                        </label>
                        <label>
                            Quốc gia
                            <select
                                value={form.countryCode}
                                onChange={(event) => setField("countryCode", event.target.value)}
                            >
                                {COUNTRIES.map(([code, label]) => (
                                    <option key={code} value={code}>
                                        {label}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <label>
                            Ngôn ngữ ưu tiên
                            <select
                                value={form.locale}
                                onChange={(event) =>
                                    setField("locale", event.target.value as "vi" | "en")
                                }
                            >
                                <option value="vi">Tiếng Việt</option>
                                <option value="en">English</option>
                            </select>
                        </label>
                        <label className="account-field-wide">
                            Múi giờ
                            <select
                                value={form.timezone}
                                onChange={(event) => setField("timezone", event.target.value)}
                            >
                                {TIMEZONES.map(([zone, label]) => (
                                    <option key={zone} value={zone}>
                                        {label}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <label className="account-field-wide">
                            Email đăng nhập <small>KHÔNG THỂ THAY ĐỔI</small>
                            <input value={profile.email} readOnly />
                        </label>
                    </div>

                    {notice && (
                        <p className="form-success" role="status">
                            ✓ {notice}
                        </p>
                    )}
                    {error && (
                        <p className="form-error" role="alert">
                            {error}
                        </p>
                    )}
                    <div className="account-actions">
                        <button disabled={!dirty || busy}>
                            {busy ? "Đang lưu…" : "Lưu thay đổi →"}
                        </button>
                    </div>
                </form>

                <aside className="account-security-column">
                    <section className="account-security-card">
                        <div className="account-section-heading">
                            <span>02 / SECURITY</span>
                            <div>
                                <h2>Bảo mật</h2>
                                <p>Quản lý thông tin xác thực và quyền truy cập.</p>
                            </div>
                        </div>
                        <dl>
                            <div>
                                <dt>Mật khẩu</dt>
                                <dd>Được bảo vệ bằng hàm băm và salt riêng.</dd>
                            </div>
                            <div>
                                <dt>Email</dt>
                                <dd>
                                    {profile.emailVerified
                                        ? "Đã xác minh quyền sở hữu."
                                        : "Chưa có bản ghi xác minh."}
                                </dd>
                            </div>
                        </dl>
                        <button
                            type="button"
                            className="secondary account-security-action"
                            onClick={() => setPasswordOpen((open) => !open)}
                        >
                            {passwordOpen ? "Đóng đổi mật khẩu" : "Đổi mật khẩu →"}
                        </button>
                    </section>

                    <nav className="account-quick-links" aria-label="Quản lý tài khoản">
                        <Link href="/account/billing">
                            <span>Gói & thanh toán</span>
                            <small>Xem quyền lợi và hạn mức →</small>
                        </Link>
                        <Link href="/account/history">
                            <span>Lịch sử phân tích</span>
                            <small>Quản lý dữ liệu đã lưu →</small>
                        </Link>
                        <Link href="/account/api-key">
                            <span>API key</span>
                            <small>Quản lý truy cập tích hợp →</small>
                        </Link>
                        <Link href="/account/mcp-connect">
                            <span>Kết nối MCP</span>
                            <small>Dùng Prewise trong công cụ AI →</small>
                        </Link>
                    </nav>
                </aside>
            </div>

            {passwordOpen && (
                <form className="password-panel" onSubmit={changePassword}>
                    <span>SECURITY / PASSWORD</span>
                    <h2>Đổi mật khẩu</h2>
                    <p>Nhập mật khẩu hiện tại để xác nhận đây là tài khoản của bạn.</p>
                    <input
                        aria-label="Mật khẩu hiện tại"
                        type="password"
                        value={currentPassword}
                        onChange={(event) => setCurrentPassword(event.target.value)}
                        placeholder="Mật khẩu hiện tại"
                        required
                    />
                    <input
                        aria-label="Mật khẩu mới"
                        type="password"
                        value={newPassword}
                        onChange={(event) => setNewPassword(event.target.value)}
                        minLength={12}
                        placeholder="Mật khẩu mới · tối thiểu 12 ký tự"
                        required
                    />
                    <div className="account-actions">
                        <button
                            type="button"
                            className="secondary"
                            onClick={() => setPasswordOpen(false)}
                        >
                            Hủy
                        </button>
                        <button disabled={busy}>Xác nhận →</button>
                    </div>
                </form>
            )}
        </div>
    );
}
