"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";
import { canUseApiKeyMcp } from "@/lib/entitlements";
import type { ApiKeyInfo } from "@/lib/types";

const mask = (key: string) =>
    key.length > 12 ? `${key.slice(0, 8)}••••••••${key.slice(-4)}` : "••••••••";

export default function ApiKeyPage() {
    const { plan } = useAuth();
    const tier = plan?.tier;
    const eligible = canUseApiKeyMcp(tier);
    const [key, setKey] = useState<ApiKeyInfo | null | undefined>(undefined);
    const [show, setShow] = useState(false);
    const [confirm, setConfirm] = useState(false);
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState("");

    useEffect(() => {
        if (!tier) return;
        if (!eligible) {
            setKey(null);
            return;
        }
        getApiClient().getApiKey().then(setKey).catch(() => setKey(null));
    }, [eligible, tier]);

    async function copy() {
        if (!key?.secretAvailable) {
            setNotice("Bản key đã che không thể sử dụng. Hãy tạo lại key để nhận secret mới.");
            return;
        }
        try {
            await navigator.clipboard.writeText(key.key);
            setNotice("Đã sao chép secret key vào clipboard");
        } catch {
            setNotice("Không thể sao chép tự động");
        }
    }

    async function rotate() {
        setBusy(true);
        try {
            const next = await getApiClient().rotateApiKey();
            setKey(next);
            setShow(true);
            setNotice("Key mới chỉ hiển thị lần này. Hãy sao chép và lưu ngay; key cũ đã mất hiệu lực.");
        } catch {
            setNotice("Không thể tạo lại key");
        } finally {
            setBusy(false);
            setConfirm(false);
        }
    }

    return (
        <div className="account-page">
            <header>
                <span>DEVELOPER / CREDENTIALS</span>
                <h1>API & MCP key</h1>
                <p>Kết nối Prewise với AI agent, automation và ứng dụng nội bộ.</p>
            </header>

            {tier && !eligible && (
                <div className="account-callout">
                    <span>TEAM FEATURE</span>
                    <p>API key và MCP chỉ khả dụng từ gói Team. Backend sẽ từ chối credential của gói thấp hơn.</p>
                    <Link href="/pricing">Xem gói Team →</Link>
                </div>
            )}

            {eligible && key === undefined && (
                <div className="key-skeleton">Đang thiết lập kênh bảo mật…</div>
            )}
            {eligible && key === null && (
                <div className="key-skeleton">Không thể tải API key. Hãy tải lại trang hoặc thử lại sau.</div>
            )}
            {eligible && key && (
                <section className="key-panel">
                    <div className="key-meta">
                        <span>{key.secretAvailable ? "SECRET KEY · CHỈ HIỂN THỊ MỘT LẦN" : "KEY ĐÃ ĐƯỢC CHE"}</span>
                        <small>CREATED · {key.createdAt}</small>
                    </div>
                    <code>{key.secretAvailable ? (show ? key.key : mask(key.key)) : key.key}</code>
                    <div className="account-actions">
                        {key.secretAvailable && (
                            <button className="secondary" onClick={() => setShow((value) => !value)}>
                                {show ? "Ẩn key" : "Hiện key"}
                            </button>
                        )}
                        <button className="secondary" disabled={!key.secretAvailable} onClick={copy}>
                            {key.secretAvailable ? "Sao chép secret" : "Không thể sao chép bản che"}
                        </button>
                        {confirm ? (
                            <>
                                <button className="danger" disabled={busy} onClick={rotate}>
                                    {busy ? "Đang tạo…" : "Xác nhận tạo lại"}
                                </button>
                                <button className="secondary" onClick={() => setConfirm(false)}>Hủy</button>
                            </>
                        ) : (
                            <button onClick={() => setConfirm(true)}>Tạo lại key →</button>
                        )}
                    </div>
                    {!key.secretAvailable && (
                        <p className="key-warning">Server không lưu secret gốc. Chuỗi có **** chỉ giúp nhận diện key và không dùng để xác thực.</p>
                    )}
                    {confirm && <p className="key-warning">Key hiện tại sẽ mất hiệu lực ngay lập tức.</p>}
                    {notice && <p className="form-success">✓ {notice}</p>}
                </section>
            )}

            {eligible && (
                <p className="key-warning">Muốn lấy secret đầy đủ, chọn “Tạo lại key”, xác nhận rồi sao chép ngay. Secret đầy đủ chỉ được trả về một lần.</p>
            )}
            <section className="integration-note">
                <span>MCP ENDPOINT</span>
                <code>https://api.prewise.site/mcp</code>
                <p>Endpoint yêu cầu gói Team hoặc Enterprise và Bearer token còn hiệu lực.</p>
                {eligible && (
                    <Link className="mcp-quick-link" href="/account/mcp-connect">
                        Kết nối nhanh với ChatGPT, Claude, Grok và các AI khác →
                    </Link>
                )}
            </section>
        </div>
    );
}
