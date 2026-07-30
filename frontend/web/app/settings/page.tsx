"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type Dispatch, type SetStateAction } from "react";
import { PrewiseShell } from "@/components/PrewiseUI";
import { useAuth } from "@/context/AuthContext";
import { useLanguage } from "@/context/LanguageContext";
import { getApiClient } from "@/lib/api";
import { clearResultHistory } from "@/lib/result-storage";
import type { UserAISettings, UserSelectableAIProvider } from "@/lib/types";
import mobileStyles from "../mobile-pages.module.css";

type Tab = "ai" | "appearance" | "privacy" | "data" | "language";
type Prefs = { motion: string; density: string; saveHistory: boolean; maskSensitive: boolean; language: string };
type AIDraft = { provider: UserSelectableAIProvider; baseUrl: string; model: string; apiKey: string; weightPercent: number };
const defaults: Prefs = { motion: "balanced", density: "comfortable", saveHistory: true, maskSensitive: true, language: "vi" };
const webProviders: UserSelectableAIProvider[] = ["adapter", "endpoint"];
const emptyAI: UserAISettings = { provider: "auto", baseUrl: "", model: "", apiKeyConfigured: false, configured: false, source: "account", percent: 0, minPercent: 0, maxPercent: 40, weightPercent: 0, weightEligible: false, weightSource: "global", allowedProviders: webProviders, allowedModels: [] };
const fallbackProvider: UserSelectableAIProvider = "adapter";
const forWeb = (value: UserAISettings): UserAISettings => ({
    ...value,
    allowedProviders: value.allowedProviders.filter(provider => webProviders.includes(provider)),
});

export default function Settings() {
    const { language, setLanguage } = useLanguage();
    const { session, isHydrated } = useAuth();
    const [tab, setTab] = useState<Tab>("ai");
    const [prefs, setPrefs] = useState<Prefs>(defaults);
    const [notice, setNotice] = useState("");
    const [confirmClear, setConfirmClear] = useState(false);
    const [ai, setAI] = useState<UserAISettings>(emptyAI);
    const [aiDraft, setAIDraft] = useState<AIDraft>({ provider: fallbackProvider, baseUrl: "", model: "", apiKey: "", weightPercent: 0 });
    const [aiBusy, setAIBusy] = useState(false);
    const [aiNotice, setAINotice] = useState("");

    useEffect(() => { try { const saved = JSON.parse(localStorage.getItem("prewise-settings") || "null"); if (saved) setPrefs({ ...defaults, ...saved, language }); } catch {} }, [language]);
    useEffect(() => { document.documentElement.dataset.motion = prefs.motion; document.documentElement.dataset.density = prefs.density; try { localStorage.setItem("prewise-settings", JSON.stringify(prefs)); } catch {} }, [prefs]);

    const loadAI = useCallback(async () => {
        if (!session) return;
        setAIBusy(true); setAINotice("");
        try {
            const value = forWeb(await getApiClient().getAISettings());
            setAI(value);
            const selected = value.source === "account" && value.provider !== "auto" && value.provider !== "local" && value.allowedProviders.includes(value.provider)
                ? value.provider
                : value.allowedProviders[0] ?? fallbackProvider;
            setAIDraft(value.source === "account" && value.provider === selected
                ? { provider: selected, baseUrl: value.baseUrl, model: value.model, apiKey: "", weightPercent: value.weightPercent }
                : { provider: selected, baseUrl: "", model: "", apiKey: "", weightPercent: value.weightPercent });
        } catch (error) {
            setAINotice(error instanceof Error ? error.message : "Không tải được cài đặt AI.");
        } finally { setAIBusy(false); }
    }, [session]);
    useEffect(() => { void loadAI(); }, [loadAI]);

    const update = (patch: Partial<Prefs>) => { setPrefs(v => ({ ...v, ...patch })); if (patch.language === "vi" || patch.language === "en") setLanguage(patch.language); setNotice("Đã lưu thay đổi"); setTimeout(() => setNotice(""), 1800); };
    const clear = () => { clearResultHistory(); setConfirmClear(false); setNotice("Đã xóa toàn bộ lịch sử cục bộ"); setTimeout(() => setNotice(""), 2200); };
    const saveAI = async () => {
        setAIBusy(true); setAINotice("");
        try {
            const { weightPercent, ...providerDraft } = aiDraft;
            const value = forWeb(await getApiClient().updateAISettings({ ...providerDraft, ...(ai.weightEligible ? { weightPercent } : {}), ...(aiDraft.apiKey ? { apiKey: aiDraft.apiKey } : {}) }));
            setAI(value); setAIDraft(current => ({ ...current, apiKey: "" }));
            setAINotice("Đã lưu cấu hình AI riêng cho tài khoản này.");
        } catch (error) { setAINotice(error instanceof Error ? error.message : "Không lưu được cài đặt AI."); }
        finally { setAIBusy(false); }
    };
    const testAI = async () => {
        setAIBusy(true); setAINotice("");
        try { const value = await getApiClient().testAISettings(); setAINotice(value.modelAvailable ? `Kết nối model thành công · endpoint có ${value.modelsCount} model.` : "Kết nối được endpoint nhưng không tìm thấy model đã chọn."); }
        catch (error) { setAINotice(error instanceof Error ? error.message : "Không kiểm tra được model."); }
        finally { setAIBusy(false); }
    };

    const nav: [Tab, string][] = [["ai", "Model AI"], ["appearance", "Giao diện"], ["privacy", "Quyền riêng tư"], ["data", "Dữ liệu"], ["language", "Ngôn ngữ"]];
    return <PrewiseShell><main className="inner-page settings-page"><header className="inner-head"><p className="eyebrow"><i /> PERSONAL EXPERIENCE</p><h1>Cài đặt</h1><p>Điều chỉnh Prewise theo cách bạn đọc, làm việc và bảo vệ dữ liệu.</p>{notice && <div className="settings-notice" role="status">✓ {notice}</div>}</header><div className="settings-grid"><nav aria-label="Danh mục cài đặt">{nav.map(([key, label]) => <button className={tab === key ? "active" : ""} onClick={() => setTab(key)} key={key}>{label}</button>)}</nav><section>
        <span className={mobileStyles.settings} hidden />
        {tab === "ai" && <AISettingsPanel hydrated={isHydrated} signedIn={Boolean(session)} ai={ai} draft={aiDraft} setDraft={setAIDraft} busy={aiBusy} notice={aiNotice} onSave={saveAI} onTest={testAI} />}
        {tab === "appearance" && <><div className="setting-block"><div><h2>Chuyển động</h2><p>Điều chỉnh animation và hiệu ứng không gian.</p></div><div className="option-cards">{[["full", "Đầy đủ", "Cinematic và phản hồi vật lý"], ["balanced", "Cân bằng", "Mượt mà, tối ưu hiệu năng"], ["reduced", "Tối giản", "Chỉ chuyển trạng thái thiết yếu"]].map(x => <button aria-label={x[1]} className={prefs.motion === x[0] ? "selected" : ""} onClick={() => update({ motion: x[0] })} key={x[0]}><i>{prefs.motion === x[0] ? "●" : "○"}</i><b>{x[1]}</b><small>{x[2]}</small></button>)}</div></div><div className="setting-block"><div><h2>Mật độ giao diện</h2><p>Khoảng cách giữa các thành phần trong workspace.</p></div><div className="segments"><button className={prefs.density === "comfortable" ? "active" : ""} onClick={() => update({ density: "comfortable" })}>Thoải mái</button><button className={prefs.density === "compact" ? "active" : ""} onClick={() => update({ density: "compact" })}>Gọn</button></div></div></>}
        {tab === "privacy" && <><Toggle title="Lưu lịch sử trên thiết bị" detail="Khi tắt, lần phân tích mới chỉ được giữ trong tab hiện tại và không xuất hiện trong lịch sử cục bộ." checked={prefs.saveHistory} onChange={v => update({ saveHistory: v })} /><Toggle title="Che dữ liệu nhạy cảm" detail="Che mật khẩu, OTP và số thẻ trong bản xem trước, lịch sử và kết quả được lưu." checked={prefs.maskSensitive} onChange={v => update({ maskSensitive: v })} /><div className="privacy-note"><b>◉ Dữ liệu thuộc quyền kiểm soát của bạn</b><p>Prewise không dùng webcam hoặc microphone. Nội dung chỉ được xử lý khi bạn chủ động nhấn Phân tích.</p></div></>}
        {tab === "data" && <><div className="setting-block"><h2>Dữ liệu được lưu cục bộ</h2><p>Trang Lịch sử trong workspace chỉ đọc dữ liệu trên trình duyệt này. Lịch sử tài khoản được tải riêng sau khi đăng nhập.</p></div><div className="danger-zone"><div><h2>Xóa lịch sử phân tích cục bộ</h2><p>Thao tác này không thể hoàn tác.</p></div>{confirmClear ? <div className="confirm-actions"><button onClick={() => setConfirmClear(false)}>Hủy</button><button className="danger-confirm" onClick={clear}>Xác nhận xóa</button></div> : <button onClick={() => setConfirmClear(true)}>Xóa dữ liệu</button>}</div></>}
        {tab === "language" && <div className="setting-block"><div><h2>Ngôn ngữ giao diện</h2><p>Lựa chọn được lưu cho các phiên truy cập tiếp theo.</p></div><div className="option-cards language-options"><button aria-label="Tiếng Việt" className={prefs.language === "vi" ? "selected" : ""} onClick={() => update({ language: "vi" })}><i>{prefs.language === "vi" ? "●" : "○"}</i><b>Tiếng Việt</b><small>Ngôn ngữ hiện tại</small></button><button aria-label="English" className={prefs.language === "en" ? "selected" : ""} onClick={() => update({ language: "en" })}><i>{prefs.language === "en" ? "●" : "○"}</i><b>English</b><small>Interface preference</small></button></div></div>}
    </section></div></main></PrewiseShell>;
}

function AISettingsPanel({ hydrated, signedIn, ai, draft, setDraft, busy, notice, onSave, onTest }: { hydrated: boolean; signedIn: boolean; ai: UserAISettings; draft: AIDraft; setDraft: Dispatch<SetStateAction<AIDraft>>; busy: boolean; notice: string; onSave: () => void; onTest: () => void }) {
    if (!hydrated) return <div className="setting-block"><p>Đang tải cài đặt tài khoản…</p></div>;
    if (!signedIn) return <div className="setting-block"><div><h2>Model AI của bạn</h2><p>Đăng nhập để chọn model/chế độ AI và đồng bộ lựa chọn riêng trên mọi thiết bị.</p></div><Link className="settings-primary-action" href="/auth">Đăng nhập để cấu hình</Link></div>;
    const hasPersonalConfig = ai.source === "account" && (ai.provider === "adapter" || ai.provider === "endpoint") && ai.allowedProviders.includes(ai.provider);
    return <><div className="setting-block ai-account-heading"><div><h2>Model và chế độ AI</h2><p>Web hỗ trợ AI bảo mật Prewise hoặc API endpoint HTTPS. Admin chỉ quyết định chế độ và model nào được phép xuất hiện.</p></div><span className={hasPersonalConfig ? "ai-setting-ready" : "ai-setting-pending"}>{hasPersonalConfig ? "Đã cấu hình" : "Chưa chọn riêng"}</span></div><div className="setting-block ai-settings-form">
        {ai.weightEligible && <label className="wide"><span>Trọng số AI cá nhân · {draft.weightPercent}%</span><input type="range" min={ai.minPercent} max={ai.maxPercent} step="1" value={draft.weightPercent} onChange={event => setDraft({ ...draft, weightPercent: Number(event.target.value) })} aria-label="Trọng số AI cá nhân" /><small>Admin cho phép từ {ai.minPercent}% đến {ai.maxPercent}%. Chỉ áp dụng cho phân tích Pro của bạn · nguồn hiện tại: {ai.weightSource === "account" ? "cá nhân" : "mặc định toàn cục"}.</small></label>}
        {ai.allowedProviders.length ? <label><span>Chế độ AI</span><select value={draft.provider} onChange={event => { const provider = event.target.value as UserSelectableAIProvider; setDraft(provider === "adapter" ? { ...draft, provider, baseUrl: "", model: "", apiKey: "" } : { ...draft, provider, baseUrl: draft.provider === "endpoint" ? draft.baseUrl : "", apiKey: "" }); }}>{ai.allowedProviders.includes("adapter") && <option value="adapter">AI bảo mật Prewise</option>}{ai.allowedProviders.includes("endpoint") && <option value="endpoint">API endpoint · model riêng</option>}</select></label> : <p className="wide ai-inline-notice" role="status">Hiện chưa có chế độ AI nào phù hợp với web được admin cho phép.</p>}
        {draft.provider !== "adapter" && <label><span>Model ID</span>{ai.allowedModels.length ? <select value={draft.model} onChange={event => setDraft({ ...draft, model: event.target.value })}><option value="">Chọn model được phép</option>{ai.allowedModels.map(model => <option value={model} key={model}>{model}</option>)}</select> : <input value={draft.model} onChange={event => setDraft({ ...draft, model: event.target.value })} placeholder="Ví dụ: qwen2.5:7b hoặc model-id" autoComplete="off" />}</label>}
        {draft.provider === "endpoint" && <label className="wide"><span>Base URL</span><input value={draft.baseUrl} onChange={event => setDraft({ ...draft, baseUrl: event.target.value })} placeholder="https://api.example.com/v1" inputMode="url" /></label>}
        {draft.provider === "endpoint" && <label className="wide"><span>API key {ai.apiKeyConfigured && <small>● Đã lưu mã hóa</small>}</span><input type="password" value={draft.apiKey} onChange={event => setDraft({ ...draft, apiKey: event.target.value })} placeholder={ai.apiKeyConfigured ? "Để trống để giữ API key hiện tại" : "Nhập API key của bạn"} autoComplete="new-password" /></label>}
        <p className="wide ai-data-note">Local LLM trên máy cá nhân không thể được web hosted truy cập an toàn. Tùy chọn này chỉ có trên Desktop khi Core API cũng chạy local. Endpoint từ xa bắt buộc HTTPS.</p>
        <div className="wide ai-setting-actions"><button className="settings-primary-action" onClick={onSave} disabled={busy || !ai.allowedProviders.length}>{busy ? "Đang xử lý…" : "Lưu cho tài khoản của tôi"}</button><button onClick={onTest} disabled={busy || !hasPersonalConfig || ai.provider !== "endpoint"}>Kiểm tra model</button></div>
        {notice && <p className="wide ai-inline-notice" role="status">{notice}</p>}
    </div></>;
}

function Toggle({ title, detail, checked, onChange }: { title: string; detail: string; checked: boolean; onChange: (v: boolean) => void }) { return <div className="setting-block switch-row"><div><h2>{title}</h2><p>{detail}</p></div><label className="switch"><input aria-label={title} checked={checked} onChange={e => onChange(e.target.checked)} type="checkbox" /><span /></label></div>; }
