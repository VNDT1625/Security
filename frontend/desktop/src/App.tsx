import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Ban,
  BarChart3,
  Bell,
  Box,
  Check,
  ChevronDown,
  CircleUserRound,
  Cpu,
  Database,
  Download,
  FileSearch,
  FileUp,
  Globe2,
  HardDrive,
  HelpCircle,
  Info,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Mail,
  MessageSquare,
  Monitor,
  PackageOpen,
  RefreshCw,
  RotateCcw,
  Search,
  Send,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Users,
  Wifi,
  Zap,
} from "lucide-react";
import {
  AdminOverview,
  AdminUser,
  AnalysisDepth,
  Assessment,
  CloudSandboxMode,
  CloudSandboxSession,
  GmailMessageSummary,
  GmailStatus,
  MailItem,
  SmsAssessment,
  UserAIProvider,
  UserAISettings,
  UserSession,
  apiBaseUrl,
  askContext,
  assessEmail,
  assessEmailFile,
  assessGmailMessage,
  assessSms,
  assessUrl,
  checkHealth,
  connectGmail,
  createCloudSandboxSession,
  disconnectGmail,
  getAdminOverview,
  getAdminUsers,
  getCloudSandboxSession,
  getCloudSandboxStatus,
  getGmailMessagePreview,
  getGmailStatus,
  getProfile,
  getUserAISettings,
  issueCloudRemoteAccess,
  listGmailMessages,
  login,
  logout,
  register,
  saveUserAISettings,
  setAdminUserStatus,
  setSessionToken,
  stopCloudSandboxSession,
  submitFeedback,
  testUserAISettings,
  uploadCloudSandboxSample,
} from "./api";
import FullAdminConsole from "./AdminConsole";

type View = "home" | "web" | "email" | "sms" | "local" | "settings" | "admin";
const riskText = (r?: Assessment) =>
  !r
    ? ""
    : r.riskLevel === "danger"
      ? "RỦI RO CAO"
      : r.riskLevel === "warn"
        ? "ĐÁNG NGỜ"
        : "AN TOÀN";
const readStoredList = (key: string) => {
  try {
    return JSON.parse(localStorage.getItem(key) || "[]") as string[];
  } catch {
    return [];
  }
};
const storeUnique = (key: string, value: string) => {
  const next = [...new Set([...readStoredList(key), value])];
  localStorage.setItem(key, JSON.stringify(next));
  return next;
};
const readPreferences = () => {
  try {
    return {
      ...defaultPreferences,
      ...JSON.parse(localStorage.getItem("armor-preferences") || "{}"),
    } as Preferences;
  } catch {
    return defaultPreferences;
  }
};
const gmailSummaryToMail = (message: GmailMessageSummary): MailItem => ({
  id: message.id,
  sender: message.from,
  email: message.from,
  subject: message.subject,
  preview: message.snippet,
  content: "",
  date: message.date,
  labelIds: message.labelIds,
  source: "gmail",
});
const gmailSenderQuery = (value: string) => {
  const query = value.trim();
  if (!query) return "";
  if (/(?:^|\s)(?:from|to|subject|is|label|in):/i.test(query)) return query;
  return query.includes("@") ? `from:${query}` : `from:"${query.replace(/["\\]/g, " ")}"`;
};
const emailUrls = (content: string) =>
  Array.from(new Set(content.match(/https?:\/\/[^\s<>'"`]+/gi) || []))
    .map((url) => url.replace(/[),.;!?]+$/, ""))
    .filter((url) => {
      try {
        const parsed = new URL(url);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
      } catch {
        return false;
      }
    });

function App() {
  const [session, setSession] = useState<UserSession | null>(() => {
    try {
      const stored = JSON.parse(
        localStorage.getItem("armor-session") || "null",
      ) as UserSession | null;
      return stored ? { ...stored, user: { ...stored.user, role: "user" } } : null;
    } catch {
      return null;
    }
  });
  const [view, setView] = useState<View>(() => {
    const saved = localStorage.getItem("armor-last-view") as View | null;
    return readPreferences().rememberLastView &&
      saved &&
      ["home", "web", "email", "sms", "local", "settings"].includes(saved)
      ? saved
      : "home";
  });
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<Assessment>();
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Sẵn sàng");
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [shellPrefs, setShellPrefs] = useState<Preferences>(readPreferences);
  const [urlDepth, setUrlDepth] = useState<AnalysisDepth>("balanced");
  const [emailDepth, setEmailDepth] = useState<AnalysisDepth>("balanced");
  const [mails, setMails] = useState<MailItem[]>([]);
  const [selected, setSelected] = useState<MailItem | null>(null);
  const [mailBusy, setMailBusy] = useState(false);
  const [mailError, setMailError] = useState("");
  const [mailFilter, setMailFilter] = useState<"all" | Assessment["riskLevel"]>("all");
  const [gmailStatus, setGmailStatus] = useState<GmailStatus | null>(null);
  const [gmailQuery, setGmailQuery] = useState("");
  const [gmailLoading, setGmailLoading] = useState(false);
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<{ role: "user" | "ai"; text: string }[]>([]);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatBusy, setChatBusy] = useState(false);
  const context = useMemo(
    () => (view === "web" ? url : selected?.content || selected?.preview || ""),
    [view, url, selected],
  );
  const contextualChatEnabled =
    (view === "web" && urlDepth === "pro") || (view === "email" && emailDepth === "pro");
  const contextualChatReady =
    (view === "web" && Boolean(result)) || (view === "email" && Boolean(selected?.result));
  useEffect(() => {
    setSessionToken(session?.token || null);
    if (session) localStorage.setItem("armor-session", JSON.stringify(session));
    else localStorage.removeItem("armor-session");
  }, [session]);
  useEffect(() => {
    if (!session) return;
    setSessionToken(session.token);
    void getProfile()
      .then((user) => {
        setSession((current) =>
          current ? { ...current, user: { ...current.user, ...user } } : current,
        );
        if (user.role !== "admin") setView((current) => (current === "admin" ? "home" : current));
      })
      .catch(() => {
        /* Keep the session, but never restore admin UI from an unverified cache. */
      });
  }, [session?.token]);
  useEffect(() => {
    let active = true;
    const probe = () =>
      void checkHealth()
        .then(() => active && setBackendOnline(true))
        .catch(() => active && setBackendOnline(false));
    probe();
    const timer = window.setInterval(probe, 15_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    if (view !== "email" || !session) return;
    void refreshGmail();
  }, [view, session?.token]);
  useEffect(() => {
    if (shellPrefs.rememberLastView && view !== "admin")
      localStorage.setItem("armor-last-view", view);
    else if (!shellPrefs.rememberLastView) localStorage.removeItem("armor-last-view");
  }, [view, shellPrefs.rememberLastView]);
  useEffect(() => {
    if (!contextualChatEnabled) setChatOpen(false);
  }, [contextualChatEnabled]);
  async function scanUrl(target = url) {
    let normalized = target.trim();
    if (!normalized) return;
    if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`;
    try {
      const parsed = new URL(normalized);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
      normalized = parsed.toString();
    } catch {
      setStatus("URL không hợp lệ. Hãy nhập địa chỉ HTTP/HTTPS đầy đủ.");
      return;
    }
    setUrl(normalized);
    setBusy(true);
    setResult(undefined);
    const steps = [
      "Phân tích cấu trúc URL",
      "Chạy model phân loại",
      "Kiểm tra nội dung & prompt injection",
      "Sinh giải thích & khuyến nghị",
    ];
    let step = 0;
    setStatus(steps[step]);
    const progress = window.setInterval(() => {
      step = Math.min(step + 1, steps.length - 1);
      setStatus(steps[step]);
    }, 650);
    try {
      const r = await assessUrl(normalized, urlDepth, "");
      setResult(r);
      const prefs = readPreferences();
      if (prefs.autoBlock && r.score >= prefs.threshold) {
        const host = new URL(normalized).hostname;
        storeUnique("armor-blocked-domains", host);
        setStatus(`Đã hoàn tất và tự thêm ${host} vào danh sách chặn.`);
      } else setStatus("Đã hoàn tất");
    } catch (e) {
      setStatus(e instanceof Error ? e.message : "Quét thất bại");
    } finally {
      window.clearInterval(progress);
      setBusy(false);
    }
  }
  async function reportIncorrect(assessment: Assessment, setMessage: (message: string) => void) {
    const feedbackType = assessment.riskLevel === "safe" ? "false_negative" : "false_positive";
    setMessage("Đang gửi phản hồi tới Core API…");
    try {
      await submitFeedback({
        requestId: assessment.requestId,
        feedbackType,
        reason: feedbackType === "false_positive" ? "incorrect_verdict" : "missed_threat",
        idempotencyKey: `desktop-${feedbackType}-${assessment.requestId}`,
      });
      setMessage("Đã gửi phản hồi báo sai. Cảm ơn bạn đã giúp cải thiện kết quả phân tích.");
    } catch (error) {
      setMessage(
        error instanceof Error
          ? `Không gửi được phản hồi: ${error.message}`
          : "Không gửi được phản hồi tới Core API.",
      );
    }
  }
  async function refreshGmail(query = "") {
    setGmailLoading(true);
    setMailError("");
    try {
      const status = await getGmailStatus();
      setGmailStatus(status);
      if (!status.connected) {
        setMails([]);
        setSelected(null);
        return;
      }
      const senderQuery = gmailSenderQuery(query);
      const items = (await listGmailMessages(senderQuery)).map(gmailSummaryToMail);
      setMails(items);
      setSelected((current) =>
        current && items.some((item) => item.id === current.id) ? current : null,
      );
      if (senderQuery && !items.length) setMailError(`Không tìm thấy email từ “${query.trim()}”.`);
    } catch (e) {
      setMailError(e instanceof Error ? e.message : "Không thể tải Gmail.");
    } finally {
      setGmailLoading(false);
    }
  }
  async function beginGmail() {
    setGmailLoading(true);
    setMailError("");
    try {
      const { authUrl } = await connectGmail();
      if (window.desktop) await window.desktop.openExternal(authUrl);
      else window.open(authUrl, "_blank", "noopener,noreferrer");
      setMailError("Đã mở Google trong trình duyệt. Hoàn tất cấp quyền, ứng dụng sẽ tự đồng bộ.");
      for (let attempt = 0; attempt < 45; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const status = await getGmailStatus();
        setGmailStatus(status);
        if (status.connected) {
          await refreshGmail("");
          setMailError(`Đã kết nối ${status.address}.`);
          return;
        }
      }
      setMailError("Chưa nhận được xác nhận từ Google. Bạn có thể bấm Đồng bộ để kiểm tra lại.");
    } catch (e) {
      setMailError(e instanceof Error ? e.message : "Không thể bắt đầu kết nối Gmail.");
    } finally {
      setGmailLoading(false);
    }
  }
  async function removeGmail() {
    setGmailLoading(true);
    try {
      await disconnectGmail();
      setGmailStatus({ configured: true, connected: false, address: "", status: "not_connected" });
      setMails([]);
      setSelected(null);
      setMailError("Đã ngắt kết nối Gmail và thu hồi token đã lưu.");
    } catch (e) {
      setMailError(e instanceof Error ? e.message : "Không thể ngắt Gmail.");
    } finally {
      setGmailLoading(false);
    }
  }
  async function selectMail(mail: MailItem) {
    setSelected(mail);
    setMailError("");
    if (mail.source !== "gmail" || mail.content) return;
    setMailBusy(true);
    try {
      const preview = await getGmailMessagePreview(mail.id);
      const loaded = {
        ...mail,
        sender: preview.from,
        email: preview.from,
        subject: preview.subject,
        content: preview.body,
        date: preview.date,
        labelIds: preview.labelIds,
        attachments: preview.attachments,
        linksRemoved: preview.linksRemoved,
      };
      setMails((items) => items.map((item) => (item.id === mail.id ? loaded : item)));
      setSelected(loaded);
    } catch (e) {
      setMailError(e instanceof Error ? e.message : "Không thể tải nội dung email.");
    } finally {
      setMailBusy(false);
    }
  }
  async function scanMail(mail: MailItem, force = false) {
    setSelected(mail);
    if (mail.result && !force) return;
    setMailBusy(true);
    setMailError("");
    try {
      const r =
        mail.source === "gmail"
          ? await assessGmailMessage(mail.id, emailDepth, "")
          : mail.localFile
            ? await assessEmailFile(mail.localFile, emailDepth, "")
            : await assessEmail(
                `${mail.sender}\nChủ đề: ${mail.subject}\n${mail.content}`,
                emailDepth,
                "",
              );
      const assessed = { ...mail, result: r, score: r.score };
      setMails((v) => v.map((x) => (x.id === mail.id ? assessed : x)));
      setSelected(assessed);
      const prefs = readPreferences();
      if (prefs.autoBlock && r.score >= prefs.threshold) {
        storeUnique("armor-blocked-senders", mail.email);
        setMailError(`Đã tự thêm ${mail.email} vào danh sách chặn cục bộ.`);
      }
    } catch (e) {
      setMailError(e instanceof Error ? e.message : "Không thể đánh giá email.");
    } finally {
      setMailBusy(false);
    }
  }
  async function send() {
    if (!question.trim() || chatBusy) return;
    setChatOpen(true);
    setChatBusy(true);
    const q = question;
    setQuestion("");
    setMessages((v) => [...v, { role: "user", text: q }, { role: "ai", text: "[...]" }]);
    const replacePending = (text: string) =>
      setMessages((items) => {
        const next = [...items];
        for (let i = next.length - 1; i >= 0; i--) {
          if (next[i].role === "ai" && next[i].text === "[...]") {
            next[i] = { role: "ai", text };
            break;
          }
        }
        return next;
      });
    try {
      replacePending(await askContext(q, contextualChatReady ? context : ""));
    } catch (e) {
      replacePending(e instanceof Error ? e.message : "Không thể nhận phản hồi từ Core AI.");
    } finally {
      setChatBusy(false);
    }
  }
  function exportReport() {
    const r = view === "web" ? result : selected?.result;
    if (!r) return;
    const layers =
      r.scoreLayers
        ?.map(
          (layer) =>
            `- ${layer.layer}: ${layer.status} · ${Math.round(layer.score)}/100 · ${layer.signals} tín hiệu`,
        )
        .join("\n") || "";
    const text = `AI SECURITY ARMOR\nĐiểm: ${r.score}/100 — ${riskText(r)}\nĐộ tin cậy: ${Math.round(r.confidence * 100)}%\nThreat level: ${r.threatLevel || "—"}\nThời gian backend: ${r.latencyMs || 0} ms\n\nPHẠM VI ĐÃ KIỂM TRA\n${layers || "Không có dữ liệu lớp"}\n\nBẰNG CHỨNG\n${r.reasons.map((x) => "- " + x).join("\n") || "- Không phát hiện tín hiệu rủi ro nổi bật"}\n\nKHUYẾN NGHỊ\n${r.explanation || ""}`;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    a.download = `ai-security-report-${r.requestId}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  }
  async function signOut() {
    try {
      await logout();
    } catch {
      /* Session may already be expired. */
    } finally {
      setSession(null);
      setView("home");
    }
  }
  if (!session)
    return (
      <AuthScreen
        onAuthenticated={(next) => {
          setSession(next);
          setView("home");
        }}
      />
    );
  return (
    <main className={`app-shell ${shellPrefs.compactMode ? "compact-ui" : ""}`}>
      <header className="topbar">
        <button
          className="brand"
          onClick={() => setView("home")}
          aria-label="AI Security Armor — về trang chủ"
        >
          <span className="brandmark">
            <ShieldCheck size={20} />
          </span>
          <span>
            AI Security <b>Armor</b>
          </span>
        </button>
        <nav aria-label="Điều hướng chính">
          <button className={view === "home" ? "active" : ""} onClick={() => setView("home")}>
            <Shield />
            Trang chủ
          </button>
          <button className={view === "web" ? "active" : ""} onClick={() => setView("web")}>
            <Globe2 />
            Website Check
          </button>
          <button className={view === "email" ? "active" : ""} onClick={() => setView("email")}>
            <Mail />
            Email Guard
          </button>
          <button className={view === "sms" ? "active" : ""} onClick={() => setView("sms")}>
            <MessageSquare />
            SMS Guard
          </button>
          <button className={view === "local" ? "active" : ""} onClick={() => setView("local")}>
            <HardDrive />
            Local Shield
          </button>
          {session.user.role === "admin" && (
            <button className={view === "admin" ? "active" : ""} onClick={() => setView("admin")}>
              <LayoutDashboard />
              Quản trị
            </button>
          )}
        </nav>
        <div className="top-actions">
          <span className={`online ${backendOnline === false ? "offline" : ""}`} title={apiBaseUrl}>
            <i />
            {backendOnline === null
              ? "Đang kiểm tra Core API"
              : backendOnline
                ? "Core backend connected"
                : "Core backend offline"}
          </span>
          <button
            className={view === "settings" ? "icon active" : "icon"}
            onClick={() => setView("settings")}
            aria-label="Cài đặt"
          >
            <Settings />
          </button>
          <button className="profile" onClick={signOut} title="Đăng xuất">
            <CircleUserRound />
            <span>{session.user.displayName}</span>
            <LogOut size={15} />
          </button>
        </div>
      </header>
      {view === "home" && (
        <HomePage user={session.user.displayName} start={(next) => setView(next)} />
      )}
      {view === "web" && (
        <section className="workspace">
          <div className="browserbar">
            <div className="browser-actions">
              <button disabled title="Ứng dụng không mở website thật">
                <ArrowLeft />
              </button>
              <button disabled title="Ứng dụng không mở website thật">
                <ArrowRight />
              </button>
              <button
                title="Xóa kết quả hiện tại"
                onClick={() => {
                  setResult(undefined);
                  setStatus("Sẵn sàng");
                }}
              >
                <RotateCcw />
              </button>
            </div>
            <div className="address">
              <Shield size={16} />
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && scanUrl()}
                placeholder="Nhập URL cần kiểm tra..."
              />
              <span>Không mở trang thật</span>
            </div>
            <button
              className="scan"
              disabled={busy || !url.trim() || backendOnline === false}
              onClick={() => scanUrl()}
            >
              {busy ? <RefreshCw className="spin" /> : <Search />}
              {busy ? "Đang quét" : "Quét URL"}
            </button>
          </div>
          <AnalysisControls
            depth={urlDepth}
            setDepth={(next) => {
              setUrlDepth(next);
              setResult(undefined);
              setStatus("Sẵn sàng");
            }}
            mode="url"
            disabled={busy}
          />
          {busy ? (
            <Pipeline current={status} />
          ) : result ? (
            <ResultPanel
              result={result}
              target={url}
              exportReport={exportReport}
              onBlock={() => {
                try {
                  const host = new URL(url).hostname;
                  storeUnique("armor-blocked-domains", host);
                  setStatus(`Đã thêm ${host} vào danh sách chặn cục bộ.`);
                } catch {
                  setStatus("URL không hợp lệ.");
                }
              }}
              onFeedback={() => void reportIncorrect(result, setStatus)}
            />
          ) : null}
        </section>
      )}
      {view === "email" && (
        <section className="workspace email">
          <div className="email-tools">
            {gmailStatus?.connected ? (
              <>
                <span className="gmail-account">
                  <Mail />
                  {gmailStatus.address}
                </span>
                <button
                  onClick={() => {
                    setGmailQuery("");
                    void refreshGmail("");
                  }}
                  disabled={gmailLoading}
                >
                  <RefreshCw className={gmailLoading ? "spin" : ""} />
                  30 thư gần nhất
                </button>
                <button onClick={() => void removeGmail()} disabled={gmailLoading}>
                  <LogOut />
                  Ngắt Gmail
                </button>
              </>
            ) : (
              <button
                className="gmail-connect"
                onClick={() => void beginGmail()}
                disabled={gmailLoading || gmailStatus?.configured === false}
              >
                <Mail />
                {gmailLoading ? "Đang kết nối…" : "Kết nối Gmail thật"}
              </button>
            )}
            <label className="button">
              <FileUp />
              Nhập file .eml
              <input
                type="file"
                accept=".eml,.rfc822,message/rfc822"
                hidden
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) {
                    const reader = new FileReader();
                    reader.onload = () => {
                      const mail: MailItem = {
                        id: String(Date.now()),
                        sender: "Email đã nhập",
                        email: f.name,
                        subject: f.name,
                        preview: "Tệp email RFC822/MIME cục bộ",
                        content: String(reader.result),
                        source: "file",
                        localFile: f,
                      };
                      setMails((v) => [mail, ...v]);
                      setSelected(mail);
                    };
                    reader.readAsText(f);
                  }
                }}
              />
            </label>
            <form
              className="gmail-search"
              onSubmit={(e) => {
                e.preventDefault();
                void refreshGmail(gmailQuery);
              }}
            >
              <Search />
              <input
                value={gmailQuery}
                onChange={(e) => setGmailQuery(e.target.value)}
                placeholder="Tên hoặc địa chỉ người gửi, ví dụ an@gmail.com"
              />
              <button disabled={!gmailStatus?.connected || gmailLoading}>Tìm người gửi</button>
            </form>
            <button onClick={() => setMailFilter("all")}>
              <SlidersHorizontal />
              {mailFilter === "all"
                ? "Tất cả"
                : mailFilter === "danger"
                  ? "Rủi ro cao"
                  : mailFilter === "warn"
                    ? "Đáng ngờ"
                    : "An toàn"}
            </button>
            <div className="risk-filter">
              <button aria-label="Lọc rủi ro cao" onClick={() => setMailFilter("danger")}>
                <i className="danger" />
              </button>
              <button aria-label="Lọc đáng ngờ" onClick={() => setMailFilter("warn")}>
                <i className="warn" />
              </button>
              <button aria-label="Lọc an toàn" onClick={() => setMailFilter("safe")}>
                <i className="safe" />
              </button>
            </div>
          </div>
          <AnalysisControls
            depth={emailDepth}
            setDepth={(next) => {
              setEmailDepth(next);
              setMails((items) =>
                items.map((item) => ({ ...item, result: undefined, score: undefined })),
              );
              setSelected((current) =>
                current ? { ...current, result: undefined, score: undefined } : current,
              );
            }}
            mode="email"
            disabled={mailBusy}
          />
          {mailError && (
            <div className="admin-error">
              <AlertTriangle />
              {mailError}
            </div>
          )}
          <div className="mail-grid">
            <aside>
              <div className="pane-title">
                <div>
                  <b>{gmailStatus?.connected ? "Hộp thư Gmail thật" : "Hộp thư bảo vệ"}</b>
                  <small>
                    {gmailStatus?.connected
                      ? gmailQuery.trim()
                        ? `${mails.length} kết quả theo người gửi`
                        : `${mails.length}/30 email gần nhất`
                      : "Kết nối Gmail hoặc nhập tệp .eml"}
                  </small>
                </div>
                <ShieldCheck />
              </div>
              {gmailLoading && !mails.length ? (
                <div className="mail-list-loading">
                  <RefreshCw className="spin" />
                  Đang tải Gmail…
                </div>
              ) : (
                mails
                  .filter((m) => mailFilter === "all" || m.result?.riskLevel === mailFilter)
                  .map((m) => (
                    <button
                      key={m.id}
                      onClick={() => void selectMail(m)}
                      className={
                        selected?.id === m.id ? "mail-item selected" : "mail-item"
                      }
                    >
                      <span className={`mail-score ${m.result?.riskLevel || ""}`}>
                        {m.result ? m.result.score : "—"}
                      </span>
                      <span>
                        <b>{m.sender}</b>
                        <strong>{m.subject}</strong>
                        <small>{m.preview}</small>
                      </span>
                      <time>
                        {m.labelIds?.includes("UNREAD")
                          ? "Chưa đọc"
                          : m.source === "gmail"
                            ? "Gmail"
                            : "Tệp"}
                      </time>
                    </button>
                  ))
              )}
            </aside>
            <article className="mail-detail">
              {mailBusy ? (
                <Pipeline
                  current={
                    selected?.result
                      ? "Đang phân tích email thật"
                      : "Đang tải bản xem trước an toàn"
                  }
                  compact
                />
              ) : selected ? (
                <MailResult
                  mail={selected}
                  onScan={() => void scanMail(selected)}
                  onCheckUrl={(target) => {
                    setUrl(target);
                    setResult(undefined);
                    setStatus("Sẵn sàng");
                    setView("web");
                  }}
                  exportReport={exportReport}
                  onBlock={() => {
                    storeUnique("armor-blocked-senders", selected.email);
                    setMailError(`Đã thêm ${selected.email} vào danh sách chặn cục bộ.`);
                  }}
                  onFeedback={() => {
                    if (selected.result) void reportIncorrect(selected.result, setMailError);
                  }}
                />
              ) : (
                <EmptyMailbox
                  connected={Boolean(gmailStatus?.connected)}
                  configured={gmailStatus?.configured !== false}
                  connect={() => void beginGmail()}
                />
              )}
            </article>
          </div>
        </section>
      )}
      {view === "sms" && <SmsGuard />}
      {view === "local" && <LocalShield authToken={session.token} />}
      {view === "settings" && (
        <SettingsView
          session={session}
          backendOnline={backendOnline}
          onSignOut={signOut}
          onPreferencesChange={setShellPrefs}
        />
      )}
      {view === "admin" && <FullAdminConsole currentUserId={session.user.id} />}
      {contextualChatEnabled && (
        <>
          <div className={chatOpen ? "chat-drawer open" : "chat-drawer"}>
            {chatOpen && (
              <>
                <div className="chat-head">
                  <span>
                    <MessageSquare />
                    Trợ lý theo ngữ cảnh
                  </span>
                  <button onClick={() => setChatOpen(false)}>×</button>
                </div>
                <div className="chat-log">
                  {messages.length === 0 && (
                    <p>
                      {contextualChatReady
                        ? "Hãy hỏi về kết quả đang xem."
                        : "Bạn có thể hỏi kiến thức an toàn chung ngay bây giờ; hãy quét để trợ lý có thêm bằng chứng cụ thể."}
                    </p>
                  )}
                  {messages.map((m, i) => (
                    <div
                      key={i}
                      className={`${m.role}${m.role === "ai" && m.text === "[...]" ? " pending" : ""}`}
                    >
                      {m.text}
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
          <footer className="chatbar">
            <button className="chat-shield" onClick={() => setChatOpen((v) => !v)}>
              <Shield />
            </button>
            <input
              value={question}
              disabled={chatBusy}
              onFocus={() => setChatOpen(true)}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void send()}
              placeholder={
                chatBusy
                  ? "AI đang trả lời..."
                  : contextualChatReady
                    ? view === "email"
                      ? "Hỏi về email này..."
                      : "Hỏi về kết quả đánh giá này..."
                    : "Hỏi AI về an toàn số..."
              }
            />
            <span className="context">
              {chatBusy
                ? "AI đang xử lý"
                : contextualChatReady
                  ? "Ngữ cảnh: kết quả đã quét"
                  : "Chế độ: hỏi đáp chung"}
            </span>
            <button
              className="send"
              disabled={chatBusy || !question.trim()}
              onClick={() => void send()}
            >
              <Send />
              Gửi
            </button>
          </footer>
        </>
      )}
      <div className="statusbar">
        <span>
          <Wifi />
          API {backendOnline === false ? "offline" : "online"}
        </span>
        <span>Browser Cover · Không render trang nguy hiểm</span>
        <span>Electron {window.desktop?.version || "web preview"}</span>
      </div>
    </main>
  );
}
const DEPTH_OPTIONS: Array<{ key: AnalysisDepth; label: string; badge: string }> = [
  { key: "quick", label: "Nhanh", badge: "Không mở nội dung" },
  { key: "balanced", label: "Cân bằng", badge: "HTTP sandbox" },
  { key: "deep", label: "Chuyên sâu", badge: "Browser sandbox" },
  { key: "pro", label: "Pro AI", badge: "Browser + AI" },
];
function AnalysisControls({
  depth,
  setDepth,
  mode,
  disabled = false,
}: {
  depth: AnalysisDepth;
  setDepth: (depth: AnalysisDepth) => void;
  mode: "url" | "email" | "sms";
  disabled?: boolean;
}) {
  const descriptions: Record<AnalysisDepth, string> =
    mode === "url"
      ? {
          quick: "URL, domain, DNS/IP, model và Risk Core; không tải HTML.",
          balanced:
            "Toàn bộ mức Nhanh và đọc HTTP/HTML trong tiến trình cô lập; không chạy JavaScript.",
          deep: "Chạy browser sandbox để quan sát JavaScript, network, DOM và redirect.",
          pro: "Browser sandbox đầy đủ và AI Evaluate đối chiếu mục đích trang với ngữ cảnh bạn nhập.",
        }
      : {
          quick: "Chấm nội dung cốt lõi và tối đa một liên kết.",
          balanced: "Mở rộng bằng chứng, metadata và tối đa hai liên kết.",
          deep: "Điều tra tối đa ba liên kết cùng phạm vi metadata/tệp sâu hơn.",
          pro: "AI phân tích ý đồ toàn cục cùng ngữ cảnh bạn cung cấp.",
        };
  return (
    <section className="analysis-depth">
      <div className="depth-heading">
        <span>
          <SlidersHorizontal />
          <b>Mức độ phân tích</b>
        </span>
        <small>{descriptions[depth]}</small>
      </div>
      <div className="depth-options">
        {DEPTH_OPTIONS.map((option) => (
          <button
            type="button"
            disabled={disabled}
            className={depth === option.key ? "active" : ""}
            aria-pressed={depth === option.key}
            onClick={() => setDepth(option.key)}
            key={option.key}
          >
            <b>{option.label}</b>
            <small>{option.badge}</small>
          </button>
        ))}
      </div>
    </section>
  );
}
function AdminConsole() {
  const [tab, setTab] = useState<"overview" | "users" | "models">("overview");
  const [overview, setOverview] = useState<AdminOverview | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const load = async () => {
    setBusy(true);
    setError("");
    try {
      const [nextOverview, nextUsers] = await Promise.all([getAdminOverview(), getAdminUsers()]);
      setOverview(nextOverview);
      setUsers(nextUsers.users);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Không thể tải dữ liệu quản trị.");
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void load();
  }, []);
  const toggleUser = async (user: AdminUser) => {
    try {
      await setAdminUserStatus(user.id, user.status === "active" ? "suspended" : "active");
      setUsers((items) =>
        items.map((item) =>
          item.id === user.id
            ? { ...item, status: user.status === "active" ? "suspended" : "active" }
            : item,
        ),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Không thể cập nhật tài khoản.");
    }
  };
  const stamp = (value?: string | null) =>
    value
      ? new Intl.DateTimeFormat("vi-VN", { dateStyle: "short", timeStyle: "short" }).format(
          new Date(value),
        )
      : "Chưa đăng nhập";
  return (
    <section className="admin-console">
      <aside className="admin-sidebar">
        <div>
          <span className="eyebrow">CONTROL CENTER</span>
          <h2>Quản trị hệ thống</h2>
          <p>Giám sát dữ liệu, người dùng và các thành phần AI từ một nơi.</p>
        </div>
        <nav>
          <button className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}>
            <LayoutDashboard />
            Tổng quan
          </button>
          <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>
            <Users />
            Người dùng <b>{overview?.metrics.usersTotal || 0}</b>
          </button>
          <button className={tab === "models" ? "active" : ""} onClick={() => setTab("models")}>
            <Cpu />
            Mô hình & job
          </button>
        </nav>
        <div className="admin-security">
          <ShieldCheck />
          <span>
            <b>Phiên quản trị an toàn</b>
            <small>RBAC đang được áp dụng</small>
          </span>
        </div>
      </aside>
      <article className="admin-content">
        <header className="admin-heading">
          <div>
            <span className="eyebrow">SYSTEM ADMINISTRATION</span>
            <h1>
              {tab === "overview"
                ? "Bức tranh vận hành"
                : tab === "users"
                  ? "Quản lý người dùng"
                  : "Mô hình & tác vụ nền"}
            </h1>
            <p>
              {tab === "overview"
                ? "Theo dõi các chỉ số quan trọng và những sự kiện mới nhất."
                : tab === "users"
                  ? "Kiểm soát trạng thái truy cập của từng tài khoản."
                  : "Theo dõi phiên bản model và tiến trình huấn luyện."}
            </p>
          </div>
          <button className="admin-refresh" onClick={load} disabled={busy}>
            <RefreshCw className={busy ? "spin" : ""} />
            Làm mới
          </button>
        </header>
        {error && (
          <div className="admin-error">
            <AlertTriangle />
            {error}
          </div>
        )}
        {busy && !overview && (
          <div className="admin-loading">
            <RefreshCw className="spin" />
            Đang đồng bộ dữ liệu hệ thống…
          </div>
        )}{" "}
        {overview && tab === "overview" && (
          <>
            <div className="metric-grid">
              <Metric
                icon={<Users />}
                label="Tổng người dùng"
                value={overview.metrics.usersTotal}
                note={`${overview.metrics.activeUsers} đang hoạt động`}
              />
              <Metric
                icon={<Activity />}
                label="Lần quét đã ghi nhận"
                value={overview.metrics.scansTotal}
                note="Toàn bộ kênh đánh giá"
              />
              <Metric
                icon={<ShieldAlert />}
                label="Rủi ro cao"
                value={overview.metrics.dangerousScans}
                note="Cần ưu tiên theo dõi"
                danger
              />
              <Metric
                icon={<BarChart3 />}
                label="Độ trễ trung bình"
                value={`${overview.metrics.averageLatencyMs} ms`}
                note="Từ các yêu cầu đã hoàn thành"
              />
            </div>
            <div className="admin-panels">
              <section className="admin-panel wide">
                <div className="panel-title">
                  <div>
                    <span className="eyebrow">LIVE ACTIVITY</span>
                    <h3>Đánh giá gần đây</h3>
                  </div>
                  <span className="live-dot">Dữ liệu thật</span>
                </div>
                {overview.recentScans.length ? (
                  <div className="scan-list">
                    {overview.recentScans.map((scan) => (
                      <div key={scan.id}>
                        <span className={`risk-badge ${scan.riskLevel}`}>{scan.score}</span>
                        <span>
                          <b>{scan.target}</b>
                          <small>
                            {scan.modality} · {stamp(scan.createdAt)}
                          </small>
                        </span>
                        <strong className={scan.riskLevel}>
                          {scan.riskLevel === "danger"
                            ? "Rủi ro cao"
                            : scan.riskLevel === "warn"
                              ? "Đáng ngờ"
                              : "An toàn"}
                        </strong>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyAdmin icon={<Activity />} text="Chưa có sự kiện quét nào được lưu." />
                )}
              </section>
              <section className="admin-panel">
                <div className="panel-title">
                  <div>
                    <span className="eyebrow">OPERATIONS</span>
                    <h3>Job gần đây</h3>
                  </div>
                </div>
                {overview.recentJobs.length ? (
                  overview.recentJobs.map((job) => (
                    <div className="job-row" key={job.id}>
                      <div>
                        <b>
                          {job.type === "model_training" ? "Huấn luyện model" : "Thực thi đặc tả"}
                        </b>
                        <small>
                          {job.message || "Đang chờ cập nhật"} · {stamp(job.createdAt)}
                        </small>
                      </div>
                      <span className={`job-status ${job.status}`}>
                        {job.status} {job.progress}%
                      </span>
                      <meter min="0" max="100" value={job.progress} />
                    </div>
                  ))
                ) : (
                  <EmptyAdmin icon={<Cpu />} text="Chưa có job quản trị." />
                )}
              </section>
            </div>
          </>
        )}
        {overview && tab === "users" && (
          <section className="admin-panel user-panel">
            <div className="panel-title">
              <div>
                <span className="eyebrow">ACCESS CONTROL</span>
                <h3>{users.length} tài khoản</h3>
              </div>
            </div>
            <div className="user-table">
              <div className="user-row table-head">
                <span>Người dùng</span>
                <span>Vai trò</span>
                <span>Trạng thái</span>
                <span>Đăng nhập gần nhất</span>
                <span />
              </div>
              {users.map((user) => (
                <div className="user-row" key={user.id}>
                  <span>
                    <b>{user.displayName}</b>
                    <small>{user.email}</small>
                  </span>
                  <span className="role-tag">{user.role}</span>
                  <span className={`state-tag ${user.status}`}>
                    {user.status === "active" ? "Đang hoạt động" : "Đã khóa"}
                  </span>
                  <small>{stamp(user.lastLoginAt)}</small>
                  <button
                    className="user-action"
                    disabled={user.role === "admin"}
                    onClick={() => toggleUser(user)}
                  >
                    {user.role === "admin"
                      ? "Được bảo vệ"
                      : user.status === "active"
                        ? "Khóa"
                        : "Mở lại"}
                  </button>
                </div>
              ))}
            </div>
          </section>
        )}
        {overview && tab === "models" && (
          <div className="admin-panels models">
            <section className="admin-panel wide">
              <div className="panel-title">
                <div>
                  <span className="eyebrow">MODEL REGISTRY</span>
                  <h3>Phiên bản model</h3>
                </div>
              </div>
              {overview.models.length ? (
                <div className="model-grid">
                  {overview.models.map((model) => (
                    <div className="model-card" key={model.id}>
                      <Cpu />
                      <span
                        className={`state-tag ${model.status === "promoted" ? "active" : "candidate"}`}
                      >
                        {model.status}
                      </span>
                      <h4>{model.name}</h4>
                      <p>
                        {model.modality} · tạo lúc {stamp(model.createdAt)}
                      </p>
                      <div>
                        <span>
                          F1 <b>{model.f1 != null ? `${(model.f1 * 100).toFixed(1)}%` : "—"}</b>
                        </span>
                        <span>
                          Accuracy{" "}
                          <b>
                            {model.accuracy != null ? `${(model.accuracy * 100).toFixed(1)}%` : "—"}
                          </b>
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyAdmin icon={<Cpu />} text="Chưa có model version được đăng ký." />
              )}
            </section>
          </div>
        )}
      </article>
    </section>
  );
}
function Metric({
  icon,
  label,
  value,
  note,
  danger = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  note: string;
  danger?: boolean;
}) {
  return (
    <div className={`metric-card ${danger ? "danger" : ""}`}>
      <span>{icon}</span>
      <small>{label}</small>
      <b>{value}</b>
      <p>{note}</p>
    </div>
  );
}
function EmptyAdmin({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="admin-empty">
      {icon}
      <p>{text}</p>
    </div>
  );
}
function AuthScreen({ onAuthenticated }: { onAuthenticated: (session: UserSession) => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (mode === "register" && name.trim().length === 0)
      return setError("Vui lòng nhập tên hiển thị.");
    if (!/^\S+@\S+\.\S+$/.test(email)) return setError("Email không hợp lệ.");
    if (
      mode === "register" &&
      (!/[a-z]/i.test(password) || !/[0-9]/.test(password) || password.length < 12)
    )
      return setError("Mật khẩu cần ít nhất 12 ký tự, gồm chữ và số.");
    setBusy(true);
    try {
      onAuthenticated(
        mode === "login" ? await login(email, password) : await register(name, email, password),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Không thể kết nối tới Core API.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="auth-shell">
      <section className="auth-story">
        <div className="auth-brand">
          <span className="brandmark">
            <ShieldCheck />
          </span>
          AI Security <b>Armor</b>
        </div>
        <span className="eyebrow">TRUSTED AI SECURITY</span>
        <h1>
          Đánh giá thật.
          <br />
          <em>Quyết định an toàn hơn.</em>
        </h1>
        <p>Đăng nhập để dùng Core AI, lưu lịch sử và quản lý quota đánh giá của riêng bạn.</p>
        <div className="auth-points">
          <span>
            <Check />
            Core risk engine
          </span>
          <span>
            <Check />
            Bằng chứng có thể kiểm tra
          </span>
          <span>
            <Check />
            Không mở trang nguy hiểm
          </span>
        </div>
      </section>
      <section className="auth-panel">
        <form onSubmit={submit}>
          <span className="eyebrow">SECURE ACCESS</span>
          <h2>{mode === "login" ? "Chào mừng trở lại" : "Tạo tài khoản"}</h2>
          <p>
            {mode === "login"
              ? "Đăng nhập để bắt đầu phiên đánh giá an toàn."
              : "Tài khoản mới được cấp quota quét miễn phí."}
          </p>
          {mode === "register" && (
            <label>
              Tên hiển thị
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Nguyễn An"
                autoComplete="name"
              />
            </label>
          )}
          <label>
            Email
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              type="email"
              autoComplete="email"
            />
          </label>
          <label>
            Mật khẩu
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              type="password"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
            />
          </label>
          {error && <div className="auth-error">{error}</div>}
          <button className="scan" disabled={busy}>
            {busy ? (
              <RefreshCw className="spin" />
            ) : mode === "login" ? (
              <Shield />
            ) : (
              <ShieldCheck />
            )}
            {busy ? "Đang xác thực..." : mode === "login" ? "Đăng nhập an toàn" : "Tạo tài khoản"}
          </button>
          <button
            type="button"
            className="auth-switch"
            onClick={() => {
              setMode(mode === "login" ? "register" : "login");
              setError("");
            }}
          >
            {mode === "login" ? "Chưa có tài khoản? Đăng ký" : "Đã có tài khoản? Đăng nhập"}
          </button>
          <small>Phiên đăng nhập được xác thực bởi AI Security Armor Core.</small>
        </form>
      </section>
    </main>
  );
}
function HomePage({ user, start }: { user: string; start: (view: View) => void }) {
  return (
    <section className="home-page">
      <div className="home-hero">
        <span className="eyebrow">AI SECURITY ARMOR • DESKTOP</span>
        <h1>
          Chào {user}.<br />
          <em>Bảo vệ trước khi tương tác.</em>
        </h1>
        <p>
          Chọn một vùng bảo vệ để đánh giá bằng Core backend hiện tại. Mọi kết quả được gắn với tài
          khoản và quota của bạn.
        </p>
        <div className="home-actions">
          <button className="scan" onClick={() => start("web")}>
            <Globe2 />
            Kiểm tra website
          </button>
          <button onClick={() => start("email")}>
            <Mail />
            Phân tích email
          </button>
        </div>
      </div>
      <div className="home-grid">
        <button onClick={() => start("web")}>
          <Globe2 />
          <span className="eyebrow">BROWSER COVER</span>
          <h2>Website Check</h2>
          <p>Phân tích URL thật với URL Risk Core và mô hình AI.</p>
          <b>
            Bắt đầu quét <ArrowRight />
          </b>
        </button>
        <button onClick={() => start("email")}>
          <Mail />
          <span className="eyebrow">EMAIL GUARD</span>
          <h2>Đánh giá email</h2>
          <p>Kiểm tra nội dung nghi ngờ mà không render liên kết nguy hiểm.</p>
          <b>
            Mở Email Guard <ArrowRight />
          </b>
        </button>
        <button onClick={() => start("local")}>
          <HardDrive />
          <span className="eyebrow">LOCAL SHIELD + CLOUD LAB</span>
          <h2>Bảo vệ tệp</h2>
          <p>
            Quét local-first, cô lập tại máy, rồi nâng cấp sang phân tích tự động hoặc desktop điều
            tra 5–10 phút.
          </p>
          <b>
            Mở Local Shield <ArrowRight />
          </b>
        </button>
      </div>
    </section>
  );
}
function Pipeline({ current, compact }: { current: string; compact?: boolean }) {
  const steps = [
    "Phân tích cấu trúc URL",
    "Chạy model phân loại",
    "Kiểm tra nội dung & prompt injection",
    "Sinh giải thích & khuyến nghị",
  ];
  const index = Math.max(0, steps.indexOf(current));
  return (
    <div className={`pipeline ${compact ? "compact" : ""}`}>
      <div className="scanner">
        <Shield />
        <span />
      </div>
      <span className="eyebrow">SECURE ANALYSIS PIPELINE</span>
      <h2>{current}</h2>
      <p>Website/email không được mở trên máy của bạn.</p>
      <div className="steps">
        {steps.map((x, i) => (
          <div className={i < index ? "done" : i === index ? "running" : ""} key={x}>
            <span>
              {i < index ? <Check /> : i === index ? <RefreshCw className="spin" /> : i + 1}
            </span>
            <b>{x}</b>
            <small>{i < index ? "Hoàn tất" : i === index ? "Đang xử lý..." : "Đang chờ"}</small>
          </div>
        ))}
      </div>
    </div>
  );
}
function ResultPanel({
  result,
  target,
  exportReport,
  onBlock,
  onFeedback,
}: {
  result: Assessment;
  target: string;
  exportReport: () => void;
  onBlock: () => void;
  onFeedback: () => void;
}) {
  return (
    <div className="result">
      <div className="result-head">
        <div>
          <span className="eyebrow">KẾT QUẢ PHÂN TÍCH</span>
          <h2>{target}</h2>
          <small>Mã yêu cầu: {result.requestId}</small>
        </div>
        <div className={`verdict ${result.riskLevel}`}>
          <b>{result.score}</b>
          <span>
            /100
            <br />
            {riskText(result)}
          </span>
        </div>
      </div>
      <div className="result-grid">
        <div className="score-card">
          <RiskRing result={result} />
          <p>
            Độ tin cậy <b>{Math.round(result.confidence * 100)}%</b>
          </p>
          <small>Điểm số không thay thế đánh giá của con người.</small>
        </div>
        <div className="evidence">
          <h3>
            <Search />
            Bằng chứng phân tích
          </h3>
          {result.evidence.map((e, i) => (
            <div className="evidence-row" key={i}>
              <span>{i + 1}</span>
              <div>
                <b>{e.feature || e.source}</b>
                <p>{e.message}</p>
                <meter min="-0.5" max="0.5" value={e.contribution || 0} />
              </div>
              <strong>
                {e.contribution != null
                  ? `${e.contribution > 0 ? "+" : ""}${e.contribution.toFixed(2)}`
                  : ""}
              </strong>
            </div>
          ))}
        </div>
      </div>
      <div className={`explanation ${result.riskLevel}`}>
        <AlertTriangle />
        <div>
          <b>Giải thích & khuyến nghị</b>
          <p>{result.explanation || result.reasons.join(". ")}</p>
        </div>
      </div>
      <div className="actions">
        <button className="danger-btn" onClick={onBlock}>
          <Ban />
          Chặn domain này
        </button>
        <button onClick={exportReport}>
          <Download />
          Xuất báo cáo
        </button>
        <button onClick={onFeedback}>
          <HelpCircle />
          Báo sai
        </button>
        <span>{result.latencyMs || 0} ms • AI hỗ trợ quyết định</span>
      </div>
    </div>
  );
}
function RiskRing({ result }: { result: Assessment }) {
  return (
    <div className="risk-score-stack">
      <div
        className={`risk-ring ${result.riskLevel}`}
        style={{ "--score": `${result.score * 3.6}deg` } as React.CSSProperties}
      >
        <div>
          <Shield />
          <b>{result.score}</b>
          <span>/100</span>
          <strong>{riskText(result)}</strong>
        </div>
      </div>
      {result.aiContext && (
        <div
          className="ai-score-chip"
          aria-label={`AI chấm ${result.aiContext.score} trên 100, trọng số ${result.aiContext.weightPercent}%`}
        >
          <span>AI THỰC CHẤM</span>
          <b>
            {Number.isInteger(result.aiContext.score)
              ? result.aiContext.score
              : result.aiContext.score.toFixed(1)}
            <small>/100</small>
          </b>
          <em>
            Trọng số {result.aiContext.weightPercent}%
            {result.aiContext.effectiveWeightPercent != null &&
            result.aiContext.effectiveWeightPercent !== result.aiContext.weightPercent
              ? ` · hiệu lực ${result.aiContext.effectiveWeightPercent}%`
              : ""}
          </em>
        </div>
      )}
    </div>
  );
}
function EmptyMailbox({
  connected,
  configured,
  connect,
}: {
  connected: boolean;
  configured: boolean;
  connect: () => void;
}) {
  return (
    <div className="mail-empty">
      <Mail />
      <h2>
        {connected
          ? "Chọn một email thật"
          : configured
            ? "Kết nối hộp thư của bạn"
            : "Gmail OAuth chưa được cấu hình"}
      </h2>
      <p>
        {connected
          ? "Bấm một thư ở cột bên trái để tải bản xem trước an toàn."
          : configured
            ? "Ứng dụng chỉ yêu cầu quyền Gmail chỉ đọc. Token được mã hóa ở backend và có thể thu hồi bất cứ lúc nào."
            : "Quản trị viên cần đặt Gmail OAuth Client ID, Client Secret, redirect URI và khóa mã hóa token trên backend."}
      </p>
      {!connected && configured && (
        <button className="scan" onClick={connect}>
          <Mail />
          Kết nối Gmail
        </button>
      )}
    </div>
  );
}
function MailResult({
  mail,
  onScan,
  onCheckUrl,
  exportReport,
  onBlock,
  onFeedback,
}: {
  mail: MailItem;
  onScan: () => void;
  onCheckUrl: (url: string) => void;
  exportReport: () => void;
  onBlock: () => void;
  onFeedback: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const safeContent = mail.content.replace(/https?:\/\/\S+/gi, "[LIÊN KẾT ĐÃ KHỬ]");
  const links = emailUrls(mail.content);
  const linkActions = links.length ? (
    <div className="email-link-actions">
      <b>
        <Globe2 />
        Liên kết trong email
      </b>
      <small>Chọn liên kết để chuyển sang Website Check. Trang đích không được mở trực tiếp.</small>
      {links.map((link, index) => (
        <button key={link} type="button" onClick={() => onCheckUrl(link)}>
          <Globe2 />
          <span>Liên kết {index + 1}</span>
          <code>{link}</code>
          <ArrowRight />
        </button>
      ))}
    </div>
  ) : null;
  if (!mail.result)
    return (
      <>
        <div className="mail-meta">
          <span>Từ</span>
          <b>{mail.sender}</b>
          <span>Chủ đề</span>
          <b>{mail.subject}</b>
          {mail.date && (
            <>
              <span>Ngày gửi</span>
              <b>{mail.date}</b>
            </>
          )}
        </div>
        <div className="safe-preview-head">
          <span>
            <ShieldCheck />
            <b>Bản xem trước an toàn</b>
          </span>
          <small>{mail.linksRemoved || 0} liên kết đã khử · ảnh từ xa không được tải</small>
        </div>
        <pre className="safe-mail-content visible">
          {safeContent || mail.preview || "Email không có nội dung text có thể hiển thị."}
        </pre>
        {linkActions}
        {Boolean(mail.attachments?.length) && (
          <div className="safe-attachments">
            <b>Tệp đính kèm — chưa được mở</b>
            {mail.attachments!.map((item) => (
              <span key={`${item.filename}-${item.size}`}>
                <FileSearch />
                {item.filename}
                <small>
                  {item.contentType} · {(item.size / 1024).toFixed(1)} KB
                </small>
              </span>
            ))}
          </div>
        )}
        <div className="preview-actions">
          <button className="scan" onClick={onScan}>
            <Shield />
            Phân tích email thật
          </button>
          <small>Raw email chỉ được xử lý ở backend, không đưa vào renderer.</small>
        </div>
      </>
    );
  const r = mail.result;
  return (
    <>
      <div className="mail-meta">
        <span>Từ</span>
        <b>{mail.sender}</b>
        <span>Chủ đề</span>
        <b>{mail.subject}</b>
      </div>
      <div className={`mail-verdict ${r.riskLevel}`}>
        <RiskRing result={r} />
        <div>
          <span className="eyebrow">ĐÁNH GIÁ THƯ ĐANG CHỌN</span>
          <h2>{riskText(r)}</h2>
          <p>Độ tin cậy {Math.round(r.confidence * 100)}%</p>
        </div>
      </div>
      <h3 className="why">Vì sao bị chấm điểm này</h3>
      <div className="reason-list">
        {r.reasons.map((x, i) => (
          <div key={`${i}-${x}`}>
            <span>{i + 1}</span>
            <p>{x}</p>
          </div>
        ))}
      </div>
      <div className="explanation">
        <Shield />
        <p>{r.explanation}</p>
      </div>
      {linkActions}
      <div className="actions">
        <button className="danger-btn" onClick={onBlock}>
          <Ban />
          Chặn người gửi
        </button>
        <button onClick={exportReport}>
          <Download />
          Xuất báo cáo
        </button>
        <button onClick={onFeedback}>
          <AlertTriangle />
          Báo sai
        </button>
      </div>
      <button className="reveal" onClick={() => setRevealed((v) => !v)}>
        <HelpCircle />
        {revealed ? "Ẩn thư đã khử liên kết" : "Xem lại nội dung đã khử liên kết"}
      </button>
      {revealed && <pre className="safe-mail-content">{safeContent}</pre>}
    </>
  );
}
function SmsGuard() {
  const [phone, setPhone] = useState("");
  const [content, setContent] = useState("");
  const [outcome, setOutcome] = useState<SmsAssessment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [depth, setDepth] = useState<AnalysisDepth>("balanced");
  async function analyze() {
    if (!content.trim()) {
      setError("Hãy nhập nội dung SMS cần kiểm tra.");
      return;
    }
    setBusy(true);
    setError("");
    setOutcome(null);
    try {
      setOutcome(await assessSms(content.trim(), phone.trim(), depth, ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Không thể phân tích SMS.");
    } finally {
      setBusy(false);
    }
  }
  const result = outcome?.assessment;
  return (
    <section className="sms-guard">
      <AnalysisControls
        depth={depth}
        setDepth={(next) => {
          setDepth(next);
          setOutcome(null);
        }}
        mode="sms"
        disabled={busy}
      />
      <div className="sms-layout">
        <article className="sms-editor">
          <label>
            Số điện thoại gửi <small>Không bắt buộc · mặc định quốc gia VN</small>
            <input
              inputMode="tel"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="Ví dụ: +84 912 345 678"
            />
          </label>
          <label>
            Nội dung SMS
            <textarea
              value={content}
              onChange={(e) => {
                setContent(e.target.value);
                setError("");
              }}
              placeholder="Dán nội dung tin nhắn nghi ngờ…"
            />
          </label>
          <div className="sms-editor-foot">
            <span>{content.length} ký tự</span>
            <button
              className="scan"
              onClick={() => void analyze()}
              disabled={busy || !content.trim()}
            >
              {busy ? <RefreshCw className="spin" /> : <Shield />}
              {busy ? "Đang phân tích" : "Phân tích SMS"}
            </button>
          </div>
          {error && (
            <div className="admin-error">
              <AlertTriangle />
              {error}
            </div>
          )}
        </article>
        <article className="sms-result">
          {busy ? (
            <Pipeline current="Chạy model phân loại" compact />
          ) : result ? (
            <>
              <div className="sms-verdict">
                <RiskRing result={result} />
                <div>
                  <span className="eyebrow">KẾT QUẢ ĐÁNH GIÁ</span>
                  <h2>{riskText(result)}</h2>
                  <p>
                    Độ tin cậy {Math.round(result.confidence * 100)}% · {result.latencyMs || 0} ms
                  </p>
                </div>
              </div>
              <div className="phone-intelligence">
                <span>
                  <b>Phone intelligence</b>
                  <small>{phone.trim() || "Không nhập số gửi"}</small>
                </span>
                <span>
                  <b>
                    {outcome?.providerStatus === "not_requested"
                      ? "Không yêu cầu"
                      : outcome?.providerStatus || "unavailable"}
                  </b>
                  <small>
                    {outcome?.provider || "Chưa cấu hình provider"} ·{" "}
                    {outcome?.reputation || "không có reputation"}
                  </small>
                </span>
              </div>
              <h3 className="why">Vì sao bị chấm điểm này</h3>
              <div className="reason-list">
                {result.reasons.length ? (
                  result.reasons.map((reason, index) => (
                    <div key={`${index}-${reason}`}>
                      <span>{index + 1}</span>
                      <p>{reason}</p>
                    </div>
                  ))
                ) : (
                  <div>
                    <ShieldCheck />
                    <p>Không phát hiện tín hiệu rủi ro nổi bật trong nội dung đã kiểm tra.</p>
                  </div>
                )}
              </div>
              <div className={`explanation ${result.riskLevel}`}>
                <Shield />
                <p>
                  {result.explanation ||
                    "Kết quả hỗ trợ quyết định; hãy xác minh người gửi qua kênh chính thức."}
                </p>
              </div>
            </>
          ) : (
            <div className="sms-empty">
              <MessageSquare />
              <h2>Chưa có kết quả</h2>
              <p>
                Nội dung chỉ được gửi tới Core API khi bạn bấm Phân tích SMS. Liên kết không được mở
                trong ứng dụng.
              </p>
            </div>
          )}
        </article>
      </div>
    </section>
  );
}
function LocalShield({ authToken }: { authToken: string }) {
  const [report, setReport] = useState<LocalFileReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [sandbox, setSandbox] = useState<{ available: boolean; reason: string } | null>(null);
  const [downloadGuard, setDownloadGuard] = useState(false);
  const [guardReady, setGuardReady] = useState(false);
  const [cloudSession, setCloudSession] = useState<CloudSandboxSession | null>(null);
  const [cloudBusy, setCloudBusy] = useState(false);
  const [cloudMessage, setCloudMessage] = useState("");
  const [leaseMinutes, setLeaseMinutes] = useState<5 | 10>(5);
  const [remainingSeconds, setRemainingSeconds] = useState<number | null>(null);
  useEffect(() => {
    setSessionToken(authToken);
    let active = true;
    void getCloudSandboxStatus()
      .then((status) => {
        if (!active || !status.session) return;
        setCloudSession(status.session);
        if (
          status.session.mode === "interactive" &&
          (status.session.leaseMinutes === 5 || status.session.leaseMinutes === 10)
        ) {
          setLeaseMinutes(status.session.leaseMinutes);
        }
        setCloudMessage("Đã khôi phục phiên Cloud Lab đang hoạt động trên tài khoản này.");
      })
      .catch((error) => {
        if (active)
          setCloudMessage(
            error instanceof Error ? error.message : "Không thể khôi phục trạng thái Cloud Lab.",
          );
      });
    return () => {
      active = false;
    };
  }, [authToken]);
  useEffect(() => {
    if (!window.desktop) return;
    let unsubscribe = () => {};
    void window.desktop.localSecurity
      .getDownloadGuardSettings()
      .then((settings) => {
        setDownloadGuard(settings.autoQuarantineDownloads);
        setGuardReady(true);
      })
      .catch(() => setMessage("Không thể tải trạng thái Download Guard."));
    unsubscribe = window.desktop.localSecurity.onAutoQuarantined((result) => {
      setReport(result.report || null);
      setMessage(
        `Đã tự cô lập ${result.report?.name || "tệp thực thi"} khỏi Downloads. Vị trí: ${result.path}`,
      );
    });
    return () => unsubscribe();
  }, []);
  useEffect(() => {
    if (!window.desktop) return;
    void window.desktop.localSecurity
      .sandboxStatus()
      .then(setSandbox)
      .catch(() => setSandbox({ available: false, reason: "Không thể kiểm tra Windows Sandbox." }));
  }, []);
  useEffect(() => {
    const sessionId = cloudSession?.id;
    if (!sessionId) return;
    const sessionDone = ["failed", "expired", "terminated", "destroyed", "cleanup_failed"].includes(
      cloudSession.status,
    );
    if (sessionDone) return;
    let active = true;
    const timer = window.setInterval(() => {
      void getCloudSandboxSession(sessionId)
        .then((next) => {
          if (active) {
            setCloudSession(next);
            if (next.error) setCloudMessage(next.error);
          }
        })
        .catch((error) => {
          if (active)
            setCloudMessage(error instanceof Error ? error.message : "Mất kết nối với Cloud Lab.");
        });
    }, 2000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [cloudSession?.id, cloudSession?.mode, cloudSession?.sample.status, cloudSession?.status]);
  useEffect(() => {
    const deadline = cloudSession?.leaseExpiresAt;
    if (!cloudSession?.readyAt || !deadline) {
      setRemainingSeconds(null);
      return;
    }
    const tick = () =>
      setRemainingSeconds(
        Math.max(0, Math.ceil((new Date(deadline).getTime() - Date.now()) / 1000)),
      );
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [cloudSession?.readyAt, cloudSession?.leaseExpiresAt]);
  async function choose() {
    if (!window.desktop) return setMessage("Chức năng này chỉ hoạt động trong ứng dụng Electron.");
    setBusy(true);
    setMessage("Đang đọc metadata, SHA-256 và chữ ký số...");
    try {
      const r = await window.desktop.localSecurity.chooseExecutable();
      if (r) {
        setReport(r);
        setMessage("Đã kiểm tra tĩnh. Tệp chưa được thực thi.");
      } else setMessage("Đã hủy chọn tệp.");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Không thể kiểm tra tệp.");
    } finally {
      setBusy(false);
    }
  }
  async function checkSandbox() {
    if (!window.desktop) return;
    const s = await window.desktop.localSecurity.sandboxStatus();
    setSandbox(s);
    setMessage(s.reason);
  }
  async function quarantine() {
    if (!report || !window.desktop) return;
    try {
      const r = await window.desktop.localSecurity.quarantine(report.path);
      setMessage(`${r.note} Vị trí: ${r.path}`);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Cô lập thất bại.");
    }
  }
  async function openSandbox() {
    if (!report || !window.desktop) return;
    try {
      const r = await window.desktop.localSecurity.openSandbox(report.path);
      setMessage(r.note);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Không mở được môi trường ảo.");
    }
  }
  async function toggleDownloadGuard() {
    if (!window.desktop) return;
    try {
      const next = await window.desktop.localSecurity.setDownloadGuard(!downloadGuard);
      setDownloadGuard(next.autoQuarantineDownloads);
      setMessage(
        next.autoQuarantineDownloads
          ? "Download Guard đã bật: EXE không có chữ ký hợp lệ trong Downloads sẽ được chuyển vào vault."
          : "Download Guard đã tắt.",
      );
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Không thể đổi trạng thái Download Guard.");
    }
  }
  async function startCloud(mode: CloudSandboxMode) {
    if (!report || !window.desktop) return;
    setCloudBusy(true);
    setCloudMessage(
      mode === "auto" ? "Đang cấp máy phân tích dùng một lần…" : "Đang cấp desktop điều tra riêng…",
    );
    let created: CloudSandboxSession | null = null;
    try {
      const sample = await window.desktop.localSecurity.readForCloud(report.path, report.sha256);
      created = await createCloudSandboxSession(mode, leaseMinutes);
      setCloudSession(created);
      if (created.mode !== mode) {
        setCloudMessage(
          `Đã khôi phục phiên ${created.mode === "auto" ? "Auto Analyze" : "Interactive"} đang tồn tại. Hãy tiếp tục hoặc kết thúc phiên đó trước khi tạo chế độ khác.`,
        );
        return;
      }
      if (created.sample.status !== "none") {
        setCloudMessage(
          "Đã khôi phục phiên hiện có và mẫu của phiên này đã được niêm phong; hệ thống không tải file lần hai.",
        );
        return;
      }
      if (!["provisioning", "ready"].includes(created.status)) {
        setCloudMessage(
          `Phiên hiện có đang ở trạng thái ${created.status}; chờ cleanup hoặc kết thúc phiên trước khi gửi mẫu mới.`,
        );
        return;
      }
      const file = new File([new Uint8Array(sample.data)], sample.filename, {
        type: "application/octet-stream",
      });
      const uploaded = await uploadCloudSandboxSample(created.id, file);
      setCloudSession(uploaded);
      setCloudMessage(
        mode === "auto"
          ? "Đã niêm phong mẫu. Agent sẽ tự chạy và thu thập bằng chứng."
          : "Đã niêm phong mẫu. Tệp chỉ được đặt vào máy ảo, không tự chạy; chờ desktop sẵn sàng.",
      );
    } catch (e) {
      const failure = e instanceof Error ? e.message : "Không khởi động được Cloud Lab.";
      setCloudMessage(
        created
          ? `${failure} Phiên chưa bị tự động hủy; hãy kiểm tra trạng thái và bấm “Kết thúc & hủy VM” nếu không dùng tiếp.`
          : failure,
      );
    } finally {
      setCloudBusy(false);
    }
  }
  async function stopCloud() {
    if (!cloudSession) return;
    setCloudBusy(true);
    try {
      const stopped = await stopCloudSandboxSession(cloudSession.id);
      setCloudSession({
        ...cloudSession,
        status: stopped.status,
        phase: stopped.status,
        remoteUrl: null,
        remoteAvailable: false,
        remoteStatus: stopped.cleanupPending ? "terminating" : "terminated",
        cleanupState: stopped.cleanupPending ? "requested" : "complete",
      });
      setCloudMessage(
        stopped.cleanupPending
          ? "Đã thu hồi quyền truy cập. Hệ thống đang xác nhận VM đã bị hủy…"
          : "Máy ảo đã bị hủy và phiên đã đóng.",
      );
    } catch (e) {
      setCloudMessage(e instanceof Error ? e.message : "Không thể kết thúc phiên.");
    } finally {
      setCloudBusy(false);
    }
  }
  async function openRemote() {
    if (!cloudSession?.remoteAvailable || !window.desktop) return;
    setCloudBusy(true);
    setCloudMessage("Đang cấp quyền truy cập dùng một lần…");
    try {
      const access = await issueCloudRemoteAccess(cloudSession.id);
      const target = new URL(access.connectUrl);
      const localDevelopment =
        target.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(target.hostname);
      if (target.protocol !== "https:" && !localDevelopment)
        throw new Error("Remote broker không trả về URL HTTPS hợp lệ; desktop không được mở.");
      await window.desktop.openExternal(target.toString());
      setCloudMessage(
        `Đã mở desktop. Link bắt tay hết hạn lúc ${new Date(access.tokenExpiresAt).toLocaleTimeString("vi-VN")}.`,
      );
    } catch (e) {
      setCloudMessage(e instanceof Error ? e.message : "Không cấp được quyền truy cập desktop.");
    } finally {
      setCloudBusy(false);
    }
  }
  const cloudReport = cloudSession?.sample.report || {};
  const evidenceCounts = [
    ["Tiến trình", cloudReport.process_tree],
    ["Tệp", cloudReport.file_events],
    ["Registry", cloudReport.registry_events],
    ["Mạng", cloudReport.network_events],
  ] as const;
  const reportVerdict = typeof cloudReport.verdict === "string" ? cloudReport.verdict : "";
  const reportSummary = typeof cloudReport.summary === "string" ? cloudReport.summary : "";
  const sessionActive = Boolean(
    cloudSession && !["failed", "expired", "terminated", "destroyed"].includes(cloudSession.status),
  );
  const clock =
    cloudSession?.mode === "auto"
      ? "TỰ ĐỘNG"
      : remainingSeconds == null
        ? "Bắt đầu khi máy sẵn sàng"
        : `${String(Math.floor(remainingSeconds / 60)).padStart(2, "0")}:${String(remainingSeconds % 60).padStart(2, "0")}`;
  return (
    <section className="local-shield">
      <div className="local-grid">
        <article className="local-card primary-card">
          <FileSearch />
          <span className="eyebrow">STATIC INSPECTION</span>
          <h2>Kiểm tra EXE lạ</h2>
          <p>Đọc SHA-256, kích thước và chữ ký Authenticode mà không thực thi tệp.</p>
          <button className="scan" onClick={choose} disabled={busy || cloudBusy}>
            {busy ? <RefreshCw className="spin" /> : <FileUp />}
            {busy ? "Đang kiểm tra" : "Chọn tệp EXE/MSI"}
          </button>
        </article>
        <article className="local-card">
          <ShieldAlert />
          <span className="eyebrow">DOWNLOAD GUARD</span>
          <h2>Tự cô lập Downloads</h2>
          <p>
            Theo dõi Downloads mặc định. EXE/MSI/BAT/CMD không có chữ ký hợp lệ sẽ bị chuyển bản gốc
            vào vault sau khi tải xong.
          </p>
          <button
            className={downloadGuard ? "sandbox-btn" : ""}
            disabled={!guardReady}
            onClick={toggleDownloadGuard}
          >
            <ShieldCheck />
            {downloadGuard ? "Tắt Download Guard" : "Bật Download Guard"}
          </button>
        </article>
        <article className="local-card">
          <PackageOpen />
          <span className="eyebrow">QUARANTINE VAULT</span>
          <h2>Kho cô lập</h2>
          <p>
            Tạo bản sao đổi đuôi <code>.quarantine</code> trong vùng dữ liệu riêng của ứng dụng, đặt
            chỉ đọc.
          </p>
          <button disabled={!report} onClick={quarantine}>
            <LockKeyhole />
            Cô lập bản sao
          </button>
        </article>
        <article className="local-card">
          <Box />
          <span className="eyebrow">LOCAL ISOLATION</span>
          <h2>Windows Sandbox</h2>
          <p>
            Môi trường dùng một lần, tắt mạng/clipboard/máy in và chỉ gắn thư mục mẫu ở chế độ chỉ
            đọc.
          </p>
          <button onClick={checkSandbox}>
            <RefreshCw />
            Kiểm tra hỗ trợ
          </button>
          <button
            className="sandbox-btn"
            disabled={!report || sandbox?.available === false}
            onClick={openSandbox}
          >
            <Box />
            Mở môi trường ảo
          </button>
        </article>
      </div>
      {message && (
        <div className="local-message">
          <Shield />
          {message}
        </div>
      )}
      {report && (
        <div className="file-report">
          <div className="file-report-head">
            <div>
              <span className="eyebrow">FILE ASSESSMENT</span>
              <h2>{report.name}</h2>
              <small>{report.path}</small>
            </div>
            <span className={`signature ${report.risk}`}>
              {report.signatureStatus === "Valid" ? <Check /> : <AlertTriangle />}
              {report.signatureStatus === "Valid" ? "CHỮ KÝ HỢP LỆ" : "CHƯA TIN CẬY"}
            </span>
          </div>
          <div className="file-facts">
            <div>
              <small>SHA-256</small>
              <code>{report.sha256}</code>
            </div>
            <div>
              <small>Kích thước</small>
              <b>{(report.size / 1024 / 1024).toFixed(2)} MB</b>
            </div>
            <div>
              <small>Nhà phát hành</small>
              <b>{report.signer || "Không xác định"}</b>
            </div>
            <div>
              <small>Cập nhật</small>
              <b>{new Date(report.modifiedAt).toLocaleString("vi-VN")}</b>
            </div>
          </div>
          <h3>Tín hiệu an toàn</h3>
          {report.reasons.map((x, i) => (
            <div className="local-reason" key={`${i}-${x}`}>
              <span>{i + 1}</span>
              {x}
            </div>
          ))}
          <div className="local-warning">
            <AlertTriangle />
            <p>
              <b>Không phải antivirus hoàn chỉnh.</b> Download Guard dùng chữ ký số như lớp bảo vệ
              cục bộ ban đầu. Nó không thay thế Microsoft Defender/EDR và không phải chứng nhận tệp
              an toàn.
            </p>
          </div>
        </div>
      )}
      <section className="cloud-escalation">
        <header>
          <div>
            <span className="eyebrow">CLOUD ESCALATION · SAME RISK CORE</span>
            <h2>Hai chế độ, một chuỗi bằng chứng</h2>
            <p>
              Local Shield không phụ thuộc cloud để bảo vệ cơ bản. Khi cần kết luận sâu hơn, mẫu
              được gửi có xác nhận vào máy Windows dùng một lần và tự hủy.
            </p>
          </div>
          <div className="lease-control">
            <small>THỜI LƯỢNG INTERACTIVE</small>
            <span>
              <button
                className={leaseMinutes === 5 ? "active" : ""}
                disabled={sessionActive || cloudBusy}
                onClick={() => setLeaseMinutes(5)}
              >
                5 phút
              </button>
              <button
                className={leaseMinutes === 10 ? "active" : ""}
                disabled={sessionActive || cloudBusy}
                onClick={() => setLeaseMinutes(10)}
              >
                10 phút
              </button>
            </span>
          </div>
        </header>
        <div className="cloud-modes">
          <article>
            <Activity />
            <span className="eyebrow">AUTO ANALYZE</span>
            <h3>Phân tích tự động</h3>
            <p>
              Agent chạy mẫu trong VM, ghi cây tiến trình, tệp trong vùng giám sát, khóa
              persistence, kết nối mạng theo PID và mốc thời gian.
            </p>
            <ul>
              <li>Không cần điều khiển thủ công</li>
              <li>Phù hợp demo nhanh và benchmark lặp lại</li>
              <li>VM bị hủy sau phiên</li>
            </ul>
            <button
              className="scan"
              disabled={!report || cloudBusy || sessionActive}
              onClick={() => void startCloud("auto")}
            >
              {cloudBusy ? <RefreshCw className="spin" /> : <Cpu />}Phân tích tự động
            </button>
          </article>
          <article>
            <Monitor />
            <span className="eyebrow">INTERACTIVE INVESTIGATE</span>
            <h3>Điều khiển desktop thật</h3>
            <p>
              Mẫu chỉ được đặt vào thư mục điều tra. Bạn quyết định thao tác trong desktop cô lập
              qua phiên truy cập ngắn hạn.
            </p>
            <ul>
              <li>Đồng hồ chỉ chạy khi máy đã ready</li>
              <li>Token truy cập gắn với phiên và tự hết hạn</li>
              <li>Không mở RDP công khai</li>
            </ul>
            <button
              className="sandbox-btn"
              disabled={!report || cloudBusy || sessionActive}
              onClick={() => void startCloud("interactive")}
            >
              {cloudBusy ? <RefreshCw className="spin" /> : <Monitor />}Mở lượt điều tra
            </button>
          </article>
        </div>
        {cloudMessage && (
          <div className="cloud-notice">
            <Shield />
            {cloudMessage}
          </div>
        )}
        {cloudSession && (
          <div className="cloud-session">
            <div className="cloud-session-head">
              <span>
                <i className={cloudSession.status} />
                <small>SESSION {cloudSession.id.slice(0, 8)}</small>
                <b>
                  {cloudSession.mode === "auto" ? "AUTO ANALYZE" : "INTERACTIVE"} ·{" "}
                  {cloudSession.phase || cloudSession.status}
                </b>
              </span>
              <strong>{clock}</strong>
            </div>
            <div className="cloud-evidence">
              {evidenceCounts.map(([label, value]) => (
                <span key={label}>
                  <small>{label}</small>
                  <b>{Array.isArray(value) ? value.length : 0}</b>
                </span>
              ))}
            </div>
            {(reportVerdict || reportSummary) && (
              <div className={`cloud-conclusion ${reportVerdict}`}>
                <ShieldCheck />
                <span>
                  <small>KẾT LUẬN TỪ BẰNG CHỨNG</small>
                  <b>{reportVerdict || cloudSession.sample.status}</b>
                  <p>
                    {reportSummary ||
                      "Agent đã hoàn tất chuỗi thu thập bằng chứng trong máy ảo dùng một lần."}
                  </p>
                </span>
              </div>
            )}
            {cloudSession.mode === "interactive" && (
              <div className={`remote-access ${cloudSession.remoteAvailable ? "ready" : ""}`}>
                <Monitor />
                <div>
                  <b>
                    {cloudSession.remoteAvailable
                      ? "Desktop điều tra đã sẵn sàng"
                      : cloudSession.remoteStatus === "provisioning"
                        ? "Đang chuẩn bị desktop…"
                        : "Desktop tương tác chưa khả dụng"}
                  </b>
                  <small>
                    {cloudSession.remoteAvailable
                      ? "Mỗi lần mở được cấp token một lần, tối đa 60 giây để bắt tay."
                      : cloudSession.remoteUnavailableReason ||
                        cloudSession.remoteStatus ||
                        "Hạ tầng remote broker chưa được cấu hình; hệ thống không tạo URL giả."}
                  </small>
                </div>
                <button
                  disabled={!cloudSession.remoteAvailable || cloudBusy}
                  onClick={() => void openRemote()}
                >
                  Mở desktop
                </button>
              </div>
            )}
            <div className="cloud-session-actions">
              <span>
                Mẫu: <b>{cloudSession.sample.filename || "đang chờ"}</b> ·{" "}
                {cloudSession.sample.status}
              </span>
              <button disabled={cloudBusy || !sessionActive} onClick={() => void stopCloud()}>
                <Ban />
                Kết thúc & hủy VM
              </button>
            </div>
          </div>
        )}
        <footer>
          <LockKeyhole />
          <span>
            <b>Ranh giới tin cậy rõ ràng.</b> Chỉ file đã chọn, đúng SHA-256 và không vượt 10 MB mới
            được gửi. Auto mới tự chạy; Interactive tuyệt đối không tự chạy mẫu.
          </span>
        </footer>
      </section>
    </section>
  );
}
type Preferences = {
  threshold: number;
  autoBlock: boolean;
  compactMode: boolean;
  desktopNotifications: boolean;
  riskNotifications: boolean;
  rememberLastView: boolean;
};
const defaultPreferences: Preferences = {
  threshold: 70,
  autoBlock: false,
  compactMode: false,
  desktopNotifications: true,
  riskNotifications: true,
  rememberLastView: true,
};
type SettingsTab = "ai" | "general" | "protection" | "notifications" | "privacy" | "account";
type UserAIDraft = {
  provider: UserAIProvider;
  baseUrl: string;
  model: string;
  apiKey: string;
  weightPercent: number;
};
const emptyUserAI: UserAISettings = {
  provider: "auto",
  baseUrl: "",
  model: "",
  apiKeyConfigured: false,
  configured: false,
  source: "database",
  allowedProviders: ["adapter", "local", "endpoint"],
  allowedModels: [],
  percent: 0,
  minPercent: 0,
  maxPercent: 40,
  weightPercent: 0,
  weightEligible: false,
  weightSource: "global",
};
const localCoreAPI = (() => {
  try {
    return new Set(["localhost", "127.0.0.1", "::1", "[::1]"]).has(new URL(apiBaseUrl).hostname);
  } catch {
    return false;
  }
})();
const SETTINGS_META: Record<SettingsTab, { eyebrow: string; title: string; description: string }> =
  {
    ai: {
      eyebrow: "PERSONAL AI",
      title: "Model và chế độ AI",
      description:
        "Dùng cùng cấu hình AI của tài khoản; Local LLM chỉ khả dụng khi Core API chạy trên máy này.",
    },
    general: {
      eyebrow: "PREFERENCES",
      title: "Thiết lập chung",
      description: "Điều chỉnh cách AI Security Armor hiển thị và hoạt động trên thiết bị này.",
    },
    protection: {
      eyebrow: "PROTECTION",
      title: "Bảo vệ chủ động",
      description: "Thiết lập ngưỡng phản ứng và các lớp bảo vệ cục bộ của ứng dụng.",
    },
    notifications: {
      eyebrow: "NOTIFICATIONS",
      title: "Thông báo",
      description: "Kiểm soát những sự kiện bảo mật được phép thu hút sự chú ý của bạn.",
    },
    privacy: {
      eyebrow: "PRIVACY & DATA",
      title: "Dữ liệu & quyền riêng tư",
      description: "Xem và quản lý dữ liệu bảo vệ chỉ được lưu trên máy tính này.",
    },
    account: {
      eyebrow: "ACCOUNT",
      title: "Tài khoản",
      description: "Thông tin phiên đăng nhập, gói sử dụng và kết nối tới Core API.",
    },
  };
function SettingsView({
  session,
  backendOnline,
  onSignOut,
  onPreferencesChange,
}: {
  session: UserSession;
  backendOnline: boolean | null;
  onSignOut: () => void;
  onPreferencesChange: (prefs: Preferences) => void;
}) {
  const [tab, setTab] = useState<SettingsTab>("ai");
  const [prefs, setPrefs] = useState<Preferences>(readPreferences);
  const [notice, setNotice] = useState("");
  const [downloadGuard, setDownloadGuard] = useState(false);
  const [guardReady, setGuardReady] = useState(!window.desktop);
  const [guardBusy, setGuardBusy] = useState(false);
  const [dataVersion, setDataVersion] = useState(0);
  const [ai, setAI] = useState<UserAISettings>(emptyUserAI);
  const [aiDraft, setAIDraft] = useState<UserAIDraft>({
    provider: "adapter",
    baseUrl: "",
    model: "",
    apiKey: "",
    weightPercent: 0,
  });
  const [aiBusy, setAIBusy] = useState(true);
  const [aiNotice, setAINotice] = useState("");
  useEffect(() => {
    if (!window.desktop) return;
    void window.desktop.localSecurity
      .getDownloadGuardSettings()
      .then((value) => {
        setDownloadGuard(value.autoQuarantineDownloads);
        setGuardReady(true);
      })
      .catch(() => {
        setNotice("Không thể đọc trạng thái Download Guard.");
        setGuardReady(true);
      });
  }, []);
  useEffect(() => {
    let active = true;
    setAIBusy(true);
    void getUserAISettings()
      .then((value) => {
        if (!active) return;
        setAI(value);
        const available = value.allowedProviders.filter(
          (provider) => provider !== "local" || localCoreAPI,
        );
        const selected =
          value.source === "account" &&
          value.provider !== "auto" &&
          available.includes(value.provider)
            ? value.provider
            : available[0] || "adapter";
        setAIDraft({
          provider: selected,
          baseUrl:
            value.source === "account" && value.provider === selected
              ? value.baseUrl
              : selected === "local"
                ? "http://127.0.0.1:11434/v1"
                : "",
          model: value.source === "account" && value.provider === selected ? value.model : "",
          apiKey: "",
          weightPercent: value.weightPercent,
        });
      })
      .catch((error) => {
        if (active)
          setAINotice(error instanceof Error ? error.message : "Không tải được cài đặt AI.");
      })
      .finally(() => {
        if (active) setAIBusy(false);
      });
    return () => {
      active = false;
    };
  }, []);
  const update = (patch: Partial<Preferences>) => {
    const next = { ...prefs, ...patch };
    setPrefs(next);
    onPreferencesChange(next);
    localStorage.setItem("armor-preferences", JSON.stringify(next));
    setNotice("Thay đổi đã được lưu trên thiết bị.");
  };
  const counts = useMemo(
    () => ({
      domains: readStoredList("armor-blocked-domains").length,
      senders: readStoredList("armor-blocked-senders").length,
    }),
    [dataVersion],
  );
  const clearKeys = (keys: string[], message: string) => {
    keys.forEach((key) => localStorage.removeItem(key));
    if (keys.includes("armor-preferences")) {
      const reset = { ...defaultPreferences };
      setPrefs(reset);
      onPreferencesChange(reset);
      localStorage.removeItem("armor-last-view");
    }
    setDataVersion((value) => value + 1);
    setNotice(message);
  };
  async function toggleDownloadGuard() {
    if (!window.desktop) {
      setNotice("Download Guard chỉ khả dụng trong ứng dụng Windows đã cài đặt.");
      return;
    }
    setGuardBusy(true);
    try {
      const value = await window.desktop.localSecurity.setDownloadGuard(!downloadGuard);
      setDownloadGuard(value.autoQuarantineDownloads);
      setNotice(
        value.autoQuarantineDownloads
          ? "Download Guard đã được bật."
          : "Download Guard đã được tắt.",
      );
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Không thể thay đổi Download Guard.");
    } finally {
      setGuardBusy(false);
    }
  }
  async function savePersonalAI() {
    if (aiDraft.provider === "local" && !localCoreAPI) {
      setAINotice(
        "Local LLM không khả dụng khi Desktop đang kết nối Core API production từ xa.",
      );
      return;
    }
    setAIBusy(true);
    setAINotice("");
    try {
      const { weightPercent, ...providerDraft } = aiDraft;
      const value = await saveUserAISettings({
        ...providerDraft,
        ...(ai.weightEligible ? { weightPercent } : {}),
        ...(aiDraft.apiKey ? { apiKey: aiDraft.apiKey } : {}),
      });
      setAI(value);
      setAIDraft((current) => ({ ...current, apiKey: "" }));
      setAINotice("Đã lưu cấu hình AI cho tài khoản.");
    } catch (error) {
      setAINotice(error instanceof Error ? error.message : "Không lưu được cài đặt AI.");
    } finally {
      setAIBusy(false);
    }
  }
  async function testPersonalAI() {
    setAIBusy(true);
    setAINotice("");
    try {
      const value = await testUserAISettings();
      setAINotice(
        value.modelAvailable
          ? `Kết nối model thành công · endpoint có ${value.modelsCount} model.`
          : "Kết nối được endpoint nhưng không tìm thấy model đã chọn.",
      );
    } catch (error) {
      setAINotice(error instanceof Error ? error.message : "Không kiểm tra được model.");
    } finally {
      setAIBusy(false);
    }
  }
  const availableAIProviders = ai.allowedProviders.filter(
    (provider) => provider !== "local" || localCoreAPI,
  );
  const personalAIConfigured =
    ai.source === "account" && !(ai.provider === "local" && !localCoreAPI);
  const meta = SETTINGS_META[tab];
  return (
    <section className="settings-view">
      <aside>
        <div className="settings-side-head">
          <span>
            <Settings />
          </span>
          <div>
            <small>AI SECURITY ARMOR</small>
            <h2>Cài đặt</h2>
          </div>
        </div>
        <nav aria-label="Danh mục cài đặt">
          <button className={tab === "ai" ? "active" : ""} onClick={() => setTab("ai")}>
            <Cpu />
            <span>
              <b>Model AI</b>
              <small>Cấu hình theo tài khoản</small>
            </span>
          </button>
          <button className={tab === "general" ? "active" : ""} onClick={() => setTab("general")}>
            <Settings />
            <span>
              <b>Chung</b>
              <small>Hiển thị và hành vi</small>
            </span>
          </button>
          <button
            className={tab === "protection" ? "active" : ""}
            onClick={() => setTab("protection")}
          >
            <Shield />
            <span>
              <b>Bảo vệ</b>
              <small>Ngưỡng và Local Shield</small>
            </span>
          </button>
          <button
            className={tab === "notifications" ? "active" : ""}
            onClick={() => setTab("notifications")}
          >
            <Bell />
            <span>
              <b>Thông báo</b>
              <small>Cảnh báo bảo mật</small>
            </span>
          </button>
          <button className={tab === "privacy" ? "active" : ""} onClick={() => setTab("privacy")}>
            <Database />
            <span>
              <b>Dữ liệu & riêng tư</b>
              <small>Lưu trữ trên thiết bị</small>
            </span>
          </button>
          <button className={tab === "account" ? "active" : ""} onClick={() => setTab("account")}>
            <CircleUserRound />
            <span>
              <b>Tài khoản</b>
              <small>Phiên và gói sử dụng</small>
            </span>
          </button>
        </nav>
        <div className="settings-version">
          <ShieldCheck />
          <span>
            <b>Desktop {window.desktop?.version || "preview"}</b>
            <small>
              Core API{" "}
              {backendOnline
                ? "đang kết nối"
                : backendOnline === false
                  ? "ngoại tuyến"
                  : "đang kiểm tra"}
            </small>
          </span>
        </div>
      </aside>
      <article>
        <header className="settings-heading">
          <div>
            <span className="eyebrow">{meta.eyebrow}</span>
            <h1>{meta.title}</h1>
            <p>{meta.description}</p>
          </div>
          <span
            className={`settings-health ${backendOnline ? "online-state" : backendOnline === false ? "offline-state" : ""}`}
          >
            <i />
            {backendOnline
              ? "Core API sẵn sàng"
              : backendOnline === false
                ? "Core API ngoại tuyến"
                : "Đang kiểm tra Core API"}
          </span>
        </header>
        {notice && (
          <div className="settings-notice" role="status">
            <Check />
            {notice}
            <button aria-label="Đóng thông báo" onClick={() => setNotice("")}>
              ×
            </button>
          </div>
        )}
        {tab === "ai" && (
          <>
            {aiNotice && (
              <div className="settings-notice" role="status">
                <Info />
                {aiNotice}
                <button aria-label="Đóng thông báo AI" onClick={() => setAINotice("")}>
                  ×
                </button>
              </div>
            )}
            <div className="setting-group desktop-ai-settings">
              <h3>
                <Cpu />
                Cấu hình AI cá nhân
              </h3>
              {ai.weightEligible && (
                <label>
                  <span>
                    <b>Trọng số AI cá nhân · {aiDraft.weightPercent}%</b>
                    <small>
                      Admin cho phép từ {ai.minPercent}% đến {ai.maxPercent}% cho phân tích Pro.
                    </small>
                  </span>
                  <input
                    aria-label="Trọng số AI cá nhân"
                    type="range"
                    min={ai.minPercent}
                    max={ai.maxPercent}
                    value={aiDraft.weightPercent}
                    onChange={(event) =>
                      setAIDraft({ ...aiDraft, weightPercent: Number(event.target.value) })
                    }
                  />
                </label>
              )}
              <label>
                <span>
                  <b>Chế độ AI</b>
                  <small>
                    {personalAIConfigured ? "Đã cấu hình cho tài khoản" : "Chưa chọn riêng"}
                  </small>
                </span>
                <select
                  aria-label="Chế độ AI"
                  value={availableAIProviders.includes(aiDraft.provider) ? aiDraft.provider : ""}
                  disabled={aiBusy || availableAIProviders.length === 0}
                  onChange={(event) => {
                    const provider = event.target.value as UserAIProvider;
                    setAIDraft(
                      provider === "adapter"
                        ? { ...aiDraft, provider, baseUrl: "", model: "", apiKey: "" }
                        : provider === "local"
                          ? {
                              ...aiDraft,
                              provider,
                              baseUrl: "http://127.0.0.1:11434/v1",
                              apiKey: "",
                            }
                          : { ...aiDraft, provider, baseUrl: "", apiKey: "" },
                    );
                  }}
                >
                  {availableAIProviders.length === 0 && (
                    <option value="">Không có provider khả dụng</option>
                  )}
                  {ai.allowedProviders.includes("adapter") && (
                    <option value="adapter">AI bảo mật Prewise</option>
                  )}
                  {ai.allowedProviders.includes("local") && (
                    <option value="local" disabled={!localCoreAPI}>
                      Local LLM {!localCoreAPI ? "· cần Core API local" : ""}
                    </option>
                  )}
                  {ai.allowedProviders.includes("endpoint") && (
                    <option value="endpoint">API endpoint · model riêng</option>
                  )}
                </select>
              </label>
              {aiDraft.provider !== "adapter" && (
                <label>
                  <span>
                    <b>Model ID</b>
                    <small>Ví dụ: qwen2.5:7b hoặc model-id OpenAI-compatible.</small>
                  </span>
                  {ai.allowedModels.length ? (
                    <select
                      aria-label="Model ID"
                      value={aiDraft.model}
                      onChange={(event) => setAIDraft({ ...aiDraft, model: event.target.value })}
                    >
                      <option value="">Chọn model được phép</option>
                      {ai.allowedModels.map((model) => (
                        <option value={model} key={model}>
                          {model}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      aria-label="Model ID"
                      value={aiDraft.model}
                      onChange={(event) => setAIDraft({ ...aiDraft, model: event.target.value })}
                      placeholder="qwen2.5:7b"
                    />
                  )}
                </label>
              )}
              {(aiDraft.provider === "local" || aiDraft.provider === "endpoint") && (
                <label>
                  <span>
                    <b>Base URL</b>
                    <small>
                      {aiDraft.provider === "local"
                        ? "Ollama/OpenAI-compatible trên cùng máy với Core API."
                        : "Endpoint công cộng bắt buộc HTTPS."}
                    </small>
                  </span>
                  <input
                    aria-label="Base URL"
                    value={aiDraft.baseUrl}
                    onChange={(event) => setAIDraft({ ...aiDraft, baseUrl: event.target.value })}
                    placeholder={
                      aiDraft.provider === "local"
                        ? "http://127.0.0.1:11434/v1"
                        : "https://api.example.com/v1"
                    }
                  />
                </label>
              )}
              {aiDraft.provider === "endpoint" && (
                <label>
                  <span>
                    <b>API key</b>
                    <small>
                      {ai.apiKeyConfigured
                        ? "Đã lưu mã hóa; để trống để giữ khóa hiện tại."
                        : "Khóa được gửi tới Core API qua kết nối hiện tại."}
                    </small>
                  </span>
                  <input
                    aria-label="API key"
                    type="password"
                    value={aiDraft.apiKey}
                    onChange={(event) => setAIDraft({ ...aiDraft, apiKey: event.target.value })}
                    autoComplete="new-password"
                  />
                </label>
              )}
            </div>
            <div className={`desktop-local-ai-note ${localCoreAPI ? "available" : ""}`}>
              <HardDrive />
              <div>
                <b>
                  Local LLM: {localCoreAPI ? "có thể sử dụng" : "không khả dụng với Core API hiện tại"}
                </b>
                <p>
                  {localCoreAPI
                    ? "Desktop đang kết nối Core API localhost. Ollama phải chạy trên cùng máy và cung cấp API OpenAI-compatible."
                    : `Desktop đang dùng ${apiBaseUrl}. Địa chỉ 127.0.0.1 tại backend từ xa không phải máy của bạn, nên tùy chọn Local LLM bị khóa.`}
                </p>
              </div>
            </div>
            <div className="desktop-ai-actions">
              <button
                className="scan"
                disabled={aiBusy || !availableAIProviders.includes(aiDraft.provider)}
                onClick={() => void savePersonalAI()}
              >
                {aiBusy ? "Đang xử lý…" : "Lưu cho tài khoản"}
              </button>
              <button
                disabled={
                  aiBusy ||
                  !personalAIConfigured ||
                  !["endpoint", "local"].includes(ai.provider) ||
                  (ai.provider === "local" && !localCoreAPI)
                }
                onClick={() => void testPersonalAI()}
              >
                Kiểm tra model
              </button>
            </div>
          </>
        )}
        {tab === "general" && (
          <>
            <div className="setting-group">
              <h3>
                <Monitor />
                Giao diện
              </h3>
              <div className="setting-row">
                <span>
                  <b>Ngôn ngữ ứng dụng</b>
                  <small>Bản Desktop hiện dùng tiếng Việt nhất quán trên toàn bộ giao diện.</small>
                </span>
                <div className="theme-chip">Tiếng Việt</div>
              </div>
              <Toggle
                title="Giao diện thu gọn"
                note="Giảm khoảng cách và chiều cao điều khiển để hiển thị nhiều nội dung hơn."
                on={prefs.compactMode}
                setOn={(value) => update({ compactMode: value })}
              />
            </div>
            <div className="setting-group">
              <h3>
                <Zap />
                Khởi động
              </h3>
              <Toggle
                title="Ghi nhớ khu vực gần nhất"
                note="Cho phép ứng dụng ghi nhớ lựa chọn điều hướng cho lần mở tiếp theo."
                on={prefs.rememberLastView}
                setOn={(value) => update({ rememberLastView: value })}
              />
              <div className="setting-row">
                <span>
                  <b>Chế độ màu</b>
                  <small>
                    Giao diện bảo mật tối giúp nội dung cảnh báo có độ tương phản ổn định.
                  </small>
                </span>
                <div className="theme-chip">
                  <Monitor />
                  Tối bảo mật
                </div>
              </div>
            </div>
          </>
        )}
        {tab === "protection" && (
          <>
            <div className="protection-summary">
              <ShieldCheck />
              <div>
                <b>Lớp bảo vệ đang hoạt động</b>
                <span>Website Check · Email Guard · SMS Guard · Local Shield</span>
              </div>
              <strong>{downloadGuard ? "4/4" : "3/4"}</strong>
            </div>
            <div className="setting-group">
              <h3>
                <Shield />
                Phản ứng tự động
              </h3>
              <div className="setting-row">
                <span>
                  <b>Ngưỡng tự chặn</b>
                  <small>Mục vượt ngưỡng sẽ được đưa vào danh sách chặn cục bộ.</small>
                </span>
                <div className="range">
                  <input
                    aria-label="Ngưỡng tự chặn"
                    type="range"
                    min="40"
                    max="90"
                    value={prefs.threshold}
                    onChange={(e) => update({ threshold: +e.target.value })}
                  />
                  <b>
                    {prefs.threshold}
                    <small>/100</small>
                  </b>
                </div>
              </div>
              <Toggle
                title="Tự chặn rủi ro cao"
                note="Tự lưu domain hoặc người gửi khi điểm đánh giá vượt ngưỡng."
                on={prefs.autoBlock}
                setOn={(value) => update({ autoBlock: value })}
              />
            </div>
            <div className="setting-group">
              <h3>
                <HardDrive />
                Bảo vệ Windows
              </h3>
              <Toggle
                title="Download Guard"
                note={
                  window.desktop
                    ? "Tự cô lập EXE/MSI/BAT/CMD không có chữ ký hợp lệ trong thư mục Downloads."
                    : "Chỉ khả dụng trong bản desktop Windows đã cài đặt."
                }
                on={downloadGuard}
                disabled={!guardReady || guardBusy || !window.desktop}
                setOn={() => void toggleDownloadGuard()}
              />
              <div className="setting-footnote">
                <Info />
                Download Guard là lớp kiểm tra chữ ký ban đầu, không thay thế Microsoft Defender
                hoặc EDR.
              </div>
            </div>
          </>
        )}
        {tab === "notifications" && (
          <>
            <div className="setting-group">
              <h3>
                <Bell />
                Cảnh báo trên desktop
              </h3>
              <Toggle
                title="Cho phép thông báo hệ thống"
                note="Hiển thị thông báo khi tác vụ bảo mật cần bạn chú ý."
                on={prefs.desktopNotifications}
                setOn={(value) => update({ desktopNotifications: value })}
              />
              <Toggle
                title="Ưu tiên phát hiện rủi ro cao"
                note="Giữ cảnh báo quan trọng ngay cả khi các thông báo thông thường bị hạn chế."
                on={prefs.riskNotifications}
                disabled={!prefs.desktopNotifications}
                setOn={(value) => update({ riskNotifications: value })}
              />
            </div>
            <div className="notification-preview">
              <span>
                <ShieldAlert />
              </span>
              <div>
                <small>AI SECURITY ARMOR</small>
                <b>Phát hiện mục có rủi ro cao</b>
                <p>Cảnh báo sẽ hiển thị theo kiểu này khi một tác vụ cần bạn xem lại.</p>
              </div>
              <time>Bây giờ</time>
            </div>
          </>
        )}
        {tab === "privacy" && (
          <>
            <div className="data-overview">
              <div>
                <Globe2 />
                <b>{counts.domains}</b>
                <span>Domain đã chặn</span>
              </div>
              <div>
                <Mail />
                <b>{counts.senders}</b>
                <span>Người gửi đã chặn</span>
              </div>
            </div>
            <div className="setting-group data-actions">
              <h3>
                <Database />
                Dữ liệu trên thiết bị
              </h3>
              <div className="data-row">
                <span>
                  <b>Danh sách chặn</b>
                  <small>
                    {counts.domains + counts.senders} mục · chỉ lưu trong hồ sơ ứng dụng này
                  </small>
                </span>
                <button
                  onClick={() =>
                    clearKeys(
                      ["armor-blocked-domains", "armor-blocked-senders"],
                      "Đã xóa toàn bộ danh sách chặn cục bộ.",
                    )
                  }
                  disabled={counts.domains + counts.senders === 0}
                >
                  <Trash2 />
                  Xóa
                </button>
              </div>
            </div>
            <div className="privacy-note">
              <LockKeyhole />
              <div>
                <b>Phạm vi lưu trữ</b>
                <p>
                  Các tùy chọn và danh sách trên trang này nằm trong localStorage của ứng dụng. Nội
                  dung email, SMS và website không được lưu tại đây.
                </p>
              </div>
            </div>
            <button
              className="danger-zone"
              onClick={() =>
                clearKeys(
                  [
                    "armor-blocked-domains",
                    "armor-blocked-senders",
                    "armor-false-positive-reports",
                    "armor-preferences",
                  ],
                  "Đã xóa dữ liệu bảo vệ và đưa tùy chọn về mặc định.",
                )
              }
            >
              <Trash2 />
              Xóa toàn bộ dữ liệu cục bộ
            </button>
          </>
        )}
        {tab === "account" && (
          <>
            <div className="account-card">
              <div className="account-avatar">
                {session.user.displayName.trim().charAt(0).toUpperCase() || "U"}
              </div>
              <div>
                <span>Đang đăng nhập</span>
                <h2>{session.user.displayName}</h2>
                <p>{session.user.email}</p>
              </div>
              <span className="account-role">
                {session.user.role === "admin" ? "Quản trị viên" : "Người dùng"}
              </span>
            </div>
            <div className="account-grid">
              <div>
                <small>Gói hiện tại</small>
                <b>{session.plan.label || session.plan.tier}</b>
                <span>{session.plan.dailyScanLimit} lượt phân tích/ngày</span>
              </div>
              <div>
                <small>Trạng thái Core API</small>
                <b className={backendOnline ? "safe-text" : "warn-text"}>
                  {backendOnline ? "Đã kết nối" : "Chưa kết nối"}
                </b>
                <span>{apiBaseUrl}</span>
              </div>
              <div>
                <small>Mã tài khoản</small>
                <b>{session.user.id}</b>
                <span>Định danh từ Core API</span>
              </div>
              <div>
                <small>Phiên bản ứng dụng</small>
                <b>{window.desktop?.version || "Web preview"}</b>
                <span>AI Security Armor Desktop</span>
              </div>
            </div>
            <div className="setting-group">
              <h3>
                <LockKeyhole />
                Phiên đăng nhập
              </h3>
              <div className="account-action">
                <span>
                  <b>Đăng xuất khỏi thiết bị này</b>
                  <small>
                    Xóa token phiên khỏi ứng dụng; dữ liệu chặn cục bộ vẫn được giữ lại.
                  </small>
                </span>
                <button onClick={onSignOut}>
                  <LogOut />
                  Đăng xuất
                </button>
              </div>
            </div>
          </>
        )}
      </article>
    </section>
  );
}
function Toggle({
  title,
  note,
  on,
  setOn,
  disabled = false,
}: {
  title: string;
  note: string;
  on: boolean;
  setOn: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="setting-row">
      <span>
        <b>{title}</b>
        <small>{note}</small>
      </span>
      <button
        type="button"
        role="switch"
        aria-label={title}
        aria-checked={on}
        disabled={disabled}
        onClick={() => setOn(!on)}
        className={`toggle ${on ? "on" : ""}`}
      >
        <i />
      </button>
    </div>
  );
}
export default App;
