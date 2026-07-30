"use client";

import {
  Activity,
  ArrowLeft,
  Bot,
  CheckCircle2,
  Clock3,
  Download,
  ExternalLink,
  Fingerprint,
  Globe2,
  Image as ImageIcon,
  Mail,
  Network,
  Phone,
  RefreshCw,
  Server,
  ShieldAlert,
} from "lucide-react";
import NextImage from "next/image";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { PrewiseShell } from "@/components/PrewiseUI";
import { useAuth } from "@/context/AuthContext";
import { canUseProAI } from "@/lib/entitlements";
import { getRiskLevelForContext } from "@/lib/risk";
import { loadResultRecord, persistResultRecord } from "@/lib/result-storage";
import { readStoredAccessToken } from "@/lib/auth-session";
import mobileStyles from "../../../mobile-pages.module.css";

type SourceStatus = { source?: string; status?: string; detail?: string };
type URLIntelligence = {
  domain?: string;
  ip_addresses?: string[];
  primary_ip?: string | null;
  ip_location?: string | null;
  asn?: string | null;
  provider?: string | null;
  registrar?: string | null;
  registrant?: string | null;
  registrant_phone?: string | null;
  registered_at?: string | null;
  expires_at?: string | null;
  nameservers?: string[];
  mx_records?: string[];
  sources?: SourceStatus[];
};
type PageIdentity = {
  page_title?: string;
  final_url?: string;
  status_code?: number | null;
  description?: string;
  site_name?: string;
  image_url?: string;
  canonical_url?: string;
  language?: string;
  phones?: string[];
  emails?: string[];
  forms?: number;
  password_fields?: number;
};
type SandboxReport = {
  behaviors?: Array<Record<string, unknown>>;
  redirects?: Array<Record<string, unknown>>;
  scripts_executed?: string[];
  network_calls?: string[];
  dom_modifications?: Array<Record<string, unknown>>;
  page_identity?: PageIdentity;
  screenshot_data_url?: string | null;
  analysis_time_ms?: number;
  error?: string | null;
};
type DeepResult = {
  url?: string;
  risk_score?: number;
  threat_level?: string;
  analysis_time_ms?: number;
  evidence?: Array<{
    source?: string;
    message?: string;
    severity?: string;
    feature?: string;
  }>;
  ai_detection?: {
    detected?: boolean;
    confidence?: number;
    model_version?: string;
  };
  score_layers?: Array<{
    layer?: string;
    status?: string;
    score?: number;
    signals?: number;
    summary?: string;
  }>;
  url_intelligence?: URLIntelligence | null;
  sandbox_report?: SandboxReport | null;
  contextual_analysis?: {
    status?: string;
    adapter_id?: string;
    scoring_mode?: string;
    confidence?: number | null;
    error?: string;
  };
};
type StoredRecord = {
  id?: string;
  content?: string;
  score?: number;
  result?: DeepResult;
  [key: string]: unknown;
};

const PHASES = [
  "Tiếp nhận kết quả phân tích nội dung",
  "Truy vấn domain, DNS và IP/ASN",
  "Mở website trong browser sandbox",
  "Theo dõi redirect, script và network",
  "AI tổng hợp nhận diện và bằng chứng",
];

function valueFrom(record: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number") return String(value);
  }
  return "";
}

function formatDate(value?: string | null): string {
  if (!value) return "Không công khai";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : new Intl.DateTimeFormat("vi-VN").format(parsed);
}

function hostname(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

function screenshotFilename(domain?: string, url?: string): string {
  const source = domain || (url ? hostname(url) : "website") || "website";
  const safeName = source
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `prewise-sandbox-${safeName || "website"}.jpg`;
}

function AiAnalysisContent(): JSX.Element {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const { isHydrated, plan } = useAuth();
  const started = useRef(false);
  const [record, setRecord] = useState<StoredRecord | null>(null);
  const [result, setResult] = useState<DeepResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [phase, setPhase] = useState(0);
  const [error, setError] = useState("");

  const runDeepAnalysis = useCallback(
    async (source: StoredRecord) => {
      if (!canUseProAI(plan?.tier)) {
        setError("Chế độ Pro AI yêu cầu gói Pro hoặc cao hơn.");
        setLoading(false);
        return;
      }
      const url = source.content?.trim();
      if (!url) {
        setError(
          "Không tìm thấy URL của lần phân tích trước trong trình duyệt này.",
        );
        setLoading(false);
        return;
      }
      setLoading(true);
      setError("");
      setPhase(0);
      try {
        const accessToken = readStoredAccessToken();
        const response = await fetch("/api/demo/url/analyze", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          },
          body: JSON.stringify({
            url,
            deep_analysis: true,
            advanced_analysis: true,
            scan_all: true,
            ai_context: "on",
          }),
        });
        const payload = (await response.json()) as DeepResult & {
          detail?: string;
        };
        if (!response.ok)
          throw new Error(
            payload.detail || "Không thể hoàn tất phân tích AI chuyên sâu.",
          );
        const updated: StoredRecord = {
          ...source,
          score: Math.round(payload.risk_score || 0),
          result: payload,
          analysisDepth: "pro",
          aiDeepAnalyzedAt: new Date().toISOString(),
        };
        setRecord(updated);
        setResult(payload);
        setPhase(PHASES.length - 1);
        persistResultRecord(id, updated);
      } catch (reason) {
        setError(
          reason instanceof Error
            ? reason.message
            : "Phân tích chuyên sâu thất bại.",
        );
      } finally {
        setLoading(false);
      }
    },
    [id, plan?.tier],
  );

  useEffect(() => {
    if (!isHydrated || !id || started.current) return;
    if (!canUseProAI(plan?.tier)) {
      setError("Chế độ Pro AI yêu cầu gói Pro hoặc cao hơn.");
      setLoading(false);
      return;
    }
    started.current = true;
    try {
      const source = loadResultRecord<StoredRecord>(id);
      if (!source) {
        setError(
          "Không tìm thấy kết quả phân tích gốc. Hãy phân tích URL lại trước khi mở AI chuyên sâu.",
        );
        setLoading(false);
        return;
      }
      setRecord(source);
      void runDeepAnalysis(source);
    } catch {
      setError("Dữ liệu phân tích gốc không hợp lệ hoặc đã bị xóa.");
      setLoading(false);
    }
  }, [id, isHydrated, plan?.tier, runDeepAnalysis]);

  useEffect(() => {
    if (!loading) return;
    const timer = window.setInterval(
      () => setPhase((current) => Math.min(current + 1, PHASES.length - 2)),
      1800,
    );
    return () => window.clearInterval(timer);
  }, [loading]);

  const sandbox = result?.sandbox_report;
  const identity = sandbox?.page_identity || {};
  const intel = result?.url_intelligence;
  const risk = Math.round(result?.risk_score || 0);
  const displayLevel = getRiskLevelForContext(undefined, result?.threat_level, risk);
  const redirects = sandbox?.redirects || [];
  const contacts = useMemo(
    () => ({
      phones: Array.from(
        new Set(
          [intel?.registrant_phone, ...(identity.phones || [])].filter(
            Boolean,
          ) as string[],
        ),
      ),
      emails: Array.from(new Set(identity.emails || [])),
    }),
    [identity.emails, identity.phones, intel?.registrant_phone],
  );
  const networkHosts = useMemo(
    () =>
      Array.from(
        new Set((sandbox?.network_calls || []).map(hostname).filter(Boolean)),
      ).slice(0, 12),
    [sandbox?.network_calls],
  );

  return (
    <PrewiseShell>
      <main
        id="main-content"
        className={`ai-investigation ${mobileStyles.investigation}`}
      >
        <header className="ai-investigation-head">
          <div>
            <Link href={`/result/${id}`}>
              <ArrowLeft size={16} /> Kết quả phân tích nội dung
            </Link>
            <span>
              AI INVESTIGATION /{" "}
              {loading ? "ĐANG CHẠY" : error ? "CHƯA HOÀN TẤT" : "HOÀN TẤT"}
            </span>
            <h1>Phân tích thêm bằng AI</h1>
            <p>
              Điều tra website trong môi trường cô lập, kết hợp dấu vết truy cập
              và dữ liệu nhận diện công khai.
            </p>
          </div>
          {record?.content && (
            <code title={record.content}>{record.content}</code>
          )}
        </header>

        <section className="ai-pipeline" aria-label="Tiến trình phân tích AI">
          {PHASES.map((label, index) => (
            <div
              className={
                index < phase || (!loading && !error)
                  ? "done"
                  : index === phase && loading
                    ? "active"
                    : "pending"
              }
              key={label}
            >
              <i>
                {index < phase || (!loading && !error) ? (
                  <CheckCircle2 size={18} />
                ) : index === phase && loading ? (
                  <RefreshCw className="spin" size={18} />
                ) : (
                  <Clock3 size={18} />
                )}
              </i>
              <span>{label}</span>
            </div>
          ))}
        </section>

        {loading && (
          <section className="ai-loading" aria-live="polite">
            <Bot size={32} />
            <div>
              <b>{PHASES[phase]}</b>
              <p>
                Sandbox chỉ dùng dữ liệu canary tổng hợp và chặn gửi biểu mẫu,
                tải xuống, mạng riêng.
              </p>
            </div>
            <span>{Math.round(((phase + 1) / PHASES.length) * 100)}%</span>
          </section>
        )}
        {error && (
          <section className="ai-error" role="alert">
            <ShieldAlert size={24} />
            <div>
              <b>Chưa thể hoàn tất phân tích chuyên sâu</b>
              <p>{error}</p>
            </div>
            {!canUseProAI(plan?.tier) ? (
              <Link href="/account/billing">Xem gói Pro</Link>
            ) : (
              record?.content && (
                <button
                  type="button"
                  onClick={() => void runDeepAnalysis(record)}
                >
                  <RefreshCw size={16} /> Thử lại
                </button>
              )
            )}
          </section>
        )}

        {result && (
          <>
            <section className="ai-summary-band">
              <div
                className={`ai-risk ${risk >= 70 ? "danger" : risk >= 40 ? "warn" : "safe"}`}
              >
                <span>Kết luận rủi ro</span>
                <strong>{displayLevel.icon}</strong>
                <b>{displayLevel.label}</b>
              </div>
              <div>
                <Fingerprint />
                <span>AI Evaluate</span>
                <strong>
                  {result.contextual_analysis?.adapter_id ||
                    result.ai_detection?.model_version ||
                    "Chưa cấu hình"}
                </strong>
                <small>
                  {result.contextual_analysis?.status === "completed"
                    ? `${result.contextual_analysis.scoring_mode === "shadow" ? "Shadow · không đổi điểm" : "Đã đánh giá"}`
                    : `Trạng thái: ${result.contextual_analysis?.status || "không chạy"}`}
                </small>
              </div>
              <div>
                <Activity />
                <span>Dấu vết browser</span>
                <strong>
                  {(sandbox?.behaviors?.length || 0) + redirects.length}
                </strong>
                <small>
                  {sandbox?.network_calls?.length || 0} network request
                </small>
              </div>
              <div>
                <Clock3 />
                <span>Thời gian phân tích</span>
                <strong>
                  {result.analysis_time_ms || sandbox?.analysis_time_ms || 0} ms
                </strong>
                <small>Backend + sandbox cô lập</small>
              </div>
            </section>

            <div className="ai-investigation-grid">
              <section className="ai-visual" aria-labelledby="ai-visual-title">
                <header>
                  <div>
                    <ImageIcon size={20} />
                    <div>
                      <span>ẢNH GHI NHẬN TRỰC TIẾP</span>
                      <h2 id="ai-visual-title">Website trong sandbox</h2>
                    </div>
                  </div>
                  <em>
                    {identity.status_code
                      ? `HTTP ${identity.status_code}`
                      : "Không có HTTP"}
                  </em>
                </header>
                {sandbox?.screenshot_data_url ? (
                  <>
                    <div className="ai-screenshot-frame">
                      <NextImage
                        src={sandbox.screenshot_data_url}
                        width={1280}
                        height={800}
                        unoptimized
                        alt={`Ảnh chụp an toàn của ${identity.page_title || intel?.domain || "website"}`}
                      />
                    </div>
                    <div className="ai-visual-actions">
                      <span>
                        <CheckCircle2 size={14} /> Ảnh JPEG chụp trong browser
                        sandbox cô lập
                      </span>
                      <div>
                        <a
                          href={sandbox.screenshot_data_url}
                          target="_blank"
                          rel="noreferrer"
                        >
                          <ExternalLink size={14} /> Mở ảnh đầy đủ
                        </a>
                        <a
                          href={sandbox.screenshot_data_url}
                          download={screenshotFilename(
                            intel?.domain,
                            identity.final_url || record?.content,
                          )}
                        >
                          <Download size={14} /> Tải ảnh JPG
                        </a>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="ai-no-visual">
                    <ImageIcon size={34} />
                    <b>Không tạo được ảnh chụp</b>
                    <span>
                      {sandbox?.error
                        ? `Sandbox báo lỗi: ${sandbox.error}`
                        : "Website có thể chặn trình duyệt tự động hoặc browser engine chưa khả dụng."}
                    </span>
                  </div>
                )}
                <div className="ai-page-caption">
                  <b>{identity.page_title || "Không đọc được tiêu đề trang"}</b>
                  <p>
                    {identity.description ||
                      "Không có mô tả công khai trong metadata."}
                  </p>
                  <code>{identity.final_url || record?.content}</code>
                </div>
              </section>

              <section
                className="ai-identity"
                aria-labelledby="ai-identity-title"
              >
                <header>
                  <div>
                    <Fingerprint size={20} />
                    <div>
                      <span>NHẬN DIỆN WEBSITE</span>
                      <h2 id="ai-identity-title">Danh tính và đăng ký</h2>
                    </div>
                  </div>
                </header>
                <dl>
                  <div>
                    <dt>
                      <Globe2 /> Domain / tên miền
                    </dt>
                    <dd>{intel?.domain || "Không xác định"}</dd>
                  </div>
                  <div>
                    <dt>
                      <Server /> IP và nhà cung cấp
                    </dt>
                    <dd>
                      {intel?.primary_ip ||
                        intel?.ip_addresses?.join(", ") ||
                        "Không tìm thấy"}
                      <small>
                        {[intel?.asn, intel?.provider, intel?.ip_location]
                          .filter(Boolean)
                          .join(" · ") || "Không có ASN/vị trí công khai"}
                      </small>
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Fingerprint /> Nhà đăng ký / chủ thể
                    </dt>
                    <dd>
                      {intel?.registrar || "Không công khai"}
                      <small>
                        {intel?.registrant ||
                          "Thông tin chủ thể bị ẩn hoặc không công khai"}
                      </small>
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Phone /> Số điện thoại công khai
                    </dt>
                    <dd>
                      {contacts.phones.length
                        ? contacts.phones.join(", ")
                        : "Không tìm thấy / đã ẩn"}
                      <small>
                        WHOIS/RDAP hoặc nội dung hiển thị trên website
                      </small>
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Mail /> Email công khai trên trang
                    </dt>
                    <dd>
                      {contacts.emails.length
                        ? contacts.emails.join(", ")
                        : "Không tìm thấy"}
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Clock3 /> Vòng đời tên miền
                    </dt>
                    <dd>
                      {formatDate(intel?.registered_at)} →{" "}
                      {formatDate(intel?.expires_at)}
                    </dd>
                  </div>
                </dl>
                <div className="ai-source-row">
                  {intel?.sources?.map((source) => (
                    <span
                      className={source.status || "unavailable"}
                      title={source.detail || ""}
                      key={source.source}
                    >
                      <i />
                      {source.source}
                    </span>
                  ))}
                </div>
              </section>
            </div>

            <section className="ai-trace" aria-labelledby="ai-trace-title">
              <header>
                <div>
                  <Network size={20} />
                  <div>
                    <span>LUỒNG TRUY CẬP & TRUY VẾT</span>
                    <h2 id="ai-trace-title">
                      Dấu vết từ URL đầu vào đến trang đích
                    </h2>
                  </div>
                </div>
                <b>
                  {redirects.length} chuyển hướng · {networkHosts.length} máy
                  chủ
                </b>
              </header>
              <div className="ai-trace-flow">
                <article>
                  <i>01</i>
                  <div>
                    <span>URL người dùng nhập</span>
                    <code>{record?.content}</code>
                  </div>
                </article>
                {redirects.map((redirect, index) => (
                  <article key={index}>
                    <i>{String(index + 2).padStart(2, "0")}</i>
                    <div>
                      <span>Chuyển hướng {index + 1}</span>
                      <code>
                        {valueFrom(redirect, [
                          "to_url",
                          "url",
                          "to",
                          "target",
                        ]) || JSON.stringify(redirect).slice(0, 240)}
                      </code>
                    </div>
                  </article>
                ))}
                <article className="destination">
                  <i>{String(redirects.length + 2).padStart(2, "0")}</i>
                  <div>
                    <span>Trang đích trong sandbox</span>
                    <code>{identity.final_url || record?.content}</code>
                  </div>
                  <ExternalLink size={18} />
                </article>
              </div>
              {networkHosts.length > 0 && (
                <div className="ai-network-hosts">
                  <span>Hạ tầng được website gọi tới</span>
                  {networkHosts.map((host) => (
                    <code key={host}>{host}</code>
                  ))}
                </div>
              )}
            </section>

            <div className="ai-investigation-grid lower">
              <section
                className="ai-evidence"
                aria-labelledby="ai-evidence-title"
              >
                <header>
                  <div>
                    <ShieldAlert size={20} />
                    <div>
                      <span>BẰNG CHỨNG AI</span>
                      <h2 id="ai-evidence-title">Tín hiệu quan trọng</h2>
                    </div>
                  </div>
                  <b>{result.evidence?.length || 0}</b>
                </header>
                <div>
                  {(result.evidence || []).slice(0, 10).map((item, index) => (
                    <article key={`${item.feature}-${index}`}>
                      <i className={item.severity || "info"}>
                        {String(index + 1).padStart(2, "0")}
                      </i>
                      <div>
                        <b>
                          {item.feature || item.source || "Tín hiệu nhận diện"}
                        </b>
                        <p>{item.message}</p>
                        <code>{item.source}</code>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
              <section
                className="ai-tech-facts"
                aria-labelledby="ai-tech-title"
              >
                <header>
                  <div>
                    <Server size={20} />
                    <div>
                      <span>HẠ TẦNG KỸ THUẬT</span>
                      <h2 id="ai-tech-title">DNS và bề mặt trang</h2>
                    </div>
                  </div>
                </header>
                <dl>
                  <div>
                    <dt>Nameserver</dt>
                    <dd>
                      {intel?.nameservers?.join(", ") || "Không tìm thấy"}
                    </dd>
                  </div>
                  <div>
                    <dt>Mail server (MX)</dt>
                    <dd>{intel?.mx_records?.join(", ") || "Không tìm thấy"}</dd>
                  </div>
                  <div>
                    <dt>Canonical URL</dt>
                    <dd>{identity.canonical_url || "Không khai báo"}</dd>
                  </div>
                  <div>
                    <dt>Ngôn ngữ</dt>
                    <dd>{identity.language || "Không khai báo"}</dd>
                  </div>
                  <div>
                    <dt>Biểu mẫu / ô mật khẩu</dt>
                    <dd>
                      {identity.forms || 0} / {identity.password_fields || 0}
                    </dd>
                  </div>
                  <div>
                    <dt>Script / DOM mutation</dt>
                    <dd>
                      {sandbox?.scripts_executed?.length || 0} /{" "}
                      {sandbox?.dom_modifications?.length || 0}
                    </dd>
                  </div>
                </dl>
              </section>
            </div>
          </>
        )}
        <footer className="ai-investigation-foot">
          <p>
            Kết quả là bằng chứng hỗ trợ điều tra, không khẳng định danh tính
            pháp lý khi nguồn đăng ký bị ẩn.
          </p>
          <Link href="/analyze">Phân tích URL khác</Link>
        </footer>
      </main>
    </PrewiseShell>
  );
}

export default function AiAnalysisPage(): JSX.Element {
  return <AiAnalysisContent />;
}
