import type { Metadata } from "next";
import Script from "next/script";
import "./globals.css";
import "./witness.css";
import "./threat-effects.css";
import "./phish-effects.css";
import "./phish-visibility.css";
import "./alarm-effects.css";
import "./footer.css";
import "./scroll-fix.css";
import "./organic-eye.css";
import "./eye-v2.css";
import "./hero-cta.css";
import "./evidence-effects.css";
import "./gaze-safe.css";
import "./sandbox-session.css";
import "./landing-readability-step-1.css";
import "./app-readability-step-2.css";
import "./mobile-foundation.css";
import { AuthProvider } from "@/context/AuthContext";
import { LanguageProvider } from "@/context/LanguageContext";
import AppChrome from "@/components/AppChrome";

export const metadata: Metadata = {
  metadataBase: new URL("https://prewise.site"),
  title: { default: "Prewise — Thấy rõ rủi ro trước khi quá muộn", template: "%s · Prewise" },
  description: "Phân tích website, email và tin nhắn để phát hiện dấu hiệu lừa đảo, giả mạo và dữ liệu nhạy cảm.",
  applicationName: "Prewise",
  authors: [{ name: "Nguyễn Duy Thuận" }, { name: "Trần Đình Bảo Khang" }],
  keywords: ["Prewise", "phishing detection", "scam detection", "AI security", "an toàn trực tuyến"],
  openGraph: { type: "website", locale: "vi_VN", alternateLocale: "en_US", siteName: "Prewise", title: "Prewise — See the risk before it is too late", description: "Explainable scam analysis for websites, emails and messages." },
  robots: { index: true, follow: true },
};
export default function RootLayout({children}:{children:React.ReactNode}) {return <html lang="vi" suppressHydrationWarning><body suppressHydrationWarning><Script id="prewise-chunk-recovery" strategy="beforeInteractive">{`(() => {
  const marker = "__chunk_retry";
  const retryKey = "prewise:chunk-retry:" + location.pathname;
  const isChunkFailure = (value) => /ChunkLoadError|Loading chunk .* failed|\\/_next\\/static\\/chunks\\//i.test(String(value || ""));
  const retry = (value) => {
    if (!isChunkFailure(value)) return;
    let recent = false;
    try {
      const previous = Number(sessionStorage.getItem(retryKey) || 0);
      recent = Date.now() - previous < 60000;
      if (!recent) sessionStorage.setItem(retryKey, String(Date.now()));
    } catch {}
    if (recent) return;
    const next = new URL(location.href);
    next.searchParams.set(marker, String(Date.now()));
    location.replace(next.toString());
  };
  addEventListener("error", (event) => retry(event.message || event.filename));
  addEventListener("unhandledrejection", (event) => retry(event.reason?.stack || event.reason));
  if (new URL(location.href).searchParams.has(marker)) {
    addEventListener("load", () => setTimeout(() => {
      const clean = new URL(location.href);
      clean.searchParams.delete(marker);
      history.replaceState(null, "", clean.toString());
      try { sessionStorage.removeItem(retryKey); } catch {}
    }, 5000), { once: true });
  }
})();`}</Script><LanguageProvider><AuthProvider><AppChrome>{children}</AppChrome></AuthProvider></LanguageProvider></body></html>}
