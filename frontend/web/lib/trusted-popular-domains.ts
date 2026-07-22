import type { AssessResult } from "@/lib/types";

export const TRUSTED_POPULAR_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "x.com",
    "twitter.com", "wikipedia.org", "reddit.com", "amazon.com", "yahoo.com",
    "bing.com", "microsoft.com", "apple.com", "linkedin.com", "netflix.com",
    "office.com", "live.com", "github.com", "stackoverflow.com", "tiktok.com",
    "whatsapp.com", "telegram.org", "discord.com", "twitch.tv", "spotify.com",
    "pinterest.com", "imdb.com", "ebay.com", "paypal.com", "adobe.com",
    "dropbox.com", "zoom.us", "slack.com", "notion.so", "canva.com",
    "cloudflare.com", "openai.com", "chatgpt.com", "claude.ai", "gemini.google.com",
    "drive.google.com", "docs.google.com", "mail.google.com", "maps.google.com", "news.google.com",
    "meet.google.com", "calendar.google.com", "translate.google.com", "play.google.com", "photos.google.com",
    "outlook.com", "onedrive.com", "teams.microsoft.com", "azure.com", "microsoftonline.com",
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "forbes.com", "bloomberg.com", "medium.com", "quora.com", "tumblr.com",
    "wordpress.com", "blogger.com", "w3.org", "mozilla.org", "npmjs.com",
    "docker.com", "gitlab.com", "bitbucket.org", "atlassian.com", "figma.com",
    "salesforce.com", "shopify.com", "walmart.com", "target.com", "booking.com",
    "airbnb.com", "tripadvisor.com", "expedia.com", "uber.com", "grab.com",
    "baidu.com", "qq.com", "weibo.com", "yandex.com", "naver.com",
    "samsung.com", "intel.com", "nvidia.com", "amd.com", "dell.com",
    "hp.com", "lenovo.com", "tiktokshop.com", "shopee.vn", "lazada.vn",
] as const;

export function trustedPopularDomain(input: string): string | null {
    try {
        const url = new URL(input);
        if (url.protocol !== "http:" && url.protocol !== "https:") return null;
        const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
        return TRUSTED_POPULAR_DOMAINS.find(
            (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
        ) ?? null;
    } catch {
        return null;
    }
}

export function trustedPopularResult(input: string): AssessResult | null {
    const domain = trustedPopularDomain(input);
    if (!domain) return null;
    const reason = `${domain} nằm trong danh sách 100 dịch vụ phổ biến được tin cậy sẵn.`;
    return {
        score: 0,
        riskLevel: "safe",
        confidence: 1,
        reasons: [reason],
        evidence: [{
            source: "trusted_popular_domains",
            message: reason,
            severity: "info",
            feature: "popular_domain_policy",
        }],
        explanation: "Kết quả được trả trực tiếp theo chính sách tên miền phổ biến; hệ thống không truy xét độ an toàn của URL này.",
        modality: "url",
        modelVersion: "trusted-popular-domains-v1",
        latencyMs: 0,
        requestId: globalThis.crypto?.randomUUID?.() ?? `trusted-${Date.now()}`,
    };
}
