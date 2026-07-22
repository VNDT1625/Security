"""Product-policy allowlist for popular web services.

These domains intentionally bypass URL intelligence and model evaluation.  Keep
matching label-aware so lookalikes such as ``youtube.com.attacker.example`` do
not inherit an allowlisted verdict.
"""

from __future__ import annotations

from urllib.parse import urlsplit
from uuid import uuid4

from shared.schemas import AssessResponse, Decision, Evidence, Modality, RiskLevel, Severity


TRUSTED_POPULAR_DOMAINS: tuple[str, ...] = (
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
)


def trusted_popular_domain(url: str) -> str | None:
    """Return the matching policy domain for an HTTP(S) URL, if any."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return None
    return next(
        (
            domain
            for domain in TRUSTED_POPULAR_DOMAINS
            if hostname == domain or hostname.endswith(f".{domain}")
        ),
        None,
    )


def trusted_popular_assessment(url: str) -> AssessResponse | None:
    """Build the shared zero-latency policy verdict without scanning the URL."""
    domain = trusted_popular_domain(url)
    if domain is None:
        return None
    reason = f"{domain} nằm trong danh sách 100 dịch vụ phổ biến được tin cậy sẵn."
    return AssessResponse(
        risk_score=0.0,
        risk_level=RiskLevel.SAFE,
        decision=Decision.ALLOW,
        confidence=1.0,
        modality=Modality.URL,
        reasons=[reason],
        evidence=[Evidence(
            source="trusted_popular_domains",
            message=reason,
            severity=Severity.INFO,
            feature="popular_domain_policy",
        )],
        explanation="Kết quả được trả trực tiếp theo chính sách tên miền phổ biến; hệ thống không truy xét độ an toàn của URL này.",
        recommended_agent_behavior="Cho phép tiếp tục theo chính sách tên miền phổ biến.",
        model_version="trusted-popular-domains-v1",
        latency_ms=0.0,
        request_id=str(uuid4()),
        raw_score=0.0,
        final_score=0.0,
        cache_hit=True,
        cache_status="hit",
    )
