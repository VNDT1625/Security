"""Popular-domain lookup used as supporting evidence, never as a score bypass."""

from __future__ import annotations

from urllib.parse import urlsplit

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

# Platforms that hand out subdomains to arbitrary users. The organisation is
# trustworthy, but ``attacker.wordpress.com`` is not: it is attacker-controlled
# content on a trusted parent. For these, only the apex and ``www`` skip the
# engine; every other label is scanned normally.
USER_CONTENT_PARENT_DOMAINS: frozenset[str] = frozenset(
    {
        "wordpress.com",
        "blogger.com",
        "blogspot.com",
        "tumblr.com",
        "medium.com",
        "shopify.com",
        "myshopify.com",
        "notion.so",
        "weebly.com",
        "wixsite.com",
        "github.io",
        "pages.dev",
        "web.app",
        "firebaseapp.com",
        "glitch.me",
        "repl.co",
        "vercel.app",
        "netlify.app",
    }
)

# Query parameters that carry a second URL. A trusted host used as an open
# redirector (``google.com/url?q=...``) is a real phishing delivery path, so a
# URL carrying a nested absolute URL is never short-circuited.
_NESTED_URL_MARKERS = ("http://", "https://", "%3a%2f%2f")


def _has_nested_url(parsed) -> bool:
    haystack = f"{parsed.query}?{parsed.fragment}".lower()
    return any(marker in haystack for marker in _NESTED_URL_MARKERS)


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
    if _has_nested_url(parsed):
        return None
    for domain in TRUSTED_POPULAR_DOMAINS:
        if hostname == domain:
            return domain
        if not hostname.endswith(f".{domain}"):
            continue
        if domain in USER_CONTENT_PARENT_DOMAINS:
            # Only "www" is the platform itself; anything else is user content.
            if hostname == f"www.{domain}":
                return domain
            continue
        return domain
    return None
