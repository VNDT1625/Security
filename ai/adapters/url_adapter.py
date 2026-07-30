"""URL Risk Adapter — lexical feature extraction (module-specification.md M1).

Extracts a 15-dimensional feature vector from a raw URL and detects phishing signals
(homoglyph, risky TLD, IP host, suspicious keywords). Pure-Python + stdlib only, so it
runs without numpy; the ML training scripts consume the same feature order.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qs, parse_qsl, unquote, urlparse

from shared.constants import HIGH_RISK_TLDS, KNOWN_BRANDS

# Single source of truth for URL shorteners. The message risk core imports this
# set too: the two used to maintain divergent lists, so the same shortened link
# was a signal in an email but invisible to URL criterion 17, and vice versa.
SHORTLINK_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "t.ly",
    "tiny.cc",
    "tinyurl.com",
    "v.gd",
}

# Shared hosting is not malicious by itself.  Attackers do, however, abuse these
# services to make a brand-looking subdomain appear trustworthy.  The risk core
# only scores this signal when a credential lure, impersonation, or disguised
# download is present as well.
SHARED_HOSTING_SUFFIXES = {
    "workers.dev",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "vercel.app",
    "netlify.app",
    "github.io",
    "gitlab.io",
    "azurewebsites.net",
    "onrender.com",
    "ngrok-free.app",
    "trycloudflare.com",
}

DANGEROUS_DOWNLOAD_EXTENSIONS = {
    "apk", "bat", "cmd", "com", "dll", "dmg", "exe", "hta", "img", "iso",
    "jar", "js", "jse", "lnk", "msi", "pkg", "ps1", "scr", "vbe", "vbs", "wsf",
}
ARCHIVE_EXTENSIONS = {"7z", "gz", "rar", "tar", "zip"}
DOCUMENT_EXTENSIONS = {
    "csv", "doc", "docx", "jpeg", "jpg", "pdf", "png", "ppt", "pptx", "rtf",
    "txt", "xls", "xlsx",
}
DOWNLOAD_LURE_TERMS = {
    "cv", "delivery", "document", "hoadon", "hoso", "invoice", "order", "quotation",
    "receipt", "report", "resume", "shipment", "ungvien",
}
SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "signin",
    "password",
    "otp",
    "bank",
    "gift",
    "free",
    "wallet",
    "bonus",
    "prize",
    "claim",
    "reward",
    "unlock",
    "payment",
    "billing",
    "card",
    "cccd",
    "dangnhap",
    "dang-nhap",
    "xacminh",
    "xac-minh",
    "taikhoan",
    "tai-khoan",
    "thanhtoan",
    "thanh-toan",
    "mokhoa",
    "mo-khoa",
    "giaohang",
    "giao-hang",
    "redelivery",
    "toll",
)

MULTI_PART_PUBLIC_SUFFIXES = {
    "ac.vn",
    "biz.vn",
    "com.vn",
    "edu.vn",
    "gov.vn",
    "health.vn",
    "info.vn",
    "int.vn",
    "name.vn",
    "net.vn",
    "org.vn",
    "pro.vn",
    "co.uk",
    "org.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.kr",
    "com.br",
    "com.sg",
    "com.my",
    "com.hk",
    "com.cn",
    "com.tw",
    "co.id",
    "co.th",
    "co.in",
    "co.nz",
    "co.za",
    "co.il",
    "co.ke",
    "co.tz",
    "co.ug",
    "com.ar",
    "com.bd",
    "com.co",
    "com.ec",
    "com.mx",
    "com.ng",
    "com.pe",
    "com.ph",
    "com.pk",
    "com.sa",
    "com.tr",
    "com.ua",
}

BRAND_CANONICAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "facebook": ("facebook.com", "fb.com"),
    "google": ("google.com",),
    "apple": ("apple.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
    "amazon": ("amazon.com",),
    "vietcombank": ("vietcombank.com.vn",),
    "techcombank": ("techcombank.com.vn",),
    "mbbank": ("mbbank.com.vn",),
    "tpbank": ("tpbank.com.vn", "tpb.vn"),
    "bidv": ("bidv.com.vn",),
    "agribank": ("agribank.com.vn",),
    "vietinbank": ("vietinbank.vn",),
    "vpbank": ("vpbank.com.vn",),
    "sacombank": ("sacombank.com.vn",),
    "hdbank": ("hdbank.com.vn",),
    "seabank": ("seabank.com.vn",),
    "netflix": ("netflix.com",),
    "instagram": ("instagram.com",),
    "shopee": ("shopee.vn", "shopee.com"),
    "tiki": ("tiki.vn",),
    "zalo": ("zalo.me", "zalo.vn"),
    "momo": ("momo.vn",),
    "zalopay": ("zalopay.vn",),
    "vnpost": ("vnpost.vn",),
    "viettelpost": ("viettelpost.com.vn",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "vneid": ("vneid.gov.vn",),
    "dichvucong": ("dichvucong.gov.vn",),
    "vcb": ("vietcombank.com.vn",),
    "acb": ("acb.com.vn",),
    "vib": ("vib.com.vn",),
    "msb": ("msb.com.vn",),
    "ocb": ("ocb.com.vn",),
    "ghn": ("ghn.vn",),
    "ghtk": ("ghtk.vn",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
}

# Common Cyrillic/Greek characters used to make an IDN label look like an
# ASCII brand.  This is deliberately a small visual-confusable map, not a
# transliterator: unrelated internationalized domains must not become brands.
_CONFUSABLE_TO_ASCII = str.maketrans({
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h",
    "і": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "о": "o",
    "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x",
    "Α": "a", "α": "a", "Β": "b", "β": "b", "Ε": "e", "ε": "e",
    "Ι": "i", "ι": "i", "Κ": "k", "κ": "k", "Ν": "n", "ν": "v",
    "Ο": "o", "ο": "o", "Ρ": "p", "ρ": "p", "Τ": "t", "τ": "t",
    "Υ": "y", "υ": "y", "Χ": "x", "χ": "x",
})

_BRAND_COMBO_AFFIXES = {
    "account", "auth", "bank", "billing", "card", "customer", "id", "login",
    "online", "official", "pay", "payment", "secure", "security", "service",
    "signin", "support", "update", "verify", "wallet",
}

LEGACY_FEATURE_NAMES = (
    "url_length", "domain_entropy", "subdomain_depth", "tld_risk_score",
    "has_ip_address", "special_char_ratio", "path_depth", "query_param_count",
    "has_https", "homoglyph_score", "is_shortlink", "digit_ratio",
    "vowel_consonant_ratio", "url_path_entropy", "has_suspicious_keywords",
)

STATIC_FEATURE_NAMES = LEGACY_FEATURE_NAMES + (
    "host_length",
    "registrable_domain_length",
    "path_length",
    "query_length",
    "fragment_length",
    "url_entropy",
    "host_entropy",
    "query_entropy",
    "hyphen_count",
    "dot_count",
    "slash_count",
    "at_count",
    "percent_count",
    "equals_count",
    "ampersand_count",
    "underscore_count",
    "digit_count",
    "letter_count",
    "non_ascii_count",
    "punycode_label_count",
    "subdomain_label_count",
    "max_label_length",
    "average_label_length",
    "suspicious_keyword_count",
    "brand_mention_count",
    "brand_mismatch",
    "brand_in_subdomain",
    "deceptive_subdomain",
    "excessive_dots",
    "many_delimiters",
    "percent_encoded",
    "has_at_symbol",
    "has_nonstandard_port",
    "embedded_credentials",
    "nested_url_count",
    "redirect_param_count",
    "dangerous_file_extension",
    "disguised_download",
    "archive_lure",
    "shared_hosting",
    "max_repeated_character_run",
    "max_consecutive_digit_run",
    "hex_token_count",
    "base64_like_token_count",
    "path_token_count",
    "query_key_count",
    "duplicate_query_key_count",
    "parameter_value_entropy",
    "scheme_is_http",
    "scheme_was_missing",
)

CONTEXT_FEATURE_NAMES = (
    "dns_available",
    "dns_resolves",
    "dns_record_count",
    "rdap_available",
    "domain_age_days_normalized",
    "tls_available",
    "tls_present",
    "tls_hostname_match",
    "tls_days_remaining_normalized",
    "redirect_available",
    "redirect_count_normalized",
    "cross_domain_redirect_count",
    "final_domain_changed",
    "dom_available",
    "login_form_present",
    "password_form_present",
    "external_form_present",
    "hidden_iframe_present",
    "script_count_normalized",
    "visual_hash_available",
    "visual_brand_similarity",
    "local_feed_checked",
    "local_feed_hit",
)

# Context values have explicit availability flags, so an unavailable collector is
# never confused with a verified clean result.
FEATURE_NAMES = STATIC_FEATURE_NAMES + CONTEXT_FEATURE_NAMES


@dataclass(frozen=True)
class URLParts:
    normalized_url: str
    host: str
    domain_label: str
    registrable_domain: str
    subdomain: str
    suffix: str


@dataclass(frozen=True)
class URLSignals:
    parts: URLParts
    brand_mentions: tuple[str, ...]
    brand_mismatch: bool
    brand_in_subdomain: bool
    deceptive_subdomain: bool
    suspicious_keywords: tuple[str, ...]
    long_url: bool
    many_delimiters: bool
    excessive_dots: bool
    percent_encoded: bool
    at_symbol: bool
    risky_tld: bool
    ip_host: bool
    no_https: bool
    shortlink: bool
    homoglyph: bool
    path_depth: int
    query_param_count: int
    delimiter_count: int
    shared_hosting: bool
    dangerous_download: bool
    disguised_download: bool
    archive_lure: bool


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _decode_idna_host(host: str) -> str:
    """Decode ASCII IDNA labels without rejecting ordinary Unicode hosts."""
    decoded: list[str] = []
    for label in host.strip(".").split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, UnicodeDecodeError):
                pass
        decoded.append(label)
    return ".".join(decoded).casefold()


def _brand_skeleton(text: str) -> str:
    """Fold brand-like visual confusables while preserving label delimiters."""
    decoded = _decode_idna_host(text)
    decomposed = unicodedata.normalize("NFKD", decoded)
    without_marks = "".join(
        char for char in decomposed if unicodedata.category(char) != "Mn"
    )
    return without_marks.translate(_CONFUSABLE_TO_ASCII).translate(_DIGIT_TO_LETTER)


def min_brand_distance(domain: str) -> float:
    """Normalized min edit distance to any known brand (lower = more suspicious)."""
    if not domain:
        return 1.0
    brands = tuple(dict.fromkeys((*KNOWN_BRANDS, *BRAND_CANONICAL_DOMAINS.keys())))
    # Compare both the full label and hyphen/underscore-delimited tokens.  Without
    # this, a typo such as ``viettcombank-login`` looks far away from
    # ``vietcombank`` merely because the attacker appended a lure word.
    candidates = tuple(
        dict.fromkeys(
            candidate
            for candidate in (
                _brand_skeleton(domain),
                *re.split(r"[-_]+", _brand_skeleton(domain)),
            )
            if candidate
        )
    )
    dists = [
        levenshtein(candidate, brand) / max(len(candidate), len(brand))
        for candidate in candidates
        for brand in brands
    ]
    return min(dists)


def _registered_domain(host: str) -> str:
    """Best-effort registrable domain without tldextract."""
    return parse_url_parts(host).registrable_domain


def _normalize_for_urlparse(url: str) -> str:
    """Normalize URL for urlparse, handling edge cases."""
    url = url.strip()
    # Analysts and users often paste defanged indicators.  Refang only the URL
    # syntax for offline parsing; this function never performs a network request.
    url = re.sub(r"^hxxps://", "https://", url, flags=re.I)
    url = re.sub(r"^hxxp://", "http://", url, flags=re.I)
    url = re.sub(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}", ".", url, flags=re.I)
    # Handle IPv6 URLs by ensuring they're properly formatted
    if '[' in url and ']' in url:
        # Already has IPv6 brackets
        if '://' not in url:
            return f"http://{url}"
        return url
    # Regular URL normalization
    return url if "://" in url else f"http://{url}"


def parse_url_parts(url: str) -> URLParts:
    """Return host/subdomain/registrable-domain pieces used by URL rules."""
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    try:
        normalized = _normalize_for_urlparse(url.strip()[:2048])
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").strip(".").lower()
        if not host:
            raise ValueError("URL must include a host")
        if is_ip_host(normalized):
            return URLParts(
                normalized_url=normalized,
                host=host,
                domain_label=host,
                registrable_domain=host,
                subdomain="",
                suffix="",
            )
    except Exception as e:
        # Handle malformed URLs gracefully
        raise ValueError(f"Cannot parse URL: {e}") from e

    labels = [label for label in host.split(".") if label]
    if len(labels) == 1:
        return URLParts(
            normalized_url=normalized,
            host=host,
            domain_label=labels[0],
            registrable_domain=labels[0],
            subdomain="",
            suffix="",
        )

    # Treat known platform tenant suffixes (for example ``github.io``) as an
    # effective public suffix too.  The tenant label is the accountable domain,
    # not the platform operator's domain.
    effective_suffixes = MULTI_PART_PUBLIC_SUFFIXES | SHARED_HOSTING_SUFFIXES
    matched_suffix = next(
        (
            candidate
            for candidate in sorted(
                effective_suffixes,
                key=lambda item: (item.count("."), len(item)),
                reverse=True,
            )
            if host.endswith("." + candidate)
        ),
        "",
    )
    if matched_suffix:
        suffix_labels = len(matched_suffix.split("."))
        domain_index = -(suffix_labels + 1)
    else:
        suffix_labels = 1
        domain_index = -2

    domain_label = labels[domain_index]
    suffix = ".".join(labels[-suffix_labels:])
    registrable_domain = ".".join(labels[domain_index:])
    subdomain_labels = labels[:domain_index]
    return URLParts(
        normalized_url=normalized,
        host=host,
        domain_label=domain_label,
        registrable_domain=registrable_domain,
        subdomain=".".join(subdomain_labels),
        suffix=suffix,
    )


def _split_host(url: str) -> tuple[str, str, str]:
    parts = parse_url_parts(url)
    return parts.host, parts.domain_label, parts.subdomain + "|" + parts.suffix


# Map look-alike digits back to the letters they impersonate.
_DIGIT_TO_LETTER = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def has_homoglyph(url: str) -> bool:
    parts = parse_url_parts(url)
    decoded_domain = _decode_idna_host(parts.domain_label)
    skeleton = _brand_skeleton(parts.domain_label)
    was_visually_folded = skeleton != unicodedata.normalize("NFKD", decoded_domain)
    if not was_visually_folded:
        return False
    # A non-ASCII or digit-bearing label is a brand homoglyph only when folding
    # it produces an actual/near brand.  This avoids flagging every legitimate
    # internationalized domain merely because it uses Unicode.
    return bool(_brand_mentions(skeleton)) or min_brand_distance(skeleton) <= 0.20


def is_ip_host(url: str) -> bool:
    """Check if URL uses an IP address (IPv4 or IPv6) instead of domain name."""
    try:
        parsed = urlparse(_normalize_for_urlparse(url))
        host = (parsed.hostname or "").lower()
        # IPv4 pattern
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return True
        # IPv6 pattern (simplified check)
        if ":" in host and not host.startswith("["):
            return True
        return False
    except Exception:
        return False


def _brand_names() -> tuple[str, ...]:
    return tuple(dict.fromkeys((*KNOWN_BRANDS, *BRAND_CANONICAL_DOMAINS.keys())))


def _brand_mentions(text: str) -> tuple[str, ...]:
    labels = [label for label in _brand_skeleton(text).split(".") if label]
    mentions = []
    for brand in _brand_names():
        matched = False
        for label in labels:
            tokens = [token for token in re.split(r"[-_]+", label) if token]
            if brand in tokens:
                matched = True
                break
            if len(brand) > 4 and any(
                (token.startswith(brand) and token[len(brand):] in _BRAND_COMBO_AFFIXES)
                or (token.endswith(brand) and token[:-len(brand)] in _BRAND_COMBO_AFFIXES)
                for token in tokens
            ):
                matched = True
                break
        if matched:
            mentions.append(brand)
    return tuple(mentions)


def _brand_domain_allowed(brand: str, host: str, registrable_domain: str) -> bool:
    allowed = BRAND_CANONICAL_DOMAINS.get(brand, (f"{brand}.com",))
    ascii_host = host.encode("idna").decode("ascii").lower()
    ascii_registrable = registrable_domain.encode("idna").decode("ascii").lower()
    return any(
        ascii_registrable == domain
        or ascii_host == domain
        or ascii_host.endswith("." + domain)
        for domain in allowed
    )


def analyze_url_signals(url: str) -> URLSignals:
    """Extract explainable phishing signals from the URL string itself.

    This complements the fixed 15-value ML feature vector. It is intentionally
    pure-stdlib and does not fetch the webpage.
    """
    parts = parse_url_parts(url)
    parsed = urlparse(parts.normalized_url)
    decoded_url = unquote(parts.normalized_url).lower()
    decoded_host = _decode_idna_host(unquote(parts.host))
    brand_host = _brand_skeleton(decoded_host)
    path = parsed.path or ""
    query = parsed.query or ""
    query_param_count = len(parse_qs(query))
    path_depth = len([p for p in path.split("/") if p])
    delimiter_count = sum(parts.normalized_url.count(ch) for ch in ("-", "_", "%", "@", "?", "="))
    mentions = _brand_mentions(brand_host)
    brand_mismatch = any(
        not _brand_domain_allowed(brand, parts.host, parts.registrable_domain)
        for brand in mentions
    )
    brand_subdomain = _brand_skeleton(parts.subdomain)
    brand_in_subdomain = any(
        brand in re.split(r"[.\-_]+", brand_subdomain)
        for brand in mentions
    )
    subdomain_labels = [label for label in parts.subdomain.split(".") if label]
    deceptive_subdomain = (
        brand_in_subdomain
        or any(label in {"com", "vn", "net", "org", "security", "secure", "login"}
               for label in subdomain_labels)
    ) and brand_mismatch
    keywords = tuple(k for k in SUSPICIOUS_KEYWORDS if k in decoded_url)
    decoded_path = unquote(path).lower()
    filename = decoded_path.rsplit("/", 1)[-1]
    filename_parts = [part for part in filename.split(".") if part]
    final_extension = filename_parts[-1] if len(filename_parts) >= 2 else ""
    previous_extension = filename_parts[-2] if len(filename_parts) >= 3 else ""
    dangerous_download = final_extension in DANGEROUS_DOWNLOAD_EXTENSIONS
    disguised_download = dangerous_download and previous_extension in DOCUMENT_EXTENSIONS
    lure_context = any(term in decoded_url for term in DOWNLOAD_LURE_TERMS)
    archive_lure = final_extension in ARCHIVE_EXTENSIONS and (
        lure_context or previous_extension in DOCUMENT_EXTENSIONS
    )
    shared_hosting = any(
        parts.host == suffix or parts.host.endswith("." + suffix)
        for suffix in SHARED_HOSTING_SUFFIXES
    )

    return URLSignals(
        parts=parts,
        brand_mentions=mentions,
        brand_mismatch=brand_mismatch,
        brand_in_subdomain=brand_in_subdomain,
        deceptive_subdomain=deceptive_subdomain,
        suspicious_keywords=keywords,
        long_url=len(parts.normalized_url) >= 100,
        many_delimiters=delimiter_count >= 5,
        excessive_dots=parts.host.count(".") >= 3,
        percent_encoded="%" in parts.normalized_url,
        at_symbol="@" in parts.normalized_url,
        risky_tld=parts.suffix.split(".")[-1] in HIGH_RISK_TLDS,
        ip_host=is_ip_host(parts.normalized_url),
        no_https=parsed.scheme != "https",
        shortlink=parts.host in SHORTLINK_DOMAINS,
        homoglyph=has_homoglyph(parts.normalized_url),
        path_depth=path_depth,
        query_param_count=query_param_count,
        delimiter_count=delimiter_count,
        shared_hosting=shared_hosting,
        dangerous_download=dangerous_download,
        disguised_download=disguised_download,
        archive_lure=archive_lure,
    )


def _max_repeated_run(text: str) -> int:
    longest = current = 0
    previous = ""
    for char in text:
        current = current + 1 if char == previous else 1
        longest = max(longest, current)
        previous = char
    return longest


def _context_number(context: dict[str, object], name: str, default: float = 0.0) -> float:
    try:
        return float(context.get(name, default) or 0.0)
    except (TypeError, ValueError):
        return default


def extract_url_feature_map(
    url: str,
    context: dict[str, object] | None = None,
) -> dict[str, float]:
    """Return the complete named URL and enrichment feature map."""
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    raw_url = url.strip()[:2048]
    normalized_url = _normalize_for_urlparse(raw_url)
    parsed = urlparse(normalized_url)
    host, domain, sub_tld = _split_host(raw_url)
    subdomain, tld = (sub_tld.split("|", 1) + [""])[:2]
    path = parsed.path or ""
    query = parsed.query or ""
    signals = analyze_url_signals(raw_url)
    labels = [label for label in host.split(".") if label]
    pairs = parse_qsl(query, keep_blank_values=True)
    query_keys = [key.lower() for key, _ in pairs]
    redirect_keys = {
        "url", "uri", "redirect", "redirect_uri", "return", "return_url",
        "next", "continue", "target", "destination", "dest",
    }
    decoded = unquote(normalized_url).lower()
    nested_urls = max(
        0,
        len(re.findall(r"(?:https?://|https?%3a%2f%2f)", normalized_url, flags=re.I)) - 1,
    )
    path_tokens = [token for token in re.split(r"[/._~-]+", path) if token]
    all_tokens = [token for token in re.split(r"[^a-zA-Z0-9+/=_-]+", decoded) if token]
    parameter_values = "".join(value for _, value in pairs)
    context = context or {}
    domain_age_days = max(0.0, _context_number(context, "domain_age_days"))
    tls_days_remaining = max(0.0, _context_number(context, "tls_days_remaining"))
    vowels = sum(1 for c in domain if c in "aeiou")
    cons = sum(1 for c in domain if c.isalpha() and c not in "aeiou")

    return {
        "url_length": float(min(len(raw_url), 2048)),
        "domain_entropy": shannon_entropy(domain),
        "subdomain_depth": float(len(subdomain.split(".")) if subdomain else 0),
        "tld_risk_score": 1.0 if tld in HIGH_RISK_TLDS else 0.0,
        "has_ip_address": 1.0 if is_ip_host(raw_url) else 0.0,
        "special_char_ratio": sum(1 for char in domain if char in "@-_") / max(len(domain), 1),
        "path_depth": float(len([part for part in path.split("/") if part])),
        "query_param_count": float(len(parse_qs(query))),
        "has_https": 1.0 if parsed.scheme == "https" else 0.0,
        "homoglyph_score": min_brand_distance(domain),
        "is_shortlink": 1.0 if host in SHORTLINK_DOMAINS else 0.0,
        "digit_ratio": sum(1 for char in domain if char.isdigit()) / max(len(domain), 1),
        "vowel_consonant_ratio": vowels / max(cons, 1),
        "url_path_entropy": shannon_entropy(path),
        "has_suspicious_keywords": 1.0
        if any(keyword in path.lower() for keyword in SUSPICIOUS_KEYWORDS)
        else 0.0,
        "host_length": float(len(host)),
        "registrable_domain_length": float(len(signals.parts.registrable_domain)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "fragment_length": float(len(parsed.fragment or "")),
        "url_entropy": shannon_entropy(decoded),
        "host_entropy": shannon_entropy(host),
        "query_entropy": shannon_entropy(query),
        "hyphen_count": float(raw_url.count("-")),
        "dot_count": float(raw_url.count(".")),
        "slash_count": float(raw_url.count("/")),
        "at_count": float(raw_url.count("@")),
        "percent_count": float(raw_url.count("%")),
        "equals_count": float(raw_url.count("=")),
        "ampersand_count": float(raw_url.count("&")),
        "underscore_count": float(raw_url.count("_")),
        "digit_count": float(sum(char.isdigit() for char in raw_url)),
        "letter_count": float(sum(char.isalpha() for char in raw_url)),
        "non_ascii_count": float(sum(ord(char) > 127 for char in raw_url)),
        "punycode_label_count": float(sum(label.startswith("xn--") for label in labels)),
        "subdomain_label_count": float(len([label for label in subdomain.split(".") if label])),
        "max_label_length": float(max((len(label) for label in labels), default=0)),
        "average_label_length": sum(map(len, labels)) / max(len(labels), 1),
        "suspicious_keyword_count": float(len(signals.suspicious_keywords)),
        "brand_mention_count": float(len(signals.brand_mentions)),
        "brand_mismatch": float(signals.brand_mismatch),
        "brand_in_subdomain": float(signals.brand_in_subdomain),
        "deceptive_subdomain": float(signals.deceptive_subdomain),
        "excessive_dots": float(signals.excessive_dots),
        "many_delimiters": float(signals.many_delimiters),
        "percent_encoded": float(signals.percent_encoded),
        "has_at_symbol": float(signals.at_symbol),
        "has_nonstandard_port": float(parsed.port not in {None, 80, 443}),
        "embedded_credentials": float(bool(parsed.username or parsed.password)),
        "nested_url_count": float(nested_urls),
        "redirect_param_count": float(sum(key in redirect_keys for key in query_keys)),
        "dangerous_file_extension": float(signals.dangerous_download),
        "disguised_download": float(signals.disguised_download),
        "archive_lure": float(signals.archive_lure),
        "shared_hosting": float(signals.shared_hosting),
        "max_repeated_character_run": float(_max_repeated_run(domain)),
        "max_consecutive_digit_run": float(
            max((len(match.group(0)) for match in re.finditer(r"\d+", domain)), default=0)
        ),
        "hex_token_count": float(
            sum(bool(re.fullmatch(r"[0-9a-fA-F]{8,}", token)) for token in all_tokens)
        ),
        "base64_like_token_count": float(
            sum(bool(re.fullmatch(r"[A-Za-z0-9_-]{20,}={0,2}", token)) for token in all_tokens)
        ),
        "path_token_count": float(len(path_tokens)),
        "query_key_count": float(len(query_keys)),
        "duplicate_query_key_count": float(len(query_keys) - len(set(query_keys))),
        "parameter_value_entropy": shannon_entropy(parameter_values),
        "scheme_is_http": float(parsed.scheme == "http"),
        "scheme_was_missing": float("://" not in raw_url),
        "dns_available": _context_number(context, "dns_available"),
        "dns_resolves": _context_number(context, "dns_resolves"),
        "dns_record_count": min(_context_number(context, "dns_record_count"), 50.0) / 50.0,
        "rdap_available": _context_number(context, "rdap_available"),
        "domain_age_days_normalized": min(domain_age_days, 3650.0) / 3650.0,
        "tls_available": _context_number(context, "tls_available"),
        "tls_present": _context_number(context, "tls_present"),
        "tls_hostname_match": _context_number(context, "tls_hostname_match"),
        "tls_days_remaining_normalized": min(tls_days_remaining, 825.0) / 825.0,
        "redirect_available": _context_number(context, "redirect_available"),
        "redirect_count_normalized": min(_context_number(context, "redirect_count"), 10.0) / 10.0,
        "cross_domain_redirect_count": min(
            _context_number(context, "cross_domain_redirect_count"), 10.0
        ) / 10.0,
        "final_domain_changed": _context_number(context, "final_domain_changed"),
        "dom_available": _context_number(context, "dom_available"),
        "login_form_present": _context_number(context, "login_form_present"),
        "password_form_present": _context_number(context, "password_form_present"),
        "external_form_present": _context_number(context, "external_form_present"),
        "hidden_iframe_present": _context_number(context, "hidden_iframe_present"),
        "script_count_normalized": min(_context_number(context, "script_count"), 200.0) / 200.0,
        "visual_hash_available": _context_number(context, "visual_hash_available"),
        "visual_brand_similarity": _context_number(context, "visual_brand_similarity"),
        "local_feed_checked": _context_number(context, "local_feed_checked"),
        "local_feed_hit": _context_number(context, "local_feed_hit"),
    }


def extract_url_features(
    url: str,
    feature_names: tuple[str, ...] | list[str] | None = None,
    context: dict[str, object] | None = None,
) -> list[float]:
    """Return a stable vector; defaults to the deployed legacy 15-feature schema."""
    selected = tuple(feature_names or LEGACY_FEATURE_NAMES)
    feature_map = extract_url_feature_map(url, context=context)
    unknown = [name for name in selected if name not in feature_map]
    if unknown:
        raise ValueError(f"Unknown URL feature names: {', '.join(unknown[:5])}")
    return [float(feature_map[name]) for name in selected]


def extract_enriched_url_features(
    url: str,
    context: dict[str, object] | None = None,
) -> list[float]:
    """Return the complete 54+ feature vector used by new training jobs."""
    return extract_url_features(url, FEATURE_NAMES, context=context)
