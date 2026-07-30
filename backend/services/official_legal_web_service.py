"""Bounded live retrieval from allow-listed Vietnamese government websites.

The search engine is discovery-only. Evidence is accepted only after Prewise
fetches the final HTTPS page from an explicit official-domain allowlist.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urljoin, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import httpx

from security.legal_rag import LegalReference

_OFFICIAL_HOSTS = frozenset(
    {
        "vanban.chinhphu.vn",
        "congbao.chinhphu.vn",
        "xaydungchinhsach.chinhphu.vn",
        "chinhphu.vn",
        "www.chinhphu.vn",
        "baochinhphu.vn",
        "www.baochinhphu.vn",
        "bocongan.gov.vn",
        "www.bocongan.gov.vn",
        "mps.gov.vn",
        "www.mps.gov.vn",
        "mic.gov.vn",
        "www.mic.gov.vn",
        "moj.gov.vn",
        "www.moj.gov.vn",
        "phapluat.gov.vn",
        "www.phapluat.gov.vn",
        "vbpl.vn",
        "www.vbpl.vn",
        "quochoi.vn",
        "www.quochoi.vn",
    }
)
_TOPIC_QUERIES = (
    ("dữ liệu cá nhân", '"Luật Bảo vệ dữ liệu cá nhân"'),
    ("an ninh mạng", '"Luật An ninh mạng"'),
    ("trí tuệ nhân tạo", '"Luật Trí tuệ nhân tạo"'),
    ("giao dịch điện tử", '"Luật Giao dịch điện tử"'),
    ("trẻ em", '"Luật Trẻ em" an toàn trên môi trường mạng'),
    ("quyền tác giả", '"Luật Sở hữu trí tuệ" quyền tác giả'),
)
_IGNORED_TAGS = frozenset(
    {"script", "style", "svg", "noscript", "form", "nav", "header", "footer", "aside"}
)
_DATE_ISO = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")
_DATE_VI = re.compile(r"\b([0-3]?\d)[/-]([01]?\d)[/-](20\d{2})\b")
_DOCUMENT_NUMBER = re.compile(
    r"\b\d{1,4}/\d{4}/(?:QH\d+|NĐ-CP|ND-CP|TT-[A-ZĐ0-9-]+|QĐ-[A-ZĐ0-9-]+)\b",
    re.IGNORECASE,
)


def _enabled_by_default() -> bool:
    raw = os.getenv("PREWISE_LEGAL_WEB_SEARCH_ENABLED", "")
    if raw:
        return raw.strip().casefold() in {"1", "true", "yes", "on"}
    return os.getenv("APP_ENV", "").strip().casefold() == "production"


def _clean_url(value: str) -> str:
    try:
        parsed = urlsplit(html.unescape(value).strip())
    except ValueError:
        return ""
    if parsed.hostname and parsed.hostname.casefold().endswith("duckduckgo.com"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        if target:
            parsed = urlsplit(unquote(target))
    host = (parsed.hostname or "").casefold()
    try:
        port = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme.casefold() != "https"
        or host not in _OFFICIAL_HOSTS
        or parsed.username
        or parsed.password
        or port not in {None, 443}
    ):
        return ""
    return urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))


def _authority(host: str) -> str:
    if host.endswith("bocongan.gov.vn"):
        return "Bộ Công an"
    if host.endswith("mps.gov.vn"):
        return "Bộ Công an"
    if host.endswith("mic.gov.vn"):
        return "Cơ quan quản lý thông tin và truyền thông"
    if host.endswith("moj.gov.vn") or host.endswith("vbpl.vn"):
        return "Bộ Tư pháp"
    if host.endswith("quochoi.vn"):
        return "Quốc hội"
    if host.endswith("phapluat.gov.vn"):
        return "Cổng Pháp luật quốc gia"
    if host.endswith("baochinhphu.vn"):
        return "Báo Điện tử Chính phủ"
    return "Cổng Thông tin điện tử Chính phủ"


def _build_queries(question: str, reference_hints: Sequence[str]) -> tuple[str, ...]:
    queries: list[str] = []
    for hint in reference_hints:
        compact = " ".join(str(hint).split()).strip(" -")
        if compact:
            queries.append(f'"{compact[:180]}"')
    normalized_question = " ".join(question.casefold().split())
    for phrase, query in _TOPIC_QUERIES:
        if phrase in normalized_question:
            queries.append(query)
    if not queries:
        queries.append(f'"{" ".join(question.split())[:300]}" Chính phủ')
    return tuple(dict.fromkeys(queries))[:4]


class _SearchResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str]] = []
        self._href = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        classes = values.get("class", "").split()
        if tag.casefold() == "a" and "result__a" in classes:
            self._href = values.get("href", "")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href:
            self.items.append((self._href, " ".join(self._text).strip()))
            self._href = ""
            self._text = []


class _RSSResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str]] = []
        self._in_item = False
        self._field = ""
        self._title: list[str] = []
        self._link: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        if lowered == "item":
            self._in_item = True
            self._title = []
            self._link = []
        elif self._in_item and lowered in {"title", "link"}:
            self._field = lowered

    def handle_data(self, data: str) -> None:
        if self._field == "title":
            self._title.append(data)
        elif self._field == "link":
            self._link.append(data)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered in {"title", "link"}:
            self._field = ""
        elif lowered == "item" and self._in_item:
            self.items.append(
                (
                    "".join(self._link).strip(),
                    " ".join(self._title).strip(),
                )
            )
            self._in_item = False


class _OfficialPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.published = ""
        self._title_depth = 0
        self._ignored_depth = 0
        self._main_depth = 0
        self._body_text: list[str] = []
        self._main_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        values = {key.casefold(): value or "" for key, value in attrs}
        if self._ignored_depth:
            self._ignored_depth += 1
            return
        if lowered in _IGNORED_TAGS:
            self._ignored_depth = 1
            return
        if self._main_depth:
            self._main_depth += 1
        elif lowered in {"main", "article"}:
            self._main_depth = 1
        if lowered == "title":
            self._title_depth = 1
        if lowered == "meta":
            key = (values.get("property") or values.get("name") or "").casefold()
            content = values.get("content", "")
            if key in {"og:title", "twitter:title"} and content and not self.title:
                self.title = content.strip()
            if key in {
                "article:published_time",
                "date",
                "datepublished",
                "publishdate",
                "pubdate",
            } and content:
                self.published = content.strip()

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_depth:
            self._ignored_depth -= 1
            return
        if self._main_depth:
            self._main_depth -= 1
        if tag.casefold() == "title":
            self._title_depth = 0

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        value = " ".join(data.split())
        if not value:
            return
        self._body_text.append(value)
        if self._main_depth:
            self._main_text.append(value)
        if self._title_depth and not self.title:
            self.title = value

    def evidence_text(self) -> str:
        preferred = self._main_text if len(" ".join(self._main_text)) >= 300 else self._body_text
        return " ".join(preferred)


def _search_items(content: str) -> list[tuple[str, str]]:
    if "<rss" in content[:500].casefold():
        parser = _RSSResultParser()
        parser.feed(content)
        return parser.items
    parser = _SearchResultParser()
    parser.feed(content)
    return parser.items


@dataclass(frozen=True)
class OfficialWebSearchResult:
    references: tuple[LegalReference, ...] = ()
    query_count: int = 0
    candidate_count: int = 0
    fetched_count: int = 0
    rejected_count: int = 0
    degraded_reasons: tuple[str, ...] = ()

    def trace(self) -> dict[str, object]:
        return {
            "mode": "official_web",
            "query_count": self.query_count,
            "candidate_count": self.candidate_count,
            "fetched_count": self.fetched_count,
            "rejected_count": self.rejected_count,
            "degraded_reasons": list(self.degraded_reasons),
        }


class OfficialLegalWebRetriever:
    """Search and fetch a small, fail-soft set of official live sources."""

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        search_url: str = "https://www.bing.com/search",
        timeout_seconds: float | None = None,
        max_results: int | None = None,
        max_page_bytes: int | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.enabled = _enabled_by_default() if enabled is None else enabled
        self.search_url = search_url
        timeout = timeout_seconds or float(
            os.getenv("PREWISE_LEGAL_WEB_SEARCH_TIMEOUT_SECONDS", "8")
        )
        result_limit = max_results or int(
            os.getenv("PREWISE_LEGAL_WEB_SEARCH_MAX_RESULTS", "6")
        )
        page_limit = max_page_bytes or int(
            os.getenv("PREWISE_LEGAL_WEB_SEARCH_MAX_PAGE_BYTES", "750000")
        )
        self.timeout_seconds = max(1.0, min(20.0, timeout))
        self.max_results = max(1, min(10, result_limit))
        self.max_page_bytes = max(64_000, min(2_000_000, page_limit))
        self.transport = transport

    async def _search(
        self,
        client: httpx.AsyncClient,
        question: str,
        reference_hints: Sequence[str],
    ) -> tuple[list[tuple[str, str]], list[str]]:
        found: list[tuple[str, str]] = []
        degraded: list[str] = []
        for query in _build_queries(question, reference_hints):
            try:
                response = await client.get(
                    self.search_url,
                    params={
                        "q": query,
                        **({"format": "rss"} if "bing.com" in self.search_url else {}),
                    },
                )
                response.raise_for_status()
                if len(response.content) > 1_000_000:
                    degraded.append("search_response_too_large")
                    continue
                for raw_url, title in _search_items(response.text):
                    url = _clean_url(raw_url)
                    normalized_title = title.casefold()
                    if url and "dự thảo" not in normalized_title and "du thao" not in normalized_title:
                        found.append((url, title))
            except Exception as exc:
                degraded.append(f"search_{type(exc).__name__}")
        deduplicated: list[tuple[str, str]] = []
        seen: set[str] = set()
        for item in found:
            if item[0] in seen:
                continue
            seen.add(item[0])
            deduplicated.append(item)
        return deduplicated[: self.max_results], degraded

    async def _fetch_official(
        self,
        client: httpx.AsyncClient,
        candidate: tuple[str, str],
        *,
        index: int,
        jurisdiction: str,
    ) -> LegalReference | None:
        current = candidate[0]
        response: httpx.Response | None = None
        for _ in range(4):
            if not _clean_url(current):
                return None
            response = await client.get(current, follow_redirects=False)
            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            location = response.headers.get("location", "")
            current = _clean_url(urljoin(current, location))
            if not current:
                return None
        if response is None or response.status_code != 200:
            return None
        final_url = _clean_url(str(response.url))
        content_type = response.headers.get("content-type", "").casefold()
        try:
            content_length = int(response.headers.get("content-length", "0") or "0")
        except ValueError:
            content_length = 0
        if (
            not final_url
            or "html" not in content_type
            or content_length > self.max_page_bytes
            or len(response.content) > self.max_page_bytes
        ):
            return None

        parser = _OfficialPageParser()
        parser.feed(response.text[: self.max_page_bytes])
        evidence = parser.evidence_text()
        if len(evidence) < 200:
            return None
        evidence = evidence[:40_000]
        title = " ".join((parser.title or candidate[1] or "Nguồn chính phủ").split())[:500]
        today = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).date().isoformat()
        effective = self._publication_date(parser.published or evidence) or today
        document_number_match = _DOCUMENT_NUMBER.search(f"{title} {evidence[:2_000]}")
        document_number = (
            document_number_match.group(0).upper() if document_number_match else "OFFICIAL-WEB"
        )
        digest = hashlib.sha256(f"{final_url}\n{evidence}".encode()).hexdigest()
        document_digest = hashlib.sha256(final_url.encode()).hexdigest()
        host = (urlsplit(final_url).hostname or "").casefold()
        return LegalReference(
            chunk_id=f"official-web::{digest[:24]}",
            document_id=f"official-web::{document_digest[:24]}",
            title=title,
            document_number=document_number,
            legal_weight="official_guidance",
            status="current",
            effective_date=effective,
            section="Nội dung trang chính thức",
            page_start=1,
            page_end=1,
            source_page_url=final_url,
            source_pdf_sha256=hashlib.sha256(response.content).hexdigest(),
            extraction_method="official_html_text",
            text_preview=evidence[:900],
            retrieval_score=1.0 / max(1, index),
            jurisdiction=jurisdiction,
            status_checked_at=today,
            document_type="official_web",
            authority=_authority(host),
            full_text=evidence,
            relevance_score=1.0 / max(1, index),
            retrieval_channels=("official_web",),
            is_primary=True,
            text_verification_status="live_official_html",
            corpus_release_id=f"official-web-{today}",
        )

    @staticmethod
    def _publication_date(value: str) -> str:
        iso_match = _DATE_ISO.search(value)
        if iso_match:
            try:
                return date.fromisoformat("-".join(iso_match.groups())).isoformat()
            except ValueError:
                pass
        vi_match = _DATE_VI.search(value)
        if vi_match:
            day, month, year = vi_match.groups()
            try:
                return date(int(year), int(month), int(day)).isoformat()
            except ValueError:
                pass
        return ""

    async def search(
        self,
        question: str,
        *,
        jurisdiction: str,
        reference_hints: Sequence[str] = (),
    ) -> OfficialWebSearchResult:
        normalized_jurisdiction = jurisdiction.strip().casefold()
        if not self.enabled or normalized_jurisdiction not in {
            "vn",
            "vietnam",
            "viet nam",
            "việt nam",
        }:
            return OfficialWebSearchResult()

        headers = {
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Prewise-Legal-Retriever/1.0 (+https://prewise.site)",
        }
        degraded: list[str] = []
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            headers=headers,
            transport=self.transport,
        ) as client:
            queries = _build_queries(question, reference_hints)
            candidates, search_degraded = await self._search(
                client,
                question,
                reference_hints,
            )
            degraded.extend(search_degraded)
            references: list[LegalReference] = []
            rejected = 0
            fetches = await asyncio.gather(
                *(
                    self._fetch_official(
                        client,
                        candidate,
                        index=index,
                        jurisdiction="VN",
                    )
                    for index, candidate in enumerate(candidates, start=1)
                ),
                return_exceptions=True,
            )
            for result in fetches:
                if isinstance(result, BaseException):
                    degraded.append(f"fetch_{type(result).__name__}")
                    reference = None
                else:
                    reference = result
                if reference is None:
                    rejected += 1
                    continue
                references.append(reference)

        return OfficialWebSearchResult(
            references=tuple(references),
            query_count=len(queries),
            candidate_count=len(candidates),
            fetched_count=len(references),
            rejected_count=rejected,
            degraded_reasons=tuple(dict.fromkeys(degraded)),
        )


__all__ = [
    "OfficialLegalWebRetriever",
    "OfficialWebSearchResult",
]
