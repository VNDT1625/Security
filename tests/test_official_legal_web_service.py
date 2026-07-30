from __future__ import annotations

from urllib.parse import quote

import httpx
import pytest

from backend.services.official_legal_web_service import OfficialLegalWebRetriever


def _search_html(*urls: str) -> str:
    links = "".join(
        f'<a class="result__a" href="https://duckduckgo.com/l/?uddg={quote(url)}">'
        f"Nguồn {index}</a>"
        for index, url in enumerate(urls, start=1)
    )
    return f"<html><body>{links}</body></html>"


def _search_rss(*urls: str) -> str:
    items = "".join(
        f"<item><title>Nguồn {index}</title><link>{url.replace('&', '&amp;')}</link></item>"
        for index, url in enumerate(urls, start=1)
    )
    return f'<?xml version="1.0"?><rss><channel>{items}</channel></rss>'


@pytest.mark.asyncio
async def test_fetches_only_allowlisted_official_pages_as_evidence() -> None:
    official_url = "https://vanban.chinhphu.vn/?pageid=27160&docid=214590"
    malicious_url = "https://attacker.example/fake-law"
    fetched_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched_hosts.append(request.url.host)
        if request.url.host == "www.bing.com":
            return httpx.Response(
                200,
                text=_search_rss(official_url, malicious_url),
                headers={"content-type": "application/rss+xml; charset=utf-8"},
            )
        if request.url.host == "vanban.chinhphu.vn":
            content = (
                "<html><head><title>Luật Dữ liệu số 91/2025/QH15</title></head>"
                "<body><main><p>"
                + "Nội dung chính thức về bảo vệ dữ liệu và an ninh mạng. " * 20
                + "</p></main></body></html>"
            )
            return httpx.Response(
                200,
                text=content,
                headers={"content-type": "text/html; charset=utf-8"},
            )
        raise AssertionError(f"Unexpected outbound host: {request.url.host}")

    retriever = OfficialLegalWebRetriever(
        enabled=True,
        transport=httpx.MockTransport(handler),
    )
    result = await retriever.search(
        "Quy định bảo vệ dữ liệu cá nhân",
        jurisdiction="VN",
    )

    assert len(result.references) == 1
    reference = result.references[0]
    assert reference.source_page_url == official_url
    assert reference.legal_weight == "official_guidance"
    assert reference.retrieval_channels == ("official_web",)
    assert reference.authority == "Cổng Thông tin điện tử Chính phủ"
    assert reference.extraction_method == "official_html_text"
    assert "Nội dung chính thức" in reference.full_text
    assert "attacker.example" not in fetched_hosts


@pytest.mark.asyncio
async def test_rejects_redirect_from_official_host_to_untrusted_host() -> None:
    official_url = "https://vanban.chinhphu.vn/redirect"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "html.duckduckgo.com":
            return httpx.Response(
                200,
                text=_search_html(official_url),
                headers={"content-type": "text/html"},
            )
        if request.url.host == "vanban.chinhphu.vn":
            return httpx.Response(
                302,
                headers={"location": "https://attacker.example/fake-law"},
            )
        raise AssertionError("The retriever must never follow an untrusted redirect")

    result = await OfficialLegalWebRetriever(
        enabled=True,
        search_url="https://html.duckduckgo.com/html/",
        transport=httpx.MockTransport(handler),
    ).search("Quy định mới", jurisdiction="VN")

    assert result.references == ()
    assert result.rejected_count == 1


@pytest.mark.asyncio
async def test_disabled_or_unsupported_jurisdiction_makes_no_request() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("No network request expected")

    transport = httpx.MockTransport(handler)
    disabled = OfficialLegalWebRetriever(enabled=False, transport=transport)
    unsupported = OfficialLegalWebRetriever(enabled=True, transport=transport)

    assert (await disabled.search("test", jurisdiction="VN")).references == ()
    assert (await unsupported.search("test", jurisdiction="US")).references == ()
