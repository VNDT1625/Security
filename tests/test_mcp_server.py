import asyncio

from mcp_server import server as mcp_server_module
from mcp_server.server import build_server
from mcp_server.tools import MCPTools


def test_mcp_server_registers_required_tools() -> None:
    server = build_server()
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert {
        "prewise_connection_test",
        "assess_url",
        "assess_text",
        "scan_prompt_injection",
        "assess_action",
        "assess_page",
        "assess_file_static",
        "quick_scan_exe",
        "quick_scan_exe_content",
        "get_exe_quick_scan_report",
        "summarize_risk_safely",
    } <= names


def test_connection_tool_replies_done() -> None:
    response = MCPTools().dispatch("prewise_connection_test", {"request": "agent test"})
    assert response["status"] == "done"
    assert response["message"] == "done"
    assert response["received"] == "agent test"
    assert response["service"] == "prewise-mcp"
    assert response["ok"] is True
    assert response["schema_version"] == "1.0"
    assert response["request_id"]


def test_mcp_http_apps_can_be_constructed() -> None:
    server = build_server(host="127.0.0.1", port=3001)
    assert server.sse_app() is not None
    assert server.streamable_http_app() is not None


def test_mcp_transport_uses_allowed_hosts_from_settings(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp_server_module.settings,
        "mcp_allowed_hosts",
        "api.prewise.site,api.prewise.site:*",
    )
    monkeypatch.setattr(
        mcp_server_module.settings,
        "mcp_allowed_origins",
        "https://chatgpt.com",
    )

    server = build_server(host="127.0.0.1", port=3001)
    security = server.settings.transport_security

    assert "api.prewise.site" in security.allowed_hosts
    assert "api.prewise.site:*" in security.allowed_hosts
    assert security.allowed_origins == ["https://chatgpt.com"]


def test_invalid_tool_input_and_provider_poll_do_not_consume_quota(monkeypatch) -> None:
    calls = 0

    def reserve() -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(mcp_server_module, "reserve_mcp_scan_quota", reserve)
    server = build_server()

    asyncio.run(server.call_tool("assess_url", {"url": "ftp://example.com"}))
    asyncio.run(server.call_tool("get_exe_quick_scan_report", {"data_id": "job-1"}))

    assert calls == 0
