from __future__ import annotations

from security import sandbox_worker
from security.url_sandbox import URLSandboxRunner


def test_runner_blocks_private_network() -> None:
    result = URLSandboxRunner(process_timeout_seconds=4).inspect("http://127.0.0.1:8000")

    assert result.ok is False
    assert result.execution_status == "failed"
    assert result.issues[0].code == "private_network_blocked"
    assert any(step.status == "failed" for step in result.scan_steps)


def test_worker_reports_live_html_signals(monkeypatch) -> None:
    html = b"""
        <html><head><title>Secure account verification</title></head>
        <body>
          <p>Verify your account. Act now.</p>
          <form action="https://collector.example/submit">
            <input name="user"><input type="password" name="password">
          </form>
          <iframe src="https://tracker.example/frame"></iframe>
        </body></html>
    """

    def fake_request(url: str, timeout: float, max_bytes: int) -> dict:
        return {
            "status": 200,
            "reason": "OK",
            "headers": {"content-type": "text/html; charset=utf-8"},
            "body": html,
            "truncated": False,
            "resolved_ip": "93.184.216.34",
            "tls": {"protocol": "TLSv1.3"},
        }

    monkeypatch.setattr(sandbox_worker, "_request_once", fake_request)
    result = sandbox_worker.run({"url": "https://safe.example/login"})
    codes = {issue["code"] for issue in result["issues"]}

    assert result["ok"] is True
    assert result["status_code"] == 200
    assert result["page_title"] == "Secure account verification"
    assert result["page_signals"]["password_inputs"] == 1
    assert {"password_form", "external_sensitive_form_action", "external_iframe"} <= codes
    html_step = next(step for step in result["scan_steps"] if step["key"] == "inspect_html")
    assert html_step["status"] == "failed"


def test_worker_reports_business_policy_and_content_findings(monkeypatch) -> None:
    html = b"""
      <html><head><title>Virus detected - Buy now</title></head><body>
      <p>Buy now. You have won. Verify your account. Act now.</p>
      <form><input type="password" name="password"></form>
      <p>Email: billing@unrelated.example</p>
      </body></html>
    """
    monkeypatch.setattr(sandbox_worker, "_request_once", lambda *args: {
        "status": 200, "reason": "OK", "headers": {"content-type": "text/html"},
        "body": html, "truncated": False, "resolved_ip": "93.184.216.34", "tls": {},
    })
    result = sandbox_worker.run({"url": "https://shop.example.test"})
    codes = {issue["code"] for issue in result["issues"]}
    assert {"missing_privacy_policy", "missing_terms_refund",
            "scam_template_content", "coercive_action_context"} <= codes
    assert "missing_contact_information" not in codes
    assert result["page_signals"]["has_contact_channel"] is True


def test_worker_requires_real_policy_links_and_structured_business_facts(monkeypatch) -> None:
    html = b"""
      <html><head><title>Store</title></head><body>
      <p>Address and privacy are important words, but they are not evidence.</p>
      <p>Contact support@gmail.com</p>
      <p>Buy now - giam 95%</p>
      <form action="https://forms.example/news"><input name="email"></form>
      </body></html>
    """
    monkeypatch.setattr(sandbox_worker, "_request_once", lambda *args: {
        "status": 200, "reason": "OK", "headers": {"content-type": "text/html"},
        "body": html, "truncated": False, "resolved_ip": "93.184.216.34", "tls": {},
    })

    result = sandbox_worker.run({"url": "https://shop.example.test"})
    codes = {issue["code"] for issue in result["issues"]}

    assert "missing_business_address" in codes
    assert "missing_privacy_policy" not in codes
    assert "external_sensitive_form_action" not in codes
    assert "extreme_price_discount" in codes
    assert result["page_signals"]["max_discount_percent"] == 95


def test_worker_accepts_dedicated_policy_links_and_complete_identity(monkeypatch) -> None:
    html = b"""
      <html><head><title>Example Store</title></head><body>
      <p>Buy now for 100 USD. Example Trading Company Ltd.</p>
      <p>Tax ID: VN123456789</p>
      <p>Address: 12 Nguyen Hue Street, District 1, Ho Chi Minh City</p>
      <a href="/privacy-policy">Privacy policy</a>
      <a href="/terms">Terms</a>
      <form><input type="password" name="password"></form>
      </body></html>
    """
    monkeypatch.setattr(sandbox_worker, "_request_once", lambda *args: {
        "status": 200, "reason": "OK", "headers": {"content-type": "text/html"},
        "body": html, "truncated": False, "resolved_ip": "93.184.216.34", "tls": {},
    })

    result = sandbox_worker.run({"url": "https://shop.example.test"})
    codes = {issue["code"] for issue in result["issues"]}

    assert "missing_business_address" not in codes
    assert "missing_legal_identity" not in codes
    assert "missing_privacy_policy" not in codes
    assert "missing_terms_refund" not in codes


def test_payment_recipient_makes_page_commercial_without_shop_words(monkeypatch) -> None:
    html = b"""
      <html><head><title>Summer tournament registration</title></head><body>
      <p>Registration fee</p>
      <p>STK: 123456789012</p>
      <form><input name="phone"><input name="team"></form>
      </body></html>
    """
    monkeypatch.setattr(sandbox_worker, "_request_once", lambda *args: {
        "status": 200, "reason": "OK", "headers": {"content-type": "text/html"},
        "body": html, "truncated": False, "resolved_ip": "93.184.216.34", "tls": {},
    })

    result = sandbox_worker.run({"url": "https://event.example.test"})
    codes = {issue["code"] for issue in result["issues"]}

    assert result["page_signals"]["is_commercial"] is True
    assert {
        "unverified_payment_recipient",
        "missing_contact_information",
        "missing_business_address",
        "missing_legal_identity",
        "missing_terms_refund",
    } <= codes


def test_worker_follows_and_records_redirect(monkeypatch) -> None:
    responses = iter(
        [
            {
                "status": 302,
                "reason": "Found",
                "headers": {"location": "/landing"},
                "body": b"",
                "truncated": False,
                "resolved_ip": "93.184.216.34",
                "tls": {},
            },
            {
                "status": 404,
                "reason": "Not Found",
                "headers": {"content-type": "text/html"},
                "body": b"<title>Missing</title>",
                "truncated": False,
                "resolved_ip": "93.184.216.34",
                "tls": {},
            },
        ]
    )
    monkeypatch.setattr(sandbox_worker, "_request_once", lambda *args: next(responses))

    result = sandbox_worker.run({"url": "https://example.com/start"})

    assert result["final_url"] == "https://example.com/landing"
    assert result["redirects"][0]["status_code"] == 302
    assert any(issue["code"] == "http_client_error" for issue in result["issues"])
    response_step = next(step for step in result["scan_steps"] if step["key"] == "inspect_response")
    assert response_step["status"] == "failed"
