import ssl
import time

import pytest

from security import browser_sandbox_worker, sandbox_worker


@pytest.mark.parametrize(
    "message",
    [
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired",
        "certificate is not yet valid",
        "hostname mismatch",
        "self signed certificate",
        "unable to get local issuer certificate",
        "certificate revoked",
    ],
)
def test_http_worker_recognizes_real_certificate_validation_errors(message):
    assert sandbox_worker._is_tls_certificate_error(OSError(message)) is True


def test_http_worker_does_not_label_generic_tls_protocol_error_as_bad_certificate():
    assert (
        sandbox_worker._is_tls_certificate_error(
            ssl.SSLError("[SSL: WRONG_VERSION_NUMBER] wrong version number")
        )
        is False
    )


def test_http_worker_prioritizes_certificate_error_over_later_ip_failure(monkeypatch):
    class FakeHTTPSConnection:
        def __init__(self, _host, _port, address, _timeout):
            self.address = address

        def request(self, *_args, **_kwargs):
            if self.address == "203.0.113.10":
                raise ssl.SSLCertVerificationError(
                    1, "[SSL: CERTIFICATE_VERIFY_FAILED] hostname mismatch"
                )
            raise ConnectionRefusedError("later address refused")

        def close(self):
            return None

    monkeypatch.setattr(
        sandbox_worker,
        "_public_addresses",
        lambda _host, _port: ["203.0.113.10", "203.0.113.11"],
    )
    monkeypatch.setattr(
        sandbox_worker, "PinnedHTTPSConnection", FakeHTTPSConnection
    )

    with pytest.raises(ssl.SSLCertVerificationError):
        sandbox_worker._request_once(
            "https://certificate.example/", timeout=1, max_bytes=1024
        )


@pytest.mark.parametrize(
    "error",
    [
        "page.goto: net::ERR_CERT_DATE_INVALID at https://example.test/",
        "page.goto: net::ERR_CERT_COMMON_NAME_INVALID",
        "page.goto: net::ERR_CERT_AUTHORITY_INVALID",
        "page.goto: net::ERR_CERT_REVOKED",
        "page.goto: net::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED",
    ],
)
def test_browser_worker_maps_chromium_certificate_errors_to_criterion_issue(error):
    assert browser_sandbox_worker._playwright_failure_code(error) == (
        "tls_certificate_error"
    )
    result = browser_sandbox_worker._failure(
        "https://example.test", "tls_certificate_error", error, time.perf_counter()
    )
    assert result["issues"][0]["code"] == "tls_certificate_error"


def test_browser_worker_keeps_non_certificate_navigation_error_separate():
    assert (
        browser_sandbox_worker._playwright_failure_code(
            "page.goto: net::ERR_CONNECTION_REFUSED"
        )
        == "browser_navigation_failed"
    )


def test_browser_subresource_certificate_failure_becomes_issue():
    issues = browser_sandbox_worker._issues_from_signals(
        {"fields": [], "forms": []},
        [],
        [
            {
                "url": "https://cdn.example.test/app.js",
                "reason": "net::ERR_CERT_AUTHORITY_INVALID",
            }
        ],
        {},
    )

    certificate_issue = next(
        issue for issue in issues if issue["code"] == "tls_certificate_error"
    )
    assert certificate_issue["severity"] == "high"
    assert "cdn.example.test" in certificate_issue["detail"]
