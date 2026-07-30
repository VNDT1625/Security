"""Headless browser sandbox worker with canary credential probes.

The worker is intentionally process-isolated. It uses Playwright when available,
blocks non-public network destinations before requests are allowed to continue,
and fills only synthetic canary values. No real account, password, or OTP should
ever be supplied to this worker.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import select
import socket
import socketserver
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

if os.name == "nt" and not os.environ.get("SYSTEMROOT"):
    os.environ["SYSTEMROOT"] = r"C:\Windows"
    os.environ["WINDIR"] = r"C:\Windows"

try:  # pragma: no cover - import shape differs when run as a script.
    from .sandbox_worker import _issue, _normalize_url, _public_addresses
    from .visual_hash import analyze_visual_hash
except ImportError:  # pragma: no cover
    from sandbox_worker import _issue, _normalize_url, _public_addresses
    from visual_hash import analyze_visual_hash


MAX_NETWORK_EVENTS = 160
MAX_PROXY_HEADER_BYTES = 64 * 1024

BROWSER_SCAN_STEPS = (
    ("normalize_url", "Normalize URL and reject unsafe schemes"),
    ("resolve_public_ip", "Resolve DNS and block private networks"),
    ("launch_browser", "Launch isolated headless browser profile"),
    ("install_guards", "Install network, download, permission and canary guards"),
    ("navigate_page", "Navigate page in the sandbox"),
    ("fill_canary", "Fill only synthetic canary values"),
    ("probe_forms", "Probe sensitive forms and block submit"),
    ("inspect_events", "Inspect network, console and canary events"),
    ("capture_visual_hash", "Hash screenshot and compare curated brand references"),
    ("close_context", "Close temporary browser context"),
)

BROWSER_FAILURE_STEP = {
    "unsupported_scheme": "normalize_url",
    "missing_hostname": "normalize_url",
    "credentials_in_url": "normalize_url",
    "invalid_port": "normalize_url",
    "private_network_blocked": "resolve_public_ip",
    "dns_error": "resolve_public_ip",
    "browser_engine_unavailable": "launch_browser",
    "browser_navigation_failed": "navigate_page",
    "browser_sandbox_error": "inspect_events",
}


def _write_progress(stage: str) -> None:
    path = os.environ.get("AISEC_BROWSER_PROGRESS_PATH")
    if not path:
        return
    try:
        Path(path).write_text(stage, encoding="utf-8")
    except OSError:
        pass


def _write_result_checkpoint(result: dict) -> None:
    """Publish a complete result before browser cleanup can block.

    Chromium can occasionally hang while Playwright closes a persistent context
    on Windows. The parent process treats this file as the completion boundary
    and then owns termination of the isolated browser process tree.
    """
    path = os.environ.get("AISEC_BROWSER_RESULT_PATH")
    if not path:
        return
    try:
        Path(path).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _read_proxy_headers(connection: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_PROXY_HEADER_BYTES:
            raise ValueError("proxy_header_too_large")
    return bytes(data)


def _split_authority(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ValueError("invalid_proxy_authority")
        host = authority[1:end]
        suffix = authority[end + 1 :]
        port = int(suffix[1:]) if suffix.startswith(":") else default_port
        return host, port

    host, separator, raw_port = authority.rpartition(":")
    if separator and raw_port.isdigit():
        return host, int(raw_port)
    return authority, default_port


class _PinnedProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        self.events: list[dict] = []
        self._event_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _PinnedProxyHandler)

    def record(self, event: dict) -> None:
        with self._event_lock:
            if len(self.events) < MAX_NETWORK_EVENTS:
                self.events.append(event)


class _PinnedProxyHandler(socketserver.BaseRequestHandler):
    server: _PinnedProxyServer

    def _record(self, target: str, method: str, blocked: bool, reason: str, ip: str = "") -> None:
        self.server.record(
            {
                "url": target,
                "method": method,
                "resource_type": "egress_proxy",
                "status": None,
                "blocked": blocked,
                "reason": reason,
                "same_origin": None,
                "resolved_ip": ip,
            }
        )

    def _reject(self, status_code: int, reason: str, target: str, method: str) -> None:
        message = f"HTTP/1.1 {status_code} Sandbox Blocked\r\nConnection: close\r\n\r\n"
        # Persist the security decision before notifying the client.  Sending
        # first lets the client observe the rejection while the handler thread
        # has not recorded its audit event yet, which makes callers race the
        # proxy's security telemetry.
        self._record(target, method, True, reason)
        self.request.sendall(message.encode("ascii"))

    @staticmethod
    def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
            if exceptional:
                return
            for source in readable:
                data = source.recv(64 * 1024)
                if not data:
                    return
                destination = upstream if source is client else client
                destination.sendall(data)

    def _connect_upstream(self, host: str, port: int) -> tuple[socket.socket, str]:
        addresses = _public_addresses(host, port)
        last_error: OSError | None = None
        for address in addresses:
            try:
                return socket.create_connection((address, port), timeout=10), address
            except OSError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise ConnectionError(f"No public address available for {host}")

    def _handle_connect(self, target: str) -> None:
        host, port = _split_authority(target, 443)
        upstream, address = self._connect_upstream(host, port)
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._record(target, "CONNECT", False, "dns_pinned", address)
            self._tunnel(self.request, upstream)
        finally:
            upstream.close()

    def _handle_http(self, method: str, target: str, version: str, raw: bytes) -> None:
        parts = urlsplit(target)
        if parts.scheme != "http" or not parts.hostname:
            self._reject(400, "invalid_proxy_target", target, method)
            return
        port = parts.port or 80
        upstream, address = self._connect_upstream(parts.hostname, port)
        try:
            header_blob, separator, buffered_body = raw.partition(b"\r\n\r\n")
            lines = header_blob.split(b"\r\n")[1:]
            filtered = [
                line
                for line in lines
                if not line.lower().startswith((b"proxy-connection:", b"connection:"))
            ]
            path = parts.path or "/"
            if parts.query:
                path += f"?{parts.query}"
            request_head = (
                f"{method} {path} {version}\r\n".encode("ascii")
                + b"\r\n".join(filtered)
                + b"\r\nConnection: close\r\n\r\n"
            )
            upstream.sendall(request_head + (buffered_body if separator else b""))
            self._record(target, method, False, "dns_pinned", address)
            self._tunnel(self.request, upstream)
        finally:
            upstream.close()

    def handle(self) -> None:
        self.request.settimeout(12)
        target = ""
        method = "UNKNOWN"
        try:
            raw = _read_proxy_headers(self.request)
            first_line = raw.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, version = first_line.split(" ", 2)
            if method.upper() == "CONNECT":
                self._handle_connect(target)
            else:
                self._handle_http(method.upper(), target, version, raw)
        except PermissionError:
            self._reject(403, "private_network_blocked", target, method)
        except (OSError, ValueError) as exc:
            self._reject(502, f"egress_proxy_error:{type(exc).__name__}", target, method)


class _PinnedEgressProxy:
    def __init__(self) -> None:
        self.server = _PinnedProxyServer()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    @property
    def events(self) -> list[dict]:
        return list(self.server.events)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port
    default_port = 443 if parts.scheme == "https" else 80
    host = parts.hostname or ""
    if port and port != default_port:
        return f"{parts.scheme}://{host}:{port}"
    return f"{parts.scheme}://{host}"


def _scan_steps(
    failed_code: str = "",
    detail: str = "",
    issues: list[dict] | None = None,
) -> list[dict]:
    failed_key = BROWSER_FAILURE_STEP.get(failed_code, failed_code)
    steps: list[dict] = []
    failed_seen = False
    for key, label in BROWSER_SCAN_STEPS:
        if failed_key and key == failed_key:
            steps.append({"key": key, "label": label, "status": "failed", "detail": detail[:180]})
            failed_seen = True
        elif failed_seen:
            steps.append({"key": key, "label": label, "status": "skipped"})
        else:
            steps.append({"key": key, "label": label, "status": "passed"})
    if issues and not failed_code:
        issue_step = {
            "http": "navigate_page",
            "credential": "probe_forms",
            "network": "inspect_events",
            "isolation": "probe_forms",
        }
        issue_details: dict[str, list[str]] = {}
        for issue in issues:
            step_key = issue_step.get(str(issue.get("category", "")))
            if step_key:
                issue_details.setdefault(step_key, []).append(str(issue.get("code", "")))
        for step in steps:
            codes = issue_details.get(step["key"])
            if codes:
                step["status"] = "failed"
                step["detail"] = ", ".join(code for code in codes if code)[:180]
    return steps


def _same_origin(root_origin: str, candidate: str) -> bool:
    try:
        return _origin(candidate) == root_origin
    except ValueError:
        return False


def _make_canary() -> dict[str, str]:
    nonce = secrets.token_hex(4)
    otp = f"{int(nonce, 16) % 1_000_000:06d}"
    phone_tail = f"{int(nonce, 16) % 10_000_000:07d}"
    return {
        "email": f"clone-{nonce}@example.invalid",
        "username": f"clone_{nonce}",
        "password": f"ASArmor-{nonce}-canary",
        "otp": otp,
        "phone": f"090{phone_tail}",
    }


def _payload_contains_canary(value: object, canary: dict[str, str]) -> bool:
    if value is None:
        return False
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore")
    elif isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False)
        except TypeError:
            text = str(value)
    return any(token and token in text for token in canary.values())


def _event_contains_canary(events: list[dict], canary: dict[str, str]) -> bool:
    return any(_payload_contains_canary(event, canary) for event in events)


def _request_failure_text(request) -> str:
    failure = getattr(request, "failure", None)
    if callable(failure):
        failure = failure()
    return str(failure or "request_failed")


def _preflight_public_url(raw_url: str) -> tuple[str, str]:
    normalized = _normalize_url(raw_url)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = _public_addresses(host, port)
    return normalized, addresses[0]


def _failure(raw_url: str, code: str, detail: str, started: float) -> dict:
    messages = {
        "unsupported_scheme": "Browser sandbox only allows HTTP or HTTPS URLs.",
        "missing_hostname": "The URL does not contain a valid hostname.",
        "credentials_in_url": "The URL contains inline credentials and was blocked.",
        "invalid_port": "The URL port is invalid.",
        "private_network_blocked": "Browser sandbox blocked a private or non-public network target.",
        "dns_error": "The hostname could not be resolved.",
        "browser_engine_unavailable": "The browser engine is not installed for advanced sandboxing.",
        "browser_navigation_failed": "The isolated browser could not open the page.",
        "browser_sandbox_error": "The browser sandbox failed while inspecting the page.",
    }
    return {
        "ok": False,
        "execution_status": "failed",
        "url": raw_url,
        "final_url": "",
        "status_code": None,
        "page_title": "",
        "isolation": {
            "mode": "headless_browser",
            "network_private_block": True,
            "egress_proxy": "dns_pinned",
            "downloads": "blocked",
            "permissions": "denied",
            "service_workers": "blocked",
            "websockets": "blocked",
            "webrtc_non_proxied_udp": "blocked",
            "canary_credentials": "synthetic_only",
        },
        "canary": {"enabled": True, "mode": "dry_run"},
        "network_events": [],
        "browser_events": [],
        "console_errors": [],
        "page_identity": {},
        "screenshot_data_url": None,
        "issues": [
            _issue(code, "high", "execution", messages.get(code, messages["browser_sandbox_error"]), detail[:800])
        ],
        "scan_steps": _scan_steps(code, detail),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _status_issue(status_code: int | None) -> list[dict]:
    if status_code is None:
        return []
    if status_code >= 500:
        return [_issue("http_server_error", "high", "http", f"Server returned HTTP {status_code}.")]
    if status_code >= 400:
        return [_issue("http_client_error", "medium", "http", f"Page returned HTTP {status_code}.")]
    return []


def _issues_from_signals(
    fill_report: dict,
    browser_events: list[dict],
    network_events: list[dict],
    canary: dict[str, str],
    download_events: list[dict] | None = None,
) -> list[dict]:
    issues: list[dict] = []
    field_types = Counter(field.get("kind", "unknown") for field in fill_report.get("fields", []))
    forms = fill_report.get("forms", [])
    external_forms = [
        form.get("action", "")
        for form in forms
        if form.get("external") and form.get("action")
    ]

    if field_types.get("otp", 0):
        issues.append(
            _issue(
                "otp_input_detected",
                "critical",
                "credential",
                "The page asks for an OTP or verification code.",
                f"Fields: {field_types['otp']}",
            )
        )
    if field_types.get("password", 0):
        issues.append(
            _issue(
                "password_input_detected",
                "high",
                "credential",
                "The page asks for a password.",
                f"Fields: {field_types['password']}",
            )
        )
    if external_forms:
        issues.append(
            _issue(
                "cross_origin_form_action",
                "critical",
                "credential",
                "A form would submit data to another origin.",
                ", ".join(external_forms[:5]),
            )
        )

    blocked_canary = any(event.get("reason") == "canary_payload_blocked" for event in network_events)
    scripted_canary = _event_contains_canary(browser_events, canary)
    if blocked_canary or scripted_canary:
        issues.append(
            _issue(
                "canary_exfiltration_blocked",
                "critical",
                "network",
                "Synthetic clone credentials were about to leave the sandbox and were blocked.",
            )
        )

    blocked_forms = [
        event for event in browser_events if str(event.get("type", "")).endswith("form_submit_blocked")
    ]
    if blocked_forms:
        issues.append(
            _issue(
                "form_submission_blocked",
                "medium",
                "isolation",
                "The sandbox prevented form submission during the canary probe.",
                f"Blocked submit events: {len(blocked_forms)}",
            )
        )

    blocked_private = [event for event in network_events if event.get("reason") == "private_network_blocked"]
    if blocked_private:
        issues.append(
            _issue(
                "private_network_request_blocked",
                "critical",
                "network",
                "The page tried to reach a private or non-public network address.",
                ", ".join(event.get("url", "") for event in blocked_private[:5]),
            )
        )
    blocked_websockets = [
        event for event in network_events if event.get("reason") == "websocket_blocked"
    ]
    blocked_websockets.extend(
        event for event in browser_events if event.get("type") == "websocket_blocked"
    )
    if blocked_websockets:
        issues.append(
            _issue(
                "websocket_request_blocked",
                "medium",
                "network",
                "The page tried to open a WebSocket and the sandbox blocked it.",
                f"Blocked attempts: {len(blocked_websockets)}",
            )
        )
    permission_events = [
        event for event in browser_events if event.get("type") == "permission_request_blocked"
    ]
    if permission_events:
        issues.append(
            _issue(
                "permission_request_blocked",
                "high",
                "browser",
                "The page requested a browser capability that the sandbox denied.",
                ", ".join(str(event.get("permission", "unknown")) for event in permission_events[:8]),
            )
        )
    popup_events = [event for event in browser_events if event.get("type") == "popup_open_blocked"]
    if popup_events:
        issues.append(
            _issue(
                "deceptive_popup",
                "high",
                "browser",
                "The page attempted to open a popup window without leaving the sandbox.",
                ", ".join(str(event.get("url", "")) for event in popup_events[:5]),
            )
        )
    downloads = list(download_events or [])
    if downloads:
        issues.append(
            _issue(
                "download_attempt_blocked",
                "high",
                "download",
                "The page attempted to start a download; the sandbox cancelled it.",
                ", ".join(str(event.get("filename", "")) for event in downloads[:5]),
            )
        )
    ad_markers = (
        "doubleclick.net",
        "googlesyndication.com",
        "adservice.google.",
        "taboola.com",
        "outbrain.com",
        "propellerads.com",
        "popads.net",
    )
    ad_requests = [
        event
        for event in network_events
        if any(marker in str(event.get("url", "")).lower() for marker in ad_markers)
    ]
    if ad_requests and (popup_events or downloads):
        issues.append(
            _issue(
                "malvertising_behavior",
                "critical",
                "browser",
                "Advertising traffic was coupled with a popup or download attempt.",
                f"Ad requests: {len(ad_requests)}; popups: {len(popup_events)}; downloads: {len(downloads)}",
            )
        )
    return issues


INIT_SCRIPT_TEMPLATE = r"""
(() => {
  const TOKENS = Object.values(__CANARY_JSON__).filter(Boolean).map(String);
  const events = [];
  window.__aisecSandboxEvents = events;
  const now = () => Math.round(performance.now());
  const toText = (value) => {
    try {
      if (!value) return "";
      if (value instanceof FormData) {
        return Array.from(value.entries()).map(([k, v]) => `${k}=${String(v)}`).join("&");
      }
      if (value instanceof URLSearchParams) return value.toString();
      if (typeof value === "string") return value;
      if (value instanceof Blob) return "[blob]";
      return JSON.stringify(value);
    } catch (_) {
      return String(value);
    }
  };
  const containsCanary = (value) => {
    const text = toText(value);
    return TOKENS.some((token) => token && text.includes(token));
  };
  const record = (type, detail) => {
    events.push({ type, at_ms: now(), ...detail });
  };

  window.open = function(url) {
    record("popup_open_blocked", { url: String(url || "") });
    return null;
  };
  if (typeof Notification !== "undefined") {
    Notification.requestPermission = function() {
      record("permission_request_blocked", { permission: "notifications" });
      return Promise.resolve("denied");
    };
  }
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    navigator.mediaDevices.getUserMedia = function() {
      record("permission_request_blocked", { permission: "camera_or_microphone" });
      return Promise.reject(new DOMException("Denied by sandbox", "NotAllowedError"));
    };
  }
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition = function(_success, error) {
      record("permission_request_blocked", { permission: "geolocation" });
      if (error) error({ code: 1, message: "Denied by sandbox" });
    };
    navigator.geolocation.watchPosition = function(_success, error) {
      record("permission_request_blocked", { permission: "geolocation" });
      if (error) error({ code: 1, message: "Denied by sandbox" });
      return 0;
    };
  }

  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const body = init && init.body;
    if (containsCanary(url) || containsCanary(body)) {
      record("canary_fetch_attempt", { url: String(url), contains_canary: true });
    }
    return originalFetch.apply(this, arguments);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {
    this.__aisecUrl = String(url || "");
    this.__aisecMethod = String(method || "GET");
    return originalOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    if (containsCanary(this.__aisecUrl) || containsCanary(body)) {
      record("canary_xhr_attempt", {
        url: this.__aisecUrl || "",
        method: this.__aisecMethod || "GET",
        contains_canary: true
      });
    }
    return originalSend.apply(this, arguments);
  };

  const originalBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;
  if (originalBeacon) {
    navigator.sendBeacon = function(url, data) {
      if (containsCanary(url) || containsCanary(data)) {
        record("canary_beacon_blocked", { url: String(url || ""), contains_canary: true });
        return false;
      }
      return originalBeacon(url, data);
    };
  }

  const NativeWebSocket = window.WebSocket;
  class BlockedWebSocket {
    static CONNECTING = NativeWebSocket.CONNECTING;
    static OPEN = NativeWebSocket.OPEN;
    static CLOSING = NativeWebSocket.CLOSING;
    static CLOSED = NativeWebSocket.CLOSED;
    constructor(url) {
      record("websocket_blocked", { url: String(url || "") });
      throw new DOMException("WebSocket blocked by sandbox", "SecurityError");
    }
  }
  window.WebSocket = BlockedWebSocket;

  window.addEventListener("submit", (event) => {
    const form = event.target;
    if (!form || !form.tagName || form.tagName.toLowerCase() !== "form") return;
    let body = "";
    try { body = toText(new FormData(form)); } catch (_) {}
    record("form_submit_blocked", {
      action: form.action || location.href,
      method: (form.method || "GET").toUpperCase(),
      contains_canary: containsCanary(body)
    });
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);

  HTMLFormElement.prototype.submit = function() {
    record("programmatic_form_submit_blocked", {
      action: this.action || location.href,
      method: (this.method || "GET").toUpperCase()
    });
  };
  HTMLFormElement.prototype.requestSubmit = function() {
    const event = new Event("submit", { bubbles: true, cancelable: true });
    this.dispatchEvent(event);
  };
})();
"""


FILL_SCRIPT = r"""
(tokens) => {
  const visibleEnough = (el) => {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
  };
  const textOf = (el) => [
    el.getAttribute("type") || "",
    el.getAttribute("name") || "",
    el.getAttribute("id") || "",
    el.getAttribute("autocomplete") || "",
    el.getAttribute("placeholder") || "",
    el.getAttribute("aria-label") || ""
  ].join(" ").toLowerCase();
  const classify = (el) => {
    const type = (el.getAttribute("type") || "text").toLowerCase();
    const text = textOf(el);
    if (["hidden", "submit", "button", "reset", "checkbox", "radio", "file", "image"].includes(type)) return "";
    if (type === "password" || /pass|password|mat.?khau|mật.?khẩu/.test(text)) return "password";
    if (/otp|2fa|mfa|code|verify|verification|pin|ma.?xac.?minh|xác.?minh/.test(text)) return "otp";
    if (type === "email" || /email|e-mail|mail/.test(text)) return "email";
    if (type === "tel" || /phone|mobile|sdt|so.?dien.?thoai|điện.?thoại/.test(text)) return "phone";
    if (/user|login|account|tai.?khoan|tài.?khoản/.test(text)) return "username";
    return "";
  };
  const values = {
    email: tokens.email,
    username: tokens.username,
    password: tokens.password,
    otp: tokens.otp,
    phone: tokens.phone
  };
  const fields = [];
  for (const el of Array.from(document.querySelectorAll("input, textarea"))) {
    if (el.disabled || el.readOnly || !visibleEnough(el)) continue;
    const kind = classify(el);
    if (!kind || !values[kind]) continue;
    el.focus();
    el.value = values[kind];
    el.dispatchEvent(new InputEvent("input", { bubbles: true, data: values[kind] }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.blur();
    fields.push({
      kind,
      type: el.getAttribute("type") || "",
      name: el.getAttribute("name") || "",
      id: el.getAttribute("id") || "",
      autocomplete: el.getAttribute("autocomplete") || ""
    });
  }
  const forms = Array.from(document.forms).map((form) => {
    let action = form.action || location.href;
    let external = false;
    try { external = new URL(action, location.href).origin !== location.origin; } catch (_) {}
    return {
      action,
      method: (form.method || "GET").toUpperCase(),
      external,
      inputs: form.querySelectorAll("input, textarea, select").length,
      sensitive_inputs: form.querySelectorAll("input[type=password], input[type=tel], input[name*=otp i], input[name*=code i], input[id*=otp i], input[id*=code i]").length
    };
  });
  return { fields, forms };
}
"""


PROBE_FORMS_SCRIPT = r"""
() => {
  const sensitiveForms = Array.from(document.forms).filter((form) =>
    form.querySelector("input[type=password], input[type=tel], input[name*=otp i], input[name*=code i], input[id*=otp i], input[id*=code i]")
  );
  for (const form of sensitiveForms.slice(0, 5)) {
    const event = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(event);
  }
  return { forms: document.forms.length, sensitive_forms: sensitiveForms.length };
}
"""


def _launch_browser(playwright, user_data_dir: str, proxy_server: str):
    launch_args = [
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-notifications",
        "--disable-popup-blocking",
        "--disable-quic",
        "--disable-sync",
        "--dns-prefetch-disable",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    common = {
        "headless": True,
        "args": launch_args,
        "viewport": {"width": 1280, "height": 800},
        "accept_downloads": False,
        "java_script_enabled": True,
        "ignore_https_errors": False,
        "locale": "vi-VN",
        "proxy": {"server": proxy_server},
        "service_workers": "block",
        "user_agent": "AI-Security-Armor-Browser-Sandbox/1.0",
    }
    last_error: Exception | None = None
    for channel in ("chrome", "msedge", None):
        try:
            kwargs = dict(common)
            if channel:
                kwargs["channel"] = channel
            return playwright.chromium.launch_persistent_context(user_data_dir, **kwargs)
        except Exception as exc:  # pragma: no cover - depends on local browsers.
            last_error = exc
    if last_error is not None:
        raise last_error
    raise RuntimeError("No Chromium browser channel is available")


def _completed_result(
    *,
    raw_url: str,
    started: float,
    initial_ip: str,
    canary: dict,
    status_code: int | None,
    final_url: str,
    title: str,
    fill_report: dict,
    probe_report: dict,
    browser_events: list,
    network_events: list[dict],
    download_events: list[dict],
    console_errors: list[str],
    visual_analysis: dict,
    page_identity: dict,
    screenshot_data_url: str,
    base_issues: list[dict] | None = None,
) -> dict:
    fields = fill_report.get("fields", []) if isinstance(fill_report, dict) else []
    field_types = dict(Counter(field.get("kind", "unknown") for field in fields))
    normalized_browser_events = browser_events if isinstance(browser_events, list) else []
    normalized_probe_report = probe_report if isinstance(probe_report, dict) else {}
    issues = list(base_issues or [])
    issues.extend(_status_issue(status_code))
    issues.extend(
        _issues_from_signals(
            fill_report,
            normalized_browser_events,
            network_events,
            canary,
            download_events,
        )
    )
    if visual_analysis.get("brand_mismatch") is True:
        issues.append(
            _issue(
                "visual_brand_impersonation",
                "critical",
                "credential",
                "The page visually matches a curated brand reference on an unofficial domain.",
                (
                    f"Brand={visual_analysis.get('matched_brand')}; "
                    f"similarity={visual_analysis.get('similarity')}"
                ),
            )
        )
        issues.append(
            _issue(
                "forged_brand_image",
                "high",
                "visual",
                "A rendered page image matches a curated brand reference on an unofficial domain.",
                (
                    f"Brand={visual_analysis.get('matched_brand')}; "
                    f"similarity={visual_analysis.get('similarity')}"
                ),
            )
        )
    canary_blocked = any(
        event.get("reason") == "canary_payload_blocked" for event in network_events
    )
    scripted_canary = _event_contains_canary(normalized_browser_events, canary)
    blocked_forms = [
        event
        for event in normalized_browser_events
        if str(event.get("type", "")).endswith("form_submit_blocked")
    ]

    return {
        "ok": True,
        "execution_status": "completed",
        "url": raw_url,
        "final_url": final_url,
        "status_code": status_code,
        "page_title": title,
        "isolation": {
            "mode": "headless_browser",
            "profile": "temporary",
            "network_private_block": True,
            "egress_proxy": "dns_pinned",
            "downloads": "blocked",
            "permissions": "denied",
            "service_workers": "blocked",
            "websockets": "blocked",
            "webrtc_non_proxied_udp": "blocked",
            "initial_resolved_ip": initial_ip,
            "canary_credentials": "synthetic_only",
        },
        "canary": {
            "enabled": True,
            "mode": "dry_run",
            "clone_email": canary["email"],
            "fields_filled": len(fields),
            "field_types": field_types,
            "form_submissions_blocked": len(blocked_forms),
            "exfiltration_blocked": bool(canary_blocked or scripted_canary),
            "notes": [
                "Synthetic clone values were used.",
                f"Sensitive forms probed: {normalized_probe_report.get('sensitive_forms', 0)}",
                "Form submissions were prevented inside the sandbox.",
            ],
        },
        "network_events": network_events,
        "browser_events": normalized_browser_events[:80],
        "console_errors": console_errors[:20],
        "visual_analysis": visual_analysis,
        "page_identity": page_identity,
        "screenshot_data_url": screenshot_data_url,
        "issues": issues,
        "scan_steps": _scan_steps(issues=issues),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def run(payload: dict) -> dict:
    started = time.perf_counter()
    raw_url = str(payload.get("url", ""))
    timeout_ms = min(max(int(payload.get("timeout_ms", 15_000)), 5_000), 30_000)
    canary = _make_canary()
    _write_progress("preflight_public_url")
    current, initial_ip = _preflight_public_url(raw_url)
    root_origin = _origin(current)

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _failure(
            raw_url,
            "browser_engine_unavailable",
            "Install the optional browser dependency: pip install -e .[browser]",
            started,
        )

    network_events: list[dict] = []
    console_errors: list[str] = []
    download_events: list[dict] = []
    issues: list[dict] = []
    completed_result: dict | None = None

    def add_network_event(event: dict) -> None:
        if len(network_events) < MAX_NETWORK_EVENTS:
            network_events.append(event)

    def route_handler(route, request) -> None:
        request_url = request.url
        event = {
            "url": request_url,
            "method": request.method,
            "resource_type": request.resource_type,
            "status": None,
            "blocked": False,
            "reason": "",
            "same_origin": _same_origin(root_origin, request_url),
        }
        try:
            parts = urlsplit(request_url)
            if parts.scheme not in {"http", "https"}:
                event.update({"blocked": True, "reason": "non_http_request_blocked"})
                add_network_event(event)
                route.abort()
                return
            port = parts.port or (443 if parts.scheme == "https" else 80)
            _public_addresses(parts.hostname or "", port)
            post_data = request.post_data
            if _payload_contains_canary(request_url, canary) or _payload_contains_canary(post_data, canary):
                event.update({"blocked": True, "reason": "canary_payload_blocked"})
                add_network_event(event)
                route.abort()
                return
            if len(network_events) >= MAX_NETWORK_EVENTS:
                event.update({"blocked": True, "reason": "network_event_limit"})
                route.abort()
                return
            add_network_event(event)
            route.continue_()
        except PermissionError:
            event.update({"blocked": True, "reason": "private_network_blocked"})
            add_network_event(event)
            route.abort()
        except Exception as exc:
            event.update({"blocked": True, "reason": f"network_guard_error:{type(exc).__name__}"})
            add_network_event(event)
            route.abort()

    def websocket_handler(web_socket) -> None:
        add_network_event(
            {
                "url": web_socket.url,
                "method": "WEBSOCKET",
                "resource_type": "websocket",
                "status": None,
                "blocked": True,
                "reason": "websocket_blocked",
                "same_origin": _same_origin(root_origin, web_socket.url),
            }
        )
        web_socket.close(code=1008, reason="Blocked by browser sandbox")

    def download_handler(download) -> None:
        try:
            download_events.append(
                {
                    "filename": str(download.suggested_filename or "")[:240],
                    "url": str(download.url or "")[:1000],
                }
            )
            download.cancel()
        except Exception:
            return

    try:
        _write_progress("start_egress_proxy")
        with _PinnedEgressProxy() as egress_proxy:
            _write_progress("create_browser_profile")
            with tempfile.TemporaryDirectory(prefix="aisec-browser-sandbox-") as profile_dir:
                _write_progress("start_playwright")
                with sync_playwright() as pw:
                    _write_progress("launch_browser")
                    context = _launch_browser(pw, profile_dir, egress_proxy.url)
                    _write_progress("install_browser_guards")
                    context.set_default_timeout(timeout_ms)
                    context.route("**/*", route_handler)
                    context.route_web_socket("**/*", websocket_handler)
                    context.add_init_script(
                        INIT_SCRIPT_TEMPLATE.replace("__CANARY_JSON__", json.dumps(canary))
                    )
                    page = context.pages[0] if context.pages else context.new_page()
                    page.on(
                        "console",
                        lambda msg: console_errors.append(msg.text[:500])
                        if msg.type in {"error", "warning"}
                        else None,
                    )
                    page.on("pageerror", lambda exc: console_errors.append(str(exc)[:500]))
                    page.on("download", download_handler)
                    page.on(
                        "requestfailed",
                        lambda request: add_network_event(
                            {
                                "url": request.url,
                                "method": request.method,
                                "resource_type": request.resource_type,
                                "status": None,
                                "blocked": True,
                                "reason": _request_failure_text(request),
                                "same_origin": _same_origin(root_origin, request.url),
                            }
                        ),
                    )
                    _write_progress("navigate_page")
                    response = page.goto(current, wait_until="domcontentloaded", timeout=timeout_ms)
                    _write_progress("inspect_page")
                    try:
                        page.wait_for_load_state("networkidle", timeout=2_500)
                    except PlaywrightTimeoutError:
                        pass

                    status_code = response.status if response is not None else None
                    fill_report = page.evaluate(FILL_SCRIPT, canary)
                    probe_report = page.evaluate(PROBE_FORMS_SCRIPT)
                    try:
                        page.wait_for_timeout(1_000)
                    except PlaywrightError:
                        pass
                    browser_events = page.evaluate("window.__aisecSandboxEvents || []")
                    title = page.title()[:200]
                    final_url = page.url
                    page_identity = page.evaluate(
                        """() => {
                            const meta = (selector) => document.querySelector(selector)?.content?.trim() || "";
                            const text = (document.body?.innerText || "").slice(0, 200000);
                            const folded = text.toLowerCase();
                            const phones = Array.from(new Set((text.match(/(?:\\+?84|0)(?:[ .-]?\\d){8,10}/g) || [])
                                .map((value) => value.replace(/\\s+/g, " ").trim()))).slice(0, 8);
                            const emails = Array.from(new Set((text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/gi) || [])
                                .map((value) => value.toLowerCase()))).slice(0, 8);
                            const hrefs = Array.from(document.querySelectorAll('a[href]')).map((node) => ({
                                href: node.href || "",
                                label: (node.innerText || node.getAttribute('aria-label') || "").trim().slice(0, 120),
                            }));
                            const socialHosts = ['facebook.com', 'instagram.com', 'linkedin.com', 'tiktok.com', 'youtube.com', 'x.com', 'twitter.com', 'zalo.me'];
                            const social_links = hrefs.filter((item) => socialHosts.some((host) => item.href.toLowerCase().includes(host))).slice(0, 12);
                            const support_links = hrefs.filter((item) => /^(mailto:|tel:)/i.test(item.href) || /contact|support|help|lien he|ho tro|hotline/i.test(item.label + ' ' + item.href)).slice(0, 12);
                            const paymentTerms = ['bank transfer', 'wire transfer', 'crypto', 'bitcoin', 'usdt', 'gift card', 'credit card', 'debit card', 'cash on delivery', 'cod', 'chuyen khoan', 'thanh toan'];
                            const payment_methods = paymentTerms.filter((term) => folded.includes(term));
                            const prices = (text.match(/(?:[$€£¥]|vnd|usd|eur|đ|dong)\\s?\\d[\\d.,]*|\\d[\\d.,]*\\s?(?:vnd|usd|eur|đ|dong)/gi) || []).slice(0, 20);
                            const recipient_hints = (text.match(/(?:account|stk|so tai khoan|wallet|vi)\\s*(?:number|no|:|-)?\\s*[A-Z0-9]{8,34}/gi) || []).slice(0, 8);
                            const address_terms = (text.match(/(?:address|dia chi|registered office|head office)\\s*[:-]?\\s*[^\\n]{8,160}/gi) || []).slice(0, 8);
                            const complaint_terms = ['scam', 'fraud', 'lua dao', 'khieu nai', 'complaint', 'not received', 'mat tien'].filter((term) => folded.includes(term));
                            const reviewNodes = Array.from(document.querySelectorAll('[itemprop="review"], [itemprop="ratingValue"], .review, .reviews, .testimonial, [class*="rating" i]'));
                            const rating_mentions = (text.match(/(?:[1-5](?:\\.\\d)?\\s*[/]\\s*5|[1-5](?:\\.\\d)?\\s*(?:stars?|sao))/gi) || []).slice(0, 30);
                            const legal_names = [];
                            const addresses = [...address_terms];
                            const ratings = [];
                            const visit = (value) => {
                                if (!value || typeof value !== 'object') return;
                                if (Array.isArray(value)) { value.forEach(visit); return; }
                                const type = String(value['@type'] || '').toLowerCase();
                                if (/organization|corporation|localbusiness|store|financialservice/.test(type)) {
                                    const name = String(value.legalName || value.name || '').trim();
                                    if (name) legal_names.push(name.slice(0, 200));
                                    const address = value.address;
                                    if (typeof address === 'string') addresses.push(address.slice(0, 240));
                                    else if (address && typeof address === 'object') addresses.push(Object.values(address).filter((part) => typeof part === 'string').join(', ').slice(0, 240));
                                }
                                const rating = value.aggregateRating || value.reviewRating;
                                if (rating && typeof rating === 'object') ratings.push({ value: rating.ratingValue || '', count: rating.reviewCount || rating.ratingCount || '' });
                                if (Array.isArray(value['@graph'])) value['@graph'].forEach(visit);
                            };
                            for (const node of document.querySelectorAll('script[type="application/ld+json"]')) {
                                try { visit(JSON.parse(node.textContent || 'null')); } catch (_) {}
                            }
                            const commercial = prices.length > 0 || payment_methods.length > 0 || recipient_hints.length > 0 || /add to cart|buy now|checkout|mua ngay|gio hang/.test(folded);
                            const image_hosts = Array.from(new Set(Array.from(document.images).map((image) => { try { return new URL(image.currentSrc || image.src, location.href).hostname; } catch (_) { return ''; } }).filter(Boolean))).slice(0, 20);
                            const script_hosts = Array.from(new Set(Array.from(document.scripts).map((script) => { try { return script.src ? new URL(script.src, location.href).hostname : ''; } catch (_) { return ''; } }).filter(Boolean))).slice(0, 20);
                            return {
                                description: meta('meta[name="description"]'),
                                site_name: meta('meta[property="og:site_name"]'),
                                image_url: meta('meta[property="og:image"]'),
                                canonical_url: document.querySelector('link[rel="canonical"]')?.href || "",
                                language: document.documentElement.lang || "",
                                phones,
                                emails,
                                forms: document.forms.length,
                                password_fields: document.querySelectorAll('input[type="password"]').length,
                                legal_names: Array.from(new Set(legal_names)).slice(0, 8),
                                addresses: Array.from(new Set(addresses.filter(Boolean))).slice(0, 8),
                                social_links,
                                support_links,
                                is_commercial: commercial,
                                prices,
                                payment_methods,
                                payment_recipient_hints: recipient_hints,
                                review_elements: reviewNodes.length,
                                rating_mentions,
                                structured_ratings: ratings.slice(0, 8),
                                complaint_terms,
                                image_count: document.images.length,
                                image_hosts,
                                script_count: document.scripts.length,
                                script_hosts,
                                content_sample: text.replace(/\\s+/g, ' ').trim().slice(0, 80000),
                            };
                        }"""
                    )
                    content_sample = str(page_identity.pop("content_sample", ""))
                    page_identity["content_fingerprint"] = (
                        hashlib.sha256(content_sample.encode("utf-8")).hexdigest()
                        if content_sample
                        else ""
                    )
                    _write_progress("capture_screenshot")
                    screenshot = page.screenshot(type="jpeg", quality=55, full_page=False)
                    screenshot_data_url = "data:image/jpeg;base64," + base64.b64encode(screenshot).decode("ascii")
                    _write_progress("analyze_visual_hash")
                    visual_analysis = analyze_visual_hash(
                        screenshot,
                        host=urlsplit(final_url).hostname or "",
                        title=title,
                        registry_path=os.environ.get("BRAND_VISUAL_HASH_REGISTRY"),
                    )
                    for event in egress_proxy.events:
                        if event.get("blocked"):
                            add_network_event(event)
                    completed_result = _completed_result(
                        raw_url=raw_url,
                        started=started,
                        initial_ip=initial_ip,
                        canary=canary,
                        status_code=status_code,
                        final_url=final_url,
                        title=title,
                        fill_report=fill_report,
                        probe_report=probe_report,
                        browser_events=browser_events,
                        network_events=network_events,
                        download_events=download_events,
                        console_errors=console_errors,
                        visual_analysis=visual_analysis,
                        page_identity=page_identity,
                        screenshot_data_url=screenshot_data_url,
                        base_issues=issues,
                    )
                    _write_progress("write_result_checkpoint")
                    _write_result_checkpoint(completed_result)
                    _write_progress("close_browser_context")
                    context.close()
                    _write_progress("browser_context_closed")
    except PlaywrightTimeoutError as exc:
        return _failure(raw_url, "browser_navigation_failed", f"Timeout: {exc}", started)
    except PlaywrightError as exc:
        return _failure(raw_url, "browser_navigation_failed", str(exc), started)

    _write_progress("serialize_result")
    if completed_result is None:
        return _failure(
            raw_url,
            "browser_sandbox_error",
            "Browser inspection finished without a completed result.",
            started,
        )
    return completed_result


def main() -> None:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    started = time.perf_counter()
    raw_url = ""
    try:
        payload = json.loads(sys.stdin.read())
        raw_url = str(payload.get("url", ""))
        result = run(payload)
    except PermissionError as exc:
        result = _failure(raw_url, "private_network_blocked", str(exc), started)
    except socket.gaierror as exc:
        result = _failure(raw_url, "dns_error", str(exc), started)
    except ValueError as exc:
        result = _failure(raw_url, str(exc), str(exc), started)
    except Exception as exc:
        result = _failure(raw_url, "browser_sandbox_error", f"{type(exc).__name__}: {exc}", started)
    _write_progress("write_result")
    result_path = os.environ.get("AISEC_BROWSER_RESULT_PATH")
    if result_path:
        _write_result_checkpoint(result)
    else:
        # Keep the stdout protocol for direct/manual worker execution.
        sys.stdout.write(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
