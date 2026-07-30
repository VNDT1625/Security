from __future__ import annotations

import socket
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from security.free_web_sandbox import (
    CanaryField,
    FreeBrowserSession,
    FreeWebSandboxManager,
)


def make_session(page: object, *, token: str = "ABC123") -> FreeBrowserSession:
    return FreeBrowserSession(
        playwright=SimpleNamespace(stop=lambda: None),
        browser=SimpleNamespace(close=lambda: None),
        context=SimpleNamespace(close=lambda: None),
        page=page,
        expires_at=datetime.utcnow() + timedelta(minutes=1),
        canary_token=token,
    )


def test_free_sandbox_rejects_private_ip() -> None:
    with pytest.raises(PermissionError):
        FreeWebSandboxManager.assert_public_url("http://127.0.0.1/admin")


def test_free_sandbox_normalizes_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )
    assert FreeWebSandboxManager.assert_public_url("example.com") == "https://example.com/"


def test_free_sandbox_only_allows_navigation_keys() -> None:
    manager = FreeWebSandboxManager()
    with pytest.raises(ValueError):
        manager.key("missing", "Control+O")


def test_expired_session_closes_without_resubmitting_to_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = FreeWebSandboxManager()
    session_id = "expired-session"
    manager._sessions[session_id] = SimpleNamespace(
        expires_at=datetime.utcnow() - timedelta(seconds=1)
    )
    closed: list[str] = []
    monkeypatch.setattr(manager, "_close", lambda value: closed.append(value))

    with pytest.raises(TimeoutError, match="free_browser_session_expired"):
        manager._get(session_id)

    assert closed == [session_id]


def test_type_text_replaces_real_input_with_per_session_canary() -> None:
    manager = FreeWebSandboxManager()
    session_id = "typing-session"
    applied: list[dict[str, str]] = []
    keyboard_typed: list[str] = []

    def evaluate(_script: str, argument: object = None) -> object:
        if argument is None:
            return {
                "fieldId": "password-field",
                "tag": "input",
                "type": "password",
                "name": "password",
                "autocomplete": "current-password",
                "placeholder": "Mật khẩu",
                "ariaLabel": "",
                "inputMode": "",
            }
        assert isinstance(argument, dict)
        applied.append(argument)
        return True

    page = SimpleNamespace(
        evaluate=evaluate,
        keyboard=SimpleNamespace(type=lambda value: keyboard_typed.append(value)),
        url="https://example.com/login",
        title=lambda: "Login form",
        screenshot=lambda **kwargs: b"image",
    )
    manager._sessions[session_id] = make_session(page)

    state = manager.type_text(session_id, "my-real-password")

    assert keyboard_typed == []
    assert applied and applied[0]["fieldId"] == "password-field"
    replacement = applied[0]["value"]
    assert replacement.startswith("Pw-SBX-ABC123-")
    assert "my-real-password" not in repr(applied)
    assert state["protection"]["realInputSent"] is False
    assert state["lastEvent"]["type"] == "input_substituted"
    assert state["lastEvent"]["replacement"] == replacement


def test_canary_submission_records_destination_without_original_input() -> None:
    manager = FreeWebSandboxManager()
    page = SimpleNamespace(url="https://bank.example/login")
    session = make_session(page)
    session.canary_fields["password-field"] = CanaryField(
        kind="password",
        value="Pw-SBX-ABC123-1!",
    )
    request = SimpleNamespace(
        url="https://collector.example/submit",
        method="POST",
        post_data="username=test&password=Pw-SBX-ABC123-1%21",
    )

    manager._observe_canary_request(session, request)

    assert len(session.events) == 1
    event = session.events[0]
    assert event["type"] == "canary_submission"
    assert event["destination"] == "collector.example"
    assert event["crossDomain"] is True
    assert event["fieldTypes"] == ["password"]
    assert "real-password" not in repr(event)


def test_submit_click_is_observed_before_canary_form_is_sent() -> None:
    manager = FreeWebSandboxManager()
    session_id = "submit-session"
    clicked: list[tuple[float, float]] = []
    page = SimpleNamespace(
        evaluate=lambda _script, _argument=None: {
            "href": "",
            "download": False,
            "filename": "",
            "text": "Đăng nhập",
            "isSubmit": True,
            "formAction": "https://collector.example/login",
            "formMethod": "POST",
            "fieldIds": ["password-field"],
        },
        mouse=SimpleNamespace(click=lambda x, y: clicked.append((x, y))),
        wait_for_timeout=lambda _milliseconds: None,
        url="https://bank.example/login",
        title=lambda: "Login",
        screenshot=lambda **kwargs: b"image",
    )
    session = make_session(page)
    session.canary_fields["password-field"] = CanaryField(
        kind="password",
        value="Pw-SBX-ABC123-1!",
    )
    manager._sessions[session_id] = session

    state = manager.click(session_id, 320, 240)

    assert clicked == [(320, 240)]
    assert state["lastEvent"]["type"] == "form_submission_attempt"
    assert state["lastEvent"]["destination"] == "collector.example"
    assert state["lastEvent"]["crossDomain"] is True


def test_clicking_download_link_is_blocked_before_page_click() -> None:
    manager = FreeWebSandboxManager()
    session_id = "download-session"
    clicked: list[tuple[float, float]] = []

    page = SimpleNamespace(
        evaluate=lambda _script, _argument=None: {
            "href": "https://files.example/invoice.exe",
            "download": False,
            "filename": "",
            "text": "Tải hóa đơn",
        },
        mouse=SimpleNamespace(click=lambda x, y: clicked.append((x, y))),
        wait_for_timeout=lambda _milliseconds: None,
        url="https://shop.example/invoice",
        title=lambda: "Invoice",
        screenshot=lambda **kwargs: b"image",
    )
    manager._sessions[session_id] = make_session(page)

    state = manager.click(session_id, 200, 120)

    assert clicked == []
    assert state["protection"]["downloadsBlocked"] == 1
    assert state["lastEvent"]["type"] == "download_blocked"
    assert state["lastEvent"]["destination"] == "files.example"
    assert state["lastEvent"]["blocked"] is True


def test_real_playwright_page_receives_canary_not_original_text() -> None:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("Playwright is not installed")

    playwright = sync_playwright().start()
    try:
        try:
            browser = playwright.chromium.launch(headless=True)
        except PlaywrightError:
            pytest.skip("Playwright Chromium is not installed")
        context = browser.new_context()
        page = context.new_page()
        page.set_content(
            '<form><input id="password" type="password" name="password">'
            '<button type="submit">Send</button></form>'
        )
        page.focus("#password")
        manager = FreeWebSandboxManager()
        manager._sessions["playwright-smoke"] = FreeBrowserSession(
            playwright=playwright,
            browser=browser,
            context=context,
            page=page,
            expires_at=datetime.utcnow() + timedelta(minutes=1),
            canary_token="ABC123",
        )

        state = manager._type_text("playwright-smoke", "REAL_SECRET")
        field_value = page.input_value("#password")

        assert field_value.startswith("Pw-SBX-ABC123-")
        assert "REAL_SECRET" not in field_value
        assert state["lastEvent"]["type"] == "input_substituted"
    finally:
        session = locals().get("manager")
        if session is not None:
            session._sessions.pop("playwright-smoke", None)
        context_value = locals().get("context")
        if context_value is not None:
            context_value.close()
        browser_value = locals().get("browser")
        if browser_value is not None:
            browser_value.close()
        playwright.stop()


def test_download_request_is_aborted_and_reported() -> None:
    manager = FreeWebSandboxManager()
    page = SimpleNamespace(url="https://shop.example")
    session = make_session(page)
    actions: list[str] = []
    route = SimpleNamespace(
        abort=lambda: actions.append("abort"),
        continue_=lambda: actions.append("continue"),
    )
    request = SimpleNamespace(
        url="https://files.example/setup.msi",
        method="GET",
        post_data=None,
        resource_type="document",
        is_navigation_request=lambda: True,
    )
    manager.assert_public_url = lambda value: value  # type: ignore[method-assign]

    manager._guard_request(session, route, request)

    assert actions == ["abort"]
    assert session.events[-1]["type"] == "download_blocked"
    assert session.events[-1]["filename"] == "setup.msi"


def test_binary_post_data_cannot_break_route_handler() -> None:
    manager = FreeWebSandboxManager()
    page = SimpleNamespace(url="https://example.com/form")
    session = make_session(page)
    actions: list[str] = []
    route = SimpleNamespace(
        abort=lambda: actions.append("abort"),
        continue_=lambda: actions.append("continue"),
    )

    class BinaryRequest:
        url = "https://example.com/telemetry"
        method = "POST"
        resource_type = "fetch"
        is_navigation_request = False

        @property
        def post_data(self) -> str:
            raise UnicodeDecodeError("utf-8", b"\x9c", 0, 1, "invalid start byte")

    manager.assert_public_url = lambda value: value  # type: ignore[method-assign]

    manager._guard_request(session, route, BinaryRequest())

    assert actions == ["continue"]


def test_observation_failure_does_not_fail_page_request(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = FreeWebSandboxManager()
    page = SimpleNamespace(url="https://example.com/form")
    session = make_session(page)
    actions: list[str] = []
    route = SimpleNamespace(
        abort=lambda: actions.append("abort"),
        continue_=lambda: actions.append("continue"),
    )
    request = SimpleNamespace(
        url="https://example.com/api",
        method="POST",
        post_data="payload",
        resource_type="fetch",
        is_navigation_request=False,
    )
    manager.assert_public_url = lambda value: value  # type: ignore[method-assign]
    monkeypatch.setattr(
        manager,
        "_observe_canary_request",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("observer failed")),
    )

    manager._guard_request(session, route, request)

    assert actions == ["continue"]


def test_auto_explore_fills_canary_and_reports_form_destination() -> None:
    manager = FreeWebSandboxManager()
    session_id = "auto-explore-session"
    applied: list[dict[str, str]] = []
    submitted: list[int] = []

    def evaluate(script: str, argument: object = None) -> object:
        if "const visible" in script:
            return {
                "forms": [
                    {
                        "formId": "prewise-auto-form-0",
                        "formIndex": 0,
                        "formAction": "https://collector.example/login",
                        "formMethod": "POST",
                        "fields": [
                            {
                                "fieldId": "email-field",
                                "tag": "input",
                                "type": "email",
                                "name": "email",
                                "autocomplete": "email",
                                "placeholder": "Email",
                                "ariaLabel": "",
                                "inputMode": "",
                            },
                            {
                                "fieldId": "password-field",
                                "tag": "input",
                                "type": "password",
                                "name": "password",
                                "autocomplete": "current-password",
                                "placeholder": "Password",
                                "ariaLabel": "",
                                "inputMode": "",
                            },
                        ],
                    }
                ],
                "downloads": [
                    {
                        "url": "https://files.example/setup.exe",
                        "filename": "setup.exe",
                        "text": "Download",
                    }
                ],
            }
        assert isinstance(argument, dict)
        if "fieldId" in argument:
            applied.append(argument)
            return True
        if "formIndex" in argument:
            submitted.append(int(argument["formIndex"]))
            return True
        return False

    page = SimpleNamespace(
        evaluate=evaluate,
        wait_for_timeout=lambda _milliseconds: None,
        url="https://bank.example/login",
        title=lambda: "Login",
        screenshot=lambda **kwargs: b"image",
    )
    session = make_session(page)
    session.navigation_history.append(page.url)
    manager._sessions[session_id] = session

    state = manager.auto_explore(session_id)

    assert len(applied) == 2
    assert submitted == [0]
    assert state["investigation"]["automationStatus"] == "completed"
    assert state["investigation"]["forms"][0]["destination"] == "collector.example"
    assert state["investigation"]["downloads"][0]["filename"] == "setup.exe"
    assert state["investigation"]["riskScore"] >= 35
    assert "REAL_SECRET" not in repr(applied)
