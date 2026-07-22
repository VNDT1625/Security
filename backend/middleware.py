"""Gateway middleware: input sanitization + token-bucket rate limiting.

- Input Sanitization Layer (required.md §9): Unicode NFC + zero-width strip applied
  uniformly to Extension and MCP input.
- Rate limiting (VULN-5.3): 60 req/min/IP default, separate concern from auth.
"""

from __future__ import annotations

import time
import unicodedata
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.config import settings

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


class RequestBodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Reject oversized upload bodies before multipart parsing/spooling."""

    def __init__(
        self,
        app,
        *,
        max_body_bytes: int,
        paths: tuple[str, ...] = (),
        exact_paths: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.max_body_bytes = max(1, int(max_body_bytes))
        self.paths = paths
        self.exact_paths = exact_paths

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        request_path = str(scope.get("path", ""))
        protected = request_path in self.exact_paths or any(
            request_path.startswith(path) for path in self.paths
        )
        if scope.get("type") != "http" or not protected:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                content_length = int(raw_length)
                if content_length < 0:
                    raise ValueError
                if content_length > self.max_body_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})(
                    scope, receive, send
                )
                return

        received = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send) -> None:
        await JSONResponse(
            status_code=413,
            content={"detail": "Request body too large"},
        )(scope, receive, send)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        if settings.app_env == "production":
            # TLS is terminated by the production reverse proxy. HSTS still
            # belongs on API responses so browsers cannot later downgrade the
            # public origin to cleartext HTTP.
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        if request.url.path.startswith(
            (
                "/v1/assess",
                "/v1/auth",
                "/v1/account",
                "/v1/admin",
                "/v1/feedback",
                "/v1/integrations/gmail",
                "/v1/report-shares",
                "/v1/sandbox-cloud",
            )
        ):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response


def sanitize_text(text: str) -> str:
    """NFC normalize + strip zero-width characters."""
    if not isinstance(text, str):
        return text
    return unicodedata.normalize("NFC", text).translate(_ZERO_WIDTH)


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_min: int = 60):
        super().__init__(app)
        self.limit = limit_per_min
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._last_prune = time.time()

    def _prune_stale_buckets(self, now: float) -> None:
        """Bound memory when many short-lived client addresses hit the service."""

        if now - self._last_prune < 60:
            return
        cutoff = now - 60
        for client, bucket in list(self._buckets.items()):
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                self._buckets.pop(client, None)
        self._last_prune = now

    async def dispatch(self, request: Request, call_next):
        if (
            not (
                settings.app_env == "development"
                and settings.local_testing_unlimited
            )
            and request.url.path.startswith("/v1/")
            and request.url.path != "/v1/health"
        ):
            client = request.client.host if request.client else "unknown"
            now = time.time()
            self._prune_stale_buckets(now)
            bucket = self._buckets[client]
            while bucket and now - bucket[0] > 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = max(1, int(61 - (now - bucket[0])))
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limited",
                        "detail": "Quá số yêu cầu cho phép",
                        "retry_after": retry_after,
                    },
                    headers={"Retry-After": str(retry_after)},
                )
            bucket.append(now)
        return await call_next(request)
