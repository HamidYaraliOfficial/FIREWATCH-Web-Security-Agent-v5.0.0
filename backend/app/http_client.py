from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping
from urllib.parse import urlparse

import httpx

from .config import settings
from .scope import ScopePolicy


_AUTH_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-session-token", "authentication",
}
_ALWAYS_BLOCKED_HEADERS = {
    "proxy-authorization", "proxy-connection", "host", "content-length",
    "transfer-encoding", "connection", "upgrade", "te", "trailer",
}


def _is_credential_header(name: str) -> bool:
    low = name.strip().lower()
    return (
        low in _AUTH_HEADER_NAMES
        or low.startswith("x-auth-")
        or low.endswith("-token")
        or "api-key" in low
        or "client-secret" in low
        or "session-id" in low
    )


@dataclass
class HTTPObservation:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    content_type: str
    body_sha256: str
    error: str | None = None
    set_cookies: list[str] | None = None


class SafeHTTPClient:
    """Scoped HTTP client with conservative pacing and root-host credential isolation.

    Authentication material is sent only to the exact hostname in the root URL.
    Additional in-scope hosts can still be discovered, but credentials are not
    forwarded to them. Redirects are never followed automatically.
    """

    def __init__(self, scope: ScopePolicy, timeout: float | None = None,
                 delay_ms: int | None = None, headers: Mapping[str, str] | None = None):
        self.scope = scope
        self.timeout = timeout or settings.request_timeout_seconds
        self.delay_ms = settings.request_delay_ms if delay_ms is None else delay_ms
        self.headers = dict(headers or {})
        root = urlparse(scope.root_url)
        self.root_host = (root.hostname or "").lower().rstrip(".")
        self.root_scheme = root.scheme.lower()
        self.client: httpx.AsyncClient | None = None
        self._last_request_at = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        base = {
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/json,text/plain,application/xml,*/*",
        }
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers=base,
            verify=True,
            trust_env=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        return self

    async def __aexit__(self, *_):
        if self.client:
            await self.client.aclose()

    async def _throttle(self):
        requested = max(0, self.delay_ms)
        effective = requested if self.scope.allow_private_targets else max(50, requested)
        gap = effective / 1000.0
        async with self._lock:
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < gap:
                await asyncio.sleep(gap - elapsed)
            self._last_request_at = time.monotonic()

    def _headers_for(self, url: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        merged: dict[str, tuple[str, str]] = {}
        for source in (self.headers, extra or {}):
            for key, value in source.items():
                low = str(key).strip().lower()
                if not low or low in _ALWAYS_BLOCKED_HEADERS:
                    continue
                merged[low] = (str(key), str(value))
        parsed = urlparse(url)
        request_host = (parsed.hostname or "").lower().rstrip(".")
        same_root_host = request_host == self.root_host
        same_root_scheme = parsed.scheme.lower() == self.root_scheme
        secure_channel = parsed.scheme.lower() == "https" or self.scope.allow_private_targets
        credentials_allowed = same_root_host and same_root_scheme and secure_channel
        result = {}
        for low, (original, value) in merged.items():
            if _is_credential_header(low) and not credentials_allowed:
                continue
            result[original] = value
        return result

    async def request(self, method: str, url: str,
                      headers: Mapping[str, str] | None = None,
                      content: str | bytes | None = None) -> HTTPObservation:
        if not self.client:
            raise RuntimeError("SafeHTTPClient must be used as an async context manager")
        clean = self.scope.validate_url(url)
        await self._throttle()
        start = time.perf_counter()
        try:
            resp = await self.client.request(
                method.upper(), clean,
                headers=self._headers_for(clean, headers),
                content=content,
            )
            elapsed = (time.perf_counter() - start) * 1000
            body = resp.text[:2_000_000]
            cookies = resp.headers.get_list("set-cookie")
            normalized = {k.lower(): v for k, v in resp.headers.items()}
            if cookies:
                normalized["set-cookie"] = "\n".join(cookies)
            return HTTPObservation(
                clean, str(resp.url), resp.status_code, normalized, body,
                round(elapsed, 2), resp.headers.get("content-type", ""),
                sha256(body.encode("utf-8", "replace")).hexdigest(), None, cookies,
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            # Exception strings can include URLs/query values; do not persist them verbatim.
            return HTTPObservation(
                clean, clean, 0, {}, "", round(elapsed, 2), "",
                sha256(b"").hexdigest(), type(exc).__name__, None,
            )
