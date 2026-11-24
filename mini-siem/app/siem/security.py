"""HTTP hardening: security headers, rate limiting, CSRF and session tokens."""
from __future__ import annotations

import asyncio
import ipaddress
import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from threading import Lock
from starlette.datastructures import MutableHeaders

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

SESSION_COOKIE = "__Host-siem"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware:
    """Wrap the entire ASGI stack, including framework-generated errors."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def hardened_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    headers[k] = v
                if "server" in headers:
                    del headers["server"]
            await send(message)
        await self.app(scope, receive, hardened_send)



class RateLimiter:
    """Per-key token bucket with a hard memory bound. One app process per container.

    * O(1) memory per key (two floats in a fixed-slot object) instead of one entry
      per request: the Phase 0/0.2 sliding-window deques reached ~107 MB at the
      10,000-key cap under a flood.
    * Idle keys expire automatically (a key whose bucket has fully refilled carries
      no information and is dropped, oldest first).
    * When the table is full of *active* keys, new keys share one strict overflow
      bucket instead of being refused outright. The earlier fail-closed behaviour
      let anyone with 10,000 source addresses (one IPv6 /64 is enough) lock every
      new client, including administrators, out of the login page.
    * Thread-safe; the critical section never awaits.

    The limiter is in-process because Phase 0 runs exactly one app worker. Caddy and
    nftables bound connection rates in front of it; a distributed limiter would only
    be needed with several app replicas (documented in SECURITY_ARCHITECTURE.md).
    """

    __slots__ = ("rate", "burst", "max_keys", "buckets", "overflow", "lock")
    MAX_KEYS = 20_000

    class _Bucket:
        __slots__ = ("tokens", "stamp")

        def __init__(self, tokens: float, stamp: float) -> None:
            self.tokens, self.stamp = tokens, stamp

    def __init__(self, limit: int, window_seconds: int, max_keys: int | None = None) -> None:
        self.burst = float(limit)
        self.rate = limit / float(window_seconds)          # tokens per second
        self.max_keys = max_keys or self.MAX_KEYS
        self.buckets: OrderedDict[str, RateLimiter._Bucket] = OrderedDict()
        self.overflow = RateLimiter._Bucket(self.burst, time.monotonic())
        self.lock = Lock()

    def _take(self, b: "RateLimiter._Bucket", now: float) -> bool:
        b.tokens = min(self.burst, b.tokens + max(0.0, now - b.stamp) * self.rate)
        b.stamp = now
        if b.tokens < 1.0:
            return False
        b.tokens -= 1.0
        return True

    def _expire(self, now: float) -> None:
        full_after = self.burst / self.rate
        while self.buckets:
            oldest = next(iter(self.buckets.values()))
            if now - oldest.stamp < full_after:
                break
            self.buckets.popitem(last=False)

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            self._expire(now)
            b = self.buckets.get(key)
            if b is None:
                if len(self.buckets) >= self.max_keys:
                    return self._take(self.overflow, now)
                b = self.buckets[key] = RateLimiter._Bucket(self.burst, now)
            self.buckets.move_to_end(key)
            return self._take(b, now)

    def __len__(self) -> int:
        return len(self.buckets)


def client_key(host: str | None) -> str:
    """Rate-limit identity. IPv6 clients are grouped per /64 (one subscriber/LAN)."""
    if not host:
        return "unknown"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "invalid"
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Strict limit on authentication paths, looser limit on everything else."""

    def __init__(self, app, auth_limit: int = 20, general_limit: int = 300) -> None:
        super().__init__(app)
        self.auth = RateLimiter(auth_limit, 60)
        self.general = RateLimiter(general_limit, 60)

    async def dispatch(self, request: Request, call_next) -> Response:
        ip = client_key(request.client.host if request.client else None)
        limiter = self.auth if request.url.path.startswith("/auth") else self.general
        if not limiter.allow(ip):
            return PlainTextResponse("Too many requests", status_code=429,
                                     headers={"Retry-After": "60"})
        return await call_next(request)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def csrf_ok(expected: str, provided: str | None) -> bool:
    return bool(provided) and len(provided) <= 100 and hmac.compare_digest(expected.encode(), provided.encode())


class RequestBoundaryMiddleware:
    """Bound form bodies even when a client reaches ASGI without Caddy.

    Phase 0 has only browser URL-encoded POST forms. Reject other media types,
    cross-origin requests and ambiguous framing before application parsing.
    """
    def __init__(self, app, origin: str, max_body: int = 16384):
        self.app, self.origin, self.max_body = app, origin.encode(), max_body

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        method = scope['method']
        headers = scope['headers']
        def values(name):
            return [v for k, v in headers if k == name]
        async def reject(status, text):
            await PlainTextResponse(text, status_code=status)(scope, receive, send)
        lengths = values(b'content-length')
        if len(lengths) > 1 or (lengths and values(b'transfer-encoding')):
            return await reject(400, 'Ambiguous body framing')
        if lengths:
            if not lengths[0].isdigit() or len(lengths[0]) > 10:
                return await reject(400, 'Invalid content length')
            if int(lengths[0]) > self.max_body:
                return await reject(413, 'Request too large')
        if method not in ('GET', 'HEAD', 'POST'):
            return await reject(405, 'Method not allowed')
        if method == 'POST':
            if values(b'origin') != [self.origin]:
                return await reject(403, 'Invalid request origin')
            content_types = values(b'content-type')
            if len(content_types) != 1 or content_types[0].split(b';', 1)[0].strip().lower() != b'application/x-www-form-urlencoded':
                return await reject(415, 'Unsupported media type')
        # Also enforce actual streamed bytes; no unbounded multipart or chunked reads.
        body = bytearray()
        try:
            async with asyncio.timeout(10):
                while True:
                    msg = await receive()
                    if msg['type'] == 'http.disconnect':
                        return
                    part = msg.get('body', b'')
                    if len(body) + len(part) > self.max_body:
                        return await reject(413, 'Request too large')
                    body.extend(part)
                    if not msg.get('more_body', False):
                        break
        except TimeoutError:
            return await reject(408, 'Request timeout')
        if lengths and len(body) != int(lengths[0]):
            return await reject(400, 'Invalid content length')
        if method in ('GET', 'HEAD') and body:
            return await reject(400, 'Unexpected request body')
        delivered = False
        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
        await self.app(scope, replay, send)
