"""Security middleware: CSP and headers, request logging, rate limiting, CSRF.

The middleware is pure ASGI, so it sees WebSocket scopes too and never buffers a body.
The request log leaves out client IPs and query strings. Over Tor there is nothing useful
to subpoena there anyway.
"""

import hashlib
import hmac
import secrets
import time
import uuid
from http.cookies import SimpleCookie

import jwt
import structlog
from fastapi import HTTPException, Request, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings

log = structlog.get_logger()

# There is no body sanitiser here. Injection is handled further in: SQLAlchemy sends
# parameterised queries, Jinja escapes output, the CSP blocks inline script and eval, and
# Pydantic checks shapes and lengths before anything reaches the database. A regex pass over
# every request body would give a false sense of safety and would mangle the base64
# ciphertext this market stores. See docs/security/THREAT-MODEL.md and
# tests/security/test_security.py.

ACCESS_COOKIE = "d1zzy_access"
REFRESH_COOKIE = "d1zzy_refresh"
CSRF_COOKIE = "d1zzy_csrf"
CSRF_HEADER = "x-csrf-token"
CSRF_FIELD = "csrf_token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = "; ".join(
    [
        "default-src 'self'",
        # libsodium instantiates WebAssembly; no 'unsafe-eval' (Alpine uses its CSP build).
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self'",
        "img-src 'self' blob: data:",
        "connect-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self' https://checkout.stripe.com",
        "frame-src 'none'",
        "worker-src 'self' blob:",
        "manifest-src 'self'",
    ]
)


def _cookies(scope: Scope) -> dict[str, str]:
    for name, value in scope.get("headers", []):
        if name == b"cookie":
            jar = SimpleCookie()
            try:
                jar.load(value.decode("latin-1"))
            except Exception:  # noqa: BLE001
                return {}
            return {k: m.value for k, m in jar.items()}
    return {}


def _header(scope: Scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k == name:
            return v.decode("latin-1")
    return None


# --- Security headers + request id ------------------------------------------------------


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex[:16]
        scope.setdefault("state", {})["request_id"] = request_id
        structlog.contextvars.bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        status_code = 500
        settings = get_settings()
        onion = settings.onion_hostname()
        host = (_header(scope, b"host") or "").split(":")[0]

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                extra = {
                    b"content-security-policy": CSP.encode(),
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"cross-origin-embedder-policy": b"require-corp",
                    b"permissions-policy": (
                        b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                        b"bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=()"
                    ),
                    b"x-request-id": request_id.encode(),
                    b"x-dns-prefetch-control": b"off",
                    b"x-download-options": b"noopen",
                    b"x-permitted-cross-domain-policies": b"none",
                }
                if settings.is_dev:
                    # HSTS only in production (onion/HTTPS)
                    pass
                else:
                    # Production: HSTS with preload, 1 year
                    extra[b"strict-transport-security"] = (
                        b"max-age=31536000; includeSubDomains; preload"
                    )
                if onion and host != onion:
                    extra[b"onion-location"] = f"http://{onion}{scope['path']}".encode()
                existing = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in extra.items() if k not in existing]
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info(
                "request",
                method=scope["method"],
                path=scope["path"],
                status=status_code,
                ms=round((time.perf_counter() - started) * 1000, 1),
            )
            structlog.contextvars.clear_contextvars()


# --- Rate limiting ----------------------------------------------------------------------


def _client_key(scope: Scope) -> str:
    """Per-user when logged in. Over Tor every anonymous request comes from the Tor
    container, so anonymous traffic effectively shares one bucket; that is intentional
    back-pressure, not a bug."""
    token = _cookies(scope).get(ACCESS_COOKIE) or _cookies(scope).get(REFRESH_COOKIE)
    if token:
        try:
            payload = jwt.decode(
                token,
                get_settings().secret_key,
                algorithms=[get_settings().jwt_algorithm],
                options={"verify_aud": False},
            )
            return f"u:{payload['sub']}"
        except jwt.PyJWTError:
            pass
    client = scope.get("client")
    return f"ip:{hashlib.sha256((client[0] if client else '-').encode()).hexdigest()[:16]}"


class RateLimitMiddleware:
    """Fixed one-minute window per client for state-changing requests and auth endpoints.

    Different limits for different endpoint categories:
    - Auth endpoints (login, register, password reset): 5/min
    - State-changing API endpoints: 30/min
    - WebSocket connections: 10/min
    - General state-changing: 60/min (configurable)
    """

    # Per-path limits (requests per minute)
    PATH_LIMITS = {
        "/auth/login": 5,
        "/auth/register": 5,
        "/auth/reset-password": 3,
        "/auth/jwt/login": 5,
        "/api/": 30,
        "/ws/conversations/": 10,
    }

    def __init__(self, app: ASGIApp, redis_getter):
        self.app = app
        self.redis_getter = redis_getter

    def _get_limit(self, path: str) -> int:
        settings = get_settings()
        if settings.rate_limit_per_minute <= 0:
            return 0  # Disabled globally
        for prefix, limit in self.PATH_LIMITS.items():
            if path.startswith(prefix):
                return limit
        return settings.rate_limit_per_minute

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self._get_limit(scope.get("path", ""))
        if (
            scope["type"] != "http"
            or limit <= 0
            or scope["path"].startswith("/webhooks/")
            or (scope["method"] in SAFE_METHODS and not scope["path"].startswith("/auth"))
        ):
            await self.app(scope, receive, send)
            return

        key = f"rl:{_client_key(scope)}:{int(time.time() // 60)}"
        try:
            redis = self.redis_getter()
            count = await redis.incr(key)
            if count == 1:
                await redis.expire(key, 70)
        except Exception as e:  # noqa: BLE001  -- fail open if Redis is down
            log.warning("rate_limit_unavailable", error=str(e))
            count = 0

        if count > limit:
            body = b"Too many requests. Slow down and try again in a minute."
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [(b"content-type", b"text/plain"), (b"retry-after", b"60")],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


# --- CSRF (signed double-submit cookie) -------------------------------------------------


def _csrf_mac(nonce: str, ts: str) -> str:
    key = get_settings().secret_key.encode()
    return hmac.new(key, f"csrf:{nonce}:{ts}".encode(), hashlib.sha256).hexdigest()[:32]


def new_csrf_token() -> str:
    nonce, ts = secrets.token_urlsafe(18), str(int(time.time()))
    return f"{nonce}.{ts}.{_csrf_mac(nonce, ts)}"


def csrf_token_valid(token: str | None) -> bool:
    if not token or token.count(".") != 2:
        return False
    nonce, ts, mac = token.split(".")
    if not hmac.compare_digest(mac, _csrf_mac(nonce, ts)):
        return False
    try:
        return time.time() - int(ts) < get_settings().csrf_max_age_seconds
    except ValueError:
        return False


class CSRFCookieMiddleware:
    """Ensures every browser has a valid CSRF cookie and exposes it as request.state.csrf_token
    for templates (hidden form field) and HTMX (hx-headers)."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        token = _cookies(scope).get(CSRF_COOKIE)
        fresh = not csrf_token_valid(token)
        if fresh:
            token = new_csrf_token()
        scope.setdefault("state", {})["csrf_token"] = token

        if not fresh or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cookie = (
            f"{CSRF_COOKIE}={token}; Path=/; SameSite=Lax; "
            f"Max-Age={get_settings().csrf_max_age_seconds}"
            + ("; Secure" if get_settings().cookie_secure else "")
        )

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"set-cookie", cookie.encode())
                ]
            await send(message)

        await self.app(scope, receive, send_wrapper)


async def csrf_protect(request: Request) -> None:
    """Dependency for every state-changing route. Accepts the token from the X-CSRF-Token
    header (fetch/HTMX) or a csrf_token form field (no-JS forms)."""
    if request.method in SAFE_METHODS:
        return
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get(CSRF_HEADER)
    if submitted is None and request.headers.get("content-type", "").startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    ):
        form = await request.form()
        value = form.get(CSRF_FIELD)
        submitted = value if isinstance(value, str) else None
    if (
        not cookie
        or not submitted
        or not csrf_token_valid(cookie)
        or not hmac.compare_digest(cookie, submitted)
    ):
        # Security event: never log the token itself, only enough to triage.
        log.warning(
            "csrf_rejected",
            method=request.method,
            path=request.url.path,
            has_cookie=bool(cookie),
            has_submitted=bool(submitted),
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")


# --- Silent access-token refresh --------------------------------------------------------

ACCESS_AUDIENCE = "fastapi-users:auth"
REFRESH_AUDIENCE = "d1zzy:refresh"


def _jwt_sub(token: str | None, audience) -> str | None:
    if not token:
        return None
    s = get_settings()
    # Support multiple secret keys for key rotation
    secret_keys = [s.secret_key]
    # Add any additional secret keys from environment variable
    additional_keys = s.additional_jwt_secrets
    if additional_keys:
        secret_keys = [s.secret_key] + [k.strip() for k in additional_keys.split(",") if k.strip()]
    else:
        secret_keys = [s.secret_key]

    # Also check the old secret key if configured
    old_secret = s.old_jwt_secret
    if old_secret:
        secret_keys.append(old_secret)

    for key in secret_keys:
        try:
            return jwt.decode(token, key, algorithms=[s.jwt_algorithm], audience=audience)["sub"]
        except (jwt.PyJWTError, KeyError):
            continue
    return None


def make_token(sub: str, *, refresh: bool) -> str:
    s = get_settings()
    lifetime = (
        s.refresh_token_expire_days * 86400 if refresh else s.access_token_expire_minutes * 60
    )
    payload = {
        "sub": sub,
        "aud": REFRESH_AUDIENCE if refresh else ACCESS_AUDIENCE,
        "exp": int(time.time()) + lifetime,
    }
    return jwt.encode(payload, s.secret_key, algorithm=s.jwt_algorithm)


def auth_cookie(name: str, value: str, max_age: int) -> str:
    settings = get_settings()
    cookie = f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    if settings.cookie_secure:
        cookie += "; Secure; SameSite=None"
    return cookie


class RefreshMiddleware:
    """If the 15-minute access cookie is missing/expired but the refresh cookie is valid,
    mint a new access token, inject it into this request's Cookie header and set it on the
    response. Lets no-JS users stay logged in without a refresh round-trip. Whether the user
    is still active (not suspended) is checked downstream by fastapi-users."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        cookies = _cookies(scope)
        if _jwt_sub(cookies.get(ACCESS_COOKIE), [ACCESS_AUDIENCE]) or not (
            sub := _jwt_sub(cookies.get(REFRESH_COOKIE), [REFRESH_AUDIENCE])
        ):
            await self.app(scope, receive, send)
            return

        token = make_token(sub, refresh=False)
        cookies[ACCESS_COOKIE] = token
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items()).encode("latin-1")
        scope = dict(scope)
        scope["headers"] = [(k, v) for k, v in scope["headers"] if k != b"cookie"] + [
            (b"cookie", cookie_header)
        ]
        set_cookie = auth_cookie(
            ACCESS_COOKIE, token, get_settings().access_token_expire_minutes * 60
        ).encode()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"set-cookie", set_cookie)
                ]
            await send(message)

        await self.app(scope, receive, send_wrapper if scope["type"] == "http" else send)


# --- Request size limiting -----------------------------------------------------------------

MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB default
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB for multipart uploads


class RequestSizeMiddleware:
    """Limit request body size to prevent DoS via large payloads."""

    def __init__(self, app: ASGIApp, max_size: int = MAX_REQUEST_SIZE):
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    content_length = int(v.decode())
                except (ValueError, UnicodeDecodeError):
                    pass
                break

        if content_length is not None and content_length > self.max_size:
            body = b"Request too large. Maximum size: " + str(self.max_size).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        # Stream and enforce size for streaming bodies
        bytes_received = 0

        async def receive_wrapper() -> Message:
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > self.max_size:
                    raise ValueError("Request body exceeds maximum allowed size")
            return message

        await self.app(scope, receive_wrapper, send)
