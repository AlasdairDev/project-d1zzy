"""Shared helpers for auth, signature checks and page rendering."""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import jwt
import structlog
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_users import BaseUserManager, FastAPIUsers, InvalidPasswordException, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, CookieTransport, JWTStrategy
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core import crypto
from app.core.queue import queue
from app.core.security import (
    ACCESS_AUDIENCE,
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    auth_cookie,
    make_token,
)
from app.db.session import get_session
from app.models import User
from app.schemas.user import UserCreate

log = structlog.get_logger()
settings = get_settings()

# --- fastapi-users ----------------------------------------------------------------------


async def get_user_db(
    session: AsyncSession = Depends(get_session),
) -> AsyncIterator[SQLAlchemyUserDatabase]:
    yield SQLAlchemyUserDatabase(session, User)


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = settings.secret_key
    verification_token_secret = settings.secret_key

    async def validate_password(self, password: str, user) -> None:
        if len(password) < 10:
            raise InvalidPasswordException("Password must be at least 10 characters")
        if user.email.split("@")[0].lower() in password.lower():
            raise InvalidPasswordException("Password must not contain your email")

    async def create(self, user_create: UserCreate, safe: bool = False, request=None) -> User:
        existing = await self.user_db.session.scalar(
            select(User.id).where(User.handle == user_create.handle)
        )
        if existing:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "REGISTER_HANDLE_TAKEN")
        return await super().create(user_create, safe=safe, request=request)

    async def on_after_register(self, user: User, request: Request | None = None) -> None:
        log.info("user_registered", user_id=str(user.id))
        await self.request_verify(user, request)

    async def on_after_request_verify(self, user: User, token: str, request=None) -> None:
        link = f"{settings.public_base_url}/verify?token={token}"
        await queue.enqueue(
            "send_email",
            user.email,
            "Verify your D1zzy account",
            f"Confirm your email address:\n\n{link}\n\nIgnore this if you did not sign up.",
        )

    async def on_after_forgot_password(self, user: User, token: str, request=None) -> None:
        link = f"{settings.public_base_url}/reset-password?token={token}"
        await queue.enqueue(
            "send_email",
            user.email,
            "Reset your D1zzy password",
            f"Reset your password:\n\n{link}\n\nThis link expires in one hour.",
        )


async def get_user_manager(user_db=Depends(get_user_db)) -> AsyncIterator[UserManager]:
    yield UserManager(user_db)


class RefreshingCookieTransport(CookieTransport):
    """Access JWT cookie (fastapi-users) plus a long-lived refresh cookie."""

    async def get_login_response(self, token: str) -> Response:
        response = await super().get_login_response(token)
        sub = (await get_jwt_strategy().read_token_sub(token)) if token else None
        if sub:
            set_refresh_cookie(response, sub)
        return response

    async def get_logout_response(self) -> Response:
        response = await super().get_logout_response()
        response.delete_cookie(REFRESH_COOKIE, path="/")
        return response


class _Strategy(JWTStrategy):
    async def read_token_sub(self, token: str) -> str | None:
        try:
            payload = jwt.decode(
                token, self.decode_key, audience=self.token_audience, algorithms=[self.algorithm]
            )
        except jwt.PyJWTError:
            return None
        return payload.get("sub")


def get_jwt_strategy() -> _Strategy:
    return _Strategy(
        secret=settings.secret_key,
        lifetime_seconds=settings.access_token_expire_minutes * 60,
        algorithm=settings.jwt_algorithm,
        token_audience=[ACCESS_AUDIENCE],
    )


def set_refresh_cookie(response: Response, sub: str) -> None:
    response.headers.append(
        "set-cookie",
        auth_cookie(
            REFRESH_COOKIE,
            make_token(sub, refresh=True),
            settings.refresh_token_expire_days * 86400,
        ),
    )


cookie_transport = RefreshingCookieTransport(
    cookie_name=ACCESS_COOKIE,
    cookie_max_age=settings.access_token_expire_minutes * 60,
    cookie_secure=settings.cookie_secure,
    cookie_httponly=True,
    cookie_samesite="lax",
)

auth_backend = AuthenticationBackend(
    name="cookie", transport=cookie_transport, get_strategy=get_jwt_strategy
)

fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_user = fastapi_users.current_user(active=True)
optional_user = fastapi_users.current_user(active=True, optional=True)
# moderator_user checks for moderator or above (can_moderate)
moderator_user = fastapi_users.current_user(active=True)


class LoginRequired(Exception):
    pass


class Forbidden(Exception):
    pass


def audit_denied(request: Request, user: User | None, need: str) -> None:
    """Record an authorization denial. No secrets, no query strings, no IPs."""
    log.warning(
        "authz_denied",
        need=need,
        path=request.url.path,
        user_id=str(user.id) if user else None,
    )


async def current_superadmin(request: Request, user: User = Depends(current_user)) -> User:
    if not user.is_superadmin:
        audit_denied(request, user, "superadmin")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Superadmin required")
    return user


async def current_admin(request: Request, user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        audit_denied(request, user, "admin")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    return user


async def current_moderator(request: Request, user: User = Depends(current_user)) -> User:
    if not user.is_moderator_or_above:
        audit_denied(request, user, "moderator")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Moderator, admin, or superadmin required")
    return user


async def current_vendor(request: Request, user: User = Depends(current_user)) -> User:
    if not user.is_vendor_active:
        audit_denied(request, user, "vendor")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Active vendor required")
    return user


# --- Page-level dependencies (HTML routes) ---


async def page_user(user: User | None = Depends(optional_user)) -> User:
    """Like current_user, but HTML routes redirect to /login instead of returning 401."""
    if user is None:
        raise LoginRequired()
    return user


async def page_superadmin(request: Request, user: User = Depends(page_user)) -> User:
    if not user.is_superadmin:
        audit_denied(request, user, "superadmin")
        raise Forbidden()
    return user


async def page_admin(request: Request, user: User = Depends(page_user)) -> User:
    if not user.is_admin:
        audit_denied(request, user, "admin")
        raise Forbidden()
    return user


async def page_moderator(request: Request, user: User = Depends(page_user)) -> User:
    if not user.is_moderator_or_above:
        audit_denied(request, user, "moderator")
        raise Forbidden()
    return user


async def page_vendor(request: Request, user: User = Depends(page_user)) -> User:
    if not user.is_vendor_active:
        audit_denied(request, user, "vendor")
        raise Forbidden()
    return user


async def page_admin_or_vendor(request: Request, user: User = Depends(page_user)) -> User:
    """For routes accessible by both admins and vendors (e.g., viewing reports)."""
    if not (user.is_admin or user.is_vendor_active):
        audit_denied(request, user, "admin_or_vendor")
        raise Forbidden()
    return user


async def page_admin_or_moderator(request: Request, user: User = Depends(page_user)) -> User:
    """For routes accessible by moderators and admins."""
    if not user.is_moderator_or_above:
        audit_denied(request, user, "admin_or_moderator")
        raise Forbidden()
    return user


# --- Signatures -------------------------------------------------------------------------


def require_user_sig(user: User, context: str, data: bytes, sig_b64: str) -> bytes:
    """Every JSON-API write must carry an Ed25519 signature by the author's own key."""
    if not user.signing_pubkey:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Set up your passphrase keys in Settings first"
        )
    sig = crypto.b64d(sig_b64)
    if not crypto.verify(user.signing_pubkey, context, data, sig):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid signature")
    return sig


def decode_b64(value: str, field: str) -> bytes:
    try:
        return crypto.b64d(value)
    except crypto.CryptoError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field}: invalid base64") from e


# --- Templates & responses --------------------------------------------------------------

templates = Jinja2Templates(directory=str(settings.base_dir / "templates"))

FLASH = {
    "listing_created": ("ok", "Listing published."),
    "listing_updated": ("ok", "Listing updated."),
    "listing_removed": ("ok", "Listing removed."),
    "offer_sent": ("ok", "Offer sent to the seller."),
    "offer_accepted": ("ok", "Offer accepted. The buyer can now pay."),
    "offer_rejected": ("ok", "Offer rejected."),
    "offer_paid": ("ok", "Payment received. The seller has been notified."),
    "offer_completed": ("ok", "Marked as received. You can now rate each other."),
    "offer_disputed": ("warn", "Dispute opened. A moderator will review it."),
    "rated": ("ok", "Thanks for rating."),
    "reported": ("ok", "Report sent to moderators. Thank you."),
    "already_reported": ("warn", "You already reported this."),
    "vendor_ok": ("ok", "You are now a vendor. Create your first listing!"),
    "keys_saved": ("ok", "Encryption keys saved."),
    "verified": ("ok", "Email verified."),
    "verify_sent": ("ok", "Verification email sent. Check your inbox."),
    "registered": ("ok", "Account created. Log in to continue."),
    "logged_out": ("ok", "Logged out."),
    "password_reset": ("ok", "Password changed. Log in with your new password."),
    "mod_done": ("ok", "Moderation action recorded."),
    "payment_unavailable": ("err", "That payment method is not configured on this server."),
    "payment_error": ("err", "The payment provider returned an error. Try again later."),
    "verify_required": ("warn", "Verify your email before becoming a vendor."),
}


def _fmt_money(cents: int | None, currency: str | None) -> str:
    if cents is None:
        return ""
    cur = (currency or "").upper()
    symbol = {"USD": "$", "EUR": "€", "GBP": "£", "SGD": "S$", "PHP": "₱"}.get(cur)
    amount = f"{cents / 100:,.2f}"
    return f"{symbol}{amount}" if symbol else f"{amount} {cur}"


def _ago(dt: datetime | None) -> str:
    if dt is None:
        return ""
    secs = int((datetime.now(UTC) - dt).total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return "just now"


templates.env.filters["money"] = _fmt_money
templates.env.filters["ago"] = _ago
templates.env.filters["b64"] = lambda b: crypto.b64e(b) if b else ""
PAYMENT_LABELS = {
    "stripe": "Card (Stripe)",
    "lightning": "Bitcoin Lightning",
    "monero": "Monero",
    "gcash": "GCash",
    "maya": "Maya",
    "paymongo": "Card or bank (PayMongo)",
    "paypal": "PayPal",
    "cod": "Cash on delivery",
}
templates.env.filters["payment_label"] = lambda method: PAYMENT_LABELS.get(method, method)
templates.env.globals["settings"] = settings


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    user: User | None = None,
    status_code: int = 200,
) -> Response:
    ctx = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, "csrf_token", ""),
        "onion": settings.onion_hostname(),
        "flash": FLASH.get(request.query_params.get("m", "")),
        **(context or {}),
    }
    return templates.TemplateResponse(request, template, ctx, status_code=status_code)


def wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "") or request.url.path.startswith(
        "/api/"
    )


def done(request: Request, url: str, data: dict | None = None, code: str | None = None):
    """Respond to a state-changing request: JSON for API clients, 303 redirect for forms."""
    if wants_json(request):
        return JSONResponse(data or {"ok": True})
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}m={code}" if code else url, status_code=303)
