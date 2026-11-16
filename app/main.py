import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import websocket
from app.api.deps import Forbidden, LoginRequired, render, wants_json
from app.api.routes import (
    admin,
    auth,
    discussions,
    listings,
    messages,
    moderation,
    offers,
    ratings,
    reports,
    social,
    users,
)
from app.config import get_settings
from app.core.queue import queue
from app.core.security import (
    CSRFCookieMiddleware,
    RateLimitMiddleware,
    RefreshMiddleware,
    RequestSizeMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import dispose_engine, get_sessionmaker


def configure_logging(level: str) -> None:
    logging.basicConfig(format="%(message)s", level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
    )
    # uvicorn's access log includes client IPs; ours does not.
    logging.getLogger("uvicorn.access").disabled = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await queue.connect()
    except Exception as e:  # noqa: BLE001 -- app still serves pages without Redis
        structlog.get_logger().warning("redis_unavailable_at_startup", error=str(e))
    yield
    await queue.close()
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    settings.assert_production_safe()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="D1zzy Market",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.is_dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.is_dev else None,
    )

    # Starlette wraps in reverse: the last middleware added is the outermost.
    app.add_middleware(RequestSizeMiddleware, max_size=get_settings().max_upload_bytes)
    app.add_middleware(RateLimitMiddleware, redis_getter=lambda: queue.redis)
    app.add_middleware(CSRFCookieMiddleware)
    app.add_middleware(RefreshMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    app.mount("/static", StaticFiles(directory=settings.base_dir / "static"), name="static")
    for module in (
        admin,
        auth,
        discussions,
        listings,
        offers,
        messages,
        ratings,
        reports,
        moderation,
        social,
        users,
    ):
        app.include_router(module.router)
    app.include_router(websocket.router)

    @app.get("/.well-known/security.txt", include_in_schema=False)
    async def security_txt():
        base = settings.public_base_url.rstrip("/")
        return PlainTextResponse(
            f"Contact: {settings.security_contact}\n"
            "Expires: 2027-11-15T00:00:00.000Z\n"
            "Preferred-Languages: en\n"
            f"Canonical: {base}/.well-known/security.txt\n"
        )

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        async with get_sessionmaker()() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ok"}

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(Forbidden)
    async def forbidden(request: Request, exc: Forbidden):
        return render(
            request,
            "pages/error.html",
            {"code": 403, "detail": "You do not have access."},
            status_code=403,
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if wants_json(request) or request.url.path.startswith(("/auth/", "/webhooks/")):
            return JSONResponse(
                {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
            )
        return render(
            request,
            "pages/error.html",
            {"code": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        if wants_json(request) or request.url.path.startswith("/auth/"):
            return JSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)
        return render(
            request,
            "pages/error.html",
            {"code": 422, "detail": "Some fields were missing or invalid."},
            status_code=422,
        )

    return app


app = create_app()
