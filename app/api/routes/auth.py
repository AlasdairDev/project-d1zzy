"""Login, registration and the auth JSON routes. The HTML forms work without JavaScript."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import exceptions
from pydantic import ValidationError

from app.api.deps import (
    UserManager,
    auth_backend,
    fastapi_users,
    get_jwt_strategy,
    get_user_manager,
    optional_user,
    render,
    set_refresh_cookie,
)
from app.core.security import (
    ACCESS_COOKIE,
    REFRESH_AUDIENCE,
    REFRESH_COOKIE,
    _jwt_sub,
    auth_cookie,
    csrf_protect,
)
from app.models import User
from app.schemas.user import UserCreate, UserRead, UserUpdate

router = APIRouter()

# JSON API (fastapi-users)
router.include_router(
    fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt", tags=["auth"]
)
router.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate), prefix="/auth", tags=["auth"]
)
router.include_router(fastapi_users.get_verify_router(UserRead), prefix="/auth", tags=["auth"])
router.include_router(fastapi_users.get_reset_password_router(), prefix="/auth", tags=["auth"])
router.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate), prefix="/api/users", tags=["users"]
)


@router.post("/auth/refresh", tags=["auth"])
async def refresh(request: Request, user_manager: UserManager = Depends(get_user_manager)):
    """Explicit refresh for API clients (browsers are refreshed silently by middleware)."""
    sub = _jwt_sub(request.cookies.get(REFRESH_COOKIE), REFRESH_AUDIENCE)
    if not sub:
        raise HTTPException(401, "Invalid refresh token")
    try:
        user = await user_manager.get(user_manager.parse_id(sub))
    except (exceptions.UserNotExists, exceptions.InvalidID) as e:
        raise HTTPException(401, "Invalid refresh token") from e
    if not user.is_active:
        raise HTTPException(401, "Account suspended")
    token = await get_jwt_strategy().write_token(user)
    response = JSONResponse({"ok": True})
    response.headers.append(
        "set-cookie", auth_cookie(ACCESS_COOKIE, token, get_jwt_strategy().lifetime_seconds)
    )
    set_refresh_cookie(response, str(user.id))  # rotate
    return response


# --- HTML pages -------------------------------------------------------------------------


def _safe_next(url: str | None) -> str:
    return url if url and url.startswith("/") and not url.startswith("//") else "/"


@router.get("/login")
async def login_page(request: Request, next: str = "/", user: User | None = Depends(optional_user)):
    if user:
        return RedirectResponse(_safe_next(next), 303)
    return render(request, "pages/login.html", {"next": _safe_next(next)})


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login_submit(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    next: str = Form("/"),
    user_manager: UserManager = Depends(get_user_manager),
):
    creds = OAuth2PasswordRequestForm(username=email, password=password)
    user = await user_manager.authenticate(creds)
    if user is None or not user.is_active:
        return render(
            request,
            "pages/login.html",
            {
                "error": "Wrong email or password, or the account is suspended.",
                "email": email,
                "next": _safe_next(next),
            },
            status_code=400,
        )
    token = await get_jwt_strategy().write_token(user)
    response = RedirectResponse(_safe_next(next), status_code=303)
    response.headers.append(
        "set-cookie", auth_cookie(ACCESS_COOKIE, token, get_jwt_strategy().lifetime_seconds)
    )
    set_refresh_cookie(response, str(user.id))
    return response


@router.post("/logout", dependencies=[Depends(csrf_protect)])
async def logout(request: Request):
    response = RedirectResponse("/?m=logged_out", status_code=303)
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/")
    return response


@router.get("/register")
async def register_page(request: Request, user: User | None = Depends(optional_user)):
    if user:
        return RedirectResponse("/", 303)
    return render(request, "pages/register.html")


@router.post("/register", dependencies=[Depends(csrf_protect)])
async def register_submit(
    request: Request,
    email: str = Form(),
    handle: str = Form(),
    password: str = Form(),
    password2: str = Form(),
    user_manager: UserManager = Depends(get_user_manager),
):
    ctx = {"email": email, "handle": handle}
    error = None
    if password != password2:
        error = "Passwords do not match."
    else:
        try:
            await user_manager.create(
                UserCreate(email=email, handle=handle.lower(), password=password),
                safe=True,
                request=request,
            )
        except ValidationError:
            error = (
                "Check your email address, and use 3-32 lowercase letters, digits or _ "
                "for the handle."
            )
        except exceptions.UserAlreadyExists:
            error = "An account with that email already exists."
        except exceptions.InvalidPasswordException as e:
            error = e.reason
        except HTTPException as e:
            error = (
                "That handle is taken." if e.detail == "REGISTER_HANDLE_TAKEN" else str(e.detail)
            )
    if error:
        return render(request, "pages/register.html", {**ctx, "error": error}, status_code=400)
    return RedirectResponse("/login?m=registered", status_code=303)


@router.get("/verify")
async def verify_page(
    request: Request, token: str, user_manager: UserManager = Depends(get_user_manager)
):
    try:
        await user_manager.verify(token, request)
    except exceptions.UserAlreadyVerified:
        pass
    except (exceptions.InvalidVerifyToken, exceptions.UserNotExists):
        return render(
            request,
            "pages/login.html",
            {"error": "That verification link is invalid or expired."},
            status_code=400,
        )
    return RedirectResponse("/settings?m=verified", status_code=303)


@router.post("/verify/resend", dependencies=[Depends(csrf_protect)])
async def verify_resend(
    request: Request,
    user: User | None = Depends(optional_user),
    user_manager: UserManager = Depends(get_user_manager),
):
    if user is None:
        return RedirectResponse("/login", 303)
    try:
        await user_manager.request_verify(user, request)
    except exceptions.UserAlreadyVerified:
        pass
    return RedirectResponse("/settings?m=verify_sent", status_code=303)


@router.get("/reset-password")
async def reset_page(request: Request, token: str = ""):
    return render(request, "pages/login.html", {"reset_token": token, "mode": "reset"})


@router.post("/reset-password", dependencies=[Depends(csrf_protect)])
async def reset_submit(
    request: Request,
    token: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    user_manager: UserManager = Depends(get_user_manager),
):
    if not token:  # step 1: request a reset email (always the same answer: no account oracle)
        try:
            user = await user_manager.get_by_email(email)
            await user_manager.forgot_password(user, request)
        except (exceptions.UserNotExists, exceptions.UserInactive):
            pass
        return render(
            request,
            "pages/login.html",
            {"notice": "If that account exists, a reset link is on its way."},
        )
    try:
        await user_manager.reset_password(token, password, request)
    except exceptions.InvalidPasswordException as e:
        return render(
            request,
            "pages/login.html",
            {"mode": "reset", "reset_token": token, "error": e.reason},
            status_code=400,
        )
    except (
        exceptions.InvalidResetPasswordToken,
        exceptions.UserNotExists,
        exceptions.UserInactive,
    ):
        return render(
            request,
            "pages/login.html",
            {"error": "That reset link is invalid or expired."},
            status_code=400,
        )
    return RedirectResponse("/login?m=password_reset", status_code=303)
