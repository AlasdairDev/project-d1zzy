"""Admin management (SUPERADMIN only)."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_superadmin, get_session
from app.models import User
from app.schemas.user import UserRole, UserUpdate

router = APIRouter()


@router.get("/api/admins", response_model=list[dict])
async def list_admins(
    session: AsyncSession = Depends(get_session),
    _: User = Depends(current_superadmin),
):
    """List all users with admin role (SUPERADMIN only)."""
    admins = (
        await session.scalars(
            select(User).where(User.role == UserRole.ADMIN).order_by(User.handle.asc())
        )
    ).unique()
    return [{"id": str(a.id), "handle": a.handle, "is_vendor": a.is_vendor} for a in admins]


@router.get("/api/admins/{user_id}")
async def get_admin(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(current_superadmin),
):
    """Get admin details by ID (SUPERADMIN only)."""
    admin = await session.get(User, user_id)
    if admin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Admin not found")
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User is not an admin")
    return {"id": str(admin.id), "handle": admin.handle, "is_vendor": admin.is_vendor}


@router.put("/api/admins/{user_id}", status_code=status.HTTP_200_OK)
async def update_admin(
    user_id: UUID,
    body: UserUpdate,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(current_superadmin),
):
    """Update admin role (SUPERADMIN only).

    Only SUPERADMIN can change a user's role to/from ADMIN.
    Cannot demote another SUPERADMIN.
    """
    admin = await session.get(User, user_id)
    if admin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if admin.is_superadmin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot modify SUPERADMIN accounts")

    if body.role is not None:
        if body.role == UserRole.SUPERADMIN:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot promote to SUPERADMIN")
        if admin.role == UserRole.SUPERADMIN and body.role != UserRole.SUPERADMIN:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot demote SUPERADMIN")
        admin.role = body.role

    if body.is_vendor is not None:
        admin.is_vendor = body.is_vendor

    if body.is_active is not None:
        admin.is_active = body.is_active

    await session.commit()
    return {
        "ok": True,
        "role": admin.role,
        "is_vendor": admin.is_vendor,
        "is_active": admin.is_active,
    }


@router.delete("/api/admins/{user_id}", status_code=status.HTTP_200_OK)
async def delete_admin(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(current_superadmin),
):
    """Delete/remove admin status (SUPERADMIN only).

    Sets user role back to USER. Cannot delete SUPERADMIN accounts.
    """
    admin = await session.get(User, user_id)
    if admin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if admin.is_superadmin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot delete SUPERADMIN accounts")

    admin.role = UserRole.USER
    admin.is_vendor = False
    await session.commit()
    return {"ok": True, "new_role": UserRole.USER}
