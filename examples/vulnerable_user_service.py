"""Example demonstrating CG-003 (Loop N+1 query) and CG-004 (Check-Then-Act uniqueness race)."""

from __future__ import annotations

from typing import Union

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import Integer, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)


class RegisterRequest(BaseModel):
    email: EmailStr


app = FastAPI(title="User Service")


async def get_db() -> AsyncSession:
    raise NotImplementedError


# -----------------------------------------------------------------------------
# CG-003: Loop N+1 Query Explode
# -----------------------------------------------------------------------------


@app.post("/users/batch-fetch")
async def batch_fetch_users(
    user_ids: list[int],
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> list[dict[str, Union[int, str]]]:
    """Vulnerable to CG-003: executing queries inside a loop."""
    results: list[dict[str, Union[int, str]]] = []
    for uid in user_ids:
        stmt = select(User).where(User.id == uid)
        res = await db.execute(stmt)
        user = res.scalar_one_or_none()
        if user:
            results.append({"id": user.id, "email": user.email})
    return results


@app.post("/users/batch-fetch-safe")
async def batch_fetch_users_safe(
    user_ids: list[int],
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> list[dict[str, Union[int, str]]]:
    """Safe from CG-003: batch query outside the loop."""
    stmt = select(User).where(User.id.in_(user_ids))
    res = await db.execute(stmt)
    users = res.scalars().all()
    return [{"id": u.id, "email": u.email} for u in users]


# -----------------------------------------------------------------------------
# CG-004: Check-Then-Act Uniqueness Race
# -----------------------------------------------------------------------------


@app.post("/users/register")
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> dict[str, str]:
    """Vulnerable to CG-004: select existence check followed by add and commit without catching IntegrityError."""
    stmt = select(User).where(User.email == request.email)
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    new_user = User(email=request.email)
    db.add(new_user)
    await db.commit()

    return {"status": "registered"}


@app.post("/users/register-safe")
async def register_safe(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> dict[str, str]:
    """Safe from CG-004: commit wrapped in try-except catching IntegrityError."""
    stmt = select(User).where(User.email == request.email)
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    new_user = User(email=request.email)
    db.add(new_user)
    try:
        await db.commit()
    except IntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    return {"status": "registered"}
