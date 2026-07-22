"""Public waitlist/download manifest and administrator release operations."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.config import settings
from backend.db import get_db
from backend.models import ProductRelease, ProductWaitlistEntry
from backend.routers.auth import AuthenticatedSession, require_admin
from backend.security_utils import utcnow
from backend.services.release_email_service import email_configured, send_release_email

router = APIRouter(prefix="/v1/waitlist", tags=["waitlist"])
ProductKey = Literal["windows", "browser_extension"]
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


class WaitlistRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    product: ProductKey

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _EMAIL_PATTERN.fullmatch(normalized):
            raise ValueError("Email không hợp lệ.")
        return normalized


class WaitlistResponse(BaseModel):
    email: str
    product: ProductKey
    registered: bool


class ReleaseInput(BaseModel):
    product: ProductKey
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
    downloadUrl: str = Field(min_length=10, max_length=2000)
    checksumSha256: str = Field(min_length=64, max_length=64)
    signatureNote: str | None = Field(default=None, max_length=500)
    notify: bool = True

    @field_validator("downloadUrl")
    @classmethod
    def trusted_download(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Đường dẫn tải phải là HTTPS công khai, không chứa thông tin đăng nhập.")
        return value.strip()

    @field_validator("checksumSha256")
    @classmethod
    def valid_checksum(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("Checksum SHA-256 không hợp lệ.")
        return value.lower()


def _release_json(row: ProductRelease) -> dict:
    return {
        "id": row.id,
        "product": row.product,
        "version": row.version,
        "downloadUrl": row.download_url,
        "checksumSha256": row.checksum_sha256,
        "signatureNote": row.signature_note,
        "publishedAt": row.published_at.isoformat(),
    }


def _unsubscribe_token(entry_id: str) -> str:
    signature = hmac.new(settings.api_key_pepper.encode(), entry_id.encode(), hashlib.sha256).digest()
    return f"{entry_id}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def _verify_unsubscribe_token(token: str) -> str | None:
    try:
        entry_id, _ = token.split(".", 1)
    except ValueError:
        return None
    return entry_id if hmac.compare_digest(token, _unsubscribe_token(entry_id)) else None


@router.post("", response_model=WaitlistResponse)
def join_waitlist(payload: WaitlistRequest, db: Annotated[DbSession, Depends(get_db)]) -> WaitlistResponse:
    existing = db.execute(select(ProductWaitlistEntry).where(
        ProductWaitlistEntry.email == payload.email,
        ProductWaitlistEntry.product == payload.product,
    )).scalar_one_or_none()
    if existing is not None:
        if existing.unsubscribed_at is not None:
            existing.unsubscribed_at = None
            db.commit()
            return WaitlistResponse(email=existing.email, product=existing.product, registered=True)
        return WaitlistResponse(email=existing.email, product=existing.product, registered=False)
    entry = ProductWaitlistEntry(email=payload.email, product=payload.product)
    db.add(entry)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return WaitlistResponse(email=payload.email, product=payload.product, registered=False)
    return WaitlistResponse(email=entry.email, product=entry.product, registered=True)


@router.get("/releases")
def public_releases(db: Annotated[DbSession, Depends(get_db)]) -> dict:
    rows = db.execute(select(ProductRelease).where(ProductRelease.active.is_(True)).order_by(ProductRelease.published_at.desc())).scalars()
    releases: dict[str, dict] = {}
    for row in rows:
        releases.setdefault(row.product, _release_json(row))
    return {"releases": releases}


@router.get("/unsubscribe")
def unsubscribe(token: str, db: Annotated[DbSession, Depends(get_db)]) -> Response:
    entry_id = _verify_unsubscribe_token(token)
    entry = db.get(ProductWaitlistEntry, entry_id) if entry_id else None
    if entry is None:
        raise HTTPException(status_code=400, detail="Liên kết hủy đăng ký không hợp lệ.")
    entry.unsubscribed_at = entry.unsubscribed_at or utcnow()
    db.commit()
    return Response("Đã hủy nhận thông báo phát hành từ Prewise.", media_type="text/plain; charset=utf-8")


@router.get("/admin", dependencies=[Depends(require_admin)])
def admin_list(product: ProductKey | None = None, active_only: bool = False, limit: int = 200, offset: int = 0, db: DbSession = Depends(get_db)) -> dict:
    statement = select(ProductWaitlistEntry).order_by(ProductWaitlistEntry.created_at.desc())
    if product:
        statement = statement.where(ProductWaitlistEntry.product == product)
    if active_only:
        statement = statement.where(ProductWaitlistEntry.unsubscribed_at.is_(None))
    rows = db.execute(statement.offset(max(0, offset)).limit(max(1, min(limit, 1000)))).scalars()
    return {"entries": [{"id": row.id, "email": row.email, "product": row.product, "createdAt": row.created_at.isoformat(), "unsubscribedAt": row.unsubscribed_at.isoformat() if row.unsubscribed_at else None, "notifiedAt": row.notified_at.isoformat() if row.notified_at else None} for row in rows]}


@router.get("/admin/export.csv", dependencies=[Depends(require_admin)])
def admin_export(product: ProductKey | None = None, db: DbSession = Depends(get_db)) -> Response:
    statement = select(ProductWaitlistEntry).order_by(ProductWaitlistEntry.created_at.desc())
    if product:
        statement = statement.where(ProductWaitlistEntry.product == product)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["email", "product", "created_at", "unsubscribed_at", "notified_at"])
    for row in db.execute(statement).scalars():
        writer.writerow([row.email, row.product, row.created_at.isoformat(), row.unsubscribed_at.isoformat() if row.unsubscribed_at else "", row.notified_at.isoformat() if row.notified_at else ""])
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=prewise-waitlist.csv"})


@router.delete("/admin/{entry_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
def admin_unsubscribe(entry_id: str, db: DbSession = Depends(get_db)) -> Response:
    row = db.get(ProductWaitlistEntry, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy đăng ký.")
    row.unsubscribed_at = row.unsubscribed_at or utcnow()
    db.commit()
    return Response(status_code=204)


@router.get("/admin/releases", dependencies=[Depends(require_admin)])
def admin_releases(db: DbSession = Depends(get_db)) -> dict:
    rows = db.execute(select(ProductRelease).order_by(ProductRelease.published_at.desc()).limit(100)).scalars()
    return {"releases": [{**_release_json(row), "active": row.active} for row in rows], "emailConfigured": email_configured()}


@router.post("/admin/releases", dependencies=[Depends(require_admin)])
def publish_release(payload: ReleaseInput, admin: Annotated[AuthenticatedSession, Depends(require_admin)], db: DbSession = Depends(get_db)) -> dict:
    db.execute(update(ProductRelease).where(ProductRelease.product == payload.product, ProductRelease.active.is_(True)).values(active=False))
    release = ProductRelease(product=payload.product, version=payload.version, download_url=payload.downloadUrl, checksum_sha256=payload.checksumSha256, signature_note=payload.signatureNote.strip() if payload.signatureNote else None, published_by_user_id=admin.user.id, active=True)
    db.add(release)
    db.commit()
    db.refresh(release)
    configured = email_configured()
    result = {"configured": configured, "attempted": 0, "sent": 0, "failed": 0}
    if payload.notify and configured:
        entries = db.execute(select(ProductWaitlistEntry).where(ProductWaitlistEntry.product == payload.product, ProductWaitlistEntry.unsubscribed_at.is_(None))).scalars().all()
        product_name = "Prewise cho Windows" if payload.product == "windows" else "Tiện ích trình duyệt Prewise"
        for entry in entries:
            result["attempted"] += 1
            token = _unsubscribe_token(entry.id)
            unsubscribe_url = f"{settings.release_unsubscribe_base_url}?token={token}"
            delivered = send_release_email(recipient=entry.email, product_name=product_name, version=release.version, download_url=release.download_url, checksum=release.checksum_sha256, unsubscribe_url=unsubscribe_url)
            if delivered.sent:
                result["sent"] += 1
                entry.notified_at = utcnow()
            else:
                result["failed"] += 1
        db.commit()
    return {"release": _release_json(release), "notification": result}
