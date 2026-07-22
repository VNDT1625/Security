"""Validated, privacy-minimised user feedback persistence."""

from __future__ import annotations

import hashlib
import re

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models import ScanEvent, UserFeedback

_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\s().-]?){8,15}(?!\w)")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def minimise_details(value: str | None) -> tuple[str | None, str | None]:
    """Remove common sensitive identifiers while retaining actionable context."""
    if not value:
        return None, None
    normalized = " ".join(value.split())
    digest = _sha256(normalized)
    redacted = _URL.sub("[URL đã ẩn]", normalized)
    redacted = _EMAIL.sub("[email đã ẩn]", redacted)
    redacted = _PHONE.sub("[số điện thoại đã ẩn]", redacted)
    return redacted[:1000], digest


def submit_feedback(
    db: Session,
    *,
    user_id: str,
    request_id: str,
    feedback_type: str,
    reason: str,
    details: str | None,
    idempotency_key: str | None,
) -> tuple[UserFeedback, bool]:
    scan = db.execute(select(ScanEvent).where(ScanEvent.request_id == request_id)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy lượt phân tích này.")
    if scan.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không có quyền phản hồi lượt phân tích này.")

    key_hash = _sha256(idempotency_key) if idempotency_key else None
    if key_hash:
        existing = db.execute(
            select(UserFeedback).where(
                UserFeedback.user_id == user_id,
                UserFeedback.idempotency_key == key_hash,
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.scan_event_id != scan.id or existing.label != feedback_type:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Khóa idempotency đã được dùng cho phản hồi khác.")
            return existing, False

    safe_details, details_hash = minimise_details(details)
    row = UserFeedback(
        scan_event_id=scan.id,
        user_id=user_id,
        label=feedback_type,
        reason=reason,
        comment=safe_details,
        comment_sha256=details_hash,
        idempotency_key=key_hash,
        status="received",
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if not key_hash:
            raise
        existing = db.execute(
            select(UserFeedback).where(
                UserFeedback.user_id == user_id,
                UserFeedback.idempotency_key == key_hash,
            )
        ).scalar_one_or_none()
        if existing is None:
            raise
        if existing.scan_event_id != scan.id or existing.label != feedback_type:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Khóa idempotency đã được dùng cho phản hồi khác.",
            ) from None
        return existing, False
    db.refresh(row)
    return row, True
