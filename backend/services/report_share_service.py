"""Create privacy-minimised, expiring report share snapshots."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from backend.models import ReportShare, ScanEvent
from backend.security_utils import utcnow

EXPIRY_HOURS = {"1h": 1, "24h": 24, "7d": 24 * 7}
MAX_ACTIVE_SHARES = 50
MAX_CREATES_PER_HOUR = 10
MAX_SNAPSHOT_BYTES = 16 * 1024
MAX_EVIDENCE = 8

_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\s().-]?){8,15}(?!\w)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?\b")
_SECRET = re.compile(r"\b(?:sk|pk|pw|api)[_-][A-Za-z0-9_-]{16,}\b", re.IGNORECASE)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")
# A 16-digit payment card slipped past _PHONE, which stops at 15 digits, and the
# 32-character floor of _LONG_TOKEN left 20-character AWS access key IDs and
# GitLab "glpat-" tokens intact on a link anyone can open.
_PAN = re.compile(r"(?<!\w)(?:\d[ -]?){13,19}(?!\w)")
_VENDOR_TOKEN = re.compile(
    r"\b(?:AKIA|ASIA|AIza|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xox[abposr]-|shpat_|shpss_)"
    r"[A-Za-z0-9_-]{8,}\b"
)


def hash_share_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sanitize_public_text(value: object, *, limit: int) -> str:
    text = " ".join(str(value or "").split())
    text = _URL.sub("[URL đã ẩn]", text)
    text = _EMAIL.sub("[email đã ẩn]", text)
    # Card numbers before phone numbers: _PHONE would otherwise consume the
    # first 15 digits of a 16-digit PAN and leave the remainder visible.
    text = _PAN.sub("[số thẻ đã ẩn]", text)
    text = _PHONE.sub("[số điện thoại đã ẩn]", text)
    text = _JWT.sub("[token đã ẩn]", text)
    text = _VENDOR_TOKEN.sub("[khóa bí mật đã ẩn]", text)
    text = _SECRET.sub("[khóa bí mật đã ẩn]", text)
    text = _LONG_TOKEN.sub("[chuỗi nhạy cảm đã ẩn]", text)
    return text[:limit]


def build_redacted_snapshot(scan: ScanEvent) -> dict:
    modality = scan.modality if scan.modality in {"url", "email", "sms", "text"} else "text"
    risk_level = scan.risk_level if scan.risk_level in {"safe", "low", "medium", "high", "critical", "warn", "danger"} else "unknown"
    evidence = []
    for item in list(scan.evidence)[:MAX_EVIDENCE]:
        evidence.append({
            "source": sanitize_public_text(item.source, limit=80),
            "message": sanitize_public_text(item.message, limit=300),
            "severity": item.severity if item.severity in {"info", "low", "medium", "high", "critical"} else "info",
            "feature": sanitize_public_text(item.feature, limit=100) if item.feature else None,
        })
    snapshot = {
        "score": max(0, min(100, round(float(scan.risk_score) * 100 if float(scan.risk_score) <= 1 else float(scan.risk_score)))),
        "type": modality,
        "decision": sanitize_public_text(scan.decision, limit=40),
        "riskLevel": risk_level,
        "confidence": max(0, min(100, round(float(scan.confidence) * 100 if float(scan.confidence) <= 1 else float(scan.confidence)))),
        "evidence": evidence,
    }
    if len(json.dumps(snapshot, ensure_ascii=False).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Bản tóm tắt vượt giới hạn chia sẻ.")
    return snapshot


def create_report_share(db: Session, *, user_id: str, request_id: str, expires_in: str) -> tuple[ReportShare, str]:
    scan = db.execute(
        select(ScanEvent).options(selectinload(ScanEvent.evidence)).where(ScanEvent.request_id == request_id)
    ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy lượt phân tích này.")
    if scan.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không có quyền chia sẻ lượt phân tích này.")
    now = utcnow()
    recent = db.scalar(select(func.count()).select_from(ReportShare).where(
        ReportShare.user_id == user_id, ReportShare.created_at >= now - timedelta(hours=1)
    )) or 0
    active = db.scalar(select(func.count()).select_from(ReportShare).where(
        ReportShare.user_id == user_id, ReportShare.revoked_at.is_(None), ReportShare.expires_at > now
    )) or 0
    if recent >= MAX_CREATES_PER_HOUR or active >= MAX_ACTIVE_SHARES:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Bạn đã tạo quá nhiều liên kết chia sẻ. Hãy thử lại sau.")
    token = secrets.token_urlsafe(32)
    row = ReportShare(
        user_id=user_id,
        scan_event_id=scan.id,
        token_hash=hash_share_token(token),
        snapshot=build_redacted_snapshot(scan),
        expires_at=now + timedelta(hours=EXPIRY_HOURS[expires_in]),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, token


def get_public_report_share(db: Session, token: str) -> ReportShare:
    row = db.execute(select(ReportShare).where(ReportShare.token_hash == hash_share_token(token))).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Liên kết chia sẻ không tồn tại hoặc đã bị thu hồi.")
    if row.expires_at <= utcnow():
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Liên kết chia sẻ đã hết hạn.")
    return row


def revoke_report_share(db: Session, *, user_id: str, share_id: str) -> None:
    row = db.get(ReportShare, share_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy liên kết chia sẻ.")
    if row.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không có quyền thu hồi liên kết này.")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        db.commit()
