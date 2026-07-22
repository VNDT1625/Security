"""User feedback and site-report API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from backend.db import get_db
from backend.models import ScanEvent, UserFeedback
from backend.routers.auth import CurrentSession, require_admin
from backend.security_utils import utcnow
from backend.services.feedback_service import minimise_details, submit_feedback

router = APIRouter(prefix="/v1/feedback", tags=["feedback"])


class FeedbackInput(BaseModel):
    requestId: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    feedbackType: Literal["false_positive", "false_negative", "report_site"]
    reason: Literal["incorrect_verdict", "missed_threat", "suspicious_site", "incorrect_evidence", "other"]
    details: str | None = Field(default=None, max_length=2000)
    idempotencyKey: str | None = Field(default=None, min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")

    @model_validator(mode="after")
    def validate_reason_for_type(self):
        allowed = {
            "false_positive": {"incorrect_verdict", "incorrect_evidence", "other"},
            "false_negative": {"missed_threat", "incorrect_evidence", "other"},
            "report_site": {"suspicious_site", "incorrect_evidence", "other"},
        }
        if self.reason not in allowed[self.feedbackType]:
            raise ValueError("Lý do không phù hợp với loại phản hồi.")
        return self


class FeedbackOutput(BaseModel):
    id: str
    requestId: str
    feedbackType: str
    reason: str
    status: str
    createdAt: datetime


def _output(row: UserFeedback, request_id: str) -> FeedbackOutput:
    return FeedbackOutput(
        id=row.id,
        requestId=request_id,
        feedbackType=row.label,
        reason=row.reason,
        status=row.status,
        createdAt=row.created_at,
    )


@router.post("", response_model=FeedbackOutput, status_code=status.HTTP_201_CREATED)
def create_feedback(
    payload: FeedbackInput,
    response: Response,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> FeedbackOutput:
    row, created = submit_feedback(
        db,
        user_id=auth.user.id,
        request_id=payload.requestId,
        feedback_type=payload.feedbackType,
        reason=payload.reason,
        details=payload.details,
        idempotency_key=payload.idempotencyKey,
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return _output(row, payload.requestId)


class FeedbackAdminUpdate(BaseModel):
    status: Literal["received", "reviewing", "resolved", "rejected"]
    note: str | None = Field(default=None, max_length=2000)


@router.get("/admin", dependencies=[Depends(require_admin)])
def list_feedback(
    status_filter: Literal["received", "reviewing", "resolved", "rejected"] | None = Query(default=None, alias="status"),
    feedback_type: Literal["false_positive", "false_negative", "report_site"] | None = None,
    modality: Literal["url", "email", "sms"] | None = None,
    query: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: DbSession = Depends(get_db),
) -> dict:
    bounded_limit = max(1, min(limit, 200))
    statement = (
        select(UserFeedback, ScanEvent.request_id, ScanEvent.modality)
        .join(ScanEvent, UserFeedback.scan_event_id == ScanEvent.id)
        .order_by(UserFeedback.created_at.desc())
    )
    if status_filter:
        statement = statement.where(UserFeedback.status == status_filter)
    if feedback_type:
        statement = statement.where(UserFeedback.label == feedback_type)
    if modality:
        statement = statement.where(ScanEvent.modality == modality)
    if query:
        safe_query = query.strip()[:100]
        if safe_query:
            statement = statement.where(ScanEvent.request_id.ilike(f"%{safe_query}%"))
    rows = db.execute(
        statement.offset(max(0, offset))
        .limit(bounded_limit)
    ).all()
    return {
        "feedback": [
            {
                **_output(row, request_id).model_dump(mode="json"),
                "modality": modality,
                "details": row.comment,
                "adminNote": row.admin_note,
                "updatedAt": row.updated_at.isoformat(),
            }
            for row, request_id, modality in rows
        ]
    }


@router.patch("/admin/{feedback_id}", dependencies=[Depends(require_admin)])
def update_feedback(
    feedback_id: str,
    payload: FeedbackAdminUpdate,
    db: DbSession = Depends(get_db),
) -> dict:
    row = db.get(UserFeedback, feedback_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy phản hồi.")
    safe_note, _ = minimise_details(payload.note)
    row.status = payload.status
    row.admin_note = safe_note
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    request_id, modality = db.execute(
        select(ScanEvent.request_id, ScanEvent.modality).where(ScanEvent.id == row.scan_event_id)
    ).one()
    return {
        **_output(row, request_id).model_dump(mode="json"),
        "modality": modality,
        "details": row.comment,
        "adminNote": row.admin_note,
        "updatedAt": row.updated_at.isoformat(),
    }
