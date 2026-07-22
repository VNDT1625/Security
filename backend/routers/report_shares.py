"""Authenticated report-share creation and public redacted report access."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Path, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db import get_db
from backend.routers.auth import CurrentSession
from backend.services.report_share_service import (
    create_report_share,
    get_public_report_share,
    revoke_report_share,
)

router = APIRouter(prefix="/v1/report-shares", tags=["report-shares"])


class CreateReportShareInput(BaseModel):
    requestId: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    expiresIn: Literal["1h", "24h", "7d"] = "24h"


class CreateReportShareOutput(BaseModel):
    id: str
    shareToken: str
    expiresAt: datetime


class PublicReportShareOutput(BaseModel):
    id: str
    snapshot: dict
    expiresAt: datetime


@router.post("", response_model=CreateReportShareOutput, status_code=status.HTTP_201_CREATED)
def create_share(payload: CreateReportShareInput, auth: CurrentSession, db: Session = Depends(get_db)) -> CreateReportShareOutput:
    row, token = create_report_share(db, user_id=auth.user.id, request_id=payload.requestId, expires_in=payload.expiresIn)
    return CreateReportShareOutput(id=row.id, shareToken=token, expiresAt=row.expires_at)


@router.get("/public/{token}", response_model=PublicReportShareOutput)
def public_share(token: str = Path(min_length=40, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"), db: Session = Depends(get_db)) -> PublicReportShareOutput:
    row = get_public_report_share(db, token)
    return PublicReportShareOutput(id=row.id, snapshot=row.snapshot, expiresAt=row.expires_at)


@router.delete("/{share_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_share(share_id: str, auth: CurrentSession, db: Session = Depends(get_db)) -> Response:
    revoke_report_share(db, user_id=auth.user.id, share_id=share_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
