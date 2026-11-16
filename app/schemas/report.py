from pydantic import BaseModel, Field

from app.models.report import REPORT_REASONS, REPORT_STATUSES, REPORT_TARGETS


class ReportCreate(BaseModel):
    target_type: str = Field(pattern="^(" + "|".join(REPORT_TARGETS) + ")$")
    target_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(pattern="^(" + "|".join(REPORT_REASONS) + ")$")
    # Market-key sealed {"text": ..., "evidence": ...}; base64.
    details_ct: str | None = Field(default=None, max_length=40_000)
    sig: str | None = None


class ReportResolve(BaseModel):
    status: str = Field(pattern="^(" + "|".join(s for s in REPORT_STATUSES if s != "open") + ")$")
