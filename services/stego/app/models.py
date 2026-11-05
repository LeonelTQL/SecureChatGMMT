from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class AnalysisRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: UUID
    user_id: UUID
    filename: str = Field(max_length=200)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime
    technique: str
    indicators: dict[str, float]
    status: Literal["pending", "sin_indicios", "sospechoso", "no_concluyente", "error"]
    action: Literal["cuarentena", "advertencia"]
    limitations: str
