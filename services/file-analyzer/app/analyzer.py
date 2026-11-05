"""Contrato local para integrar el motor de Diana sin aprobar por defecto."""
from enum import Enum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class Classification(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    classification: Classification
    reason: str = Field(min_length=1, max_length=200)


class Analyzer(Protocol):
    def analyze(self, path: Path, sha256: str) -> AnalysisResult: ...


class UnconfiguredAnalyzer:
    def analyze(self, path: Path, sha256: str) -> AnalysisResult:
        return AnalysisResult(
            sha256=sha256,
            classification=Classification.INCONCLUSIVE,
            reason="analyzer_not_configured",
        )
