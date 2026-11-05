"""Adaptador interno LSB -> transferencia. Nunca emite CLEAN."""
import json
from pathlib import Path

from .analyzer import AnalysisResult, Classification
from . import stego_lsb


class StegoAnalyzer:
    def __init__(self, config: stego_lsb.LSBConfig | None = None):
        self.config = config or stego_lsb.LSBConfig()

    def analyze(self, path: Path, sha256: str) -> AnalysisResult:
        try:
            report = stego_lsb.analyze_png(path, self.config)
            classification = Classification.INCONCLUSIVE
            if report.classification == stego_lsb.Classification.SOSPECHOSO:
                classification = Classification.SUSPICIOUS
                reason = "lsb_suspicious"
            elif report.classification == stego_lsb.Classification.SIN_INDICIOS:
                reason = "additional_security_checks_required"
            elif report.classification == stego_lsb.Classification.ERROR:
                reason = "lsb_analysis_error"
            else:
                reason = "lsb_inconclusive"
            return AnalysisResult(sha256=sha256, classification=classification,
                                  reason=reason, analysis=json.loads(json.dumps(
                                      report.to_dict(), allow_nan=False)))
        except Exception:
            # No persistir excepciones, rutas ni datos del archivo como motivo.
            report = stego_lsb.LSBResult(stego_lsb.Classification.ERROR,
                                        "detector_failed", self.config)
            return AnalysisResult(sha256=sha256,
                                  classification=Classification.INCONCLUSIVE,
                                  reason="lsb_detector_failed", analysis=json.loads(json.dumps(
                                      report.to_dict(), allow_nan=False)))
