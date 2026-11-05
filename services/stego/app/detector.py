"""Contrato activo de Diana. Reutiliza el motor histórico sin iniciar su API."""
import importlib
import importlib.util
import hashlib
from pathlib import Path
import sys


def _engine():
    # Docker copia exactamente el código histórico bajo un nombre independiente
    # de app, evitando colisiones con app.main/security del servicio activo.
    if importlib.util.find_spec("stego_diana") is None:
        source = Path(__file__).resolve().parents[2] / "file-analyzer" / "app"
        spec = importlib.util.spec_from_file_location(
            "stego_diana", source / "__init__.py", submodule_search_locations=[str(source)])
        package = importlib.util.module_from_spec(spec)
        sys.modules["stego_diana"] = package
        spec.loader.exec_module(package)
    return importlib.import_module("stego_diana.image_validation")


def analyze(path: Path) -> dict:
    engine = _engine()
    from stego_diana.stego_adapter import StegoAnalyzer

    # Lectura acotada independiente de nombre/MIME suministrados por el cliente.
    limits = engine.ImageLimits()
    with path.open("rb") as stream:
        header = stream.read(16)
    size = path.stat().st_size
    indicators = {"input_bytes": size}
    if size > limits.max_bytes:
        return {"status": "error", "technique": "IMAGE_VALIDATION_V1",
                "indicators": indicators, "limitations": "Límite de imágenes: 5 MiB.",
                "reason": "image_too_large"}
    if header.startswith(b"BM"):
        # BMP se conserva como formato de recepción del servicio del equipo;
        # el motor histórico sólo soporta JPG/PNG. No fingir verificaciones.
        return {"status": "no_concluyente", "technique": "IMAGE_VALIDATION_V1",
                "indicators": indicators, "limitations": "BMP: sin detector ni verificaciones de Diana aplicables; cuarentena.",
                "reason": "bmp_not_supported_by_analysis_pipeline"}
    suffix = ".jpg" if header.startswith(b"\xff\xd8\xff") else ".png"
    with path.open("rb") as stream:
        sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    result = engine.ValidatedImageAnalyzer(StegoAnalyzer(), "image" + suffix, limits).analyze(path, sha256)
    # El registro y las comprobaciones antes/después pertenecen al servicio activo.
    report = result.analysis or {}
    validation = report.get("validation", {})
    for dimension in ("width", "height"):
        if isinstance(validation.get(dimension), int):
            indicators["image_" + dimension] = validation[dimension]
    channels = report.get("channels", [])
    for channel in channels:
        prefix = channel["channel"].lower() + "_"
        for key in ("samples", "eligible_pairs", "coverage", "chi_square",
                    "degrees_of_freedom", "p_value", "lsb_one_fraction"):
            if channel.get(key) is not None:
                indicators[prefix + key] = channel[key]
    checks, metadata = report.get("antimalware", {}), report.get("metadata", {})
    reason = report.get("reason", result.reason)
    if not validation.get("valid"):
        status = "error"
    elif (set(checks) != {"clamav", "yara"}
          or any(c.get("status") not in {"CLEAR", "DETECTED"} for c in checks.values())
          or metadata.get("status") not in {"EXTRACTED", "ABSENT", "INCONSISTENT"}):
        status, reason = "no_concluyente", "mandatory_verification_unavailable"
    elif any(c["status"] == "DETECTED" for c in checks.values()):
        status, reason = "sospechoso", "antimalware_detected"
    elif metadata.get("status") == "INCONSISTENT":
        status, reason = "no_concluyente", "metadata_inconsistent"
    elif validation.get("format") != "PNG":
        status = "no_concluyente"
    else:
        status = {"SIN_INDICIOS": "sin_indicios", "SOSPECHOSO": "sospechoso",
                  "NO_CONCLUYENTE": "no_concluyente", "ERROR": "error"}.get(
                      report.get("classification"), "error")
    limitations = report.get("limitations", [])
    if isinstance(limitations, list):
        limitations = " ".join(limitations)
    limitations += " La ausencia de coincidencias antimalware no garantiza seguridad. El archivo permanece privado."
    reports = {key: report[key] for key in ("validation", "antimalware", "metadata") if key in report}
    if validation.get("format") == "PNG" and "channels" in report:
        reports["lsb"] = {k: v for k, v in report.items() if k not in reports}
    return {"status": status, "technique": report.get("technique", "IMAGE_VALIDATION_V1"),
            "indicators": indicators, "limitations": limitations[:2000], "reason": reason,
            "reports": reports}
