"""Validación acotada por contenido, previa a cualquier analizador de imágenes."""
from dataclasses import asdict, dataclass
from io import BytesIO
import os
from pathlib import Path
import warnings

from PIL import Image, ImageFile

from .analyzer import AnalysisResult, Analyzer, Classification
from .stego_lsb import LSBConfig, _validate_png


@dataclass(frozen=True)
class ImageLimits:
    max_bytes: int = 5 * 1024 * 1024
    max_width: int = 4096
    max_height: int = 4096
    max_pixels: int = 4_000_000

    def __post_init__(self):
        for value in asdict(self).values():
            if type(value) is not int or value <= 0:
                raise ValueError("image_limits_must_be_positive_integers")

    @classmethod
    def from_env(cls):
        return cls(**{name: int(os.getenv("IMAGE_" + name.upper(), str(default)))
                      for name, default in asdict(cls()).items()})


@dataclass(frozen=True)
class ImageValidation:
    valid: bool
    reason: str
    policy: ImageLimits
    format: str | None = None
    mime: str | None = None
    width: int | None = None
    height: int | None = None

    def to_dict(self):
        return asdict(self)


def validate_image(path: Path, filename: str, limits: ImageLimits) -> ImageValidation:
    """Nombre lógico del registro, no el UUID físico; MIME deducido de bytes."""
    detected_format = mime = None
    width = height = None

    def result(valid, reason):
        return ImageValidation(valid, reason, limits, detected_format, mime, width, height)

    suffix = Path(filename).suffix.lower()
    expected = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG"}.get(suffix)
    if expected is None:
        return result(False, "unsupported_image_extension")
    try:
        with path.open("rb") as source:
            data = source.read(limits.max_bytes + 1)
    except OSError:
        return result(False, "image_unreadable")
    if len(data) > limits.max_bytes:
        return result(False, "image_too_large")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_format, mime = "PNG", "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        detected_format, mime = "JPEG", "image/jpeg"
    else:
        return result(False, "unsupported_image_signature")
    if expected != detected_format:
        return result(False, "image_extension_content_mismatch")
    # Nunca activar la tolerancia global a truncamientos, ni heredarla silenciosamente.
    if ImageFile.LOAD_TRUNCATED_IMAGES:
        return result(False, "unsafe_image_decoder_configuration")
    try:
        if detected_format == "PNG":
            # Reutiliza la validación estructural existente, sin tocar el detector.
            config = LSBConfig(max_bytes=limits.max_bytes, max_width=limits.max_width,
                               max_height=limits.max_height, max_pixels=limits.max_pixels)
            try:
                width, height, _, _ = _validate_png(data, config)
            except ValueError as exc:
                reason = ("image_dimensions_exceeded" if str(exc) == "limite_dimensiones_o_pixeles"
                          else "image_malformed")
                return result(False, reason)
        elif not data.endswith(b"\xff\xd9"):
            return result(False, "image_malformed")
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data), formats=[detected_format]) as image:
                width, height = image.size
                if (width > limits.max_width or height > limits.max_height
                        or width * height > limits.max_pixels):
                    return result(False, "image_dimensions_exceeded")
                if image.format != detected_format:
                    return result(False, "image_signature_decoder_mismatch")
                image.verify()
            with Image.open(BytesIO(data), formats=[detected_format]) as image:
                image.load()
        return result(True, "image_valid")
    except (Image.DecompressionBombWarning, Image.DecompressionBombError):
        return result(False, "image_decompression_bomb")
    except (OSError, ValueError, SyntaxError, EOFError):
        return result(False, "image_malformed")


class ValidatedImageAnalyzer:
    """Puerta previa compatible con Analyzer; no cambia almacenamiento ni hashes."""
    def __init__(self, analyzer: Analyzer, filename: str, limits: ImageLimits):
        self.analyzer, self.filename, self.limits = analyzer, filename, limits

    def analyze(self, path: Path, sha256: str) -> AnalysisResult:
        validation = validate_image(path, self.filename, self.limits)
        details = validation.to_dict()
        if not validation.valid or validation.format == "JPEG":
            reason = validation.reason if not validation.valid else "jpeg_detector_not_available"
            return AnalysisResult(sha256=sha256, classification=Classification.INCONCLUSIVE,
                                  reason=reason, analysis={
                                      "technique": "IMAGE_VALIDATION_V1",
                                      "classification": "ERROR" if not validation.valid else "NO_CONCLUYENTE",
                                      "reason": reason, "channels": [], "validation": details,
                                      "limitations": ["La validación de formato no demuestra seguridad ni ausencia de datos ocultos."]})
        result = AnalysisResult.model_validate(self.analyzer.analyze(path, sha256))
        return result.model_copy(update={"analysis": {**(result.analysis or {}), "validation": details}})
