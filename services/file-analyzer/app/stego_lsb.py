"""Motor local PNG/LSB. No expone rutas HTTP ni decide liberar archivos."""
from dataclasses import asdict, dataclass
from enum import Enum
from io import BytesIO
from pathlib import Path
import struct
import zlib

from PIL import Image, UnidentifiedImageError
from scipy.stats import chi2


class Classification(str, Enum):
    SIN_INDICIOS = "SIN_INDICIOS"
    SOSPECHOSO = "SOSPECHOSO"
    NO_CONCLUYENTE = "NO_CONCLUYENTE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class LSBConfig:
    max_bytes: int = 10 * 1024 * 1024
    max_width: int = 4096
    max_height: int = 4096
    max_pixels: int = 4_000_000
    min_pixels: int = 4096
    min_pair_count: int = 10  # Esperado >= 5 por cada miembro del par.
    min_pairs: int = 32
    min_coverage: float = 0.90
    suspicious_p: float = 0.05
    no_indications_p: float = 0.001

    def __post_init__(self):
        for name in ("max_bytes", "max_width", "max_height", "max_pixels",
                     "min_pixels", "min_pair_count", "min_pairs"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} debe ser entero positivo")
        if self.min_pair_count < 10 or self.min_pairs > 128:
            raise ValueError("Se requieren esperados >=5 y como máximo 128 pares")
        if not 0 < self.min_coverage <= 1:
            raise ValueError("Cobertura fuera de rango")
        if not 0 < self.no_indications_p < self.suspicious_p < 1:
            raise ValueError("Umbrales p fuera de rango")


LIMITATIONS = (
    "Un p alto indica compatibilidad con pares equiprobables; no probabilidad de esteganografía.",
    "Ruido natural, imágenes sintéticas y procesadas pueden producir falsos positivos.",
    "Cargas pequeñas, localizadas, sesgadas o métodos adaptativos pueden pasar inadvertidos.",
    "Píxeles correlacionados limitan la aproximación Chi-cuadrado; umbrales heurísticos sin calibración poblacional.",
    "Sólo RGB/RGBA de 8 bits y un fotograma; no se examinan alfa, metadatos ni contenido del mensaje.",
    "SIN_INDICIOS no garantiza ausencia de esteganografía, malware ni seguridad del archivo.",
)


@dataclass(frozen=True)
class ChannelIndicators:
    channel: str
    samples: int
    eligible_pairs: int
    coverage: float
    chi_square: float
    degrees_of_freedom: int
    p_value: float | None
    lsb_one_fraction: float
    sufficient: bool


@dataclass(frozen=True)
class LSBResult:
    classification: Classification
    reason: str
    policy: LSBConfig
    channels: tuple[ChannelIndicators, ...] = ()
    width: int | None = None
    height: int | None = None
    technique: str = "LSB_POV_CHI_SQUARE_RGB_V1"
    limitations: tuple[str, ...] = LIMITATIONS

    def to_dict(self) -> dict:
        return asdict(self)


def _validate_png(data: bytes, config: LSBConfig) -> tuple[int, int, int, int]:
    """Inspección acotada de firma, IHDR, chunks/CRC e IEND antes de decodificar."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("firma_no_png")
    if len(data) < 33 or data[8:16] != b"\x00\x00\x00\rIHDR":
        raise ValueError("ihdr_invalido")
    width, height, depth, color = struct.unpack(">IIBB", data[16:26])
    if not width or not height:
        raise ValueError("dimensiones_invalidas")
    if (width > config.max_width or height > config.max_height
            or width * height > config.max_pixels):
        raise ValueError("limite_dimensiones_o_pixeles")
    offset = 8
    while offset + 12 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("chunk_truncado")
        kind = data[offset + 4:offset + 8]
        crc = zlib.crc32(memoryview(data)[offset + 4:end - 4]) & 0xffffffff
        if crc != int.from_bytes(data[end - 4:end], "big"):
            raise ValueError("crc_invalido")
        if kind == b"IEND":
            if length or end != len(data):
                raise ValueError("final_png_invalido")
            return width, height, depth, color
        offset = end
    raise ValueError("iend_ausente")


def _channel(histogram: list[int], name: str, config: LSBConfig) -> ChannelIndicators:
    samples = sum(histogram)
    pairs = [(histogram[i], histogram[i + 1]) for i in range(0, 256, 2)
             if histogram[i] + histogram[i + 1] >= config.min_pair_count]
    covered = sum(a + b for a, b in pairs)
    statistic = sum((a - b) ** 2 / (a + b) for a, b in pairs)
    # Una restricción de igualdad por par, condicionando por su total: k grados.
    p_value = float(chi2.sf(statistic, len(pairs))) if pairs else None
    coverage = covered / samples
    sufficient = (samples >= config.min_pixels and len(pairs) >= config.min_pairs
                  and coverage >= config.min_coverage)
    return ChannelIndicators(name, samples, len(pairs), coverage, statistic,
                             len(pairs), p_value, sum(histogram[1::2]) / samples,
                             sufficient)


def analyze_png_bytes(data: bytes, config: LSBConfig | None = None) -> LSBResult:
    """Analiza bytes ya acotados por el llamador; nunca confía en nombre o MIME."""
    config = config or LSBConfig()
    if not isinstance(data, bytes):
        raise TypeError("data debe ser bytes")
    if len(data) > config.max_bytes:
        return LSBResult(Classification.ERROR, "limite_bytes", config)
    try:
        width, height, depth, color = _validate_png(data, config)
        with Image.open(BytesIO(data), formats=["PNG"]) as image:
            image.verify()
        with Image.open(BytesIO(data), formats=["PNG"]) as image:
            image.load()
            if depth != 8 or color not in (2, 6) or image.n_frames != 1:
                return LSBResult(Classification.NO_CONCLUYENTE,
                                 "png_fuera_del_alcance_rgb8_estatico", config,
                                 width=width, height=height)
            histogram = image.convert("RGB").histogram()
    except ValueError as exc:
        # Los mensajes del parser son códigos fijos; no se divulgan metadatos.
        reason = str(exc) if str(exc) in {
            "firma_no_png", "ihdr_invalido", "dimensiones_invalidas",
            "limite_dimensiones_o_pixeles", "chunk_truncado", "crc_invalido",
            "final_png_invalido", "iend_ausente",
        } else "png_no_decodificable"
        return LSBResult(Classification.ERROR, reason, config)
    except (OSError, SyntaxError, EOFError, UnidentifiedImageError,
            Image.DecompressionBombError):
        return LSBResult(Classification.ERROR, "png_no_decodificable", config)

    channels = tuple(_channel(histogram[i * 256:(i + 1) * 256], name, config)
                     for i, name in enumerate("RGB"))
    if not all(c.sufficient for c in channels):
        classification, reason = Classification.NO_CONCLUYENTE, "muestra_o_cobertura_insuficiente"
    elif sum(c.p_value >= config.suspicious_p for c in channels) >= 2:
        classification, reason = Classification.SOSPECHOSO, "pares_equiprobables_en_al_menos_dos_canales"
    elif all(c.p_value <= config.no_indications_p for c in channels):
        classification, reason = Classification.SIN_INDICIOS, "equiprobabilidad_rechazada_en_tres_canales"
    else:
        classification, reason = Classification.NO_CONCLUYENTE, "evidencia_intermedia_o_discordante"
    return LSBResult(classification, reason, config, channels, width, height)


def analyze_png(path: str | Path, config: LSBConfig | None = None) -> LSBResult:
    """Lee como máximo max_bytes+1 de un archivo local; no persiste resultados."""
    config = config or LSBConfig()
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(config.max_bytes + 1)
    except OSError:
        return LSBResult(Classification.ERROR, "archivo_no_legible", config)
    return analyze_png_bytes(data, config)
