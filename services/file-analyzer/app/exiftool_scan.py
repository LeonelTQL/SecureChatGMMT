"""Extracción de sólo lectura con proyección de privacidad antes de persistir."""
from dataclasses import asdict, dataclass
from datetime import datetime
import json
import math
from pathlib import Path
import re

from .scan_runner import ScanLimits, check_file, run_scan


@dataclass(frozen=True)
class MetadataReport:
    status: str  # EXTRACTED, ABSENT, INCONSISTENT, UNAVAILABLE
    reason: str
    metadata: dict
    issues: tuple[str, ...]
    limits: dict
    engine: str = "exiftool"

    def to_dict(self):
        result = asdict(self)
        result["issues"] = list(self.issues)
        return result


DATE_TAGS = {
    "ExifIFD:DateTimeOriginal": "date_time_original",
    "ExifIFD:CreateDate": "create_date",
    "IFD0:ModifyDate": "modify_date",
    "XMP-exif:DateTimeOriginal": "xmp_date_time_original",
    "XMP-xmp:CreateDate": "xmp_create_date",
    "XMP-xmp:ModifyDate": "xmp_modify_date",
    "PNG:CreationTime": "png_creation_date",
}
NUMERIC_TAGS = {
    "IFD0:Orientation": ("orientation", 1, 8),
    "ExifIFD:ColorSpace": ("color_space", 0, 65535),
    "ExifIFD:ISO": ("iso", 0, 1_000_000),
    "ExifIFD:ExposureTime": ("exposure_time_seconds", 0, 1_000_000),
    "ExifIFD:FNumber": ("f_number", 0, 10_000),
    "ExifIFD:FocalLength": ("focal_length_mm", 0, 1_000_000),
}


class ExifToolInspector:
    def __init__(self, limits: ScanLimits | None = None):
        self.limits = limits or ScanLimits(timeout_seconds=5, cpu_seconds=3,
                                          memory_bytes=256 * 1024 ** 2)

    def unavailable(self, reason="exiftool_failed") -> MetadataReport:
        return MetadataReport("UNAVAILABLE", reason, {}, (), asdict(self.limits))

    def inspect(self, path: Path, expected: dict) -> MetadataReport:
        error = check_file(path, self.limits)
        if error:
            return self.unavailable(error)
        # -config debe ser la primera opción: no cargar configuración Perl local.
        # No EXIF:all, GPS, comentarios, autores, rutas ni identificadores de cámara.
        command = ["exiftool", "-config", "", "-j", "-G1", "-a", "-n",
                   "-FileType", "-MIMEType", "-ImageWidth", "-ImageHeight",
                   "-ExifImageWidth", "-ExifImageHeight", "-Software", "-CreatorTool",
                   "-DateTimeOriginal", "-CreateDate", "-ModifyDate", "-CreationTime",
                   "-EXIF:ExifVersion", "-EXIF:Orientation", "-EXIF:ColorSpace",
                   "-EXIF:ISO", "-EXIF:ExposureTime", "-EXIF:FNumber", "-EXIF:FocalLength",
                   "-Warning", "-Error", "--", str(path.resolve())]
        completed = run_scan(command, self.limits)
        if completed.error:
            return self.unavailable(completed.error)
        if completed.returncode != 0:
            return self.unavailable("exiftool_failed")
        try:
            parsed = json.loads(completed.output)
            if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
                return self.unavailable("exiftool_invalid_output")
            tags = parsed[0]
            if "ExifTool:Error" in tags:
                return self.unavailable("exiftool_failed")
            return self._evaluate(tags, expected)
        except (ValueError, TypeError, OverflowError):
            return self.unavailable("exiftool_invalid_output")

    def _evaluate(self, tags: dict, expected: dict) -> MetadataReport:
        issues, details = [], {}
        file_type = tags.get("File:FileType")
        mime = tags.get("File:MIMEType")
        if file_type not in {"PNG", "JPEG"} or mime not in {"image/png", "image/jpeg"}:
            return self.unavailable("exiftool_incomplete_output")
        details.update({"format": file_type, "mime": mime})
        if file_type != expected.get("format") or mime != expected.get("mime"):
            issues.append("format_mismatch")
        group = "PNG" if file_type == "PNG" else "File"
        for dimension in ("Width", "Height"):
            value = tags.get(f"{group}:Image{dimension}")
            if type(value) is not int or value <= 0:
                return self.unavailable("exiftool_incomplete_output")
            details[dimension.lower()] = value
            if value != expected.get(dimension.lower()):
                issues.append("decoded_dimensions_mismatch")
            for field in (f"ExifIFD:ExifImage{dimension}", f"IFD0:Image{dimension}"):
                if field in tags and tags[field] != value:
                    issues.append("exif_dimensions_mismatch")
        if "ExifTool:Warning" in tags:
            # El mensaje puede incluir valores privados: conservar sólo su presencia.
            issues.append("metadata_parser_warning")
        exif = {}
        for tag, (name, minimum, maximum) in NUMERIC_TAGS.items():
            if tag not in tags:
                continue
            value = tags[tag]
            if (type(value) in (int, float) and math.isfinite(value)
                    and minimum <= value <= maximum):
                exif[name] = value
            else:
                issues.append("invalid_exif_value")
        if "ExifIFD:ExifVersion" in tags:
            value = tags["ExifIFD:ExifVersion"]
            if isinstance(value, str) and re.fullmatch(r"\d{4}", value):
                exif["exif_version"] = value
            else:
                issues.append("invalid_exif_value")
        dates = {}
        for tag, name in DATE_TAGS.items():
            if tag not in tags:
                continue
            value = tags[tag]
            if isinstance(value, str) and re.fullmatch(
                r"\d{4}[:-]\d{2}[:-]\d{2}[ T]\d{2}:\d{2}:\d{2}"
                r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})?", value
            ):
                try:
                    normalized = value[:10].replace(":", "-") + value[10:]
                    dates[name] = datetime.fromisoformat(normalized).date().isoformat()
                    continue
                except ValueError:
                    pass
            issues.append("invalid_metadata_date")
        software = []
        for tag in ("IFD0:Software", "PNG:Software", "XMP-xmp:CreatorTool"):
            if tag not in tags:
                continue
            family = "unrecognized"
            value = tags[tag]
            if isinstance(value, str) and len(value) <= 80:
                for candidate in ("Adobe Photoshop", "Adobe Lightroom", "GIMP", "Pillow",
                                  "ImageMagick", "Paint.NET", "Affinity Photo", "ExifTool"):
                    if re.fullmatch(re.escape(candidate) + r"(?: [0-9][0-9.\-]*)?", value):
                        family = candidate
                        break
            software.append(family)
        details.update({"exif": exif, "dates": dates, "software_families": sorted(set(software))})
        has_exif = any(tag.startswith(("IFD0:", "ExifIFD:")) for tag in tags if tag in {
            *DATE_TAGS, *NUMERIC_TAGS, "ExifIFD:ExifVersion", "IFD0:Software",
            "ExifIFD:ExifImageWidth", "ExifIFD:ExifImageHeight", "IFD0:ImageWidth", "IFD0:ImageHeight"})
        details["has_allowlisted_exif"] = has_exif
        issues = tuple(sorted(set(issues)))
        status = "INCONSISTENT" if issues else (
            "EXTRACTED" if has_exif or dates or software else "ABSENT")
        reason = {"INCONSISTENT": "metadata_inconsistent", "EXTRACTED": "metadata_extracted",
                  "ABSENT": "no_allowlisted_metadata"}[status]
        return MetadataReport(status, reason, details, issues, asdict(self.limits))
