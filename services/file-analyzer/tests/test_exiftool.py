"""JSON simulado para errores y privacidad; real_* exige ExifTool instalado."""
from dataclasses import replace
from io import BytesIO
import json
from pathlib import Path
import shutil
import sys

from fastapi.testclient import TestClient
from PIL import Image
import pytest

from app import exiftool_scan
from app.antimalware import MalwareChecks
from app.clamav_scan import ScanResult
from app.exiftool_scan import ExifToolInspector
from app.image_validation import ImageLimits, validate_image
from app.main import create_app
from app.scan_runner import CommandResult, ScanLimits


EXPECTED = {"format": "JPEG", "mime": "image/jpeg", "width": 64, "height": 64}
BASE_TAGS = {"File:FileType": "JPEG", "File:MIMEType": "image/jpeg",
             "File:ImageWidth": 64, "File:ImageHeight": 64}


def image_bytes(fmt="JPEG", metadata=False, mismatch=False, malformed=False):
    output = BytesIO()
    kwargs = {}
    if metadata:
        exif = Image.Exif()
        exif[0x0131] = "GIMP 2.10.36"
        exif[0x0132] = "2026:11:04 12:34:56"
        exif[0x8769] = {0x9000: b"0232", 0x9003: "2026:11:04 10:20:30",
                        0xA002: 999 if mismatch else 64, 0xA003: 64, 0x8827: 200}
        # GPS real en la imagen: el informe jamás debe incluir estas coordenadas.
        exif[0x8825] = {1: "N", 2: (47.0, 23.0, 1.0),
                        3: "E", 4: (8.0, 2.0, 3.0)}
        kwargs["exif"] = exif
    if malformed:
        kwargs["exif"] = b"Exif\x00\x00broken TIFF metadata"
    Image.new("RGB", (64, 64), "blue").save(output, format=fmt, **kwargs)
    return output.getvalue()


@pytest.fixture
def target(tmp_path):
    path = tmp_path / "object"
    path.write_bytes(image_bytes())
    return path


def simulate(monkeypatch, tags, code=0):
    calls = []
    def runner(argv, limits):
        calls.append(argv)
        return CommandResult(code, json.dumps([tags]))
    monkeypatch.setattr(exiftool_scan, "run_scan", runner)
    return calls


def test_simulated_absence_is_not_suspicious(target, monkeypatch):
    calls = simulate(monkeypatch, BASE_TAGS)
    report = ExifToolInspector().inspect(target, EXPECTED)
    assert report.status == "ABSENT" and report.issues == ()
    assert calls[0][:3] == ["exiftool", "-config", ""]
    assert "-EXIF:all" not in calls[0] and "-GPS:all" not in calls[0]
    assert calls[0][-2:] == ["--", str(target.resolve())]


def test_simulated_privacy_projection(target, monkeypatch):
    tags = {**BASE_TAGS, "SourceFile": "SECRET/private.jpg", "GPS:GPSLatitude": 47.383611,
            "GPS:GPSLongitude": 8.034167, "IFD0:Artist": "SECRET PERSON",
            "ExifIFD:SerialNumber": "SECRET SERIAL", "IFD0:Software": "SECRET GPS 47.383611",
            "ExifIFD:DateTimeOriginal": "2026:11:04 12:34:56",
            "ExifIFD:ISO": 200, "ExifIFD:ExifVersion": "0232"}
    simulate(monkeypatch, tags)
    report = ExifToolInspector().inspect(target, EXPECTED)
    assert report.status == "EXTRACTED"
    serialized = json.dumps(report.to_dict())
    for secret in ("SECRET", "47.383611", "8.034167", "12:34:56", "GPSLatitude", "SerialNumber"):
        assert secret not in serialized
    assert report.metadata["dates"]["date_time_original"] == "2026-11-04"
    assert report.metadata["software_families"] == ["unrecognized"]
    assert report.metadata["exif"]["iso"] == 200


@pytest.mark.parametrize("tag,value,issue", [
    ("File:FileType", "PNG", "format_mismatch"),
    ("File:ImageWidth", 65, "decoded_dimensions_mismatch"),
    ("ExifIFD:ExifImageWidth", 999, "exif_dimensions_mismatch"),
    ("ExifIFD:DateTimeOriginal", "2026:02:30 12:00:00", "invalid_metadata_date"),
    ("ExifIFD:ISO", "SECRET GPS", "invalid_exif_value"),
    ("ExifTool:Warning", "SECRET warning content", "metadata_parser_warning"),
])
def test_simulated_inconsistencies(target, monkeypatch, tag, value, issue):
    tags = {**BASE_TAGS, tag: value}
    if tag == "File:FileType":
        tags.update({"PNG:ImageWidth": 64, "PNG:ImageHeight": 64})
    simulate(monkeypatch, tags)
    report = ExifToolInspector().inspect(target, EXPECTED)
    assert report.status == "INCONSISTENT" and issue in report.issues
    assert "SECRET" not in json.dumps(report.to_dict())


@pytest.mark.parametrize("result,reason", [
    (CommandResult(error="engine_missing"), "engine_missing"),
    (CommandResult(error="scan_timeout"), "scan_timeout"),
    (CommandResult(error="scan_output_limit"), "scan_output_limit"),
    (CommandResult(error="resource_limits_unavailable"), "resource_limits_unavailable"),
    (CommandResult(1, "SECRET failure"), "exiftool_failed"),
    (CommandResult(0, "not JSON SECRET"), "exiftool_invalid_output"),
    (CommandResult(0, "[]"), "exiftool_invalid_output"),
    (CommandResult(0, '[{"ExifTool:Error":"SECRET"}]'), "exiftool_failed"),
    (CommandResult(0, "[{}]"), "exiftool_incomplete_output"),
])
def test_simulated_failures_never_become_extracted(target, monkeypatch, result, reason):
    monkeypatch.setattr(exiftool_scan, "run_scan", lambda *args: result)
    report = ExifToolInspector().inspect(target, EXPECTED)
    assert report.status == "UNAVAILABLE" and report.reason == reason
    assert report.metadata == {} and "SECRET" not in json.dumps(report.to_dict())


def test_input_limit_before_process(target, monkeypatch):
    def forbidden(*args):
        pytest.fail("No ejecutar sobre archivo mayor al límite")
    monkeypatch.setattr(exiftool_scan, "run_scan", forbidden)
    assert ExifToolInspector(ScanLimits(max_bytes=1)).inspect(target, EXPECTED).status == "UNAVAILABLE"


class NoMatches:
    def scan(self, path):
        # Doble explícito: sólo para aislar la integración de metadatos.
        return ScanResult("test_engine", "CLEAR", "simulated_for_metadata_test", {})


@pytest.mark.parametrize("mode", ["unavailable", "inconsistent", "exception", "tamper"])
def test_pipeline_metadata_failure_stays_blocked(tmp_path, monkeypatch, mode):
    class Inspector:
        def inspect(self, path, expected):
            if mode == "exception":
                raise RuntimeError("SECRET internal path")
            if mode == "tamper":
                path.write_bytes(b"modified during metadata scan")
            if mode == "inconsistent":
                simulate(monkeypatch, {**BASE_TAGS, "ExifIFD:ExifImageWidth": 999})
                return ExifToolInspector().inspect(path, expected)
            return ExifToolInspector().unavailable("engine_missing")
    checks = MalwareChecks(NoMatches(), NoMatches())
    with TestClient(create_app(tmp_path, antimalware=checks, metadata=Inspector())) as client:
        initial = client.post("/files/upload", files={"file": ("a.jpg", image_bytes())}).json()
        record = client.get(f'/files/{initial["id"]}/status').json()
        assert record["status"] == "QUARANTINED" and record["classification"] == "INCONCLUSIVE"
        assert record["reason"] == ("integrity_mismatch" if mode == "tamper" else
                                     "metadata_inconsistent" if mode == "inconsistent" else "metadata_unavailable")
        assert "SECRET" not in json.dumps(record)
        assert client.get(f'/files/{initial["id"]}/content').status_code == 423
    with TestClient(create_app(tmp_path, antimalware=checks)) as client:
        assert client.get(f'/files/{initial["id"]}/status').json() == record


REAL = sys.platform == "linux" and shutil.which("prlimit") and shutil.which("exiftool")


@pytest.mark.skipif(not REAL, reason="Requiere ExifTool y límites Linux reales")
@pytest.mark.parametrize("fmt", ["JPEG", "PNG"])
@pytest.mark.parametrize("metadata", [True, False])
def test_real_formats_with_metadata_and_absence(tmp_path, fmt, metadata):
    path = tmp_path / "private-object"
    path.write_bytes(image_bytes(fmt, metadata=metadata))
    expected = {"format": fmt, "mime": "image/jpeg" if fmt == "JPEG" else "image/png",
                "width": 64, "height": 64}
    report = ExifToolInspector().inspect(path, expected)
    assert report.status == ("EXTRACTED" if metadata else "ABSENT"), report
    if metadata:
        assert report.metadata["software_families"] == ["GIMP"]
        assert report.metadata["dates"]["date_time_original"] == "2026-11-04"
        assert report.metadata["exif"]["iso"] == 200
    serialized = json.dumps(report.to_dict())
    assert "GPS" not in serialized and "12:34:56" not in serialized
    assert "private-object" not in serialized


@pytest.mark.skipif(not REAL, reason="Requiere ExifTool y límites Linux reales")
def test_real_inconsistent_exif_dimensions(target):
    target.write_bytes(image_bytes(metadata=True, mismatch=True))
    report = ExifToolInspector().inspect(target, EXPECTED)
    assert report.status == "INCONSISTENT"
    assert "exif_dimensions_mismatch" in report.issues


@pytest.mark.skipif(not REAL, reason="Requiere ExifTool y límites Linux reales")
def test_real_malformed_metadata(target):
    target.write_bytes(image_bytes(malformed=True))
    # El JPEG sigue siendo decodificable aunque el bloque EXIF esté malformado.
    assert validate_image(target, "a.jpg", ImageLimits()).valid
    report = ExifToolInspector().inspect(target, EXPECTED)
    assert report.status in {"INCONSISTENT", "UNAVAILABLE"}, report


@pytest.mark.skipif(not REAL, reason="Requiere ExifTool y límites Linux reales")
def test_real_output_and_memory_limits(target):
    output = ExifToolInspector(ScanLimits(output_bytes=10)).inspect(target, EXPECTED)
    assert output.status == "UNAVAILABLE" and output.reason == "scan_output_limit"
    memory = ExifToolInspector(ScanLimits(memory_bytes=1024 * 1024)).inspect(target, EXPECTED)
    assert memory.status == "UNAVAILABLE"


@pytest.mark.skipif(not REAL, reason="Requiere ExifTool y límites Linux reales")
def test_real_http_privacy_persistence_and_blocking(tmp_path):
    checks = MalwareChecks(NoMatches(), NoMatches())
    with TestClient(create_app(tmp_path, antimalware=checks)) as client:
        initial = client.post("/files/upload", files={"file": ("a.jpg", image_bytes(metadata=True))}).json()
        record = client.get(f'/files/{initial["id"]}/status').json()
        assert record["analysis"]["metadata"]["status"] == "EXTRACTED"
        serialized = json.dumps(record)
        assert "GPS" not in serialized and "12:34:56" not in serialized
        assert record["status"] == "QUARANTINED"
        assert client.get(f'/files/{initial["id"]}/content').status_code == 423
    with TestClient(create_app(tmp_path, antimalware=checks)) as client:
        assert client.get(f'/files/{initial["id"]}/status').json() == record
