"""Contrato activo y seguridad; real_* ejecuta los motores CLI reales."""
import asyncio
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import random
import shutil
import sys
from uuid import uuid4

from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin
import pytest

from app import detector
from app.detector_adapter import analyze as isolated_analyze, validate_result
from app.main import create_app
from app.security import Denied
from test_stego import setup, keys, token, image


def original_and_modified():
    # Mismo portador reproducible histórico; generador independiente del detector.
    rng = random.Random(2026)
    raw = bytes(2 * rng.randrange(128) for _ in range(256 * 256 * 3))
    payload = random.Random(7401).randbytes(len(raw) // 8)
    modified = bytes((value & 254) | ((payload[i // 8] >> (7 - i % 8)) & 1)
                     for i, value in enumerate(raw))
    def encode(data):
        output = io.BytesIO()
        Image.frombytes("RGB", (256, 256), data).save(output, format="PNG")
        return output.getvalue()
    return encode(raw), encode(modified)


def test_reports_contract_is_optional_bounded_and_finite():
    base = {"status": "no_concluyente", "technique": "test", "indicators": {"input_bytes": 1}, "limitations": "test"}
    assert validate_result(base) == base
    for reports in [{"unknown": {}}, {"lsb": {"metric": float("nan")}}, {"metadata": "x" * 33000}]:
        with pytest.raises((ValueError, TypeError)):
            validate_result({**base, "reports": reports})


@pytest.mark.parametrize("kind,expected_status", [("invalid_token", 401), ("denied", 403), ("auth_down", 503)])
def test_no_real_analysis_or_body_consumption_without_authorization(setup, keys, monkeypatch, kind, expected_status):
    settings, state, app, client, _ = setup
    def forbidden(*args):
        pytest.fail("Nunca llamar al motor sin autorización")
    monkeypatch.setattr(detector, "analyze", forbidden)
    state["allowed"] = kind != "denied"
    state["down"] = kind == "auth_down"
    encoded = "invalid" if kind == "invalid_token" else token(keys)
    response = client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + encoded}, content=b"invalid body")
    assert response.status_code == expected_status
    assert state["detector_calls"] == 0
    assert not list(app.state.storage.quarantine.iterdir())


def test_real_detector_entry_denied_before_parsing(setup, keys, tmp_path, monkeypatch):
    settings, state, _, _, decider = setup
    calls = []
    async def entry(path):
        calls.append(path)
        return await isolated_analyze(path)
    active = create_app(replace(settings, storage=tmp_path / "secured"), decider, entry)
    state["down"] = True
    with TestClient(active) as client:
        response = client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + token(keys)}, content=b"must not parse")
        assert response.status_code == 503 and calls == []
        assert not list(active.state.storage.quarantine.iterdir())


def test_integrity_change_by_detector_is_quarantined(setup, keys, tmp_path):
    settings, _, _, _, decider = setup
    async def tamper(path):
        path.write_bytes(b"tampered")
        return {"status": "sin_indicios", "technique": "test_tamper", "indicators": {"bytes": 1}, "limitations": "test"}
    app = create_app(replace(settings, storage=tmp_path / "tampered"), decider, tamper)
    with TestClient(app) as client:
        result = client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + token(keys)}, files={"file": ("a.png", image(), "image/png")})
        assert result.status_code == 503
        assert result.json()["reason"] == "integrity_mismatch"
        assert result.json()["status"] == "error" and result.json()["action"] == "cuarentena"


def test_real_auth_transport_unreachable_blocks_detector(setup, keys, tmp_path):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    settings, _, _, _, _ = setup
    private = serialization.load_pem_private_key(keys[0], password=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(private.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private, hashes.SHA256()))
    ca = tmp_path / "ca.pem"
    ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    async def forbidden(path):
        pytest.fail("AUTH inaccesible debe impedir el detector")
    app = create_app(replace(settings, storage=tmp_path / "auth-unreachable",
                             auth_url="https://127.0.0.1:1", ca_file=str(ca)), detector=forbidden)
    with TestClient(app) as client:
        response = client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + token(keys)},
                               files={"file": ("a.png", image(), "image/png")})
        assert response.status_code == 503
        assert not list(app.state.storage.quarantine.iterdir())


REAL = (sys.platform == "linux" and all(shutil.which(name) for name in ("clamscan", "yara", "exiftool", "prlimit"))
        and any(Path("/var/lib/clamav").glob("main.c?d")))


@pytest.mark.skipif(not REAL, reason="Requiere los tres motores reales y firmas ClamAV")
def test_real_active_contract_original_and_lsb(tmp_path):
    original, modified = original_and_modified()
    reports = []
    for index, (data, status) in enumerate(((original, "sin_indicios"), (modified, "sospechoso"))):
        path = tmp_path / str(index)
        path.write_bytes(data)
        report = validate_result(asyncio.run(isolated_analyze(path)))
        assert report["status"] == status, {"reason": report["reason"], "checks": report["reports"].get("antimalware"), "metadata": report["reports"].get("metadata")}
        assert report["technique"] == "LSB_POV_CHI_SQUARE_RGB_V1"
        assert report["indicators"]["r_degrees_of_freedom"] == 128
        assert all(r["status"] == "CLEAR" for r in report["reports"]["antimalware"].values())
        assert report["reports"]["metadata"]["status"] == "ABSENT"
        reports.append(report)
    assert reports[0]["indicators"]["r_chi_square"] == 65536
    assert reports[1]["indicators"]["r_chi_square"] < reports[0]["indicators"]["r_chi_square"]
    assert reports[1]["indicators"]["r_p_value"] > reports[0]["indicators"]["r_p_value"]


@pytest.mark.skipif(not REAL, reason="Requiere los tres motores reales y firmas ClamAV")
def test_real_http_persistence_quarantine_and_ownership(setup, keys, tmp_path):
    settings, state, _, _, decider = setup
    settings = replace(settings, storage=tmp_path / "real_active")
    app = create_app(settings, decider)
    owner = str(uuid4())
    headers = {"Authorization": "Bearer " + token(keys, sub=owner)}
    data = original_and_modified()[1]
    with TestClient(app) as client:
        response = client.post("/api/steganography/analyze", headers=headers, files={"file": ("sample.png", data, "text/plain")})
        assert response.status_code == 200, response.text
        record = response.json()
        assert record["status"] == "sospechoso" and record["action"] == "cuarentena"
        assert record["sha256"] == hashlib.sha256(data).hexdigest()
        assert record["user_id"] == owner
        assert (app.state.storage.quarantine / record["analysis_id"]).read_bytes() == data
        assert app.state.storage.get(record["analysis_id"])["reports"] == record["reports"]
        other = {"Authorization": "Bearer " + token(keys)}
        assert client.get("/api/steganography/results/" + record["analysis_id"], headers=other).status_code == 403
        state["scope"] = "all"
        assert client.get("/api/steganography/results/" + record["analysis_id"], headers=other).status_code == 200
    state["scope"] = "own"
    with TestClient(create_app(settings, decider)) as client:
        saved = client.get("/api/steganography/results/" + record["analysis_id"], headers=headers)
        assert saved.status_code == 200
        assert saved.json()["reports"] == record["reports"]


@pytest.mark.skipif(not REAL, reason="Requiere los tres motores reales y firmas ClamAV")
def test_real_jpeg_and_bmp_no_applicable_detector(tmp_path):
    for fmt in ("JPEG", "BMP"):
        path = tmp_path / fmt
        path.write_bytes(image(fmt))
        result = validate_result(asyncio.run(isolated_analyze(path)))
        assert result["status"] == "no_concluyente", result
        assert result["indicators"]["input_bytes"] == path.stat().st_size


@pytest.mark.skipif(not REAL, reason="Requiere motores reales para comprobar indisponibilidad controlada")
def test_real_missing_database_never_approves(tmp_path, monkeypatch):
    path = tmp_path / "image"
    path.write_bytes(original_and_modified()[0])
    monkeypatch.setenv("CLAMAV_DATABASE_DIR", str(tmp_path / "missing"))
    report = validate_result(asyncio.run(isolated_analyze(path)))
    assert report["status"] == "no_concluyente"
    assert report["reports"]["antimalware"]["clamav"]["status"] == "UNAVAILABLE"


@pytest.mark.skipif(not REAL, reason="Requiere motores reales")
def test_real_yara_marker_with_active_contract(tmp_path):
    output = io.BytesIO()
    info = PngImagePlugin.PngInfo()
    info.add_text("test", "SECURECHAT_YARA_TEST_MARKER_V1")
    Image.new("RGB", (64, 64)).save(output, format="PNG", pnginfo=info)
    path = tmp_path / "marker"
    path.write_bytes(output.getvalue())
    result = validate_result(asyncio.run(isolated_analyze(path)))
    assert result["status"] == "sospechoso", result
    assert result["reports"]["antimalware"]["yara"]["indicators"]["matched_rules"] == 1


@pytest.mark.skipif(not REAL, reason="Requiere motores reales")
def test_real_metadata_privacy_with_active_contract(tmp_path):
    exif = Image.Exif()
    exif[0x0131] = "GIMP 2.10.36"
    exif[0x0132] = "2026:11:04 12:34:56"
    exif[0x8825] = {1: "N", 2: (47.0, 23.0, 1.0), 3: "E", 4: (8.0, 2.0, 3.0)}
    output = io.BytesIO()
    Image.new("RGB", (64, 64)).save(output, format="JPEG", exif=exif)
    path = tmp_path / "private-metadata"
    path.write_bytes(output.getvalue())
    result = validate_result(asyncio.run(isolated_analyze(path)))
    assert result["status"] == "no_concluyente"
    assert result["reports"]["metadata"]["status"] == "EXTRACTED"
    assert result["reports"]["metadata"]["metadata"]["software_families"] == ["GIMP"]
    assert "GPS" not in json.dumps(result) and "12:34:56" not in json.dumps(result)
