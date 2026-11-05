"""Integración real: multipart -> almacén de Paul -> LSB -> cuarentena."""
import hashlib
from io import BytesIO
import json
import sqlite3
from uuid import uuid4

from fastapi.testclient import TestClient
from PIL import Image
import pytest

from app import main, stego_lsb
from app.main import create_app
from app.stego_adapter import StegoAnalyzer
from app.storage import Storage
from tools.stego_samples import samples


@pytest.fixture(scope="module")
def corpus():
    images = samples()
    images["corrupt"] = images["original"][:-20]
    output = BytesIO()
    Image.new("RGB", (64, 64)).save(output, format="JPEG")
    images["jpeg"] = output.getvalue()
    return images


def upload_and_status(client, data, filename="image.png"):
    response = client.post("/files/upload", files={"file": (filename, data, "image/png")})
    assert response.status_code == 202
    initial = response.json()
    assert initial["status"] == "PENDING"
    assert initial["analysis"] is None
    assert initial["sha256"] == hashlib.sha256(data).hexdigest()
    return client.get(f'/files/{initial["id"]}/status').json()


@pytest.mark.parametrize("name,classification,reason", [
    ("original", "INCONCLUSIVE", "additional_security_checks_required"),
    ("lsb_full", "SUSPICIOUS", "lsb_suspicious"),
    ("tiny", "INCONCLUSIVE", "lsb_inconclusive"),
    ("corrupt", "INCONCLUSIVE", "image_malformed"),
    ("jpeg", "INCONCLUSIVE", "jpeg_detector_not_available"),
])
def test_real_upload_analysis_persistence_and_blocking(tmp_path, corpus, name, classification, reason):
    data = corpus[name]
    # Los objetos se guardan sin extensión. El motor debe validar sus bytes.
    expected = json.loads(json.dumps(stego_lsb.analyze_png_bytes(data).to_dict()))
    with TestClient(create_app(tmp_path)) as client:
        record = upload_and_status(client, data, "image.jpg" if name == "jpeg" else "image.png")
        assert record["status"] == "QUARANTINED"
        assert record["classification"] == classification
        assert record["reason"] == reason
        report = dict(record["analysis"])
        validation = report.pop("validation")
        if name != "corrupt":
            metadata = report.pop("metadata")
            assert metadata["status"] in {"EXTRACTED", "ABSENT"}
            checks = report.pop("antimalware")
            assert all(r["status"] == "CLEAR" for r in checks.values())
        assert validation["valid"] is (name != "corrupt")
        if name not in {"corrupt", "jpeg"}:
            assert report == expected
        else:
            assert report["classification"] == ("ERROR" if name == "corrupt" else "NO_CONCLUYENTE")
        assert (tmp_path / "objects" / record["id"]).read_bytes() == data
        assert client.get(f'/files/{record["id"]}/content').status_code == 423
    with TestClient(create_app(tmp_path)) as restarted:
        assert restarted.get(f'/files/{record["id"]}/status').json() == record
        assert restarted.get(f'/files/{record["id"]}/content').status_code == 423


def test_detector_exception_is_controlled_and_persisted(tmp_path, corpus, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("SECRET C:/private/file.png")
    monkeypatch.setattr(stego_lsb, "analyze_png", broken)
    with TestClient(create_app(tmp_path)) as client:
        record = upload_and_status(client, corpus["original"])
        assert record["classification"] == "INCONCLUSIVE"
        assert record["reason"] == "lsb_detector_failed"
        assert record["analysis"]["classification"] == "ERROR"
        assert record["analysis"]["reason"] == "detector_failed"
        assert record["analysis"]["channels"] == []
        assert record["status"] == "QUARANTINED"
        assert "SECRET" not in json.dumps(record)
        assert client.get(f'/files/{record["id"]}/content').status_code == 423
    with TestClient(create_app(tmp_path)) as client:
        assert client.get(f'/files/{record["id"]}/status').json() == record


def test_uvicorn_module_app_uses_real_adapter(tmp_path, corpus, monkeypatch):
    # Usa exactamente app.main:app (no sólo la fábrica). Cambia sólo la raíz
    # física para evitar tocar almacenamiento real durante la prueba.
    monkeypatch.setattr(main, "Storage", lambda root: Storage(tmp_path))
    with TestClient(main.app) as client:
        record = upload_and_status(client, corpus["lsb_full"])
        assert record["classification"] == "SUSPICIOUS"
        assert record["analysis"]["classification"] == "SOSPECHOSO"
        assert client.get(f'/files/{record["id"]}/content').status_code == 423


@pytest.mark.parametrize("when", ["before", "after"])
def test_real_adapter_preserves_integrity_checks(tmp_path, corpus, monkeypatch, when):
    store = Storage(tmp_path)
    file_id = str(uuid4())
    data = corpus["lsb_full"]
    path = store.path(file_id)
    path.write_bytes(data)
    store.add(file_id, "image.png", len(data), hashlib.sha256(data).hexdigest())
    original = stego_lsb.analyze_png
    calls = []

    def detector(path, config):
        calls.append(path)
        report = original(path, config)
        path.write_bytes(b"tampered after analysis")
        return report

    monkeypatch.setattr(stego_lsb, "analyze_png", detector)
    if when == "before":
        path.write_bytes(b"tampered before analysis")
    store.process(file_id, StegoAnalyzer())
    record = store.get(file_id)
    assert len(calls) == (0 if when == "before" else 1)
    assert record["status"] == "QUARANTINED"
    assert record["reason"] == "integrity_mismatch"
    assert record["analysis"] is None  # No registrar como fiables métricas de bytes alterados.
    with TestClient(create_app(tmp_path)) as client:
        assert client.get(f"/files/{file_id}/content").status_code == 423


def test_upgrade_existing_paul_database(tmp_path):
    file_id = str(uuid4())
    data = b"old private object"
    (tmp_path / "objects").mkdir()
    (tmp_path / "objects" / file_id).write_bytes(data)
    # Esquema anterior a esta integración, sin analysis_json.
    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        db.execute("""CREATE TABLE files (
            id TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER NOT NULL,
            sha256 TEXT NOT NULL, status TEXT NOT NULL, classification TEXT, reason TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        db.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (file_id, "old.png", len(data), hashlib.sha256(data).hexdigest(),
                    "QUARANTINED", "INCONCLUSIVE", "old_reason", "old_date", "old_date"))
    with TestClient(create_app(tmp_path)) as client:
        record = client.get(f"/files/{file_id}/status").json()
        assert record["analysis"] is None
        assert record["reason"] == "old_reason"
        assert record["status"] == "QUARANTINED"
        assert (tmp_path / "objects" / file_id).read_bytes() == data
        assert client.get(f"/files/{file_id}/content").status_code == 423
    # También debe admitir nuevas cargas después de migrar, sin recrear la BD.
    store = Storage(tmp_path)
    assert store.add(str(uuid4()), "new.png", 1, "0" * 64)["analysis"] is None
