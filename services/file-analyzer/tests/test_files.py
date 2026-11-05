import hashlib
import threading
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app.analyzer import AnalysisResult
from app.main import create_app
from app.storage import Storage


# La validación real de imágenes pertenece a Diana: estas muestras prueban
# transferencia e integridad de bytes con resultados del motor controlados.
SAMPLE = b"\x89PNG\r\n\x1a\ntransfer-test"


class SimulatedAnalyzer:
    def __init__(self, classification="CLEAN"):
        self.classification = classification
        self.calls = 0

    def analyze(self, path, sha256):
        self.calls += 1
        assert path.read_bytes() == SAMPLE
        return AnalysisResult(sha256=sha256, classification=self.classification,
                              reason="simulated_test_result")


def upload(client, content=SAMPLE, filename="image.png"):
    return client.post("/files/upload", files={"file": (filename, content, "image/png")})


def check_upload_hash_private_storage_and_clean_download(tmp_path):
    engine = SimulatedAnalyzer()
    with TestClient(create_app(tmp_path, engine)) as client:
        response = upload(client, filename="../../image.png")
        assert response.status_code == 202
        record = response.json()
        assert record["status"] == "PENDING"
        assert record["classification"] is None
        assert record["filename"] == "image.png"
        assert record["sha256"] == hashlib.sha256(SAMPLE).hexdigest()
        assert record["size"] == len(SAMPLE)
        assert (tmp_path / "objects" / record["id"]).read_bytes() == SAMPLE
        location = response.url.join(response.headers["location"])
        state = client.get(str(location)).json()
        assert state["status"] == "APPROVED"
        assert state["classification"] == "CLEAN"
        downloaded = client.get(f'/files/{record["id"]}/content')
        assert downloaded.status_code == 200
        assert downloaded.content == SAMPLE
        assert downloaded.headers["x-content-type-options"] == "nosniff"
        assert downloaded.headers["cache-control"] == "no-store"
        assert client.get(f'/storage/objects/{record["id"]}').status_code == 404
        assert client.get(f'/objects/{record["id"]}').status_code == 404
        assert engine.calls == 1


def check_non_clean_results_are_quarantined(tmp_path, classification):
    with TestClient(create_app(tmp_path, SimulatedAnalyzer(classification))) as client:
        file_id = upload(client).json()["id"]
        result = client.get(f"/files/{file_id}/status").json()
        assert result["status"] == "QUARANTINED"
        assert result["classification"] == classification
        assert client.get(f"/files/{file_id}/content").status_code == 423


def check_no_analyzer_never_approves(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        file_id = upload(client).json()["id"]
        record = client.get(f"/files/{file_id}/status").json()
        assert record["status"] == "QUARANTINED"
        assert record["reason"] == "analyzer_not_configured"
        assert client.get(f"/files/{file_id}/content").status_code == 423


def check_failed_or_untrustworthy_analysis_is_blocked(tmp_path, mode, reason):
    class BrokenAnalyzer:
        def analyze(self, path, sha256):
            if mode == "exception":
                raise RuntimeError("sensitive internal path")
            if mode == "malformed":
                return {"classification": "CLEAN"}
            if mode == "modified":
                path.write_bytes(b"tampered")
            return AnalysisResult(sha256="0" * 64 if mode == "wrong_hash" else sha256,
                                  classification="CLEAN", reason="test")

    with TestClient(create_app(tmp_path, BrokenAnalyzer())) as client:
        file_id = upload(client).json()["id"]
        record = client.get(f"/files/{file_id}/status").json()
        assert record["status"] == "QUARANTINED"
        assert record["reason"] == reason
        assert "sensitive" not in str(record)
        assert client.get(f"/files/{file_id}/content").status_code == 423


def check_download_rechecks_integrity(tmp_path, missing):
    with TestClient(create_app(tmp_path, SimulatedAnalyzer())) as client:
        file_id = upload(client).json()["id"]
        path = tmp_path / "objects" / file_id
        if missing:
            path.unlink()
        else:
            path.write_bytes(b"changed after approval")
        assert client.get(f"/files/{file_id}/content").status_code == 423
        record = client.get(f"/files/{file_id}/status").json()
        assert record["status"] == "QUARANTINED"
        assert record["reason"] == "integrity_mismatch"


def check_pending_and_processing_are_blocked(tmp_path, state):
    with TestClient(create_app(tmp_path)) as client:
        store = client.app.state.storage
        file_id = str(uuid4())
        store.path(file_id).write_bytes(SAMPLE)
        store.add(file_id, "sample.png", len(SAMPLE), hashlib.sha256(SAMPLE).hexdigest())
        if state == "ANALYZING":
            store.finish(file_id, state, None, None)
        assert client.get(f"/files/{file_id}/content").status_code == 423
        assert client.get(f"/files/{file_id}/status").json()["status"] == state


def check_status_during_running_analysis_and_duplicate_claim(tmp_path):
    started, release = threading.Event(), threading.Event()

    class WaitingAnalyzer(SimulatedAnalyzer):
        def analyze(self, path, sha256):
            started.set()
            assert release.wait(timeout=10)
            return super().analyze(path, sha256)

    engine = WaitingAnalyzer()
    with TestClient(create_app(tmp_path, engine)) as client:
        store = client.app.state.storage
        file_id = str(uuid4())
        store.path(file_id).write_bytes(SAMPLE)
        store.add(file_id, "image.png", len(SAMPLE), hashlib.sha256(SAMPLE).hexdigest())
        with ThreadPoolExecutor() as pool:
            job = pool.submit(store.process, file_id, engine)
            try:
                assert started.wait(timeout=10)
                assert client.get(f"/files/{file_id}/status").json()["status"] == "ANALYZING"
                assert client.get(f"/files/{file_id}/content").status_code == 423
                store.process(file_id, engine)
            finally:
                release.set()
            job.result(timeout=10)
        assert engine.calls == 1
        assert client.get(f"/files/{file_id}/content").status_code == 200


def check_persistence_and_interrupted_work_quarantine(tmp_path):
    with TestClient(create_app(tmp_path, SimulatedAnalyzer())) as client:
        approved = upload(client).json()["id"]
        store = client.app.state.storage
        interrupted = []
        for state in ["PENDING", "ANALYZING"]:
            file_id = str(uuid4())
            store.path(file_id).write_bytes(SAMPLE)
            store.add(file_id, "sample.png", len(SAMPLE), hashlib.sha256(SAMPLE).hexdigest())
            if state == "ANALYZING":
                store.finish(file_id, state, None, None)
            interrupted.append(file_id)
    with TestClient(create_app(tmp_path)) as restarted:
        assert restarted.get(f"/files/{approved}/content").content == SAMPLE
        for file_id in interrupted:
            record = restarted.get(f"/files/{file_id}/status").json()
            assert record["status"] == "QUARANTINED"
            assert record["reason"] == "processing_interrupted"
            assert restarted.get(f"/files/{file_id}/content").status_code == 423


def check_upload_restrictions_and_cleanup(tmp_path, filename, data, expected):
    with TestClient(create_app(tmp_path, max_file_bytes=32)) as client:
        assert upload(client, data, filename).status_code == expected
        if expected != 202:
            assert list((tmp_path / "objects").iterdir()) == []


def check_malformed_unknown_and_no_approval_endpoint(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        assert client.post("/files/upload").status_code == 422
        assert client.post("/files/upload", files={"other": ("a.png", SAMPLE)}).status_code == 422
        assert client.post("/files/upload", files=[("file", ("a.png", SAMPLE)),
                                                  ("file", ("b.png", SAMPLE))]).status_code == 400
        assert client.get("/files/invalid/status").status_code == 422
        for route in ["status", "content"]:
            assert client.get(f"/files/{uuid4()}/{route}").status_code == 404
        file_id = upload(client).json()["id"]
        assert client.post(f"/files/{file_id}/result", json={"classification": "CLEAN"}).status_code == 404


def check_body_limit_with_and_without_content_length(tmp_path):
    with TestClient(create_app(tmp_path, max_file_bytes=32)) as client:
        assert client.post("/files/upload", content=b"x" * 70000).status_code == 413

        def chunked():
            for _ in range(70):
                yield b"x" * 1024

        response = client.post("/files/upload", content=chunked(),
                               headers={"Content-Type": "multipart/form-data; boundary=test"})
        assert response.status_code == 413
        assert list((tmp_path / "objects").iterdir()) == []


def check_integrity_before_analysis(tmp_path):
    store = Storage(tmp_path)
    file_id = str(uuid4())
    store.path(file_id).write_bytes(b"altered")
    store.add(file_id, "image.png", len(SAMPLE), hashlib.sha256(SAMPLE).hexdigest())
    engine = SimulatedAnalyzer()
    store.process(file_id, engine)
    assert engine.calls == 0
    assert store.get(file_id)["status"] == "QUARANTINED"
    assert store.get(file_id)["reason"] == "integrity_mismatch"


# unittest es reconocido por pytest y permite verificar sin descargar pytest
# en entornos sin red. Cada caso usa almacenamiento temporal independiente.
class FileManagementTests(unittest.TestCase):
    def run_case(self, case, *args):
        with tempfile.TemporaryDirectory() as directory:
            case(Path(directory), *args)

    def test_upload_and_clean_download(self):
        self.run_case(check_upload_hash_private_storage_and_clean_download)

    def test_quarantine(self):
        for classification in ["SUSPICIOUS", "INCONCLUSIVE"]:
            with self.subTest(classification=classification):
                self.run_case(check_non_clean_results_are_quarantined, classification)

    def test_unconfigured(self):
        self.run_case(check_no_analyzer_never_approves)

    def test_analyzer_failures(self):
        for mode, reason in [("exception", "analysis_failed"),
                             ("malformed", "analysis_failed"),
                             ("wrong_hash", "integrity_mismatch"),
                             ("modified", "integrity_mismatch")]:
            with self.subTest(mode=mode):
                self.run_case(check_failed_or_untrustworthy_analysis_is_blocked, mode, reason)

    def test_download_integrity(self):
        for missing in [False, True]:
            with self.subTest(missing=missing):
                self.run_case(check_download_rechecks_integrity, missing)

    def test_pending_processing(self):
        for state in ["PENDING", "ANALYZING"]:
            with self.subTest(state=state):
                self.run_case(check_pending_and_processing_are_blocked, state)

    def test_concurrent_analysis(self):
        self.run_case(check_status_during_running_analysis_and_duplicate_claim)

    def test_restart(self):
        self.run_case(check_persistence_and_interrupted_work_quarantine)

    def test_upload_validation(self):
        for filename, data, expected in [("image.png", b"", 422),
                                         ("script.exe", SAMPLE, 415),
                                         ("large.jpg", b"x" * 33, 413),
                                         ("limit.PNG", b"x" * 32, 202)]:
            with self.subTest(filename=filename):
                self.run_case(check_upload_restrictions_and_cleanup, filename, data, expected)

    def test_invalid_requests(self):
        self.run_case(check_malformed_unknown_and_no_approval_endpoint)

    def test_body_limit(self):
        self.run_case(check_body_limit_with_and_without_content_length)

    def test_preanalysis_integrity(self):
        self.run_case(check_integrity_before_analysis)
