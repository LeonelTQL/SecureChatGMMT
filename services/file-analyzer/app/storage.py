"""Almacén privado persistente. Toda liberación pasa por estado e integridad."""
import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import AnalysisResult, Analyzer, Classification


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Storage:
    def __init__(self, root: Path):
        self.root = root
        self.objects = root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER NOT NULL,
                sha256 TEXT NOT NULL, status TEXT NOT NULL,
                classification TEXT, reason TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""")
            db.execute("""UPDATE files SET status='QUARANTINED',
                classification='INCONCLUSIVE', reason='processing_interrupted',
                updated_at=? WHERE status IN ('PENDING', 'ANALYZING')""", (now(),))

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.root / "metadata.sqlite3", timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def path(self, file_id: str) -> Path:
        # IDs originate exclusively from UUID generation/validation in the API.
        return self.objects / file_id

    def add(self, file_id: str, filename: str, size: int, sha256: str) -> dict:
        timestamp = now()
        with self.connection() as db:
            db.execute("INSERT INTO files VALUES (?, ?, ?, ?, 'PENDING', NULL, NULL, ?, ?)",
                       (file_id, filename, size, sha256, timestamp, timestamp))
        return self.get(file_id)

    def get(self, file_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        return dict(row) if row else None

    def finish(self, file_id: str, status: str, classification: str | None, reason: str | None):
        with self.connection() as db:
            db.execute("""UPDATE files SET status=?, classification=?, reason=?, updated_at=?
                WHERE id=?""", (status, classification, reason, now(), file_id))

    def quarantine(self, file_id: str, reason: str):
        self.finish(file_id, "QUARANTINED", "INCONCLUSIVE", reason)

    def process(self, file_id: str, analyzer: Analyzer):
        with self.connection() as db:
            claimed = db.execute("""UPDATE files SET status='ANALYZING', updated_at=?
                WHERE id=? AND status='PENDING'""", (now(), file_id)).rowcount
        if not claimed:
            return
        record = self.get(file_id)
        path = self.path(file_id)
        try:
            if digest(path) != record["sha256"]:
                self.quarantine(file_id, "integrity_mismatch")
                return
            result = AnalysisResult.model_validate(analyzer.analyze(path, record["sha256"]))
            if result.sha256 != record["sha256"] or digest(path) != record["sha256"]:
                self.quarantine(file_id, "integrity_mismatch")
                return
            status = "APPROVED" if result.classification == Classification.CLEAN else "QUARANTINED"
            self.finish(file_id, status, result.classification.value, result.reason)
        except Exception:
            # No filtrar rutas, mensajes de herramientas ni detalles de excepciones.
            self.quarantine(file_id, "analysis_failed")
