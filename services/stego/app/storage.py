import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class Storage:
    def __init__(self, root: Path):
        self.root = root
        self.quarantine = root / "quarantine"
        self.quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = root / "analyses.sqlite3"
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL, record TEXT NOT NULL)""")
        os.chmod(self.database, 0o600)

    def connect(self):
        return sqlite3.connect(self.database, timeout=5)

    def save(self, record):
        with self.connect() as db:
            db.execute("INSERT INTO analyses VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET record=excluded.record",
                (record["analysis_id"], record["user_id"], json.dumps(record, allow_nan=False)))

    def get(self, analysis_id):
        with self.connect() as db:
            row = db.execute("SELECT record FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def bytes_used(self):
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())

    def purge(self, days):
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        removed = 0
        for path in self.quarantine.iterdir():
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink(); removed += 1
        return removed
