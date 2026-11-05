"""ClamAV local, firmas oficiales requeridas; ninguna falla equivale a limpio."""
from dataclasses import asdict, dataclass
from pathlib import Path
import re
import tempfile
import time

from .scan_runner import ScanLimits, check_file, run_scan


@dataclass(frozen=True)
class ScanResult:
    engine: str
    status: str  # CLEAR, DETECTED, UNAVAILABLE
    reason: str
    indicators: dict

    def to_dict(self):
        return asdict(self)


class ClamAVScanner:
    def __init__(self, database: Path = Path("/var/lib/clamav"),
                 limits: ScanLimits | None = None, max_database_age: int = 7 * 86400):
        self.database, self.limits = database, limits or ScanLimits()
        if max_database_age <= 0:
            raise ValueError("invalid_database_age")
        self.max_database_age = max_database_age

    def scan(self, path: Path) -> ScanResult:
        info = {"limits": asdict(self.limits)}
        def result(status, reason):
            return ScanResult("clamav", status, reason, info)
        error = check_file(path, self.limits)
        if error:
            return result("UNAVAILABLE", error)
        try:
            # Exigir main y daily evita declarar una cobertura ficticia con una
            # única firma local de prueba. ClamAV valida la base al cargarla.
            files = []
            for stem in ("main", "daily"):
                candidates = [self.database / (stem + ext) for ext in (".cvd", ".cld")]
                present = [p for p in candidates if p.is_file() and p.stat().st_size > 0]
                if not present:
                    return result("UNAVAILABLE", "signature_database_missing")
                files.append(max(present, key=lambda p: p.stat().st_mtime))
            age = time.time() - files[1].stat().st_mtime
            if age < -300 or age > self.max_database_age:
                return result("UNAVAILABLE", "signature_database_stale")
            info["database_files"] = [p.name for p in files]
        except OSError:
            return result("UNAVAILABLE", "signature_database_unreadable")
        command = ["clamscan", f"--database={self.database.resolve()}", "--stdout",
                   "--official-db-only=yes",
                   "--bytecode=no", "--alert-exceeds-max=yes", "--max-files=64",
                   "--max-recursion=8", f"--max-filesize={self.limits.max_bytes}",
                   f"--max-scansize={self.limits.max_bytes * 4}", "--max-scantime=10000",
                   "--", str(path.resolve())]
        with tempfile.TemporaryDirectory(prefix="stego-clam-") as private_temp:
            command.insert(1, f"--tempdir={private_temp}")
            completed = run_scan(command, self.limits)
        info["exit_code"] = completed.returncode
        if completed.error:
            return result("UNAVAILABLE", completed.error)
        if "Heuristics.Limits.Exceeded" in completed.output:
            return result("UNAVAILABLE", "scan_incomplete")
        if completed.returncode == 1 and " FOUND" in completed.output:
            info["detections"] = 1
            return result("DETECTED", "clamav_threat_detected")
        if completed.returncode != 0:
            return result("UNAVAILABLE", "clamav_failed")
        counts = {key: int(value) for key, value in re.findall(
            r"^(Known viruses|Scanned files|Infected files):\s*(\d+)\s*$",
            completed.output, flags=re.MULTILINE)}
        if (counts.get("Scanned files") != 1 or counts.get("Infected files") != 0
                or counts.get("Known viruses", 0) <= 0 or "ERROR" in completed.output):
            return result("UNAVAILABLE", "scan_incomplete")
        info.update({"scanned_files": 1, "detections": 0,
                     "known_signatures": counts["Known viruses"]})
        version = re.search(r"^Engine version:\s*([0-9]+(?:\.[0-9]+){1,3})\s*$",
                            completed.output, flags=re.MULTILINE)
        if version:
            info["engine_version"] = version.group(1)
        return result("CLEAR", "no_known_threats_found")
