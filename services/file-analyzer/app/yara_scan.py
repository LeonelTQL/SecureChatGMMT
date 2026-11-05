"""YARA sobre reglas locales de confianza; salida sin cadenas ni rutas."""
from dataclasses import asdict
import hashlib
from pathlib import Path

from .clamav_scan import ScanResult
from .scan_runner import ScanLimits, check_file, run_scan


DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "images.yar"


class YaraScanner:
    def __init__(self, rules: Path = DEFAULT_RULES, limits: ScanLimits | None = None):
        self.rules = rules
        self.limits = limits or ScanLimits(timeout_seconds=5, cpu_seconds=5,
                                          memory_bytes=256 * 1024 ** 2)

    def scan(self, path: Path) -> ScanResult:
        info = {"limits": asdict(self.limits)}
        def result(status, reason):
            return ScanResult("yara", status, reason, info)
        error = check_file(path, self.limits)
        if error:
            return result("UNAVAILABLE", error)
        try:
            with self.rules.open("rb") as source:
                data = source.read(65537)
            if not data or len(data) > 65536:
                return result("UNAVAILABLE", "yara_rules_invalid")
            info["rules_sha256"] = hashlib.sha256(data).hexdigest()
        except OSError:
            return result("UNAVAILABLE", "yara_rules_missing")
        completed = run_scan(["yara", "--fail-on-warnings", "--max-strings-per-rule=64",
                              "--timeout=3", "--count", str(self.rules.resolve()),
                              str(path.resolve())], self.limits)
        if completed.error:
            return result("UNAVAILABLE", completed.error)
        # Sólo se acepta el conteo; cualquier aviso/error es no disponible.
        if completed.returncode != 0 or not completed.output.strip().isdigit():
            return result("UNAVAILABLE", "yara_failed")
        count = int(completed.output.strip())
        info["matched_rules"] = count
        return result("DETECTED" if count else "CLEAR",
                      "yara_indicator_detected" if count else "no_rule_matches")
