"""Regresiones históricas: aíslan antimalware, no demuestran motores reales."""
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def legacy_antimalware_is_explicitly_simulated(request, monkeypatch):
    if Path(str(request.fspath)).name not in {
        "test_files.py", "test_stego_integration.py", "test_image_validation.py"
    }:
        return
    from app import main
    from app.antimalware import MalwareChecks
    from app.clamav_scan import ScanResult

    class ClearScanner:
        def __init__(self, name):
            self.name = name

        def scan(self, path):
            return ScanResult(self.name, "CLEAR", "simulated_regression_only", {})

    monkeypatch.setattr(main, "MalwareChecks", lambda: MalwareChecks(
        ClearScanner("clamav"), ClearScanner("yara")))
