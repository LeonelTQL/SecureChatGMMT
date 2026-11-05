"""Regenera el contrato de herramientas a partir de la API, sin iniciar storage."""
import json
from pathlib import Path

from app.main import app

target = Path(__file__).resolve().parents[2] / "contracts" / "files.openapi.json"
target.write_text(json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
