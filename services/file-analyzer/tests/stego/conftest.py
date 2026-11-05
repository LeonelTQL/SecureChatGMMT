from pathlib import Path
import sys

# Configuración acotada a estas pruebas; no cambia pytest.ini de Paul.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
