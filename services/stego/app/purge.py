"""Elimina archivos en cuarentena antiguos; conserva metadatos de auditoría."""
import argparse
from .main import load_settings
from .storage import Storage
parser = argparse.ArgumentParser()
parser.add_argument("--days", type=int, default=7)
args = parser.parse_args()
if args.days < 1: parser.error("La retención mínima es un día")
print({"files_removed": Storage(load_settings().storage).purge(args.days)})
