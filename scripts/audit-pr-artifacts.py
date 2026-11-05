"""Auditoría local de artefactos compartibles; nunca imprime valores encontrados.

Es una revisión heurística, no una garantía de ausencia de secretos.
"""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "jwt_literal": re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "private_user_path": re.compile(r"[A-Za-z]:[\\/](?:Users|home)[\\/]|/(?:home|Users)/[^/\s]+|/mnt/[a-z]/Users/", re.I),
    "personal_email": re.compile(r"[\w.+-]+@(?!(?:example\.(?:com|org|net)|localhost|invalid)\b)[\w.-]+\.[A-Za-z]{2,}", re.I),
}
CREDENTIAL = re.compile(r"^(?:password|invalid_password|access_token|analyst_token|refresh_token|service_token|stego_service_token|api_key|client_secret)$", re.I)


def inspect(value, location, issues):
    if isinstance(value, dict):
        for key, item in value.items():
            if CREDENTIAL.fullmatch(key) and isinstance(item, str) and item and "{{" not in item:
                issues.append({"location": location + "." + key, "kind": "credential_literal"})
            inspect(item, location + "." + key, issues)
        if CREDENTIAL.fullmatch(str(value.get("key", ""))) and value.get("value"):
            if "{{" not in str(value["value"]):
                issues.append({"location": location, "kind": "saved_credential_variable"})
        for key in ("_exporter_id", "_collection_link"):
            if key in value:
                issues.append({"location": location + "." + key, "kind": "personal_export_reference"})
    elif isinstance(value, list):
        for index, item in enumerate(value):
            inspect(item, f"{location}[{index}]", issues)
    elif isinstance(value, str):
        for kind, pattern in PATTERNS.items():
            if pattern.search(value):
                issues.append({"location": location, "kind": kind})
        # Los cuerpos JSON exportados se almacenan como cadenas.
        if value.lstrip().startswith("{"):
            try:
                nested = json.loads(value)
            except ValueError:
                pass
            else:
                inspect(nested, location + ":json", issues)


def main():
    files = sorted((ROOT / "docs/evidence").glob("*.json")) + sorted((ROOT / "postman").glob("*.json"))
    findings = []
    for path in files:
        issues = []
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except ValueError:
            issues.append({"location": "$", "kind": "invalid_json"})
        else:
            inspect(data, "$", issues)
        if issues:
            findings.append({"file": path.relative_to(ROOT).as_posix(), "issues": issues})
    print(json.dumps({"files_checked": len(files), "findings": findings,
        "scope": "Static heuristic audit; no secret values printed; does not inspect Git history or certify absence of secrets."}, indent=2))
    return bool(findings)


if __name__ == "__main__":
    raise SystemExit(main())
