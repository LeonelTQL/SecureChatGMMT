"""Exporta contratos y una muestra de auditoría permitiendo solo campos no sensibles."""
import json
import ssl
import subprocess
from pathlib import Path
import httpx

root = Path(__file__).resolve().parents[1]
context = ssl.create_default_context(cafile=str(root / 'secrets/public/ca.pem'))
for name, url in [('auth', 'https://localhost:3001/docs-json'), ('stego', 'https://localhost:8000/openapi.json')]:
    response = httpx.get(url, verify=context, trust_env=False, timeout=5)
    response.raise_for_status()
    (root / f'docs/{name}.openapi.json').write_text(json.dumps(response.json(), indent=2) + '\n', encoding='utf-8')
output = subprocess.run(['docker', 'compose', '-f', 'compose.yaml', 'logs', '--no-color', '--no-log-prefix', 'auth-service', 'stego'],
    cwd=root, text=True, encoding='utf-8', errors='replace', capture_output=True, check=True).stdout
fields = {'timestamp', 'service', 'event', 'actor_id', 'user_id', 'analysis_id', 'role_id', 'assignment_id', 'resource_id', 'action', 'allowed', 'status'}
records = []
for line in output.splitlines():
    try:
        item = json.loads(line[line.index('{'):])
        if isinstance(item, dict) and 'event' in item:
            records.append({key: value for key, value in item.items() if key in fields})
    except (ValueError, TypeError): pass
# Las altas/limpiezas de cuentas y Postman pueden desplazar todos los eventos
# analysis.completed en una ventana de 40. Mantener una muestra acotada útil.
(root / 'docs/evidence/audit.json').write_text(json.dumps(records[-200:], indent=2) + '\n', encoding='utf-8')
print('Contratos y auditoría depurada exportados')
