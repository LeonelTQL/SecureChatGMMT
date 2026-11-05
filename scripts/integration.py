"""Integración completa: autenticación de Leonel, RBAC de Alejandro y autorización con STEGO."""
import argparse
import json
import secrets
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import httpx

parser = argparse.ArgumentParser()
parser.add_argument('--failure-demo', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
context = ssl.create_default_context(cafile=str(root / 'secrets/public/ca.pem'))
auth, stego = 'https://localhost:3001', 'https://localhost:8000'
checks = []
with httpx.Client(verify=context, timeout=15, trust_env=False) as client:
    def expect(name, response, status):
        assert response.status_code == status, f'{name}: esperado {status}, recibido {response.status_code}'
        checks.append({'test': name, 'status': 'passed', 'http': status})
        return response.json() if response.content else None

    expect('AUTH disponible', client.get(auth + '/health'), 200)
    expect('STEGO disponible', client.get(stego + '/health'), 200)
    suffix = uuid4().hex[:12]
    password = secrets.token_urlsafe(24)
    dto = {'username': 'test_' + suffix, 'email': suffix + '@example.com', 'password': password}
    user = expect('Registro', client.post(auth + '/api/auth/register', json=dto), 201)
    assert 'passwordHash' not in user
    expect('Registro duplicado', client.post(auth + '/api/auth/register', json=dto), 409)
    login = {'email': dto['email'], 'password': password}
    jwt = expect('Login', client.post(auth + '/api/auth/login', json=login), 200)['access_token']
    headers = {'Authorization': 'Bearer ' + jwt}
    expect('Credenciales incorrectas', client.post(auth + '/api/auth/login', json={**login, 'password': 'Incorrecta123456!'}), 401)
    expect('Perfil sin token', client.get(auth + '/api/auth/profile'), 401)
    expect('Perfil autenticado', client.get(auth + '/api/auth/profile', headers=headers), 200)
    expect('Validar JWT', client.post(auth + '/api/auth/verify', headers=headers), 200)
    expect('JWT alterado', client.post(auth + '/api/auth/verify', headers={'Authorization': 'Bearer ' + jwt + 'x'}), 401)
    for method, path, data in [('GET', '/api/users', None), ('POST', '/api/users', dto), ('PATCH', '/api/users/' + user['id'], {'status': False})]:
        expect('Administración protegida por RBAC: ' + method, client.request(method, auth + path, headers=headers, json=data), 403)
    for path in ['/api/roles', '/api/user-roles', '/api/admin/protected']:
        expect('Ruta protegida para no-ADMIN: ' + path, client.get(auth + path, headers=headers), 403)
    expect('Decisión interna exige X-Service-Token', client.post(auth + '/internal/authorization/check'), 401)
    bootstrap_path = root / 'secrets/auth/bootstrap.json'
    if bootstrap_path.exists():
        admin_creds = json.loads(bootstrap_path.read_text(encoding='utf-8'))
        admin_jwt = expect('Login ADMIN bootstrap', client.post(auth + '/api/auth/login', json=admin_creds), 200)['access_token']
        admin_headers = {'Authorization': 'Bearer ' + admin_jwt}
        expect('ADMIN listar roles', client.get(auth + '/api/roles', headers=admin_headers), 200)
        expect('ADMIN acceso protegido', client.get(auth + '/api/admin/protected', headers=admin_headers), 200)
    expect('STEGO sin JWT', client.post(stego + '/api/steganography/analyze'), 401)
    expect('STEGO deniega usuario sin rol ANALYST/ADMIN', client.post(stego + '/api/steganography/analyze', headers=headers), 403)
    if args.failure_demo:
        try:
            subprocess.run(['docker', 'compose', '-f', 'compose.yaml', 'stop', 'auth-service'], cwd=root, check=True, stdout=subprocess.DEVNULL)
            expect('STEGO rechaza con AUTH caído', client.post(stego + '/api/steganography/analyze', headers=headers), 503)
        finally:
            subprocess.run(['docker', 'compose', '-f', 'compose.yaml', 'start', 'auth-service'], cwd=root, check=True, stdout=subprocess.DEVNULL)
            for _ in range(30):
                try:
                    if client.get(auth + '/health').status_code == 200: break
                except httpx.HTTPError: pass
                time.sleep(1)
            else: raise RuntimeError('AUTH no recuperó disponibilidad')
    expect('Logout', client.post(auth + '/api/auth/logout', headers=headers), 204)
    expect('Sesión revocada', client.get(auth + '/api/auth/profile', headers=headers), 401)
    report = {'executed_at': datetime.now(timezone.utc).isoformat(), 'scope': 'Leonel, Alejandro (RBAC) y Paul (STEGO)',
        'environment': 'Docker y PostgreSQL reales; TLS verificado', 'tests': checks}
    target = root / 'docs/evidence/integration.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'{len(checks)} verificaciones de integración aprobadas con RBAC activo')
