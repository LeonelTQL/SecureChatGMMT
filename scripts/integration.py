"""Integración completa: autenticación de Leonel, RBAC de Alejandro y autorización con STEGO."""
import argparse
import hashlib
import io
import json
import secrets
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import httpx
from PIL import Image

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
        roles = expect('ADMIN listar roles', client.get(auth + '/api/roles', headers=admin_headers), 200)
        expect('ADMIN acceso protegido', client.get(auth + '/api/admin/protected', headers=admin_headers), 200)
        role_ids = {role['name']: role['id'] for role in roles}
        assert {'ADMIN', 'ANALYST', 'USER'} <= role_ids.keys()
        other_suffix = uuid4().hex[:12]
        other_password = secrets.token_urlsafe(24)
        other = expect('Crear segundo usuario N:M', client.post(auth + '/api/users', headers=admin_headers,
            json={'username': 'test_' + other_suffix, 'email': other_suffix + '@example.com', 'password': other_password}), 201)
        for target_user in [user, other]:
            expect('T05 mismo rol para dos usuarios', client.post(auth + '/api/user-roles', headers=admin_headers,
                json={'user_id': target_user['id'], 'role_id': role_ids['USER']}), 201)
        expect('T04 USER no puede analizar', client.post(stego + '/api/steganography/analyze', headers=headers), 403)
        assignment = expect('T05 segundo rol en mismo usuario', client.post(auth + '/api/user-roles', headers=admin_headers,
            json={'user_id': user['id'], 'role_id': role_ids['ANALYST']}), 201)
        expect('T06 asignación duplicada', client.post(auth + '/api/user-roles', headers=admin_headers,
            json={'user_id': user['id'], 'role_id': role_ids['ANALYST']}), 409)
        expect('FK impide rol inexistente', client.post(auth + '/api/user-roles', headers=admin_headers,
            json={'user_id': user['id'], 'role_id': str(uuid4())}), 400)
        profile = expect('Mismo JWT obtiene roles actuales', client.get(auth + '/api/auth/profile', headers=headers), 200)
        assert set(profile['roles']) == {'USER', 'ANALYST'}
        buffer = io.BytesIO(); Image.new('RGB', (16, 16), (80, 40, 20)).save(buffer, format='PNG')
        content = buffer.getvalue()
        record = expect('ANALYST autorizado; sin detector queda en cuarentena', client.post(stego + '/api/steganography/analyze',
            headers=headers, files={'file': ('reference.png', content, 'image/png')}), 503)
        assert record['status'] == 'error' and record['action'] == 'cuarentena'
        assert record['user_id'] == user['id'] and record['sha256'] == hashlib.sha256(content).hexdigest()
        result_path = '/api/steganography/results/' + record['analysis_id']
        expect('Propietario consulta resultado', client.get(stego + result_path, headers=headers), 200)
        expect('ADMIN consulta resultado', client.get(stego + result_path, headers=admin_headers), 200)
        expect('Asignar ANALYST al segundo usuario', client.post(auth + '/api/user-roles', headers=admin_headers,
            json={'user_id': other['id'], 'role_id': role_ids['ANALYST']}), 201)
        other_jwt = expect('Login segundo ANALYST', client.post(auth + '/api/auth/login',
            json={'email': other['email'], 'password': other_password}), 200)['access_token']
        other_headers = {'Authorization': 'Bearer ' + other_jwt}
        expect('T11 ANALYST no consulta resultado ajeno', client.get(stego + result_path, headers=other_headers), 403)
        expect('T07 retirar ANALYST', client.delete(auth + '/api/user-roles/' + assignment['id'], headers=admin_headers), 204)
        expect('T07 mismo JWT pierde privilegio inmediatamente', client.post(stego + '/api/steganography/analyze', headers=headers), 403)
        expect('Resultado inaccesible tras revocar privilegio', client.get(stego + result_path, headers=headers), 403)
        expect('ADMIN deshabilita usuario', client.patch(auth + '/api/users/' + other['id'], headers=admin_headers, json={'status': False}), 200)
        expect('Cuenta deshabilitada rechaza JWT anterior', client.get(auth + '/api/auth/profile', headers=other_headers), 401)
        expect('T10 imagen corrupta', client.post(stego + '/api/steganography/analyze', headers=admin_headers,
            files={'file': ('bad.png', b'invalid', 'image/png')}), 415)
        expect('T10 carga excesiva', client.post(stego + '/api/steganography/analyze', headers=admin_headers,
            files={'file': ('large.png', b'x' * (5 * 1024 * 1024 + 1), 'image/png')}), 413)
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
    if bootstrap_path.exists():
        expect('Deshabilitar cuenta de prueba', client.patch(auth + '/api/users/' + user['id'], headers=admin_headers, json={'status': False}), 200)
    report = {'executed_at': datetime.now(timezone.utc).isoformat(), 'scope': 'Leonel, Alejandro (RBAC) y Paul (STEGO)',
        'environment': 'Docker y PostgreSQL reales; TLS verificado', 'tests': checks}
    target = root / 'docs/evidence/integration.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'{len(checks)} verificaciones de integración aprobadas con RBAC activo')
