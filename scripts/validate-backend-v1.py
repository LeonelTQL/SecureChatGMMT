"""Validación real y reproducible; sólo crea/modifica cuentas de prueba propias.

Requiere Compose activo, roles/ADMIN preparados y secretos locales existentes.
No registra JWT, contraseñas, claves privadas, respuestas de login ni GPS.
"""
import base64
import hashlib
import io
import json
import secrets
from pathlib import Path
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from PIL import Image, PngImagePlugin
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services/file-analyzer'))
from tools.stego_samples import samples

COMPOSE = ['docker', 'compose', '-f', 'compose.yaml']
AUTH, STEGO = 'https://localhost:3001', 'https://localhost:8000'
OUTPUT = ROOT / 'docs/evidence/backend-v1-live.json'


def docker(*args):
    completed = subprocess.run(COMPOSE + list(args), cwd=ROOT, capture_output=True, text=True, timeout=120)
    if completed.returncode:
        raise RuntimeError('docker_operation_failed')
    return completed.stdout


def counters():
    return json.loads(docker('exec', '-T', 'stego', 'python', '-c',
        "import json,sqlite3,pathlib; r=pathlib.Path('/app/storage'); "
        "db=sqlite3.connect(r/'analyses.sqlite3'); "
        "print(json.dumps({'records':db.execute('SELECT COUNT(*) FROM analyses').fetchone()[0],"
        "'files':sum(p.is_file() for p in (r/'quarantine').iterdir())}))"))


def jwt_claims(encoded):
    header, payload, signature = encoded.split('.')
    decode = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    assert json.loads(decode(header))['alg'] == 'RS256'
    public = serialization.load_pem_public_key((ROOT / 'secrets/public/jwt-public.pem').read_bytes())
    public.verify(decode(signature), (header + '.' + payload).encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(decode(payload))
    assert claims['iss'] == 'ms-users-auth' and claims['aud'] == 'chat-seguro'
    assert time.time() < claims['exp'] and claims['exp'] - claims['iat'] <= 900
    return claims


def main():
    evidence = {'executed_at': datetime.now(timezone.utc).isoformat(),
                'environment': 'AUTH/STEGO/PostgreSQL reales en Docker, TLS verificado',
                'tests': [], 'analyses': [], 'test_accounts_disabled': [], 'errors': []}
    checks = evidence['tests']
    def check(name, condition, **details):
        checks.append({'test': name, 'passed': bool(condition), **details})
        if not condition:
            raise AssertionError(name)
    def expect(name, response, status):
        check(name, response.status_code == status, expected_http=status, actual_http=response.status_code)
        return response.json() if response.content else None
    context = ssl.create_default_context(cafile=str(ROOT / 'secrets/public/ca.pem'))
    created, admin_headers = [], None
    auth_stopped = False
    with httpx.Client(verify=context, timeout=150, trust_env=False) as client:
        try:
            expect('AUTH health con TLS verificado', client.get(AUTH + '/health'), 200)
            expect('STEGO health con TLS verificado', client.get(STEGO + '/health'), 200)
            services = set(docker('config', '--services').split())
            check('Sólo AUTH y STEGO como aplicaciones backend', services == {'auth-service', 'stego', 'postgres', 'caddy'}, services=sorted(services))
            expect('Endpoint interno exige identidad de servicio', client.post(AUTH + '/internal/authorization/check'), 401)
            credentials = json.loads((ROOT / 'secrets/auth/bootstrap.json').read_text(encoding='utf-8'))
            bootstrap = expect('Login administrativo para crear cuentas de prueba', client.post(AUTH + '/api/auth/login', json=credentials), 200)
            admin_headers = {'Authorization': 'Bearer ' + bootstrap['access_token']}
            jwt_claims(bootstrap['access_token'])
            roles = expect('Roles reales persistidos disponibles', client.get(AUTH + '/api/roles', headers=admin_headers), 200)
            role_ids = {role['name']: role['id'] for role in roles}
            users = {}
            for label, names in [('admin', ['ADMIN']), ('analyst', ['ANALYST', 'USER']),
                                 ('other', ['ANALYST']), ('user', ['USER'])]:
                suffix = uuid4().hex[:12]
                password = secrets.token_urlsafe(24)
                dto = {'username': 'v1test_' + suffix, 'email': 'v1test_' + suffix + '@example.test', 'password': password}
                user = expect('Crear cuenta de prueba ' + label, client.post(AUTH + '/api/users', headers=admin_headers, json=dto), 201)
                created.append(user['id'])
                assignments = {}
                for name in names:
                    assignment = expect('Asignación persistida ' + label + '/' + name,
                        client.post(AUTH + '/api/user-roles', headers=admin_headers,
                                    json={'user_id': user['id'], 'role_id': role_ids[name]}), 201)
                    assignments[name] = assignment['id']
                login = expect('Login real de ' + label, client.post(AUTH + '/api/auth/login', json={'email': dto['email'], 'password': password}), 200)
                claims = jwt_claims(login['access_token'])
                check('JWT RS256 vigente de ' + label, claims['sub'] == user['id'], algorithm='RS256', lifetime_seconds=claims['exp'] - claims['iat'])
                users[label] = {'id': user['id'], 'headers': {'Authorization': 'Bearer ' + login['access_token']},
                                'assignments': assignments, 'claims': claims}

            def blocked(name, headers, expected):
                before = counters()
                response = client.post(STEGO + '/api/steganography/analyze', headers=headers,
                    content=b'body which must not be parsed', timeout=15)
                expect(name, response, expected)
                check(name + ': ningún registro ni archivo procesado', counters() == before)
            blocked('Sin JWT', {}, 401)
            blocked('JWT alterado', {'Authorization': users['admin']['headers']['Authorization'] + 'x'}, 401)
            blocked('USER sin privilegios y cabecera de rol falsificada', {**users['user']['headers'], 'X-Role': 'ADMIN'}, 403)

            corpus = samples()
            def analyze(name, data, filename, owner, expected_status, action):
                started = time.monotonic()
                response = client.post(STEGO + '/api/steganography/analyze', headers=users[owner]['headers'],
                                       files={'file': (filename, data, 'image/png')})
                record = expect(name, response, 200)
                evidence['analyses'].append(record)
                check(name + ': clasificación y política', record['status'] == expected_status and record['action'] == action,
                      classification=record['status'], action=record['action'], elapsed_seconds=round(time.monotonic()-started,3))
                check(name + ': integridad y propietario', record['sha256'] == hashlib.sha256(data).hexdigest() and record['user_id'] == users[owner]['id'])
                check(name + ': informes reales completos', set(record['reports']) >= {'validation', 'antimalware', 'metadata'})
                check(name + ': sin motores indisponibles', all(item['status'] in {'CLEAR', 'DETECTED'} for item in record['reports']['antimalware'].values())
                      and record['reports']['metadata']['status'] in {'ABSENT', 'EXTRACTED'})
                return record

            original = analyze('ADMIN analiza PNG original', corpus['original'], 'original.png', 'admin', 'sin_indicios', 'advertencia')
            altered = analyze('ANALYST analiza PNG con carga LSB', corpus['lsb_full'], 'lsb-full.png', 'analyst', 'sospechoso', 'cuarentena')
            check('T09 contraste estadístico real', original['indicators']['r_chi_square'] == 65536
                  and altered['indicators']['r_chi_square'] < original['indicators']['r_chi_square']
                  and altered['indicators']['r_p_value'] > original['indicators']['r_p_value'])
            result_path = STEGO + '/api/steganography/results/' + altered['analysis_id']
            own = expect('ANALYST consulta resultado propio', client.get(result_path, headers=users['analyst']['headers']), 200)
            check('Métricas y política recuperadas', own['indicators'] == altered['indicators'] and own['reports'] == altered['reports'] and own['action'] == 'cuarentena')
            expect('ANALYST ajeno no accede', client.get(result_path, headers=users['other']['headers']), 403)
            expect('ADMIN accede con autorización por recurso', client.get(result_path, headers=users['admin']['headers']), 200)

            info = PngImagePlugin.PngInfo()
            info.add_text('test', 'SECURECHAT_YARA_TEST_MARKER_V1')
            output = io.BytesIO()
            Image.new('RGB', (64, 64), 'blue').save(output, format='PNG', pnginfo=info)
            yara = analyze('YARA detecta marcador inerte en PNG', output.getvalue(), 'yara-test.png', 'admin', 'sospechoso', 'cuarentena')
            check('Coincidencia YARA numérica', yara['reports']['antimalware']['yara']['indicators']['matched_rules'] == 1)
            exif = Image.Exif()
            exif[0x0131] = 'GIMP 2.10.36'
            exif[0x0132] = '2026:11:04 12:34:56'
            exif[0x8825] = {1: 'N', 2: (47.0, 23.0, 1.0), 3: 'E', 4: (8.0, 2.0, 3.0)}
            output = io.BytesIO()
            Image.new('RGB', (64, 64), 'blue').save(output, format='JPEG', exif=exif)
            metadata = analyze('JPEG con metadatos sin detector LSB', output.getvalue(), 'metadata.jpg', 'admin', 'no_concluyente', 'cuarentena')
            check('ExifTool extrae software y omite datos sensibles', metadata['reports']['metadata']['status'] == 'EXTRACTED'
                  and metadata['reports']['metadata']['metadata']['software_families'] == ['GIMP']
                  and 'GPS' not in json.dumps(metadata) and '12:34:56' not in json.dumps(metadata))

            eicar_code = ("from pathlib import Path; import tempfile,json; from stego_diana.clamav_scan import ClamAVScanner; "
                "p=Path(tempfile.mkstemp(prefix='v1-eicar-',dir='/tmp')[1]); "
                "p.write_bytes(b'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$'+b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'); "
                "r=ClamAVScanner().scan(p); p.unlink(); print(json.dumps(r.to_dict()))")
            eicar = json.loads(docker('exec', '-T', 'stego', 'python', '-c', eicar_code))
            check('ClamAV real detecta EICAR sin ejecutarlo', eicar['status'] == 'DETECTED')
            evidence['clamav_eicar_direct_module_test'] = eicar

            before = counters()
            expect('Límite 5 MiB: exceso rechazado', client.post(STEGO + '/api/steganography/analyze', headers=users['admin']['headers'],
                files={'file': ('large.png', b'x' * (5 * 1024 * 1024 + 1), 'image/png')}), 413)
            check('Carga excesiva no creó análisis ni archivo', counters() == before)
            expect('Imagen corrupta rechazada antes del detector', client.post(STEGO + '/api/steganography/analyze', headers=users['admin']['headers'],
                files={'file': ('bad.png', b'invalid', 'image/png')}), 415)
            check('Imagen corrupta no creó análisis ni archivo', counters() == before)

            assignment = users['analyst']['assignments']['ANALYST']
            expect('Revocar únicamente ANALYST de cuenta de prueba', client.delete(AUTH + '/api/user-roles/' + assignment, headers=admin_headers), 204)
            check('Mismo JWT sigue vigente al revocar', time.time() < users['analyst']['claims']['exp'])
            blocked('Mismo JWT sin rol ANALYST queda denegado', users['analyst']['headers'], 403)
            expect('Resultado propio también exige permiso vigente', client.get(result_path, headers=users['analyst']['headers']), 403)

            before = counters()
            auth_stopped = True
            docker('stop', 'auth-service')
            try:
                blocked('AUTH inaccesible deniega ADMIN antes del procesamiento', users['admin']['headers'], 503)
            finally:
                docker('start', 'auth-service')
                auth_stopped = False
                for _ in range(60):
                    try:
                        if client.get(AUTH + '/health', timeout=3).status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(1)
                else:
                    raise RuntimeError('auth_recovery_failed')
            check('AUTH volvió sin generar análisis denegados', counters() == before)

            docker('restart', 'stego')
            for _ in range(60):
                try:
                    if client.get(STEGO + '/health', timeout=3).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError('stego_recovery_failed')
            saved = expect('Persistencia tras reiniciar STEGO', client.get(result_path, headers=users['admin']['headers']), 200)
            check('SHA-256, métricas, informes y cuarentena persisten', all(saved[key] == altered[key]
                  for key in ('sha256', 'indicators', 'reports', 'status', 'action', 'user_id')))
            probe = ("import hashlib,json,sys;from pathlib import Path;p=Path('/app/storage/quarantine')/sys.argv[1]; "
                     "print(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':oct(p.stat().st_mode&0o777)}))")
            stored = json.loads(docker('exec', '-T', 'stego', 'python', '-c', probe, altered['analysis_id']))
            check('Objeto privado conserva bytes y permisos 0600', stored['sha256'] == altered['sha256'] and stored['mode'] == '0o600')
            expect('No hay ruta pública de descarga', client.get(STEGO + '/storage/quarantine/' + altered['analysis_id']), 404)
        except Exception as exc:
            # Conservar evidencia de fallos sin cuerpos HTTP, JWT ni secretos.
            evidence['errors'].append({'type': type(exc).__name__, 'stage': checks[-1]['test'] if checks else 'setup'})
        finally:
            if auth_stopped:
                try:
                    docker('start', 'auth-service')
                except Exception:
                    evidence['errors'].append({'type': 'AuthRecoveryFailed'})
            if admin_headers:
                for user_id in created:
                    try:
                        response = client.patch(AUTH + '/api/users/' + user_id, headers=admin_headers, json={'status': False})
                        if response.status_code == 200:
                            evidence['test_accounts_disabled'].append(user_id)
                        else:
                            evidence['errors'].append({'type': 'TestAccountCleanupFailed'})
                    except httpx.HTTPError:
                        evidence['errors'].append({'type': 'TestAccountCleanupFailed'})
                try:
                    response = client.post(AUTH + '/api/auth/logout', headers=admin_headers)
                    evidence['bootstrap_test_session_revoked'] = response.status_code == 204
                    if response.status_code != 204:
                        evidence['errors'].append({'type': 'BootstrapSessionCleanupFailed'})
                except httpx.HTTPError:
                    evidence['errors'].append({'type': 'BootstrapSessionCleanupFailed'})
    evidence['summary'] = {'passed': sum(t['passed'] for t in checks), 'failed': sum(not t['passed'] for t in checks),
                           'errors': len(evidence['errors']), 'test_accounts_created': len(created),
                           'test_accounts_disabled': len(evidence['test_accounts_disabled'])}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence['summary']))
    return 0 if not evidence['summary']['failed'] and not evidence['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
