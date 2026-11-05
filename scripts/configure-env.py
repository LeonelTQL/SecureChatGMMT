"""Crea los .env de contenedores desde el .env raíz sin imprimir secretos."""
import os
from pathlib import Path
from urllib.parse import quote


def configure(root):
    values = {}
    for line in (root / '.env').read_text(encoding='utf-8-sig').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('\"\'')
    password = values.get('POSTGRES_PASSWORD', '')
    token = values.get('STEGO_SERVICE_TOKEN', '')
    if not password or 'CHANGE_ME' in password or len(token) < 32:
        raise ValueError('Primero configura el .env raíz con contraseña PostgreSQL y credencial de servicio reales')
    user = quote(values.get('POSTGRES_USER', 'chatseguro'), safe='')
    database = quote(values.get('POSTGRES_DB', 'chatseguro'), safe='')
    configurations = {
        'apps/auth-service/.env': {
            'DATABASE_URL': f'postgresql://{user}:{quote(password, safe="")}@postgres:5432/{database}',
            'PORT': '3001',
            'JWT_PRIVATE_KEY_PATH': '/run/keys/jwt-private.pem',
            'JWT_PUBLIC_KEY_PATH': '/run/public/jwt-public.pem',
            'TLS_KEY_PATH': '/run/keys/tls-key.pem',
            'TLS_CERT_PATH': '/run/keys/tls-cert.pem',
            'BOOTSTRAP_CONFIG_PATH': '/run/keys/bootstrap.json',
            'STEGO_SERVICE_TOKEN': token,
        },
        'services/stego/.env': {
            'AUTH_URL': 'https://auth-service:3001',
            'JWT_PUBLIC_KEY_PATH': '/run/public/jwt-public.pem',
            'AUTH_CA_PATH': '/run/public/ca.pem',
            'STORAGE_PATH': '/app/storage',
            'STEGO_SERVICE_TOKEN': token,
        },
    }
    for relative, data in configurations.items():
        target = root / relative
        if target.exists():
            print(f'{relative}: conservado')
            continue
        target.write_text('# Configuración de contenedor; generada desde el .env raíz.\n' +
            ''.join(f'{key}={value}\n' for key, value in data.items()), encoding='utf-8')
        os.chmod(target, 0o600)
        print(f'{relative}: creado')


if __name__ == '__main__':
    configure(Path(__file__).resolve().parents[1])
