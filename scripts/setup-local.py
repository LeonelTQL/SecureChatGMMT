"""Genera secretos locales sin imprimirlos; no sobrescribe una instalación existente."""
import ipaddress
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

root = Path(__file__).resolve().parents[1]
secret_dir = root / "secrets"
if secret_dir.exists():
    raise SystemExit("secrets/ ya existe; se conserva la configuración. Para rotar, respalda y retira esa carpeta manualmente.")
for folder in [secret_dir, secret_dir / "auth", secret_dir / "stego", secret_dir / "public"]:
    folder.mkdir(mode=0o700)


def write(path, data):
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    # La carpeta padre 0700 protege al usuario local; los contenedores leen archivos montados.
    os.chmod(path, 0o644)


def key_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


now = datetime.now(timezone.utc)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Chat Seguro Local CA")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    .sign(ca_key, hashes.SHA256()))
write(secret_dir / "public/ca.pem", ca.public_bytes(serialization.Encoding.PEM))
for folder, host in [("auth", "auth-service"), ("stego", "stego")]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256()))
    write(secret_dir / folder / "tls-key.pem", key_bytes(key))
    write(secret_dir / folder / "tls-cert.pem", cert.public_bytes(serialization.Encoding.PEM))
jwt_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
write(secret_dir / "auth/jwt-private.pem", key_bytes(jwt_key))
write(secret_dir / "public/jwt-public.pem", jwt_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
write(secret_dir / "auth/bootstrap.json", json.dumps({"email": "admin@example.com", "password": secrets.token_urlsafe(32)}))
env_path = root / ".env"
existing_env = env_path.exists()
example = root / '.env.example'
defaults = 'POSTGRES_DB=chatseguro\nPOSTGRES_USER=chatseguro\nPOSTGRES_PASSWORD=CHANGE_ME_USE_A_LONG_RANDOM_PASSWORD\nAPP_PORT=8080\nSTEGO_SERVICE_TOKEN=\n'
text = env_path.read_text() if existing_env else (example.read_text() if example.exists() else defaults)
if not any(line.startswith("STEGO_SERVICE_TOKEN=") and len(line.split("=", 1)[1]) >= 32 for line in text.splitlines()):
    text = '\n'.join(line for line in text.splitlines() if not line.startswith("STEGO_SERVICE_TOKEN="))
    text += "\nSTEGO_SERVICE_TOKEN=" + secrets.token_urlsafe(48) + "\n"
if not existing_env and "CHANGE_ME" in text:
    text = text.replace("CHANGE_ME_USE_A_LONG_RANDOM_PASSWORD", secrets.token_hex(24))
write(env_path, text)
os.chmod(env_path, 0o600)
from runpy import run_path
run_path(str(root / 'scripts/configure-env.py'))['configure'](root)
print("Configuración generada. Credenciales de bootstrap en secrets/auth/bootstrap.json; no se imprimen secretos.")
