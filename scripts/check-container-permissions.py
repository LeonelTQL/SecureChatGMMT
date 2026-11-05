"""Comprueba permisos con los UIDs reales sin imprimir certificados ni claves."""
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]


def execute(service, *command, user=None):
    args = ['docker', 'compose', '-f', 'compose.yaml', 'exec', '-T']
    if user: args += ['--user', user]
    subprocess.run(args + [service, *command], cwd=root, check=True)


# Reproduce en el kernel Linux por qué un directorio 0700 ajeno no se puede montar entero.
execute('stego', 'python', '-c',
    "import os,pathlib; p=pathlib.Path('/tmp/ci-permission-check'); p.mkdir(exist_ok=True); p.chmod(0o700); (p/'probe').write_text('probe'); (p/'probe').chmod(0o644)", user='root')
execute('stego', 'python', '-c',
    "import os,pathlib; assert os.getuid()!=0; p=pathlib.Path('/tmp/ci-permission-check/probe'); assert not os.access(p,os.R_OK), 'La prueba debe denegar el directorio 0700 ajeno'; print('Linux: directorio privado ajeno correctamente denegado')")
execute('stego', 'python', '-c',
    "import os,pathlib; assert os.getuid()!=0; paths=['/run/keys/tls-key.pem','/run/keys/tls-cert.pem','/run/public/ca.pem','/run/public/jwt-public.pem']; assert all(pathlib.Path(p).read_bytes() for p in paths); print('STEGO: archivos montados legibles por su usuario sin privilegios')")
execute('auth-service', 'node', '-e',
    "if(process.getuid()===0)throw Error('No ejecutar como root');const fs=require('fs');for(const p of ['/run/keys/tls-key.pem','/run/keys/tls-cert.pem','/run/keys/jwt-private.pem','/run/keys/bootstrap.json','/run/public/ca.pem','/run/public/jwt-public.pem'])if(!fs.readFileSync(p).length)throw Error('Archivo vacío');console.log('AUTH: archivos montados legibles por su usuario sin privilegios')")
