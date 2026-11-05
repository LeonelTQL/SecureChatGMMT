# Chat Seguro — Backend V1

## Preparación en Windows

Requisitos: Git, Node 22+, Python 3.10+ y Docker Desktop con contenedores Linux; Docker Compose 2.20+ si usas el alias `docker-compose.yml`.

Clona el repositorio y abre su carpeta `SecureChatGMMT`. Los comandos siguientes se ejecutan desde esa raíz:

```powershell
python -m venv services/stego/.venv
services/stego/.venv/Scripts/python.exe -m pip install -r services/stego/requirements.lock.txt
services/stego/.venv/Scripts/python.exe scripts/setup-local.py
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml exec -T auth-service node dist/database/seed.js
docker compose -f compose.yaml ps
```

En Linux usa `services/stego/.venv/bin/python` en lugar de `Scripts/python.exe`.

`setup-local.py` genera pares RSA JWT y TLS distintos, CA local y credencial entre servicios. Conserva un `.env` existente y nunca sobrescribe `secrets/`. Si ya existe `.env`, verifica que `POSTGRES_PASSWORD` coincida con tu volumen PostgreSQL; cambiar esa variable no cambia la contraseña de un volumen inicializado. No borres volúmenes para corregir credenciales.

Los `.env.example` y `.env` están ignorados por Git. El script incluye los valores de configuración necesarios para preparar una copia nueva aunque no existan ejemplos. También genera `apps/auth-service/.env` y `services/stego/.env` con valores reales para el entorno de contenedores, sin sobrescribir archivos existentes. Para generarlos sobre una instalación ya preparada: `python scripts/configure-env.py`. Compose toma el `.env` raíz; los archivos por servicio reflejan esa configuración y usan nombres/rutas internos de Docker.

El administrador inicial usa las credenciales de `secrets/auth/bootstrap.json`. Abre ese archivo localmente para iniciar sesión; no lo compartas ni lo subas a Git. El seed crea ADMIN/ANALYST/USER y una cuenta nueva; no promueve cuentas existentes ni restablece contraseñas. Solo se ejecuta explícitamente.

## APIs y certificados

| Aplicación | API propia | Documentación |
|---|---|---|
| AUTH | `https://localhost:3001/api` | `https://localhost:3001/docs` |
| STEGO | `https://localhost:8000/api` | `https://localhost:8000/docs` |

Importa `secrets/public/ca.pem` como CA de confianza en Postman; conserva la verificación TLS activada. Ambas APIs tienen `/health` fuera del prefijo `/api`. AUTH comprueba también PostgreSQL.

El proxy opcional `http://localhost:8080` sirve para demostración local y reenvía a los backends por TLS verificado. Está enlazado solo a loopback. Para credenciales y tokens usa preferentemente las APIs HTTPS directas. No publiques el puerto HTTP sin configurar HTTPS público.

El archivo `docker-compose.yml` incluye `compose.yaml`, por lo que `docker compose -f docker-compose.yml up -d` usa la misma configuración. Emplea `-f` explícito para evitar el aviso de dos nombres compatibles.

## Flujo

1. ADMIN inicia sesión y administra usuarios, roles y asignaciones N:M.
2. Un usuario inicia sesión: recibe JWT RS256 de 15 minutos y una sesión persistida.
3. STEGO valida el JWT con la clave pública y consulta a AUTH por HTTPS con `X-Service-Token`, antes de leer el cuerpo.
4. AUTH comprueba sesión, usuario y roles actuales. USER no analiza; ANALYST analiza y consulta resultados propios; ADMIN también consulta resultados ajenos.
5. STEGO valida PNG/JPG/JPEG o BMP, calcula SHA-256 y guarda de forma privada
   usando UUID. El detector integra validación segura, ClamAV/YARA, ExifTool y LSB
   para PNG, con límites y hash antes/después. JPEG/BMP sin técnica aplicable
   permanecen no concluyentes. No expone archivos por HTTP.
6. Una asignación retirada o un rol desactivado bloquea la próxima operación sin esperar expiración del JWT. Logout revoca solo la sesión actual; deshabilitar un usuario revoca todas sus sesiones.

Registro público crea usuarios **sin roles**. La administración de roles exige ADMIN. Roles en constantes expresan la política, mientras usuarios y asignaciones se consultan exclusivamente desde PostgreSQL.

## Pruebas

```powershell
cd apps/auth-service
npm.cmd ci
npm.cmd run generate
npm.cmd test
cd ../..
services/stego/.venv/Scripts/python.exe -m pytest services/stego/tests -q
services/stego/.venv/Scripts/python.exe scripts/integration.py
```

Para reproducir el fallo seguro T08, el comando siguiente detiene y reinicia AUTH temporalmente:

```powershell
services/stego/.venv/Scripts/python.exe scripts/integration.py --failure-demo
```

La integración usa PostgreSQL real, genera usuarios de prueba con nombres únicos
y los deshabilita al terminar. Guarda resultados depurados en
`docs/evidence/integration.json`. El script ahora exige métricas del detector
real y verificaciones completas sobre la muestra pequeña, que permanece no
concluyente. La pila completa AUTH/STEGO/PostgreSQL ya se verificó con cuentas
de prueba, revocación real, fallos de AUTH y motores reales. Los resultados,
correcciones y límites están en [validación real del Backend V1](docs/VALIDACION_BACKEND_V1.md).
`scripts/validate-backend-v1.py` reproduce los escenarios ampliados sin borrar datos.

Importa `postman/Backend-V1.postman_collection.json`; introduce contraseñas solo
en variables locales no compartidas. Sus nueve aserciones se verificaron con TLS
activo. Consulta `docs/VALIDACION_BACKEND_V1.md` para escenarios y evidencia del PDF.
La exportación depurada adicional es
`postman/Backend-V1-demostracion.postman_collection.json`; su alcance y las
variables privadas se explican en [guía de colecciones](postman/README.md).

## Operación

```powershell
docker compose -f compose.yaml stop auth-service
docker compose -f compose.yaml start auth-service
docker compose -f compose.yaml stop stego
docker compose -f compose.yaml start stego
docker compose -f compose.yaml logs auth-service stego
docker compose -f compose.yaml exec -T stego python -m app.purge --days 7
docker compose -f compose.yaml down
```

`down` conserva los volúmenes. El purgado elimina archivos antiguos en cuarentena, conservando metadatos de auditoría. No existe descarga de archivos ni acceso público al almacenamiento.

Los certificados TLS de desarrollo duran 90 días. Para rotar: conserva respaldo seguro, genera un nuevo conjunto en una copia de configuración, reemplaza claves/certificados/CA de forma coordinada y reinicia ambos servicios y clientes. Rotar JWT invalida tokens anteriores. No se implementa rotación automática ni se versionan secretos; restringe permisos/ACL del directorio `secrets` al usuario operador.

Límites: imagen de 5 MiB, 20 millones de píxeles, dos procesamientos simultáneos, detector con timeout y límites Linux, almacenamiento de 256 MiB. Login tiene límites locales a una réplica; varias réplicas requieren contadores compartidos. AUTH actualiza Prisma a 6.19.3 y fija deepmerge-ts 8 únicamente para su herramienta de configuración, corrigiendo la alerta de recursión; se verifican generación y migración. Repite la auditoría de dependencias antes de desplegar.

## Documentación

- `docs/ARQUITECTURA.md`: límites de confianza, ER y permisos.
- `docs/RIESGOS.md`: activos, amenazas y controles.
- `docs/PRUEBAS.md`: escenarios mínimos y responsabilidades.
- `docs/auth.openapi.json` y `docs/stego.openapi.json`: contratos exportados.
- `contracts/README.md`: decisión interna y adaptador para Diana.

Se toman principios de Zero Trust, Secure by Design y Shift Left Security como referencias de diseño; no se afirma certificación ni cumplimiento integral de ISO/IEC 27001 o 27034.
