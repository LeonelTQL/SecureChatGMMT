# Chat Seguro — Backend V1

## Levantar todo paso a paso

Ejecuta los comandos desde la raíz `SecureChatGMMT`. Necesitas Git, Node 22+, Python 3.10+ y Docker con Docker Compose. En Windows, inicia Docker Desktop con contenedores Linux. En Linux, comprueba que Docker esté iniciado y tu usuario pueda ejecutar `docker info`.

### 1. Preparar Python y las dependencias locales

Estos comandos preparan los scripts de configuración, imágenes y pruebas. Los servicios se ejecutan dentro de Docker; no necesitas iniciar cada backend por separado.

**Linux (Bash):**

```bash
python3 -m venv services/stego/.venv
services/stego/.venv/bin/python -m pip install -r services/stego/requirements.lock.txt
```

**Windows (PowerShell):**

```powershell
python -m venv services/stego/.venv
services/stego/.venv/Scripts/python.exe -m pip install -r services/stego/requirements.lock.txt
```

### 2. Crear la configuración inicial (solo en una copia nueva)

Si todavía no existe `secrets/`, genera los certificados, claves, credenciales y archivos de entorno:

**Linux:**

```bash
services/stego/.venv/bin/python scripts/setup-local.py
```

**Windows:**

```powershell
services/stego/.venv/Scripts/python.exe scripts/setup-local.py
```

Si `secrets/` ya existe, omite este paso. El script conserva esa carpeta y se detiene sin sobrescribirla. No la borres para volver a iniciar el proyecto.

### 3. Construir e iniciar todos los servicios

Los comandos son iguales en Linux y Windows. Espera a que termine cada uno antes de continuar; si alguno falla, corrige el error antes de ejecutar el siguiente.

```bash
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d --build --wait
docker compose -f compose.yaml exec -T auth-service node dist/database/seed.js
docker compose -f compose.yaml ps
```

Esto levanta PostgreSQL, AUTH, STEGO y el proxy Caddy. `--wait` espera a que los servicios estén disponibles según sus comprobaciones de salud. El seed prepara los roles y el administrador inicial.

### 4. Generar las imágenes y los archivos de prueba

**Linux:**

```bash
services/stego/.venv/bin/python scripts/generate-test-fixtures.py
```

**Windows:**

```powershell
services/stego/.venv/Scripts/python.exe scripts/generate-test-fixtures.py
```

El script genera 13 muestras en `.local/test-fixtures/` y un `manifest.json` con sus tamaños y hashes SHA-256:

- Imágenes válidas: `valida.png`, `valida.bmp` y `no_admitida.jpg` (el nombre de esta última procede del recorrido histórico; el backend actual admite JPEG).
- Archivos inválidos o disfrazados: `marcador.txt`, `texto_disfrazado.png`, `solo_firma.png`, `corrupta.png`, `vacia.png` y `bmp_disfrazado.png`.
- Casos de límites y contenido extra: `exactamente_5MiB.png`, `excede_5MiB.png`, `excede_pixeles.png` y `png_con_marcador_extra.png`.

Las muestras son inofensivas y quedan fuera de Git. El generador conserva una muestra modificada y avisa si no puede regenerarla. Para probar una carga en Postman, usa Body → form-data, campo `file` de tipo File, selecciona `.local/test-fixtures/valida.png` y utiliza un JWT ADMIN o ANALYST. Deja que Postman genere el Content-Type multipart.

Las [muestras del informe](docs/anexos/muestras/LEEME.txt) también están incluidas en `docs/anexos/muestras/`, listas para seleccionar en Postman sin ejecutar un generador. Son nueve imágenes sintéticas: controles (`original.png`, `tiny.png`, `flat.png`, `hidden_source.png`), cargas LSB (`lsb_full.png`, `lsb_small.png`), ruido sin carga (`noise_without_payload.png`) e inserciones multibit (`hidden_2bit.png`, `hidden_4bit.png`). Estas últimas documentan falsos negativos conocidos; el ruido permite demostrar un falso positivo. El [manifiesto](docs/anexos/muestras/manifest.json) registra el tamaño y SHA-256 de cada PNG.

Los generadores originales están en `services/file-analyzer/tools/stego_samples.py` y `services/file-analyzer/tools/stego_multibit_samples.py`. Para regenerarlas desde la raíz en Linux:

```bash
cd services/file-analyzer
../stego/.venv/bin/python -m tools.stego_samples ../../.local/informe-muestras
../stego/.venv/bin/python -m tools.stego_multibit_samples ../../.local/informe-muestras
cd ../..
```

En Windows sustituye `../stego/.venv/bin/python` por `../stego/.venv/Scripts/python.exe`. Estos comandos generan los PNG en `.local/informe-muestras`; el manifiesto incluido corresponde a los archivos del informe conservados en `docs/anexos/muestras/`.

### 5. Acceder a las APIs

Abre AUTH en `https://localhost:3001/docs` o STEGO en `https://localhost:8000/docs`. Consulta las credenciales del administrador localmente en `secrets/auth/bootstrap.json`. En Postman importa `secrets/public/ca.pem` como CA de confianza y mantén activa la verificación TLS.

Importa la colección `postman/Backend-V1.postman_collection.json`. Para los resultados esperados del detector actual, consulta [validación real del Backend V1](docs/VALIDACION_BACKEND_V1.md). El [walkthrough manual](docs/WALKTHROUGH-COMPLETO.md) contiene casos históricos que describen un detector ausente; esos resultados 503 y el rechazo de JPEG no corresponden al detector integrado actual.

### 6. Volver a iniciar o bajar todo

En una instalación ya preparada, estos son los comandos habituales de inicio (no repitas la creación del entorno ni el setup):

```bash
docker compose -f compose.yaml up -d --build --wait
docker compose -f compose.yaml ps
```

El seed y el generador de muestras se ejecutan explícitamente cuando los necesites. Para bajar todo conservando los datos:

```bash
docker compose -f compose.yaml down
```

Para ver los registros:

```bash
docker compose -f compose.yaml logs --tail 100 auth-service stego
```

### Detalles de configuración

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

Con los servicios activos y el seed completado, puedes ejecutar los scripts de verificación. Son opcionales para iniciar el proyecto.

**Linux:**

```bash
npm --prefix apps/auth-service ci
npm --prefix apps/auth-service run generate
npm --prefix apps/auth-service test
services/stego/.venv/bin/python -m pytest services/stego/tests -q
services/stego/.venv/bin/python scripts/integration.py
services/stego/.venv/bin/python scripts/validate-backend-v1.py
services/stego/.venv/bin/python scripts/check-container-permissions.py
```

`validate-backend-v1.py` genera sus propias imágenes de prueba y guarda evidencia en `docs/evidence/backend-v1-live.json`; no necesitas crear esas imágenes manualmente. La integración y la validación crean cuentas de prueba y las deshabilitan al finalizar correctamente. `check-container-permissions.py` verifica los permisos de los contenedores.

**Windows (PowerShell):**

```powershell
cd apps/auth-service
npm.cmd ci
npm.cmd run generate
npm.cmd test
cd ../..
services/stego/.venv/Scripts/python.exe -m pytest services/stego/tests -q
services/stego/.venv/Scripts/python.exe scripts/integration.py
services/stego/.venv/Scripts/python.exe scripts/validate-backend-v1.py
services/stego/.venv/Scripts/python.exe scripts/check-container-permissions.py
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

