# STEGO — Transferencia y gestión de Paul

**Estado actual:** STEGO exige JWT RS256 y decisión vigente antes de consumir
archivos. El detector de Diana está integrado: validación JPG/PNG, ClamAV/YARA,
ExifTool y LSB estadístico para PNG, con informes técnicos persistidos. Fallos o
verificaciones no disponibles mantienen el bloqueo. Permisos insuficientes: 403.

FastAPI independiente. JWT RS256 mediante clave pública, autorización actual por HTTPS hacia AUTH, SQLite privado, SHA-256 y archivos aislados. No recibe credenciales PostgreSQL ni clave privada JWT.

Arranque local desde esta carpeta: crea `.venv`, instala `requirements.lock.txt`, configura las variables de `.env.example` y ejecuta:

```powershell
.venv/Scripts/python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --ssl-keyfile ../../secrets/stego/tls-key.pem --ssl-certfile ../../secrets/stego/tls-cert.pem
```

Las variables deben exportarse al proceso; `.env.example` documenta valores y no se carga automáticamente. Usa el Compose raíz para configurar el entorno de forma reproducible.

API: `/api/steganography/analyze` recibe un archivo `file` PNG/JPG/JPEG o BMP;
`/api/steganography/results/{id}` consulta el registro. Máximo 5 MiB. El MIME
del cliente no es evidencia: extensión y formato decodificado deben concordar.
JPEG y BMP sin detector aplicable quedan no concluyentes, privados y en cuarentena.
Swagger `/docs`, contrato `/openapi.json`. Solo ADMIN y ANALYST; ANALYST consulta
resultados propios y ADMIN todos. El propietario procede del JWT verificado,
nunca del formulario.

Se verifica autorización antes de leer el cuerpo; cada consulta obtiene una nueva decisión. AUTH caído, timeout, certificado inválido o decisión inconsistente impiden procesar. El middleware limita también el tamaño de cuerpos sin Content-Length.

El archivo permanece privado incluso cuando el resultado es `sin_indicios`: esa clasificación es indicativa y no certifica ausencia de amenazas. No hay descarga ni ejecución del contenido recibido. El adaptador ejecuta el detector en un proceso hijo acotado; este proceso interno no es un tercer microservicio.

El contrato `app.detector.analyze(path) -> dict` conserva las cuatro
clasificaciones oficiales, métricas reales y limitaciones. `reason` y `reports`
amplían el contrato de manera opcional; los informes excluyen GPS y salida cruda.
Ver [integración, decisiones y evidencias](INTEGRACION_DIANA.md). Las pruebas con
dobles no se presentan como evidencia de motores reales.
La [validación real de Backend V1](../../docs/VALIDACION_BACKEND_V1.md) ya ejecutó
AUTH, PostgreSQL y STEGO, incluida revocación con el mismo JWT y persistencia.
ClamAV tiene un perfil centralizado de 75 s/45 s CPU; el worker externo espera
hasta 120 s. Se conserva el fallo cerrado y el límite de imágenes de 5 MiB.

Docker se construye desde la raíz para reutilizar el código histórico sin iniciar
otra API. `.dockerignore` admite sólo los archivos necesarios, excluyendo secretos:

```powershell
docker compose build --build-arg CLAMAV_DB_REV=2026-11-05 stego
```

Renovar la revisión al reconstruir firmas. No se ejecuta FreshClam en cada carga.
El contenedor conserva usuario sin privilegios, read-only, cap_drop y tmpfs;
su límite de memoria sube a 3 GiB por incompatibilidad comprobada entre el antiguo
worker de 384 MiB y los 2 GiB máximos de ClamAV. Se permite una imagen por worker.

Pruebas desde esta carpeta: `.venv/Scripts/python.exe -m pytest -q`. Purga operativa: `python -m app.purge --days 7` con las variables configuradas. Los resultados permanecen en SQLite tras borrar los archivos por retención.

Referencia: [FastAPI UploadFile](https://fastapi.tiangolo.com/tutorial/request-files/), [PyJWT RS256](https://pyjwt.readthedocs.io/en/stable/usage.html).
