# STEGO — Transferencia y gestión de Paul

**Estado actual:** Alejandro todavía no ha incorporado su endpoint de autorización. STEGO devuelve 503 para operaciones con un JWT válido porque no puede obtener una decisión vigente de AUTH; no lee ni procesa archivos en ese caso. Los módulos de Paul y sus pruebas de contrato se conservan para integrar posteriormente autorización y detector.

FastAPI independiente. JWT RS256 mediante clave pública, autorización actual por HTTPS hacia AUTH, SQLite privado, SHA-256 y archivos aislados. No recibe credenciales PostgreSQL ni clave privada JWT.

Arranque local desde esta carpeta: crea `.venv`, instala `requirements.lock.txt`, configura las variables de `.env.example` y ejecuta:

```powershell
.venv/Scripts/python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --ssl-keyfile ../../secrets/stego/tls-key.pem --ssl-certfile ../../secrets/stego/tls-cert.pem
```

Las variables deben exportarse al proceso; `.env.example` documenta valores y no se carga automáticamente. Usa el Compose raíz para configurar el entorno de forma reproducible.

API: `/api/steganography/analyze` recibe un archivo `file` PNG/BMP; `/api/steganography/results/{id}` consulta el registro. Swagger `/docs`, contrato `/openapi.json`. Solo ADMIN y ANALYST; ANALYST consulta resultados propios y ADMIN todos. El propietario procede del JWT verificado, nunca del formulario.

Se verifica autorización antes de leer el cuerpo; cada consulta obtiene una nueva decisión. AUTH caído, timeout, certificado inválido o decisión inconsistente impiden procesar. El middleware limita también el tamaño de cuerpos sin Content-Length.

El archivo permanece privado incluso cuando el resultado es `sin_indicios`: esa clasificación es indicativa y no certifica ausencia de amenazas. No hay descarga ni ejecución del contenido recibido. El adaptador ejecuta el detector en un proceso hijo acotado; este proceso interno no es un tercer microservicio.

**Detector pendiente de Diana:** implementar `app/detector.py` según `contracts/README.md`. Hasta entonces las imágenes válidas autorizadas generan registro `error`, política `cuarentena` y HTTP 503. Los dobles en pytest solo prueban el contrato y no demuestran detección real.

Pruebas desde esta carpeta: `.venv/Scripts/python.exe -m pytest -q`. Purga operativa: `python -m app.purge --days 7` con las variables configuradas. Los resultados permanecen en SQLite tras borrar los archivos por retención.

Referencia: [FastAPI UploadFile](https://fastapi.tiangolo.com/tutorial/request-files/), [PyJWT RS256](https://pyjwt.readthedocs.io/en/stable/usage.html).
