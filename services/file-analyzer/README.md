# Módulo de Paul Moreno — ms-esteganografia

Implementa carga multipart, almacenamiento privado, SHA-256, estados,
cuarentena, consulta y descarga condicionada por análisis e integridad.
La validación real JPG/PNG, malware, metadatos y esteganografía corresponde
al motor de Diana. Consultar [contrato](../../contracts/files.md).

## Desarrollo local

Desde este directorio, con Python 3.12 o superior:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Swagger: http://127.0.0.1:8000/docs. Solo para desarrollo local.
La instancia por defecto usa `StegoAnalyzer`, que ejecuta el detector PNG/LSB real.
No libera archivos: devuelve `SUSPICIOUS` o `INCONCLUSIVE`, conservando el informe
original en `analysis`. Incluso `SIN_INDICIOS` requiere otras verificaciones.
Consultar [integración LSB](STEGO_INTEGRACION.md) para correspondencias y pruebas.
La validación previa comprueba contenido PNG/JPEG, extensión coherente,
decodificación y límites de recursos. El MIME del cliente no determina el formato.
El máximo de imágenes es 5 MiB (`IMAGE_MAX_BYTES`), separado de `MAX_FILE_BYTES`.
Ver [validación de imágenes](IMAGE_VALIDACION.md) para parámetros y resultados.
Después de validar se ejecutan ClamAV y YARA en procesos Linux limitados; sus
resultados se conservan en `analysis.antimalware`. Ausencia, fallo o firmas
vencidas mantienen el bloqueo. Consultar [antimalware](ANTIMALWARE.md) para reglas,
límites, actualización de firmas y pruebas reales frente a simuladas.
ExifTool extrae y evalúa campos permitidos en `analysis.metadata`, sin GPS,
identificadores ni texto libre. Su ausencia o fallo conserva el bloqueo;
carecer de EXIF no genera sospecha. Ver [metadatos](EXIFTOOL.md).
No habilitar un resultado simulado CLEAN en despliegues.

## Verificación

```powershell
python -m pytest -q
```

La suite original de transferencia admite `python -m unittest discover -s tests -v`;
las pruebas del detector y de integración requieren pytest. Las dependencias
completas se instalan con `requirements-dev.txt`.
La suite de transferencia usa temporales aislados y resultados simulados: comprueba
integridad, persistencia al reiniciar, bloqueo durante procesamiento,
cuarentena, fallos del motor, manipulación antes/después del análisis y al
descargar, límites, rutas privadas y ausencia de aprobación pública.
Estas pruebas no verifican la detección de malware del motor de Diana.

## Docker y Postman

Desde la raíz, configurar `.env` como indica el README general y ejecutar
`docker compose up -d --build`. El volumen `file_storage_data` conserva objetos
y SQLite, incluso después de `docker compose down` sin `-v`. El contenedor
ejecuta como usuario sin privilegios, con raíz de solo lectura y volumen privado
escribible. No publica su puerto; Caddy expone la API en localhost.

Importar `postman/Paul-files.postman_collection.json`. Incluye una imagen PNG
de prueba en `postman/fixtures/pixel.png`; configurar la raíz del repositorio
como directorio de trabajo de Postman o seleccionar otra imagen local en la
petición de carga. La colección conserva el ID, consulta el estado
y verifica que la descarga permanezca bloqueada con el adaptador predeterminado.
Cuando se integre el motor real, establecer `expectedStatus` y
`expectedClassification` según la muestra. La consulta puede repetirse hasta
alcanzar el resultado final; la colección no fuerza aprobaciones.

Para ejecutar las mismas comprobaciones con Postman CLI, desde la raíz:

```powershell
postman collection run postman/Paul-files.postman_collection.json --no-report-events --delay-request 150 --timeout-request 10000 --timeout 60000
```

La ejecución local no requiere publicar resultados ni iniciar sesión. No usar
`--output` en una sesión sin autenticar: esta versión de Postman CLI lo exige.
Consultar [evidencia de validación](VALIDACION.md) para el resultado observado.

La definición FastAPI es la fuente del OpenAPI. Regenerar la copia con
`python export_contract.py` después de cambiar rutas/modelos. La colección
Postman conserva ejemplos y aserciones de los escenarios del contrato.

Configurar `FILE_STORAGE_ROOT` (predeterminado `storage`) y `MAX_FILE_BYTES`
(predeterminado 10485760) según el entorno. Ejecutar una sola instancia/worker.
La autorización de acceso por usuario queda pendiente de integración con auth;
la entrega actual está limitada al entorno local.
