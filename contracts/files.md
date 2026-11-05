# Transferencia y gestión segura de archivos (Paul Moreno)

Servicio propietario: `services/file-analyzer` (FastAPI, ms-esteganografia).
Ruta pública local: `http://localhost:8080/api/files`; ruta directa: `/files`.
El servicio NestJS `apps/file-service` sigue siendo una plantilla para fases futuras.

## API

- `POST /files/upload`: multipart con un único campo `file`. Responde **202**
  con `id`, `filename`, `size`, `sha256`, `status`, `classification`, `reason`,
  `created_at`, `updated_at`. La respuesta inicial es `PENDING`; el análisis
  se ejecuta después de responder. `Location` indica la consulta de estado.
- `GET /files/{id}/status`: **200**, mismo esquema actualizado; **404** si no existe.
- `GET /files/{id}/content`: descarga binaria **200** únicamente si está
  `APPROVED` y su integridad SHA-256 se conserva. **423** para todos los demás
  estados. Una alteración o pérdida del objeto provoca cuarentena y **423**.
- `GET /health`: comprobación del proceso.

IDs UUID. Errores con `detail`: **413** archivo/cuerpo demasiado grande,
**415** extensión distinta de JPG/JPEG/PNG, **422** archivo vacío, campo ausente
o UUID inválido, **400** multipart inválido. Límite predeterminado 10 MiB
(`MAX_FILE_BYTES`). El cuerpo multipart admite 64 KiB adicionales de cabeceras
y delimitadores. La extensión es un filtro de recepción; la validación del
formato real corresponde al motor de Diana y no confía en el MIME del cliente.

## Estados y contrato con Diana

`PENDING -> ANALYZING -> APPROVED | QUARANTINED`.
Solo `CLEAN` libera el archivo. `SUSPICIOUS`, `INCONCLUSIVE`, errores,
resultados inválidos o hashes incompatibles terminan en `QUARANTINED`.
Después de reiniciar, trabajos interrumpidos quedan en cuarentena con
`processing_interrupted`; no se aprueban ni se reintentan automáticamente.

Implementar `Analyzer.analyze(path: Path, sha256: str) -> AnalysisResult` en
`app/analyzer.py` e inyectarlo mediante `create_app(analyzer=...)`.
`path` es privado, de solo lectura para el analizador. Resultado obligatorio:

```json
{"sha256":"<64 caracteres hexadecimales minúsculos>","classification":"CLEAN","reason":"all_checks_passed"}
```

`classification`: `CLEAN | SUSPICIOUS | INCONCLUSIVE`. `reason`: código
no sensible, máximo 200 caracteres. El hash debe coincidir con los bytes recibidos.
Se verifica integridad antes y después de analizar y antes de descargar.
El adaptador predeterminado devuelve `INCONCLUSIVE / analyzer_not_configured`.
Los resultados simulados existen únicamente en las pruebas; ninguna opción de
entorno permite aprobar archivos sin un analizador real. No hay callback público
para cambiar estados ni aprobar archivos desde Postman.

## Almacenamiento y alcance

Objetos con UUID, nunca con el nombre suministrado. Bytes y metadatos SQLite
persisten en `FILE_STORAGE_ROOT` (Docker: `/app/storage`, volumen privado).
No hay rutas estáticas, rutas físicas en las respuestas ni puerto del analizador
publicado. El estado en SQLite controla la descarga: mover un objeto no basta
para publicarlo. Los archivos permanecen en el mismo almacén privado.

Primera entrega local: no implementa propiedad por usuario ni autorización JWT
de descargas; esto deberá integrarse con el equipo de autenticación antes de
exponerlo fuera de la máquina. Un UUID no sustituye autorización. El analizador
debe tener un tiempo de ejecución acotado; este módulo no es una cola distribuida.
Usar una instancia Uvicorn con un solo worker, como en el Dockerfile.
