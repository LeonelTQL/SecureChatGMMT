# Integración interna del detector LSB

`app.main:app`, la instancia que usa Uvicorn en Docker, se construye con
`StegoAnalyzer()` por defecto. `create_app(analyzer=...)` conserva la inyección de
analizadores de prueba. El detector, umbrales y muestras originales no se cambian.

## Flujo

1. La carga existente valida multipart, extensión y tamaño. Guarda los bytes en
   el almacén privado de Paul con UUID, calcula SHA-256 y registra `PENDING`.
2. La tarea existente reclama `ANALYZING` y verifica el hash antes de analizar.
3. `ValidatedImageAnalyzer` valida extensión/contenido, firma, MIME real,
   estructura, decodificación y límites; sólo un PNG válido pasa al adaptador.
   ClamAV y YARA examinan las imágenes válidas antes del detector; los informes
   se conservan por separado en `analysis.antimalware`. Ver [antimalware](ANTIMALWARE.md).
   Los JPEG válidos se conservan como no concluyentes. Ver [validación](IMAGE_VALIDACION.md).
   El adaptador llama a `stego_lsb.analyze_png(path, config)`. La ruta del objeto
   no tiene extensión; la firma, CRC, dimensiones y decodificación validan el contenido.
4. Convierte el resultado al contrato `Analyzer.analyze(path, sha256) -> AnalysisResult`.
5. El almacén comprueba nuevamente SHA-256, persiste el resultado y su informe,
   y aplica su misma política: sólo `CLEAN` permitiría `APPROVED`.
6. Este adaptador nunca emite `CLEAN`; todas sus salidas quedan `QUARANTINED` y
   la ruta de contenido devuelve HTTP 423. No se añade una vía de aprobación.

| Clasificación original LSB | Contrato de transferencia | Motivo controlado |
| --- | --- | --- |
| SOSPECHOSO | SUSPICIOUS | lsb_suspicious |
| NO_CONCLUYENTE | INCONCLUSIVE | lsb_inconclusive |
| ERROR | INCONCLUSIVE | lsb_analysis_error |
| SIN_INDICIOS | INCONCLUSIVE | additional_security_checks_required |
| Excepción inesperada | INCONCLUSIVE, informe ERROR | lsb_detector_failed |

El motivo original permanece en `analysis.reason`; para una excepción se usa
`detector_failed`, sin filtrar detalles internos. Un JPEG válido produce
`INCONCLUSIVE / jpeg_detector_not_available` antes del detector. Los archivos
inválidos se bloquean en la validación previa; un PNG decodificable fuera del alcance
RGB/RGBA estático de 8 bits conserva NO_CONCLUYENTE. Ninguno se descarga.

## Compatibilidad y persistencia

La ampliación mínima es `AnalysisResult.analysis`, objeto JSON opcional con valor
por defecto null, también expuesto en `FileStatus`. Contiene íntegro el resultado
del detector, incluyendo técnica, clasificación y motivo originales, indicadores,
dimensiones, límites, umbrales y limitaciones. Las tuplas del informe se representan
como listas JSON; no se cambian valores numéricos. No se admiten NaN/Infinity al
serializar. Los analizadores anteriores sin `analysis` siguen siendo válidos.

Al arrancar se añade, si falta, la columna nullable `analysis_json` en SQLite.
No se recrea la tabla ni se mueven objetos ni se cambia la lógica de cuarentena.
Las filas anteriores conservan sus estados y tienen `analysis=null`. Se conserva
la política anterior de cuarentena de trabajos interrumpidos. Si hay discrepancia
de integridad, se descartan las métricas del análisis y prevalece `integrity_mismatch`.

Las dependencias Docker adicionales son Pillow y SciPy, con NumPy transitivo,
reutilizando `requirements-stego.txt` desde `requirements.txt`. No se incluyen
pytest/httpx en la imagen. Se mantienen usuario sin privilegios y demás ajustes.
El límite global de carga `MAX_FILE_BYTES`, los de `ImageLimits` (5 MiB por
defecto) y los propios de `LSBConfig` son controles independientes;
sobrepasar cualquiera impide aprobación.

## Verificación ejecutada

Desde la raíz del repositorio, Python 3.12 en `.venv-stego`:

```powershell
.venv-stego/Scripts/python.exe -m pip install -r services/file-analyzer/requirements-dev.txt
# Temporal local para las pruebas de pytest y unittest en este entorno restringido.
New-Item -ItemType Directory -Path .venv-stego/test-temp -Force | Out-Null
$env:TEMP = (Resolve-Path .venv-stego/test-temp).Path
$env:TMP = $env:TEMP
.venv-stego/Scripts/python.exe -m pytest -c services/file-analyzer/pytest.ini services/file-analyzer/tests -q --basetemp=.venv-stego/integration-run1
```

Resultado de la integración inicial: **53 aprobadas, 0 fallidas; 14 subcasos aprobados**, en 7.00 s.
La ejecución posterior con validación JPG/PNG dio **90 aprobadas**, como se
documenta en [la evidencia actual](IMAGE_VALIDACION.md). La suite inicial comprendía:

- Las **31 pruebas originales** del detector, sin modificaciones.
- Las **12 pruebas de transferencia** de Paul. Sólo se ajustó la prueba del motor
  no configurado para inyectar `UnconfiguredAnalyzer` explícitamente, pues el
  motor predeterminado ahora es real. Se mantiene su comprobación de bloqueo.
- **10 nuevas pruebas de integración**: original, carga LSB completa, muestra
  insuficiente, corrupción, JPEG incompatible, excepción del detector, instancia
  `app.main:app`, integridad antes y después, y migración de la base anterior.

Las cinco muestras reales y el fallo se verificaron con carga multipart, consulta
de estado, cuarentena y persistencia. Las muestras se compararon con el informe
directo del detector; también se comprobó bloqueo tras reiniciar. Las pruebas de
Paul conservan el bloqueo de PENDING/ANALYZING y la inyección de motores de prueba.
Hubo un aviso de deprecación de TestClient/HTTPX de Starlette; no afectó los resultados.

## Pendientes y límites

El servicio sigue **sin JWT/RBAC ni autorización por propietario**: no es seguro
para producción y no cumple aún esos requisitos de integración de la consigna.
No se implementaron aquí las otras verificaciones obligatorias de seguridad;
por ello SIN_INDICIOS sigue bloqueado. Se conservan los falsos positivos y
negativos documentados en `STEGO_LSB_RESULTADOS.md`; no se declara precisión.

Actualización posterior: ClamAV y YARA ya se integraron; sus coincidencias o
indisponibilidad conservan el bloqueo. ExifTool también se integró con extracción
restringida y bloqueo ante inconsistencias o indisponibilidad; ver [metadatos](EXIFTOOL.md).
Las otras verificaciones pendientes y
la falta de autorización siguen impidiendo considerar el servicio terminado.

No se pudo construir ni ejecutar Docker porque el daemon no estaba disponible.
Se verificó la instancia ASGI real con TestClient, no un contenedor desplegado.
La construcción Docker queda pendiente. No se modifican AUTH/RBAC, Compose,
frontend ni otros servicios. No se realizan commits, push ni PR.
