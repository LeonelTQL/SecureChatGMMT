# Evidencia de metadatos con ExifTool

Rama `feature/stego-diana`. Entorno real: Ubuntu/WSL, Python 3.14, ExifTool
**13.50**, Pillow 12.3.0, SciPy 1.18.1 y pytest 9.2.0. Se instaló
`libimage-exiftool-perl` en WSL para comprobar el extractor real; el Dockerfile
incluye el mismo paquete para el despliegue, sin añadir servicios.

## Ejecución completa

Desde Ubuntu/WSL, en la raíz del repositorio:

```sh
.venv-stego/linux-env/bin/python -m pytest \
  -c services/file-analyzer/pytest.ini services/file-analyzer/tests \
  -q -p no:cacheprovider --basetemp=/tmp/securechat-exif-full1
```

Resultado: **150 aprobadas, 0 fallidas, 14 subcasos aprobados**, en **92.24 s**.
Se conserva un aviso de deprecación de TestClient/HTTPX, sin ocultarlo.

Se ejecutaron las **120 regresiones anteriores**, incluidos sus cinco casos
reales de procesos limitados, ClamAV/EICAR y YARA. No se modifica el detector LSB,
sus umbrales, sus 31 pruebas originales ni el almacenamiento de Paul.

Las **30 pruebas nuevas** de `tests/test_exiftool.py` comprenden:

| Grupo | Casos | Evidencia |
| --- | --- | --- |
| Resultados de comando y control de flujo simulados | 22 | Evaluación, privacidad, errores y cuarentena |
| Casos `real_*` con ExifTool instalado | 8 | Extracción y evaluación de archivos reales, límites y HTTP |

Los ocho casos reales son las cuatro combinaciones JPG/PNG con/sin EXIF,
dimensiones EXIF incompatibles, EXIF malformado, límites de salida/memoria y
persistencia/privacidad HTTP. En los casos HTTP nuevos sólo antimalware se
sustituye por dobles explícitos para aislar metadatos; ExifTool es real.
La regresión antimalware incluye además el flujo HTTP con ambos motores reales.

## Resultados comprobados

- JPG y PNG generados independientemente con Pillow, con software GIMP, fechas,
  ISO y GPS sintético: EXTRACTED. Se conservaron familia GIMP, día 2026-11-04
  e ISO 200; no se devolvieron GPS, rutas ni hora exacta.
- JPG y PNG sin EXIF/campos permitidos: ABSENT, sin inconsistencias ni sospecha
  añadida por esa ausencia. ABSENT no afirma que se hayan inspeccionado todos
  los campos de metadatos posibles.
- Imagen 64x64 con dimensión EXIF declarada 999: INCONSISTENT y código
  `exif_dimensions_mismatch`, sin afirmar esteganografía o malware.
- JPEG aún decodificable con bloque EXIF malformado: extracción no satisfactoria
  (INCONSISTENT o UNAVAILABLE), conservando el bloqueo.
- Proceso real con salida limitada a 10 bytes: UNAVAILABLE/scan_output_limit.
  Un límite real de memoria de 1 MiB también impidió completar la extracción.
- Informe de metadatos persistido, recuperable después de reiniciar el almacén,
  con descarga bloqueada mediante HTTP 423.
- Alteración de los bytes durante la etapa de metadatos: prevaleció
  `integrity_mismatch`, con cuarentena y sin descarga.

Las pruebas simuladas cubren motor ausente, timeout, exceso de salida, ausencia
de límites Linux, retorno de error, JSON inválido/incompleto, advertencias,
tipos/rangos inválidos, fechas imposibles y discrepancias de formato/dimensiones.
También suministran GPS, nombres, seriales, rutas y texto sensible inesperado
en el JSON para verificar que la lista permitida no los persiste. No se guarda
salida cruda ni texto de las excepciones.

## Ejecuciones parciales y límites

La suite nueva pasó inicialmente en Windows con **22 aprobadas y 8 omitidas**,
porque el ejecutor exige límites Linux. Después pasó en WSL con **30 aprobadas**
en 11.03 s, antes de ejecutar la batería completa. Una primera invocación WSL
no devolvió resultados; no se contó como prueba aprobada y se reintentó después
de comprobar que WSL respondía. No se cambió el extractor para ocultar ese bloqueo.

Las 120 regresiones mantienen sus dobles antimalware históricos donde ya existían;
no se añadió una extracción exitosa ficticia de ExifTool para hacerlas pasar.
La única adaptación de la prueba anterior de integración separa el nuevo informe
`metadata` antes de comparar los indicadores LSB intactos.

No se construyó ni ejecutó la imagen Docker en esta tarea. La prueba WSL no
certifica el contenedor Debian final. Faltan JWT/RBAC, autorización vigente y
por propietario, detector esteganográfico JPEG y revisión del conjunto completo
de requisitos del equipo. Los campos permitidos tampoco garantizan autenticidad
o anonimato; los originales privados conservan sus metadatos. El servicio sigue
sin ser seguro para producción ni exposición pública.

Archivos creados: `app/exiftool_scan.py`, `tests/test_exiftool.py`, `EXIFTOOL.md`
y este informe. Se actualizaron el cableado interno, Docker, la prueba de
integración y la documentación afectada. No se modifican AUTH/RBAC, otros
microservicios, Compose ni almacenamiento; no se realizan commits, push ni PR.
