# Extracción y evaluación restringida de metadatos

`app/exiftool_scan.py` implementa `ExifToolInspector.inspect(path, expected)`.
Recibe un archivo privado y el formato, MIME y dimensiones ya comprobados por
la validación de imágenes. No depende del almacenamiento ni altera bytes.
El flujo real conserva validación, ClamAV/YARA, ExifTool, detector PNG LSB y
verificaciones SHA-256 de Paul antes/después. Los JPEG válidos también pasan
por ExifTool, aunque no exista aún detector esteganográfico JPEG.

El informe se añade en `analysis.metadata` usando el campo JSON existente.
No se cambia el esquema SQLite, el contrato de llamada `Analyzer`, las rutas,
los cálculos LSB ni sus umbrales. `create_app(metadata=...)` permite inyección
interna para pruebas; ninguna cabecera, carga o variable de entorno puede
habilitar un resultado simulado o aprobar un archivo.

## Ejecución y límites

Se reutiliza `scan_runner.run_scan`, sin shell y sin ejecutar el archivo recibido:
ExifTool se invoca en modo lectura, con JSON, nombres de grupo, etiquetas
seleccionadas y `--` antes de la ruta absoluta. `-config ""` es la primera opción
para impedir la carga automática de configuración Perl local. No se usan
opciones de escritura, comandos persistentes ni reglas aportadas por el cliente.
Referencia: [documentación oficial de ExifTool](https://exiftool.org/exiftool_pod.html).

Límites por defecto: entrada de 5 MiB, tiempo total 5 s, CPU 3 s, espacio virtual
256 MiB y salida 64 KiB. Se mantienen los límites de descriptores, core y tamaño
de archivos auxiliares del ejecutor compartido. El grupo de procesos se elimina
ante timeout o exceso de salida. Windows o ausencia de prlimit producen
UNAVAILABLE; no se ejecuta una extracción sin límites. `ScanLimits` permite
configuración interna; no modifica los límites de transferencia o imágenes.

El Dockerfile incorpora `libimage-exiftool-perl` en el mismo contenedor. No se
añaden dependencias Python, daemons, servicios ni actualizaciones de Compose.

## Datos conservados y privacidad

Se solicitan formato, MIME, dimensiones físicas/EXIF, software, fechas y campos
EXIF seleccionados. Antes de persistir se aplica una proyección explícita:

- Formato/MIME reconocidos y dimensiones, comparados con la validación previa.
- Software: sólo familia reconocida (por ejemplo GIMP o Adobe Photoshop), sin
  versión ni texto libre. Otros valores se representan como `unrecognized`.
- Fechas EXIF/XMP y CreationTime de PNG: se valida su forma y calendario; sólo
  se conserva `YYYY-MM-DD`, eliminando hora, fracciones y zona horaria.
- EXIF permitido: orientación, espacio de color, ISO, exposición, apertura,
  distancia focal y versión EXIF, con tipos/rangos restringidos.
- `has_allowlisted_exif` informa si hubo campos EXIF de esa lista; no garantiza
  presencia o ausencia de todos los bloques EXIF posibles.

No se solicitan EXIF:all, GPS, autores, comentarios, seriales, miniaturas, nombres
de archivo, rutas ni identificadores de dispositivo. El JSON de ExifTool incluye
SourceFile automáticamente; se descarta. También se descartan campos inesperados
aunque aparezcan en la salida. Las advertencias/errores nunca se guardan como texto:
pueden contener valores privados. Tampoco se registra la salida cruda del proceso.
Las coordenadas sintéticas presentes en las muestras reales no aparecen en el
informe ni en las respuestas HTTP verificadas.

Esto minimiza información persistida; no anonimiza los archivos originales del
almacén ni garantiza anonimato de los campos permitidos. Los bytes originales
siguen siendo privados y no se modifican. Las fechas por día aún pueden ser
sensibles: requieren la misma autorización por recurso pendiente en el servicio.

## Evaluación y clasificación

| Estado del informe | Significado | Política |
| --- | --- | --- |
| EXTRACTED | Se extrajeron campos permitidos sin inconsistencias comprobadas | Conserva el resultado previo; nunca implica CLEAN |
| ABSENT | Extracción válida, sin campos permitidos de edición/EXIF/fechas | No genera sospecha ni aprobación |
| INCONSISTENT | Discrepancias o campos/advertencias que requieren revisión | INCONCLUSIVE y bloqueo, conservando indicios SUSPICIOUS previos |
| UNAVAILABLE | Motor ausente, fallo, límites, JSON inválido o extracción incompleta | INCONCLUSIVE y bloqueo, conservando indicios SUSPICIOUS previos |

Se comparan el formato/MIME y dimensiones físicas de ExifTool con los de la
validación Pillow. También se comparan dimensiones EXIF con dimensiones físicas
codificadas, sin aplicar rotación de presentación. Valores EXIF de tipo/rango
inválido, fechas imposibles y advertencias del parser se señalan con códigos
controlados. Una advertencia significa revisión pendiente, no prueba de malware.

Las discrepancias de dimensiones pueden deberse a edición o metadatos antiguos;
no demuestran esteganografía. No se infiere manipulación por ausencia de EXIF,
software desconocido ni fecha antigua. Tampoco se comparan fechas de captura
y edición para deducir cronología: reloj y zona horaria pueden ser incorrectos.
No se comprueba autenticidad, firma del autor ni que una fecha sea verdadera.

El informe incluye `engine`, `status`, `reason`, `metadata`, `issues` y `limits`.
Los motivos globales son `metadata_inconsistent` o `metadata_unavailable` cuando
corresponde. Las detecciones antimalware y LSB conservan prioridad SUSPICIOUS;
una indisponibilidad antimalware conserva su motivo global. Los informes por
verificación permanecen separados. El motor de producción sigue sin emitir CLEAN.

## Pruebas

Con Linux, ExifTool y las dependencias existentes instalados, desde la raíz:

```sh
python -m pytest -c services/file-analyzer/pytest.ini \
  services/file-analyzer/tests/test_exiftool.py -q -p no:cacheprovider
python -m pytest -c services/file-analyzer/pytest.ini \
  services/file-analyzer/tests -q -p no:cacheprovider
```

Las muestras se generan con Pillow, independientemente del extractor. Incluyen
JPG/PNG con EXIF, fechas, software y GPS sintético; imágenes sin EXIF; dimensiones
EXIF discordantes; y EXIF malformado en un JPEG todavía decodificable. Se prueba
persistencia del informe, bloqueo de descarga e integridad al modificar bytes.

Las pruebas de errores usan resultados de comando simulados, identificados
explícitamente: motor ausente, timeout, salida excesiva, fallo, JSON inválido,
advertencias y privacidad frente a campos inesperados. No se incorpora un
fallback de resultados limpios en producción. Los casos `real_*` requieren
ExifTool/Linux y se omiten explícitamente donde no están disponibles. Las
regresiones anteriores siguen usando sus dobles antimalware existentes, pero
no se sustituye ExifTool por una extracción exitosa ficticia.

La evidencia final se recoge en `EXIFTOOL_RESULTADOS.md`. Falta validar el
contenedor Docker y la autorización JWT/RBAC/propiedad del recurso. No se
habilitan rutas públicas nuevas. La API sigue limitada a desarrollo local,
sin considerarse segura para producción ni STEGO completo.
