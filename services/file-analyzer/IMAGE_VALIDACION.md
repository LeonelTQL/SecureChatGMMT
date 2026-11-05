# Validación previa de imágenes JPG y PNG

`app/image_validation.py` incorpora una puerta interna que implementa el contrato
`Analyzer`, envuelve al analizador existente y recibe el nombre lógico del archivo.
La instancia real `app.main:app` la utiliza para todas las cargas, incluidos los
analizadores inyectados. No cambia SHA-256, SQLite, rutas, almacenamiento privado
ni decisiones de cuarentena de Paul. No añade dependencias: reutiliza Pillow y
el validador estructural PNG `_validate_png` del detector sin modificarlo.

## Controles y resultados

- La recepción existente admite `.png`, `.jpg`, `.jpeg`, sin distinguir mayúsculas.
  Otras extensiones producen HTTP 415 antes de guardar.
- Se corta la escritura al superar el menor de `MAX_FILE_BYTES` e
  `IMAGE_MAX_BYTES`, con HTTP 413 y eliminación del objeto parcial. El middleware
  multipart y su límite global permanecen sin cambios. El parser puede usar su
  temporal acotado por el límite global antes del corte específico de imágenes.
- Antes del análisis estadístico se lee como máximo `IMAGE_MAX_BYTES+1`, se
  identifican firma PNG o JPEG y MIME (`image/png` / `image/jpeg`) por contenido,
  y se compara el formato con la extensión del registro, no con el UUID físico.
  El `Content-Type` enviado por el cliente se ignora: no es evidencia del formato.
- PNG reutiliza el chequeo de IHDR, longitudes, CRC y final IEND. JPEG exige SOI,
  identificación de firma y EOI final. Se restringe Pillow al formato identificado,
  se comprueban dimensiones antes de cargar píxeles y se ejecutan `verify()` y
  `load()` en aperturas separadas. No se modifican los bytes originales.
- Las advertencias y errores de bombas de descompresión se rechazan. No se
  deshabilita `Image.MAX_IMAGE_PIXELS` ni se activa tolerancia a truncamientos;
  si `LOAD_TRUNCATED_IMAGES` ya estuviera activado, la validación falla de forma
  cerrada. Véase [la documentación oficial de Pillow](https://pillow.readthedocs.io/en/stable/reference/ImageFile.html).

Los errores tardíos de firma, estructura, extensión incompatible o dimensiones
se registran en la tarea existente como `INCONCLUSIVE`, informe original `ERROR`,
estado `QUARANTINED`, descarga HTTP 423. La respuesta inicial HTTP 202 sólo
significa recepción, nunca aprobación. No se ejecuta LSB sobre esas entradas.
Los motivos son códigos fijos como `image_malformed`, `image_dimensions_exceeded`,
`image_extension_content_mismatch` o `unsupported_image_signature`; no incluyen
rutas ni mensajes de excepciones. Fallos inesperados conservan el manejo seguro
`analysis_failed` del almacén.

Un JPEG válido produce informe `NO_CONCLUYENTE`, contrato `INCONCLUSIVE`, motivo
`jpeg_detector_not_available`, y permanece bloqueado. Se informa la técnica
`IMAGE_VALIDATION_V1`, sin simular indicadores de esteganografía. Un PNG válido
continúa al detector LSB original; sus valores, umbrales y clasificaciones no se
modifican. Su comprobación interna se conserva para uso independiente del detector,
aunque implique una segunda decodificación acotada en el flujo integrado.
`SIN_INDICIOS` sigue sin ser suficiente para aprobar.
La etapa [antimalware](ANTIMALWARE.md) posterior puede elevar el resultado final
a SUSPICIOUS o mantenerlo INCONCLUSIVE por indisponibilidad. El informe original
de validación/LSB se conserva; los JPEG válidos también se escanean con ambos motores.

El informe persistente `analysis.validation` contiene `valid`, `reason`, `format`,
`mime`, `width`, `height` y `policy`. En errores muy tempranos puede faltar formato
o dimensiones; reconocer una firma no significa que `valid` sea verdadero.

## Configuración independiente

| Variable | Predeterminado |
| --- | --- |
| IMAGE_MAX_BYTES | 5242880 (5 MiB) |
| IMAGE_MAX_WIDTH | 4096 |
| IMAGE_MAX_HEIGHT | 4096 |
| IMAGE_MAX_PIXELS | 4000000 |

Son enteros positivos, evaluados al crear la aplicación. También se puede inyectar
`create_app(image_limits=ImageLimits(...))` para pruebas o configuración interna.
No se cambió `MAX_FILE_BYTES` (10 MiB por defecto) ni `LSBConfig`; si un límite de
cualquiera de las capas es más estricto, prevalece. Aumentar el límite de imágenes
no amplía automáticamente ni el límite global ni el del detector.

## Evidencia ejecutada

Desde la raíz, Python 3.12 y dependencias existentes en `.venv-stego`:

```powershell
New-Item -ItemType Directory -Path .venv-stego/test-temp -Force | Out-Null
$env:TEMP = (Resolve-Path .venv-stego/test-temp).Path
$env:TMP = $env:TEMP
.venv-stego/Scripts/python.exe -m pytest -c services/file-analyzer/pytest.ini services/file-analyzer/tests -q --basetemp=.venv-stego/image-validation-run2
```

Resultado: **90 aprobadas, 0 fallidas, 14 subcasos aprobados, en 6.80 s**.
Incluye las 31 originales LSB intactas, 12 de transferencia, 10 de integración y
37 nuevas de validación. Un aviso de deprecación de TestClient/HTTPX permanece.

Se probaron PNG/JPEG válidos, JPG/JPEG en mayúsculas, MIME declarado engañoso,
extensión incompatible, firmas falsas, truncamientos, CRC y deflate corruptos,
JPEG malformado, límite exacto/excedido, archivo de más de 5 MiB, dimensiones,
advertencia y error de bomba Pillow, PNG con dimensiones gigantes y configuración.
Las bombas usan cabeceras modificadas, sin generar ni cargar imágenes enormes.
Se verificó que inválidos y JPEG no alcanzan ni un motor inyectado de prueba,
y que los archivos rechazados o no concluyentes no permiten descarga.

En las pruebas de Paul sólo se reemplazó la muestra de bytes ficticios por un PNG
real de 1x1, preservando sus aserciones de transferencia e integridad. Las pruebas
de integración existentes se actualizaron para esperar el rechazo previo de PNG
corrupto y el reconocimiento de JPEG, en lugar de enviarlos al detector PNG.

## Límites y requisitos pendientes

Pillow y las firmas no demuestran ausencia de contenido oculto ni de malware.
El chequeo JPEG no es una auditoría independiente de cada segmento/coeficiente:
depende del decodificador, y algunos defectos tolerados por éste pueden pasar.
Se rechazan bytes posteriores a IEND y EOI; no se eliminan ni sanea el archivo.
No se extraen metadatos ni se ejecuta contenido. ExifTool no está integrado;
ClamAV y YARA se incorporaron posteriormente como verificaciones separadas.

Persisten los falsos positivos/negativos del detector LSB y falta un detector JPEG.
JWT/RBAC, autorización por propietario y otras verificaciones obligatorias siguen
pendientes. La API no es segura para producción. No se validó un contenedor Docker
en esta tarea; las pruebas ejecutan la instancia ASGI con almacenamiento temporal.
No se modifican AUTH, RBAC, Compose u otros microservicios, ni se realizan commits,
push o PR. El acceso directo a `Storage.process` es una interfaz interna: quien
lo use fuera de las rutas debe proporcionar la misma puerta de validación.
