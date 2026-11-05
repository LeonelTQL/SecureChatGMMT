# Evidencia de integración en STEGO activo

Actualizado para la revisión del PR el 5 de noviembre de 2026. La validación
de toda la pila AUTH/STEGO/PostgreSQL está en
[Backend V1 real](../../docs/VALIDACION_BACKEND_V1.md): 332 casos/comprobaciones
aprobados, 0 fallos finales y 14 subcasos adicionales, distinguiendo motores
reales de dobles. Ese total corresponde a la ejecución registrada, no incluye
las dos pruebas nuevas de varios bits descritas abajo. No se repitió toda la
pila durante esta revisión de documentación y artefactos.

Rama `feature/stego-diana`. Compose utiliza `services/stego`; no se activa el
servicio histórico file-analyzer. La autenticación, autorización y ambos
almacenamientos se conservan. Los cálculos y umbrales LSB no se modifican.

## Resultados de la integración inicial (históricos)

| Verificación | Resultado |
| --- | --- |
| Suite histórica Diana, entorno original WSL | 150 aprobadas, 0 fallidas, 14 subcasos aprobados; 138.59 s |
| STEGO activo, entorno WSL con su lock (antes de los últimos 3 casos añadidos) | 41 aprobadas, 0 fallidas; 111.81 s |
| Imagen Docker final, suite activa completa | 44 aprobadas, 0 fallidas; 131.52 s |
| Construcción Docker con motores y firmas | Correcta |

Las 44 activas comprenden las 31 pruebas existentes del equipo y 13 nuevas de
contrato, integridad, autorización e integración. Se conservaron las pruebas
existentes salvo el caso "detector ausente": ahora inyecta explícitamente la
indisponibilidad, ya que el detector real dejó de estar pendiente.

En conjunto se verificaron las 150 históricas y las 44 activas (194 casos), más
los 14 subcasos históricos. Se conserva un aviso de deprecación TestClient/HTTPX.
Las suites se ejecutan por separado por compartir el nombre de paquete app.

## Control, prueba positiva y limitaciones observadas

En esta revisión se ejecutaron las **31 pruebas LSB originales y dos nuevas:
33 aprobadas, 0 fallidas, en 5.50 s**, con el detector real y sin modificar
cálculos ni umbrales. No son pruebas del pipeline antimalware completo.
Las métricas completas se conservan en
[pr-lsb-samples.json](../../docs/evidence/pr-lsb-samples.json).

| Muestra sintética 256×256 RGB | X² R / G / B | p R / G / B | Resultado real |
| --- | --- | --- | --- |
| Control original, valores pares | 65536 / 65536 / 65536 | 0 / 0 / 0 | SIN_INDICIOS |
| Positiva, sustitución LSB completa | 115.403805 / 107.165157 / 114.416650 | 0.780134 / 0.909573 / 0.799247 | SOSPECHOSO |
| Mensaje corto conocido de 20 bytes | 65440.219371 / 65436.226420 / 65452.207083 | 0 / 0 / 0 | SIN_INDICIOS: falso negativo |
| Imagen oculta en los 2 bits inferiores | 65536 / 65536 / 65536 | 0 / 0 / 0 | SIN_INDICIOS: falso negativo |
| Imagen oculta en los 4 bits inferiores | 65536 / 65536 / 65536 | 0 / 0 / 0 | SIN_INDICIOS: falso negativo |
| Ruido sin carga oculta | 139.357692 / 148.679345 / 170.399194 | 0.232308 / 0.102059 / 0.007261 | SOSPECHOSO: falso positivo |

Las muestras de 2/4 bits ocultan una imagen propia de bloques RGB 0/128.
Las pruebas recuperan exactamente esa imagen desde los bits inferiores sin
consultar al detector. Su carga sesgada mantiene el bit menos significativo
en cero: PoV no observa la equiparidad que busca. Hay cobertura 1 y suficientes
pares: 128 por canal en 2 bits, 32 en 4 bits; no es un fallo de decodificación.
Estos casos concretos no demuestran que toda inserción de varios bits sea invisible.
Los p=0 son subdesbordamiento numérico de la cola, no certeza de ausencia.

PoV compara frecuencias de `(2j, 2j+1)` en histogramas RGB globales. Su hipótesis
estadística no equivale a presencia/ausencia de mensajes. Puede fallar con cargas
pequeñas, sesgadas, locales, adaptativas o en otros planos; ignora alfa y no extrae
contenido oculto. El ruido legítimo puede igualar pares y generar falsos positivos.
La correlación espacial limita la aproximación Chi-cuadrado y el histograma
pierde localización. Los umbrales son heurísticos, sin calibración de precisión
en fotografías representativas. JPEG/BMP carecen de detector aplicable.

En el STEGO activo, SIN_INDICIOS se representa como `sin_indicios` y aplica
`advertencia`, conservando el archivo privado. Los otros estados aplican
`cuarentena`; no existe descarga ni aprobación automática. El fallo de una
verificación obligatoria impide clasificar el resultado global como sin indicios.

### Disponibilidad y reproducción de muestras

No hacen falta fotografías externas ni los archivos de la computadora de Diana.
Los generadores versionados producen imágenes sintéticas propias, sin material
de terceros: `tools/stego_samples.py` y `tools/stego_multibit_samples.py` en
`services/file-analyzer`. No se añaden imágenes externas ni se atribuye una
licencia nueva al código del equipo. El pixel histórico de Postman se conserva;
su procedencia/licencia no está documentada y no es necesario para esta evidencia.

Desde la raíz, con el entorno de pruebas instalado (Windows; en Linux usar bin/python):

```powershell
.venv-stego/Scripts/python.exe -m pytest services/file-analyzer/tests/stego -q -p no:cacheprovider --basetemp=.venv-stego/pr-review-stego
.venv-stego/Scripts/python.exe services/file-analyzer/tools/stego_samples.py .local/test-fixtures
```

Desde `services/file-analyzer`, con el mismo intérprete del entorno:

```sh
python -m tools.stego_multibit_samples ../../.local/test-fixtures
```

La carpeta `.local` es una salida local ignorada; el código generador y las pruebas
permiten regenerar todas las muestras. La colección de demostración usa
`image_path`; seleccionar el archivo generado si Postman no resuelve esa variable.

## Comandos reproducibles

Desde la raíz, en WSL, con el entorno histórico ya instalado:

```sh
.venv-stego/linux-env/bin/python -m pytest \
  -c services/file-analyzer/pytest.ini services/file-analyzer/tests \
  -q -p no:cacheprovider --basetemp=/tmp/diana-regression150-active
```

Para STEGO usar Python con `services/stego/requirements.lock.txt` instalado,
ejecutando desde `services/stego`:

```sh
python -m pytest tests -q -p no:cacheprovider
```

Docker desde la raíz (no se publica ningún puerto para estas pruebas):

```powershell
docker build --build-arg CLAMAV_DB_REV=2026-11-05 -t securechat-stego-diana:local -f services/stego/Dockerfile .
$stegoTestMount = (Resolve-Path -LiteralPath services/stego/tests).Path
docker run --rm --network none --memory 3g --pids-limit 64 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs '/tmp:rw,noexec,nosuid,size=32m' --mount "type=bind,source=$stegoTestMount,target=/tests,readonly" securechat-stego-diana:local python -m pytest /tests -q -p no:cacheprovider --basetemp=/tmp/stego-tests
```

La imagen utiliza Python 3.12, las dependencias fijadas activas (incluidos
Pillow 12.2.0, NumPy 2.5.4 y SciPy 1.18.1) y motores CLI reales descargados
del repositorio Debian. FreshClam descargó/validó firmas oficiales durante la
construcción. No se empleó una base EICAR ficticia ni un fallback limpio.

El contexto inicial enviado a Docker fue aproximadamente 66 KiB, limitado al
código por `.dockerignore`. No se enviaron secretos, claves ni otros servicios.
La imagen copia los módulos compartidos bajo `stego_diana`, sin la API ni el
almacenamiento históricos. Se conservan TLS/RS256 y parámetros Uvicorn existentes.
También se validaron `compose.yaml` y su alias `docker-compose.yml` con
`docker compose --env-file <archivo-de-valores-ficticios> -f <manifiesto> config --quiet`,
sin iniciar servicios ni consumir credenciales reales. Ambos dieron salida 0.

## Evidencia real y simulada

Las pruebas nuevas invocan el proceso real `app.detector_worker` y su contrato,
no un sustituto estadístico. El original sintético 256x256 produjo X²=65536 por
canal, df=128 y SIN_INDICIOS. Tras la inserción LSB reproducible, X² disminuyó y
p aumentó; la clasificación fue sospechoso. Se comparan indicadores calculados,
sin alterar valores para hacer pasar las pruebas ni estimar precisión general.

Con motores reales y verificaciones completas se comprobó:

- PNG original: sin_indicios; sólo advertencia y objeto privado, sin descarga.
- PNG LSB: sospechoso; cuarentena y métricas conservadas.
- JPEG: no_concluyente; ClamAV/YARA y ExifTool ejecutados, sin fingir detector LSB.
- BMP: no_concluyente; pipeline Diana no aplicable y tamaño real, sin afirmar
  verificaciones que no se realizaron.
- Firmas ClamAV ausentes: no_concluyente, informe UNAVAILABLE, sin aprobación.
- Marcador YARA inerte dentro de PNG válido: sospechoso, una regla coincidente.
- JPEG con GPS sintético: informe EXTRACTED de campos permitidos, sin GPS ni
  hora exacta en el contrato final.
- SHA-256, bytes privados, métricas e informes persistidos y recuperables tras
  recrear la aplicación. Una modificación durante el detector impone error.

Las pruebas de solicitudes autorizadas generan JWT RS256 reales y usan un
decisor explícito de prueba para reproducir permiso vigente/scope/propietario.
Comprueban denegación ante token inválido, permiso retirado, AUTH denegado y
consulta ajena; ADMIN autorizado con scope all conserva su acceso existente.
Existe además una prueba con AuthClient real y CA de prueba válida hacia una
dirección HTTPS local realmente inaccesible: devuelve 503 y no invoca detector
ni guarda imágenes. La prueba ASGI existente confirma que no se lee el cuerpo
antes de la decisión.

Los dobles históricos de Paul, antimalware y errores de herramientas siguen
identificados como tales. No se presentan como resultados de motores reales.
Las 150 incluyen los casos reales de ClamAV/EICAR, YARA, ExifTool y límites.

## Fallo observado y límites prácticos

La primera ejecución activa produjo 40 aprobadas y una fallida: una verificación
obligatoria no completó su análisis, por lo que el original permaneció
no_concluyente. Se estaban ejecutando otras pruebas antimalware y construcción
simultáneamente; no quedó demostrada la causa exacta y no se atribuye a ellas.
Un diagnóstico aislado posterior mostró ClamAV/YARA CLEAR y ExifTool ABSENT.
La repetición activa aislada y la batería completa en Docker pasaron. En la
validación Backend V1 posterior hubo tres fallos previos adicionales de ClamAV,
conservados en las evidencias. Se amplió su presupuesto a 75 s totales/45 s CPU;
no se modificaron memoria ni algoritmos/umbrales LSB.

El worker externo y el contenedor sí requirieron ajustar los límites previos
incompatibles: 384 MiB no permitían el proceso ClamAV acotado a 2 GiB. Ahora
se mantienen límites finitos de 3 GiB y una imagen a la vez, con 120 s de timeout
externo y las cotas propias de cada herramienta. Un límite/fallo sigue bloqueando.

Se corrigió una incompatibilidad en `scripts/integration.py`: exigía HTTP 503
por detector ausente y sólo esperaba 15 segundos. Ahora exige métricas reales
y no_concluyente/cuarentena para su imagen 16x16, con hasta 150 s de espera sólo
en la solicitud de análisis. No se cambian sus operaciones AUTH/RBAC.

La integración inicial no levantó toda la pila AUTH/PostgreSQL. La validación
Backend V1 posterior sí comprobó roles persistidos, revocación real con el mismo
JWT y fallo seguro ante AUTH detenido. Quedan la revisión académica de los
entregables del equipo, sustentación y mantenimiento de motores/firmas/reglas.
No se afirma seguridad total ni cumplimiento integral de la consigna.
YARA sigue limitado a dos reglas de prueba; existen falsos positivos/negativos
LSB y no hay detector estadístico JPEG/BMP. La ausencia de coincidencias no
certifica ausencia de amenazas. No se realizan commits, push ni PR.
