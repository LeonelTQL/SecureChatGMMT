# Evidencia de integración en STEGO activo

Rama `feature/stego-diana`. Compose utiliza `services/stego`; no se activa el
servicio histórico file-analyzer. AUTH/security.py y ambos almacenamientos se
conservan. Los módulos históricos de análisis y sus umbrales no se modifican.

## Resultados finales

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
La repetición activa aislada y la batería completa en Docker pasaron. No se
relajaron los límites de los motores ni se cambiaron algoritmos/umbrales LSB.

El worker externo y el contenedor sí requirieron ajustar los límites previos
incompatibles: 384 MiB no permitían el proceso ClamAV acotado a 2 GiB. Ahora
se mantienen límites finitos de 3 GiB y una imagen a la vez, con 90 s de timeout
externo y las cotas propias de cada herramienta. Un límite/fallo sigue bloqueando.

Se corrigió una incompatibilidad en `scripts/integration.py`: exigía HTTP 503
por detector ausente y sólo esperaba 15 segundos. Ahora exige métricas reales
y no_concluyente/cuarentena para su imagen 16x16, con hasta 100 s de espera sólo
en la solicitud de análisis. No se cambian sus operaciones AUTH/RBAC.

No se levantó toda la pila AUTH/PostgreSQL ni se validó una revocación contra
roles persistidos en esa pila durante esta tarea. Tampoco se afirma seguridad
total o cumplimiento integral de la consigna: hace falta esa demostración
end-to-end, revisar el resto de entregables del equipo y mantener firmas/reglas.
YARA sigue limitado a dos reglas de prueba; existen falsos positivos/negativos
LSB y no hay detector estadístico JPEG/BMP. La ausencia de coincidencias no
certifica ausencia de amenazas. No se realizan commits, push ni PR.
