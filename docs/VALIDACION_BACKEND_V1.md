# Validación real del Backend V1

Rama `feature/stego-diana`. El árbol Git estaba limpio al comenzar. Se construyó
y levantó Compose con AUTH, STEGO, PostgreSQL y Caddy. Las únicas aplicaciones
backend desplegadas son AUTH y STEGO; PostgreSQL y Caddy son infraestructura.
El file-analyzer histórico no se activa como otro microservicio.

## Resultado final

| Grupo | Aprobadas | Fallidas | Qué verifica |
| --- | ---: | ---: | --- |
| AUTH automatizadas | 9 | 0 | JWT, Argon2id, RBAC, sesiones y DTO; BD de prueba en memoria |
| Diana históricas en Docker | 150 | 0 | Validación, LSB, motores y flujo histórico; incluye dobles y casos reales |
| STEGO activo en Docker | 44 | 0 | Autorización, contrato, motores reales, límites, persistencia y acceso por recurso |
| Integración existente con AUTH/BD reales | 47 | 0 | Autenticación, roles N:M, revocación, caídas y archivos |
| Integración ampliada real | 73 | 0 | ADMIN/ANALYST, T09, motores, privacidad y persistencia |
| Postman contra servicios reales | 9 | 0 | Nueve solicitudes y aserciones guardadas, con CA verificada |
| Total de casos/comprobaciones contabilizadas | **332** | **0** | Los 14 subcasos históricos son adicionales |

Se mantuvo un aviso de deprecación de TestClient/HTTPX. La salida 0 de Postman
corresponde a sus aserciones, no sólo a respuestas HTTP. No se publicaron eventos
de Postman ni credenciales. La colección no tenía expectativas antiguas de análisis:
sus nueve aserciones vigentes pasaron sin cambiarlas.

Los resultados finales no ocultan tres fallos previos de ClamAV, conservados en
los archivos de evidencia indicados más abajo. Las suites se ejecutaron por
separado para evitar la colisión del nombre de paquete app y la competencia de
varios escaneos de firmas. Ninguna métrica ni clasificación esperada fue simulada
para aprobar una prueba de motor real.

## Escenarios de seguridad comprobados

| Escenario | Resultado real |
| --- | --- |
| Login y JWT | HTTP 200, firma RS256 verificada con clave pública, emisor/audiencia correctos y vida <=900 s |
| ADMIN analiza PNG original | HTTP 200, sin_indicios, advertencia y archivo privado |
| ANALYST analiza PNG LSB | HTTP 200, sospechoso, cuarentena y métricas reales |
| USER, incluso con X-Role: ADMIN | HTTP 403, sin archivo ni registro de análisis nuevo |
| Sin JWT o JWT alterado | HTTP 401, sin procesar el cuerpo ni crear análisis |
| Revocar ANALYST con JWT aún vigente | El mismo token pasa a HTTP 403 inmediatamente; la lectura propia también se deniega |
| AUTH realmente detenido | STEGO responde 503 a ADMIN y no crea archivos/registros; AUTH se restaura en finally |
| Resultado propio | ANALYST autorizado recibe 200 con métricas e informes persistidos |
| Resultado ajeno | Otro ANALYST recibe 403; ADMIN autorizado recibe 200 |
| YARA | Marcador inerte en PNG produce una regla coincidente y sospechoso/cuarentena |
| ClamAV | EICAR de 68 bytes se detecta en prueba directa del módulo; nunca se ejecuta ni se admite como imagen HTTP |
| ExifTool | JPEG con EXIF/GPS sintético: EXTRACTED de campos permitidos, sin GPS ni hora exacta expuestos; no_concluyente por falta de detector JPEG |
| Persistencia | Tras reiniciar STEGO se recuperan SHA-256, propietario, métricas, informes, estado y política idénticos |
| Integridad privada | El archivo guardado conserva su hash y permisos 0600; no existe ruta pública de descarga |
| Límite de 5 MiB | 5 MiB + 1 byte recibe 413 sin archivo ni registro nuevo |
| Imagen corrupta | HTTP 415 antes del detector, sin registro/archivo nuevo |

La prueba ASGI existente confirma cero lecturas del cuerpo antes de una decisión
vigente. En vivo se envió un cuerpo inválido bajo JWT ausente/alterado, USER y AUTH
caído: se obtuvo la denegación de seguridad correspondiente, no un error de parser.
Los contadores privados de archivos/registros no cambiaron. No se modificó JWT,
RBAC ni autorización por recurso para lograr estos resultados.

La comunicación fue HTTPS con CA/hostname verificados, sin `--insecure` ni TLS
desactivado. El endpoint interno de AUTH rechazó solicitudes sin identidad de
servicio. Los análisis autorizados completaron la llamada real STEGO→AUTH.
PostgreSQL confirmó users/roles/user_roles, dos claves foráneas y unicidad; no se
usó una lista de roles o usuarios ficticia para las pruebas reales.

## Evidencia estadística T09

Las muestras proceden del generador independiente `tools/stego_samples.py`.
Para R, el original dio X²=65536, df=128 y p=0 por subdesbordamiento de la cola;
la inserción completa dio X²=115.40380489914214 y p=0.7801335382780753.
Los tres canales, sus políticas y limitaciones quedan en los informes JSON.
Esto demuestra el contraste en ese portador sintético, no precisión general.
Un valor p no es una probabilidad de esteganografía. Se conservan los falsos
positivos y negativos ya documentados en el motor.

## Problemas observados y correcciones

1. Faltaba secrets/ por completo. Se usó el preparador existente para crear sólo
   las claves/certificados faltantes, sin rotar ni sobrescribir secretos previos.
   El .env raíz existente se conservó byte por byte. Los volúmenes chat-seguro no
   existían y se crearon; no se borró ningún volumen ni base de otros proyectos.
2. Dos ejecuciones ampliadas no completaron ClamAV: primero SIGKILL (-9) y después
   timeout. El sistema respondió no_concluyente/cuarentena, sin aprobar. La suite
   histórica reprodujo una tercera interrupción de ClamAV. No se registraron
   eventos OOM en su cgroup; un diagnóstico aislado consumió unos 14 s CPU y
   988620 KiB de RSS. No se atribuye una causa exacta no demostrada al primer SIGKILL.
3. Se centralizó un perfil finito ClamAV de 75 s totales/45 s CPU, frente a
   45 s/30 s anteriores, y el adaptador externo pasó de 90 a 120 s. El cliente de
   integración permite 150 s sólo para analizar. Permanecen 2 GiB de memoria
   ClamAV, 3 GiB de contenedor, 5 MiB por imagen, cotas de salida, una imagen por
   worker y los límites YARA/ExifTool. No se tocaron algoritmos, indicadores,
   umbrales LSB, AUTH, RBAC ni almacenamiento. Las suites y pruebas reales
   pasaron con este perfil; los cuatro análisis finales tardaron aproximadamente
   16.9, 20.4, 16.5 y 16.5 segundos.
4. La exportación de auditoría de 40 eventos sólo retenía limpieza de cuentas.
   Se amplió a 200 campos/eventos permitidos: la muestra final contiene decisiones
   reales y cuatro análisis terminados, sin tokens ni contenido privado.

Todas las cuentas creadas para los escenarios se deshabilitaron, y sus sesiones
vigentes quedaron revocadas. La cuenta bootstrap sólo se usó para administrar
las cuentas de prueba; no se cambió su perfil, contraseña ni roles. Los tokens y
contraseñas no se guardan en evidencias. Los archivos de prueba quedan privados
en el volumen para conservar trazabilidad. AUTH y STEGO quedan saludables.

## Archivos de evidencia

- `evidence/backend-v1-summary.json`: contadores finales y alcance de cada grupo.
- `evidence/backend-v1-live.json`: 73 comprobaciones y cuatro registros completos
  de análisis, con SHA-256, métricas, técnica, informes, clasificación y política.
- `evidence/integration.json`: 47 comprobaciones del script existente contra toda
  la pila, incluyendo revocación y caída/restauración de AUTH.
- `evidence/backend-v1-automated.json`: códigos de salida y contadores Docker.
- `evidence/postman-backend-v1-live.json`: nueve aserciones, CA verificada, no
  publicación y limpieza de la cuenta temporal.
- `evidence/backend-v1-postgres.json`: comprobaciones SQL de sólo lectura y
  ausencia de cuentas/sesiones de prueba activas.
- `evidence/backend-v1-infrastructure.json`: servicios, salud, versiones y
  preservación de configuración. `auth.openapi.json`/`stego.openapi.json` y
  `evidence/audit.json` reflejan el contrato y la auditoría actuales.
- `evidence/backend-v1-live-first-attempt.json`, `backend-v1-live-second-attempt.json`
  y `backend-v1-automated-initial.json`: fallos iniciales conservados.

## Reproducción sin borrar datos

Con configuración local y secretos existentes, desde la raíz:

```powershell
git status --short --branch
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml exec -T auth-service node dist/database/seed.js
python scripts/check-container-permissions.py
python scripts/integration.py --failure-demo
python scripts/validate-backend-v1.py
python scripts/export-evidence.py
```

Los scripts requieren httpx, Pillow y cryptography. Si faltan claves, usar
`scripts/setup-local.py` únicamente cuando secrets/ no exista; nunca eliminarlo
para forzar regeneración. El seed no eleva cuentas existentes sin ADMIN.
No ejecutar `down -v`, resets, truncados ni purgas de datos.

Para las suites, se instalaron los lockfiles y se usaron las imágenes construidas:
AUTH ejecutó `node --test test/auth.test.cjs` con su carpeta test montada de sólo
lectura. Las suites Python ejecutaron `python -m pytest -q -p no:cacheprovider`
en contenedores aislados, sin red ni secretos, con las carpetas tests montadas
de sólo lectura; la histórica usa su pytest.ini. Mantener `OPENBLAS_NUM_THREADS=1`.
Postman se ejecutó con `--ssl-extra-ca-certs secrets/public/ca.pem`, entorno local
efímero, `--no-report-events` y una cuenta única de prueba deshabilitada al terminar.

## Requisitos pendientes y decisión sobre el PR

Los escenarios funcionales de Backend V1 solicitados están demostrados. La
evidencia inicial que dejaba pendiente AUTH/BD queda complementada por esta
validación real. No se afirma certificación ISO ni seguridad absoluta.

Pendientes operativos: FreshClam advierte que el motor 1.4.3 tiene actualización
recomendada (1.4.6); revisar/actualizar la imagen y repetir la validación antes
de producción. Mantener firmas, revisar dependencias y retención de auditoría.
YARA sólo cubre dos reglas de prueba, LSB tiene falsos positivos/negativos y
JPEG/BMP no tienen detector esteganográfico. Esas limitaciones están declaradas;
no se sustituyen por aprobaciones ficticias. Preparar la sustentación académica
y revisar el resto de entregables del equipo siguen siendo responsabilidad conjunta.

**Listo para abrir el PR de Diana para revisión**, tras revisar y confirmar los
cambios manualmente. No equivale a listo para producción. No se hicieron commits,
push ni PR; la infraestructura y los volúmenes se dejan disponibles.
