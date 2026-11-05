# Walkthrough de pruebas — Backend V1 actual

Guía para el proyecto local propio. Los resultados indicados corresponden al código actual, no a una promesa de ausencia de vulnerabilidades. No modifiques cuentas/roles de otras personas: usa cuentas de prueba nuevas y conserva un ADMIN activo para restaurar el entorno.

**Límite actual:** autenticación, RBAC, autorización vigente, validación y almacenamiento están implementados. Falta el detector real de Diana. Una imagen válida autorizada devuelve **503 con analysis_id, status=error y action=cuarentena**. No confundas ese 503 con falta de permiso, AUTH caído o éxito del detector. No se implementan chat, salas, mensajería, descarga de imágenes ni detección antimalware/esteganográfica real en el STEGO activo.

## 1. Preparar el entorno

Ejecutar desde `SecureChatGMMT` con Docker Desktop iniciado:

```powershell
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d --build --wait
docker compose -f compose.yaml exec -T auth-service node dist/database/seed.js
docker compose -f compose.yaml ps
services/stego/.venv/Scripts/python.exe scripts/generate-test-fixtures.py

##para caso de linux reemplazar el ultimo comando con este
services/stego/.venv/bin/python scripts/generate-test-fixtures.py
```

Si es una copia nueva sin secretos: crea primero el entorno virtual, instala `services/stego/requirements.lock.txt` y ejecuta `scripts/setup-local.py`, como indica el README. No repitas setup si `secrets/` ya existe ni elimines volúmenes para corregir credenciales.

AUTH: `https://localhost:3001`; STEGO: `https://localhost:8000`; proxy local: `http://localhost:8080`. Swagger: `/docs` en cada API directa. Salud: `/health`. Las rutas de negocio ya incluyen `/api`; no dupliques ese prefijo.

En Postman, importa `secrets/public/ca.pem` como CA de confianza para las APIs HTTPS, manteniendo la verificación TLS. El administrador inicial está en `secrets/auth/bootstrap.json`. Lee las credenciales localmente; no las pegues en capturas ni exportaciones públicas.

Usa variables locales: `auth_url=https://localhost:3001`, `stego_url=https://localhost:8000`, `token_admin`, `token_a`, `token_b`, `id_a`, `id_b`, `rol_user`, `rol_analyst`, `asignacion_analyst_a`, `analysis_id`. En cada petición protegida selecciona Authorization → Bearer Token y la variable correspondiente. Solo registro/login/health son públicos en este flujo.

## 2. Crear las identidades de prueba

1. `POST {{auth_url}}/api/auth/login`, Body → raw → JSON, usando email/password del bootstrap. Esperado 200 y `access_token`. Guardarlo como `token_admin`. Duración: 900 segundos. Si expira durante el recorrido, volver a iniciar sesión.
2. `GET {{auth_url}}/api/roles` con ADMIN. Esperado 200 y arreglo con ADMIN, ANALYST y USER. Guardar UUID de USER y ANALYST.
3. Crear A con `POST {{auth_url}}/api/auth/register` y este cuerpo; cambiar los nombres si ya existen:

```json
{"username":"walk_a_01","email":"walk_a_01@example.com","password":"PruebaLocal2026!"}
```

4. Repetir para B cambiando ambos valores a `walk_b_01`. Esperado 201 en ambos. Guardar `id_a`/`id_b`. Registro público no asigna privilegios y nunca devuelve password/passwordHash.
5. Login de A y B con email/password; guardar `token_a`/`token_b`. No enviar username en login: usa email. Obtener estos JWT **antes** de asignar roles permite comprobar cambios de permisos sin renovar el token.
6. ADMIN: `POST /api/user-roles` con `{"user_id":"{{id_a}}","role_id":"{{rol_user}}"}`. Esperado 201. Repetir para B.
7. ADMIN: misma ruta, asignar ANALYST a A. Guardar el **id de la asignación** en `asignacion_analyst_a`; no confundirlo con id del rol.
8. `GET /api/auth/profile` como A: 200, roles USER y ANALYST. B tiene USER. Esto demuestra N:M: un usuario con dos roles y un rol compartido por dos usuarios.

## 3. Recorrido funcional completo

| Paso | Petición | Identidad | Esperado |
|---|---|---|---|
| F01 | GET AUTH `/health` y STEGO `/health` | Sin token | 200 |
| F02 | GET AUTH `/api/auth/profile` | A | 200, identidad A y roles actuales |
| F03 | POST AUTH `/api/auth/verify` | A | 200, sub/jti/exp y roles actuales |
| F04 | GET AUTH `/api/users` | ADMIN | 200, máximo 100 registros, sin hashes |
| F05 | POST AUTH `/api/users` con nuevo username/email/password | ADMIN | 201, crea usuario sin roles |
| F06 | PATCH AUTH `/api/users/{{id_b}}` con `{"username":"walk_b_modificado"}` | ADMIN | 200, mismo ID y auditoría actualizada |
| F07 | GET AUTH `/api/user-roles` | ADMIN | 200, asignaciones persistidas |
| F08 | GET AUTH `/api/admin/protected` | ADMIN | 200 |
| F09 | GET AUTH `/api/admin/protected` | A/B | 403 |
| F10 | POST STEGO `/api/steganography/analyze` con valida.png | A | 503 con registro error/cuarentena por detector ausente |
| F11 | GET STEGO `/api/steganography/results/{{analysis_id}}` | A | 200, resultado propio |
| F12 | Misma consulta | ADMIN | 200 |
| F13 | Misma consulta | B solo USER | 403 por privilegio insuficiente |
| F14 | Asignar ANALYST a B, repetir consulta con el mismo token B | B | 403 por propiedad ajena, aunque ahora sí es ANALYST |

Para F10: Body → form-data, clave `file`, tipo **File**, seleccionar `.local/test-fixtures/valida.png`. Postman genera el Content-Type multipart y el boundary: no los escribas manualmente. El tipo de la parte debe ser `image/png` (BMP: `image/bmp`). Guarda el `analysis_id` de la respuesta aunque sea 503.

Comprueba el hash con `Get-FileHash .local/test-fixtures/valida.png -Algorithm SHA256`: debe coincidir ignorando mayúsculas/minúsculas con `sha256` del registro. La identidad propietaria debe ser `id_a`, no un campo enviado por el cliente.

## 4. Registro, login y validaciones negativas

Cambiar solo un dato por petición para identificar el control que responde. Un 429 significa que se agotó el límite y no permite evaluar otra validación hasta que pase la ventana.

| ID | Caso | Resultado actual esperado |
|---|---|---|
| V01 | Repetir username o email registrado | 409 |
| V02 | Repetir email con mayúsculas/espacios externos | 409; normalización |
| V03 | Email inválido, ausente, null, número, objeto o arreglo | 400 |
| V04 | Email mayor de 254 caracteres | 400 |
| V05 | Username de 2 o 51 caracteres | 400 |
| V06 | Username de 3 o 50 caracteres válido y único | Registro aceptado |
| V07 | Username con espacios internos, `<`, `/` o comillas | 400 |
| V08 | Password de 11 o 129 caracteres | 400 |
| V09 | Password de 12 o 128 caracteres, con algún carácter no blanco | Aceptada por política actual |
| V10 | Password de 12 espacios o no textual | 400 |
| V11 | Campos extra role, roles, isAdmin, passwordHash o id | 400 |
| V12 | JSON malformado | 400 |
| V13 | Email válido inexistente y contraseña válida por longitud | 401 genérico |
| V14 | Usuario existente y password incorrecta de longitud válida | 401 con el mismo mensaje que V13 |
| V15 | Password incorrecta de 3 caracteres | 400 por DTO, no 401 |
| V16 | Password con cambio de mayúscula o espacio agregado | 401 si pasa validación |
| V17 | Login con email en mayúsculas/espacios externos | 200 si las credenciales son correctas |
| V18 | Password que contiene texto SQL pero cumple longitud | Se trata como texto; nunca autentica por inyección |
| V19 | Email `admin@example.com' OR '1'='1` | 400; nunca accede |
| V20 | Campos de PATCH opcionales con null/tipo incorrecto | 400 |
| V21 | PATCH usuario a email/username de otro usuario | 409 |
| V22 | GET users con `?offset=100` | Página desde ese desplazamiento; hasta 100 filas |

La política actual no impide todas las contraseñas comunes ni verifica correo/MFA. Un 201 no significa que esos controles existan.

## 5. Roles y asignaciones

Usar ADMIN para distinguir errores de datos de errores de permisos.

| ID | Petición/cambio | Esperado |
|---|---|---|
| R01 | POST `/api/roles` con nombre ADMIN/USER/ANALYST ya creado | 409 |
| R02 | Crear rol SUPERADMIN | 400; la política actual admite solo los tres roles |
| R03 | Crear rol sin description o con description de más de 250 caracteres | 400 |
| R04 | PATCH `/api/roles/{rol_analyst}` con description válida | 200 |
| R05 | PATCH descripción vacía o status no booleano/null | 400 |
| R06 | Repetir asignación A–ANALYST | 409 |
| R07 | user_id/role_id sin formato UUID | 400 |
| R08 | UUID bien formado de usuario/rol inexistente al asignar | 400 por FK |
| R09 | PATCH usuario/rol con UUID inexistente | 404 |
| R10 | DELETE asignación inexistente | 404 |
| R11 | POST/GET/PATCH usuarios, roles o asignaciones como USER/ANALYST | 403 |
| R12 | Esas rutas sin JWT | 401 |
| R13 | USER manda `X-Role: ADMIN` o `X-Roles: ADMIN` | Sigue 403 |

Prueba de revocación obligatoria: copia el JWT A, elimina con ADMIN `DELETE /api/user-roles/{{asignacion_analyst_a}}` (204), y vuelve a cargar usando **ese mismo JWT**. Debe dar 403. También se bloquea la consulta de resultados que exigía ANALYST. Reasignar ANALYST da acceso en la siguiente petición sin renovar el JWT; actualiza el ID de asignación porque será otro.

Prueba de rol inactivo: desactiva solo ANALYST con `PATCH /api/roles/{id}` y `{"status":false}`. A/B pierden el permiso de análisis en nuevas solicitudes aunque sigan asignados. Restaura `{"status":true}`. No desactives ADMIN ni retires su única asignación durante esta guía.

## 6. JWT, logout y usuario deshabilitado

| ID | Cambio | Esperado |
|---|---|---|
| J01 | Sin Authorization, Basic, Bearer vacío o texto inválido | 401 |
| J02 | Modificar payload o firma del JWT | 401 |
| J03 | Agregar caracteres sobrantes no canónicos a la firma | AUTH 401 |
| J04 | Esperar expiración real de 15 minutos | 401 en nueva petición |
| J05 | Cambiar algoritmo a none o HS256 | 401 |
| J06 | Poner token solo en query o cuerpo | 401; se exige Authorization |
| J07 | Leer payload de un token localmente | Sin password/hash ni roles incrustados |
| J08 | POST `/api/auth/logout` con JWT A | 204 |
| J09 | Reutilizar ese JWT en perfil/verify/STEGO | 401; volver a login para continuar |
| J10 | Desactivar B con ADMIN: PATCH users/{id_b}, status false | 200 |
| J11 | Login de B desactivado / usar su JWT anterior | 401 |
| J12 | Reactivar B y reutilizar el JWT revocado anterior | Sigue 401; requiere nuevo login |
| J13 | Cambiar JWT A por el de B al consultar el resultado de A | 403 si B es ANALYST; no accede a datos de A |

No interpretes modificar `exp` a mano como prueba aislada de caducidad: también rompe la firma. Emisor/audiencia incorrectos, claims ausentes y firma con otra clave se prueban de forma aislada en `npm.cmd --prefix apps/auth-service test`, con claves de prueba. No es necesario exponer la clave privada real para hacer esas pruebas.

## 7. Archivos: formatos y límites

Para evaluar el archivo usa siempre token ADMIN o ANALYST **vigente**. Un 401/403 anterior al análisis no demuestra que el archivo se validó.

| ID | Archivo/cambio | Esperado actual |
|---|---|---|
| A01 | valida.png + image/png | 503 y registro error/cuarentena por detector ausente |
| A02 | valida.bmp + image/bmp | Igual que A01 |
| A03 | no_admitida.jpg | 415: el STEGO actual admite PNG/BMP |
| A04 | marcador.txt con extensión .txt | 415 |
| A05 | texto_disfrazado.png + image/png | 415 por contenido inválido |
| A06 | solo_firma.png | 415; una firma PNG inicial no basta |
| A07 | corrupta.png o vacia.png | 415 |
| A08 | bmp_disfrazado.png + image/png | 415 por discordancia real |
| A09 | PNG real con Content-Type de parte text/plain | 415 |
| A10 | PNG real con nombre imagen.exe | 415 |
| A11 | Nombre imagen.png.php | 415 |
| A12 | Texto con nombre imagen.php.png | 415 por contenido, no por el sufijo final |
| A13 | PNG real con extensión .PNG y MIME image/png | Misma ruta válida de A01 |
| A14 | excede_5MiB.png (5 MiB + 1 byte) | 413 |
| A15 | exactamente_5MiB.png | Supera validación de tamaño/formato; 503 por detector ausente |
| A16 | excede_pixeles.png (20.005.000 píxeles) | 413 |
| A17 | png_con_marcador_extra.png | Puede pasar el decodificador; 503/cuarentena; no demuestra ausencia de datos ocultos |
| A18 | Sin campo file con JWT autorizado | 422 |
| A19 | Campo other en lugar de file | 422 |
| A20 | Nombre ../../imagen.png con bytes PNG reales | Nombre reducido a imagen.png; UUID privado, nunca escribe en ruta del cliente |
| A21 | Cuerpo excesivo con/sin Content-Length | 413; automatizado en pytest |
| A22 | Sin JWT con una carga inválida pequeña | 401 antes de validar imagen |
| A23 | USER con carga inválida pequeña | 403 antes de validar imagen |
| A24 | Añadir user_id ajeno como campo multipart | Puede ignorar ese campo; propietario siempre el sujeto autenticado |

Las muestras se generan en `.local/test-fixtures/`, fuera de Git; `manifest.json` registra tamaño y hash. Son inofensivas, sin comandos ni conexiones. `png_con_marcador_extra.png` demuestra una limitación importante: imagen decodificable no equivale a contenido completamente confiable. Sin detector no se puede afirmar que se detecta esteganografía, malware o un archivo políglota.

Pruebas exploratorias adicionales: varios campos `file`, partes extra, nombres muy largos, nombres con dos extensiones, MIME con variantes y cabeceras duplicadas. Registra lo observado: no se ha implementado un rechazo explícito de todos los multipart adicionales. El mínimo exigido es no cambiar propietario/permisos, no ejecutar contenido, no escribir fuera de cuarentena y no perder los límites. No marques un caso como aprobado solo por obtener un 503; revisa cuerpo y etapa de rechazo.

## 8. Burp Suite: interceptar y sustituir una imagen

1. El proyecto usa 8080 para Caddy. Configura el listener de **Burp en 127.0.0.1:8081** para evitar colisión.
2. En Postman configura proxy HTTP personalizado a `127.0.0.1:8081`, y permite proxy para localhost si existe una lista de bypass. Para esta prueba usa la URL local `http://localhost:8080/api/steganography/analyze`. Es el proxy local de evaluación; las llamadas de Caddy a los servicios siguen usando TLS verificado.
3. En Burp activa Proxy → Intercept. Envía desde Postman la imagen válida con token ANALYST. Si no aparece, revisa listener, proxy de Postman y bypass de localhost. No necesitas desactivar la validación TLS de las APIs directas para esta prueba HTTP local.
4. Captura la solicitud, envíala a Repeater y desactiva Intercept para que no queden otras solicitudes detenidas. En Repeater verifica destino localhost:8080, HTTP, y guarda una copia sin cambios como control.
5. Envía el control: esperado 503 con registro de cuarentena por detector ausente.
6. En la copia conserva el nombre imagen.png, MIME de parte image/png, boundary y JWT; sustituye **todos los bytes del archivo** entre las cabeceras de la parte y el boundary final por `UPLOAD_PROBE_INERTE_NO_EJECUTABLE`.
7. Envía. Esperado **415**. Esto comprueba el contenido recibido aunque nombre y MIME declaren imagen. El marcador no contiene una reverse shell ni ejecuta nada.
8. Repite cambiando solo filename a imagen.txt (415), luego solo MIME a text/plain (415), después solo token a USER (403), sin token (401) y con un JWT manipulado (401).
9. Comprueba que Repeater actualiza Content-Length al modificar el cuerpo; no reutilices una longitud incorrecta. Conserva exactamente el delimitador multipart, sus guiones y la línea en blanco anterior al contenido.

Petición mínima reproducible en Repeater (sustituye TOKEN_ANALYST por uno real):

```http
POST /api/steganography/analyze HTTP/1.1
Host: localhost:8080
Authorization: Bearer TOKEN_ANALYST
Content-Type: multipart/form-data; boundary=----Segur0Boundary

------Segur0Boundary
Content-Disposition: form-data; name="file"; filename="imagen.png"
Content-Type: image/png

UPLOAD_PROBE_INERTE_NO_EJECUTABLE
------Segur0Boundary--
```

La misma sustitución se puede hacer eligiendo `texto_disfrazado.png` en Postman y fijando el MIME de su parte a image/png. La respuesta 415 prueba rechazo de ese contenido concreto; no prueba que cualquier payload imaginable sea detectado ni que exista un antivirus.

Fuentes oficiales: [interceptar tráfico](https://portswigger.net/burp/documentation/desktop/getting-started/intercepting-http-traffic), [Burp Proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy), [OWASP File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

## 9. Propiedad, almacenamiento e integridad

1. Guarda analysis_id, user_id y sha256 de una carga de A. Consulta con A: 200. Con B ANALYST: 403. Con ADMIN: 200.
2. UUID de análisis aleatorio válido, consultado por ADMIN/ANALYST: 404. UUID malformado: 404 por middleware. USER seguirá obteniendo 403 antes de buscar el recurso.
3. Intenta `/storage/quarantine/{id}`, `/quarantine/{id}` y `/api/steganography/results/{id}/content`: no deben servir el archivo. No hay endpoint de descarga en el STEGO actual.
4. Reinicia STEGO (`docker compose -f compose.yaml restart stego`) y vuelve a consultar con token vigente: el registro persiste en SQLite. No uses `down -v`.
5. Opcional: verifica dentro del contenedor el hash de `/app/storage/quarantine/{analysis_id}` con hashlib y compáralo con el original. No modifiques archivos de otros análisis.
6. Retención: `docker compose -f compose.yaml exec -T stego python -m app.purge --days 7` elimina archivos antiguos y conserva metadatos. Las pruebas automatizadas comprueban ese comportamiento sin esperar siete días.

## 10. Fallo seguro e independencia

Con un JWT recién emitido y un usuario ANALYST:

```powershell
docker compose -f compose.yaml stop auth-service
```

Envía una carga pequeña a STEGO: **503 por no poder comprobar autorización**, no un análisis exitoso. Su health propio puede seguir respondiendo 200: disponibilidad del proceso y capacidad de autorizar son cosas distintas.

```powershell
docker compose -f compose.yaml start auth-service
docker compose -f compose.yaml ps
```

Espera health correcto y repite con el mismo token aún vigente. Con el detector
integrado debe volver al flujo normal de clasificación real; una imagen pequeña
sin evidencia suficiente queda no_concluyente y en cuarentena. Un motor ausente
mantiene el bloqueo. El 503 durante la caída de AUTH no debe contener un nuevo
registro de análisis generado por esa petición. Ver la evidencia actual en
`services/stego/VALIDACION_DIANA.md`.

Detén STEGO y confirma que AUTH sigue dando health/perfil; vuelve a iniciar STEGO. Estas pruebas cambian disponibilidad temporalmente, no borran datos.

## 11. Endpoint interno y credencial de servicio

1. En AUTH directo, POST `/internal/authorization/check` sin X-Service-Token: 401, incluso con JWT de ADMIN.
2. Con X-Service-Token inventado: 401.
3. La credencial real está en el .env raíz; para una prueba local controlada configura un header privado en Postman y no lo exportes. Cuerpo: `{"subject_token":"JWT_A","action":"steganography.analyze","resource_id":null}`.
4. Con servicio válido y A ANALYST: 200, allowed=true, scope=own, subject_id=A.
5. Con A USER: 200, allowed=false. Es una decisión de AUTH; STEGO la convierte en 403.
6. subject_token inválido o revocado: 401. action no admitida o resource_id no UUID: 400. Campos extra, incluido scope/allowed enviados por el cliente: 400.
7. Por Caddy (`http://localhost:8080/internal/authorization/check`): 404; el proxy bloquea ese acceso.

## 12. Límite de login

Haz esta prueba al final. En un minuto, envía 11 peticiones de login con el mismo email y sin password: las primeras diez devuelven 400 por DTO y la siguiente 429 por límite de intentos. Usa un email de prueba diferente para no consumir la ventana del ADMIN. El contador por IP admite como máximo 30 solicitudes de registro/login por minuto; por eso podrías recibir 429 antes si ya consumiste el presupuesto compartido. Espera al menos 61 segundos para continuar.

X-Forwarded-For inventado no debe evitar el límite. El código no confía en esa cabecera; detrás de Caddy varios clientes comparten la IP del proxy. Los contadores son locales al proceso y se reinician al reiniciar AUTH; no son un bloqueo persistido de cuenta ni una solución distribuida.

## 13. Automatizar y recoger evidencias

```powershell
npm.cmd --prefix apps/auth-service test
services/stego/.venv/Scripts/python.exe -m pytest services/stego/tests -q
services/stego/.venv/Scripts/python.exe scripts/integration.py --failure-demo
python scripts/check-container-permissions.py
docker compose -f compose.yaml logs --no-color --tail 100 auth-service stego
```

La integración crea usuarios nuevos, comprueba PostgreSQL real, permisos y errores, deshabilita sus cuentas al terminar correctamente y actualiza `docs/evidence/integration.json`. `--failure-demo` detiene y restaura AUTH. Si se interrumpe una prueba, revisa sus usuarios test_* y deshabilítalos mediante ADMIN.

Un caso se aprueba por su resultado, estado persistido y ausencia de efectos indebidos. Guarda ID, petición anonimizada, respuesta, resultado esperado/observado y evidencia. Oculta Authorization, X-Service-Token y passwords en capturas. No publiques `.env`, bootstrap ni claves.

Interpretación: 200/201/204=operación prevista, 400=DTO/JSON/FK inválidos, 401=autenticación, 403=permiso/propiedad, 404=ruta/recurso inexistente, 409=duplicado, 413=tamaño/píxeles, 415=formato/MIME/contenido, 422=file ausente, 429=intentos, 503=dependencia/capacidad/detector. Un 500 inesperado o una respuesta exitosa sin permiso es un fallo que debe investigarse, no una prueba aprobada.

Pendientes que este recorrido no puede certificar: detección real de esteganografía/malware, análisis de toda imagen políglota, protección frente a toda intrusión, MFA, verificación de correo, recuperación/cambio de contraseña, rotación automática de claves y límite distribuido entre réplicas. También quedan fuera las APIs históricas de `services/file-analyzer` que no se despliegan con el Compose actual; no mezcles su contrato /files con /api/steganography.
