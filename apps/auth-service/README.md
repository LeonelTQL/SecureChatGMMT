# Autenticación — Leonel Tipan

Implementación de la primera entrega: NestJS, TypeScript, PostgreSQL, Prisma 6, Argon2id y JWT. Ubicación conservada en `apps/auth-service`; nombre lógico `ms-users-auth`.

Referencia local: `ms-users-nestjs-main/src/auth/auth.service.ts` para login y hash ficticio que reduce diferencias temporales; DTO de usuarios para normalización del correo y límites de contraseña. Se adapta persistencia a Prisma según la asignación. RBAC corresponde al integrante 2 y no se implementa aquí.

## Ejecutar con el proyecto

Desde la raíz `SecureChatGMMT`, copia `.env.example` a `.env` si todavía no existe. Configura `POSTGRES_PASSWORD` y `JWT_SECRET`. Genera este último con `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. No publiques `.env`. Para evitar errores en la URL de conexión, usa una contraseña de PostgreSQL alfanumérica larga o codifica los caracteres especiales.

```powershell
docker compose config --quiet
docker compose up -d --build
```

El contenedor de autenticación aplica la migración antes de arrancar. PostgreSQL conserva datos en el volumen existente. No uses `down -v` si quieres conservarlos.

## Postman

Importa `postman/Leonel-auth.postman_collection.json` desde la raíz del proyecto. Por defecto apunta a `http://localhost:8080/api`. El login guarda automáticamente `access_token` en la colección.

| Método | Ruta mediante Caddy | Resultado |
|---|---|---|
| POST | `/api/auth/register` | 201, id/correo/fecha, sin contraseña |
| POST | `/api/auth/login` | 200, access_token/token_type/expires_in |
| POST | `/api/auth/verify` | 200, sub/email/exp |
| GET | `/api/auth/health` | 200 |

Registro y login reciben `{"email":"leonel@example.com","password":"ClaveDePrueba123!"}`. Contraseña de 12–128 caracteres y correo válido; se rechazan campos adicionales. Registro repetido: 409. Credenciales incorrectas: 401 con mensaje genérico. Validación: 400. Verify requiere `Authorization: Bearer <token>`; rechaza tokens inválidos o expirados con 401.

Rutas directas del servicio: `/auth/register`, `/auth/login`, `/auth/verify` y `/health`. JWT HS256 dura 900 segundos, issuer `ms-users-auth`, audience `chat-seguro`, claims `sub` y `email`. Para integración, el módulo exporta `AuthService.verify`; la clave compartida debe mantenerse privada. No se incluyen roles ni revocación: el token sigue válido hasta expirar.

## Pruebas y compilación

```powershell
cd apps/auth-service
npm.cmd ci
npm.cmd run generate
npm.cmd test
```

Las pruebas usan persistencia simulada y Argon2/JWT reales: registro, duplicados, login, errores, firma, expiración, emisor, audiencia y DTO. No requieren PostgreSQL. La comprobación completa de migración y persistencia requiere ejecutar Docker Compose y las solicitudes de Postman.

También se prueba el flujo HTTP con NestJS y Supertest. Validación local: compilación y pruebas aprobadas; Compose valida correctamente. El arranque con PostgreSQL quedó pendiente porque Docker Desktop devolvió un error interno 500. La revisión de dependencias actualizó NestJS a 12; quedan alertas en dependencias de herramientas de Prisma 6 (`deepmerge-ts` y `effect`), que requieren revisión antes de desplegar.

Documentación técnica utilizada: [Prisma 6 Migrate](https://www.prisma.io/docs/orm/v6/prisma-migrate/getting-started) y [node-argon2](https://www.npmjs.com/package/argon2).
