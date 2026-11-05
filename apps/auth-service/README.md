# AUTH — Leonel y Alejandro

**Estado actual:** solo está disponible la autenticación de Leonel. Los módulos y guards RBAC de Alejandro fueron retirados para que los incorpore posteriormente. `users` conserva su código y estructura, pero sus rutas administrativas están bloqueadas con 503 por un guard temporal. Registro público, login, perfil, verificación de JWT y logout continúan disponibles. Los apartados que describen roles/autorización corresponden al diseño de integración pendiente. El seed prepara una cuenta sin crear ni asignar roles.

Aplicación independiente NestJS. Prisma administra PostgreSQL y aplica migraciones antes de arrancar. Consulta el README raíz para Docker, certificados y bootstrap.

## Estructura por módulos

Se sigue la organización de `ms-users` y `ms-users-nestjs-main`, conservando el modelo y las APIs del PDF:

```text
src/
  app.module.ts
  app.controller.ts
  main.ts
  users/          # users.module.ts, users.service.ts, users.controller.ts, dto/, entities/
  roles/          # roles.module.ts, roles.service.ts, roles.controller.ts, dto/, entities/
  user-roles/     # user-roles.module.ts, user-roles.service.ts, user-roles.controller.ts, dto/, entities/
  auth/           # auth.module.ts, auth.service.ts, auth.controller.ts
    dto/
    decorators/
    guards/
    interfaces/
    enums/
  authorization/  # integración interna con STEGO: módulo, servicio, controlador y DTO
  admin/
  database/       # PrismaService, DatabaseModule y seed
  config/         # configuración JWT y contrato OpenAPI
  common/         # auditoría, validaciones, hashing, filtros y límite de intentos
```

Los controladores reciben peticiones y delegan en servicios. Los servicios contienen las operaciones de persistencia y reglas de negocio. Cada módulo exporta solamente los proveedores necesarios; la aplicación registra los guards globales en orden: límite de intentos, autenticación y roles.

Las carpetas `entities/` exponen los tipos de entidad generados por Prisma y, en usuarios, su selección pública sin contraseña. El mapeo físico sigue centralizado en `prisma/schema.prisma`, evitando definir un segundo modelo TypeORM incompatible. Se conserva el ID propio de `user_roles`, su restricción N:M única y la descripción de `roles` exigidos por el PDF; la referencia se usa para la estructura, no para reemplazar esos requisitos.

Desarrollo local: `npm.cmd ci`, `npm.cmd run generate`, `npm.cmd run build`; copia `.env.example` a `.env`, configura rutas y credenciales reales y ejecuta `npm.cmd run migrate` y `npm.cmd start`. PostgreSQL debe estar disponible en la URL indicada; el Compose no expone su puerto públicamente. Puedes publicar un puerto únicamente local en un override de desarrollo.

Endpoints y esquemas: `/docs` y `/docs-json`; contrato versionado `docs/auth.openapi.json`. Cada ruta protegida valida JWT RS256 y sesión persistida; los roles se leen de relaciones actuales. El endpoint interno requiere `X-Service-Token` por TLS. Las respuestas de error no incluyen SQL ni secretos.

`users`, `roles`, `user_roles` y `sessions` pertenecen solo a AUTH. La migración preserva usuarios anteriores y asigna usernames `user_<UUID_sin_guiones>` a las cuentas preexistentes; no les asigna privilegios.

Logout revoca una sesión; deshabilitar usuarios revoca todas las sesiones existentes. Retirar asignación o desactivar rol afecta a la próxima solicitud protegida. La política ADMIN/ANALYST/USER es explícita; no existen usuarios o asignaciones codificados.

El seed explícito `node dist/database/seed.js` lee `BOOTSTRAP_CONFIG_PATH` o `/run/keys/bootstrap.json`. No puede convertir una cuenta ya existente sin ADMIN en administrador.

Pruebas: `npm.cmd test`. Las pruebas unitarias/HTTP simulan persistencia; `scripts/integration.py` comprueba PostgreSQL y ambos servicios reales.

Referencias locales utilizadas: autenticación y DTOs de `ms-users-nestjs-main`; persistencia adaptada a Prisma y requisitos del PDF. Referencias oficiales: [Prisma 6 Migrate](https://www.prisma.io/docs/orm/v6/prisma-migrate/getting-started), [NestJS Guards](https://docs.nestjs.com/guards), [node-argon2](https://www.npmjs.com/package/argon2).
