# Pendiente de integrar por Alejandro

Se retiraron `src/roles`, `src/user-roles`, `src/authorization`, `src/admin`, el enum de roles y los decoradores/guards JWT-RBAC de su componente.

Se conservan Prisma y las migraciones compartidas porque son el contrato del modelo del PDF y contienen datos existentes. El guard de autenticación de Leonel valida firma, sesión y usuario, pero no consulta roles. El seed ya no crea roles ni asignaciones.

Para integrar su entrega:

1. Incorporar sus módulos, DTOs, entidades, servicios y controladores usando el esquema persistido existente.
2. Registrar los módulos y el guard de roles después del guard de autenticación en `app.module.ts`.
3. Reemplazar `AuthorizationPendingGuard` de `UsersController` por la exigencia de ADMIN; nunca eliminar el bloqueo sin reemplazarlo por autorización.
4. Obtener roles/asignaciones activos desde la base y exponer el endpoint interno de decisión con identidad de servicio y TLS.
5. Reponer el bootstrap de roles/asignaciones, sus pruebas y contratos OpenAPI/Postman.
6. Ejecutar T04–T08 y T11 del PDF con JWT vigente y revocación real.

Hasta entonces las rutas de roles/asignaciones/administración e internas no existen, las rutas administrativas de usuarios devuelven 503 con sesión válida y STEGO rechaza procesar por falta de una decisión verificable. El detector de Diana continúa pendiente por separado.
