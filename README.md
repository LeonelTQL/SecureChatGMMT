# Chat Seguro — plantilla de infraestructura (Sprint 1)

**Plantilla ejecutable, no aplicación terminada ni plataforma segura para Internet.**

## Arranque local
1. Instala Docker Engine/Desktop y el plugin Docker Compose.
2. Copia `.env.example` a `.env` y establece `POSTGRES_PASSWORD` con una contraseña larga y aleatoria (sin caracteres especiales de URL, o codifica la contraseña para DATABASE_URL).
3. Ejecuta `docker compose config` para comprobar la configuración.
4. Ejecuta `docker compose up -d --build`.
5. Comprueba `docker compose ps` y visita http://localhost:8080.
6. Verifica http://localhost:8080/api/auth/health, /api/chat/health y /api/files/health.
7. Consulta registros con `docker compose logs -f`.
8. Para detener: `docker compose down` (sin `-v`, para conservar los datos).

**Aviso:** los directorios de datos son volúmenes privados. Solo el puerto 8080 está publicado y únicamente en 127.0.0.1. No configures redirección de puertos pública ni cambies el binding sin autenticar, endurecer y probar los servicios. El proxy usa HTTP LOCAL para no simular una configuración TLS de producción. El servicio Python es un placeholder: NO escanea archivos. No se exponen endpoints de carga/descarga ni de chat reales. Los endpoints `/health` indican únicamente que el proceso respondió, no que la base de datos ni controles de seguridad estén completamente operativos.

## Distribución
- `apps/auth-service/` — Leonel: autenticación y sesiones.
- `apps/chat-service/` y `apps/web/` — Alejandro: salas, frontend y mensajería.
- `services/file-analyzer/` — Diana: validaciones, malware, esteganografía e integridad.
- `apps/file-service/` — Paul: transferencia, cuarentena y auditoría.
- `infrastructure/`, `contracts/`, `compose.yaml` — configuración compartida con cambios revisados por PR.

## Pendiente para próximas iteraciones
- Definir contratos OpenAPI y eventos, migraciones Prisma, modelos de datos y sesiones.
- Añadir verdadero gateway Socket.IO, control de membresías, colas de archivos e integración segura.
- Añadir ClamAV/YARA/Tika y análisis por tipo en imagen de procesamiento aislada, con límites estrictos.
- Incorporar TLS real (Caddy con dominio y certificados, o túnel confiable) antes de exponer el servicio.
- Añadir secretos seguros, análisis de dependencias, backups, políticas RBAC, CORS/orígenes y pruebas de seguridad.
- Generar y conservar lockfiles (`package-lock.json`) por cada aplicación, para construir con `npm ci` en versiones posteriores.

## Nota sobre Docker
La plantilla ha sido creada y revisada estáticamente; aquí no se ejecutaron contenedores porque Docker no está disponible en el entorno de generación.
