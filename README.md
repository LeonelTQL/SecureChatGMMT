# Chat Seguro 

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

