# Distribución ajustada al PDF — fuera del alcance de Diana

## Leonel Tipan

Autenticación y gestión de usuarios: Argon2id, JWT RS256 con claims verificables, sesiones persistidas/revocables, perfil, logout, usuarios con username/email únicos, estado y auditoría. Administración de usuarios protegida por el guard de Alejandro. Validación de credenciales y límite de intentos. Migraciones y pruebas de autenticación.

## Alejandro Montufar

Persistencia de roles ADMIN/ANALYST/USER y asignaciones N:M con FK y unicidad; APIs administrativas de roles/asignaciones, guards y política de mínimo privilegio. Consulta de roles vigentes en cada solicitud y endpoint interno autenticado para STEGO. Pruebas de revocación con JWT aún válido y de acceso administrativo.

## Paul Moreno

API independiente FastAPI de recepción PNG/BMP mediante multipart y consulta de resultados. Verificación criptográfica local, consulta HTTPS autenticada a AUTH antes de consumir archivos y fallo seguro. SHA-256, SQLite, cuarentena, nombres UUID, propiedad de recursos, límites, retención y auditoría. Adaptador del detector con contrato estricto y ejecución acotada.

## Compartido

Dos procesos backend y Compose; configuración por aplicación; CA y claves separadas; OpenAPI, Postman, diagramas de arquitectura y ER, matriz de permisos/riesgos y pruebas reproducibles. Demostración T01–T08/T10–T12 y trazabilidad de resultados reales.

## Dependencia pendiente

Diana implementa el detector, técnica, parámetros, indicadores reales, muestras y evidencia T09. No se declara cumplida la parte de detección. Se integrará como `services/stego/app/detector.py`, dentro del mismo servicio STEGO, sin desplegar un tercer microservicio.
