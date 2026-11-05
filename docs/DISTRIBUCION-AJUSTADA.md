# Distribución ajustada al PDF y estado de integración

Actualizado el 5 de noviembre de 2026. Se conserva la distribución del equipo y
se incorpora el trabajo de Diana ya integrado y verificado. La consigna oficial
del Primer Parcial prevalece sobre los resúmenes generales del proyecto.

Revisión para el PR: contrastado con `Proyecto_Integrador_Primer_Parcial.pdf`
(§2.1–2.5, rúbrica 5–6 y T09–T12) e
`INFORME DE DISTRIBUCIÓN DE ACTIVIDADES.docx` del equipo. Se conserva la
asignación original; los cuatro estados oficiales sustituyen las tres etiquetas
anteriores del informe del equipo. Las tecnologías auxiliares no sustituyen
la técnica esteganográfica verificable exigida por la consigna.

## Leonel Tipan

Autenticación y gestión de usuarios: Argon2id, JWT RS256 con claims verificables, sesiones persistidas/revocables, perfil, logout, usuarios con username/email únicos, estado y auditoría. Administración de usuarios protegida por el guard de Alejandro. Validación de credenciales y límite de intentos. Migraciones y pruebas de autenticación.

## Alejandro Montufar

Persistencia de roles ADMIN/ANALYST/USER y asignaciones N:M con FK y unicidad; APIs administrativas de roles/asignaciones, guards y política de mínimo privilegio. Consulta de roles vigentes en cada solicitud y endpoint interno autenticado para STEGO. Pruebas de revocación con JWT aún válido y de acceso administrativo.

## Diana Guerra

Motor de validación y análisis de imágenes, integrado mediante
`services/stego/app/detector.py` con el contrato `analyze(path: Path) -> dict`.
Reutiliza los módulos de `services/file-analyzer` sin desplegar su API histórica.

Valida extensión, firma, MIME por contenido, estructura y decodificación de
JPG/PNG, con máximo de 5 MiB y límites de dimensiones/píxeles. Implementa el
análisis estadístico LSB por pares de valores y Chi-cuadrado sobre canales RGB,
con indicadores reales, parámetros, muestras reproducibles y limitaciones.
Conserva las cuatro clasificaciones oficiales: `sin_indicios`, `sospechoso`,
`no_concluyente` y `error`. Un indicio estadístico no prueba esteganografía.

Integra ClamAV y YARA para verificaciones antimalware y ExifTool para extraer y
evaluar campos permitidos de metadatos, sin exponer GPS ni información sensible.
Los procesos tienen límites de tiempo, memoria y salida; los fallos o motores
no disponibles mantienen el bloqueo. JPEG/BMP sin detector esteganográfico
aplicable permanecen no concluyentes. La cobertura YARA depende de sus reglas.

Aporta pruebas del motor y de su integración, evidencia T09, informes técnicos
estructurados y ajustes de dependencias/recursos en STEGO. El motor se ejecuta
después de la autorización existente; no reemplaza JWT/RBAC, el almacenamiento
ni la política de cuarentena de Paul.

## Paul Moreno

API independiente FastAPI de recepción multipart y consulta de resultados,
actualmente con recepción PNG/JPG/JPEG y BMP. Verificación criptográfica local,
consulta HTTPS autenticada a AUTH antes de consumir archivos y fallo seguro.
SHA-256, SQLite, cuarentena, nombres UUID, propiedad de recursos, límites,
retención y auditoría. Adaptador del detector con contrato estricto y ejecución
acotada. La integración del motor de Diana conserva estos mecanismos y verifica
integridad antes y después del análisis; no habilita descarga ni aprobación manual.

## Compartido

Dos aplicaciones backend, AUTH y STEGO, con Compose y configuración por
aplicación. PostgreSQL y Caddy son infraestructura, no microservicios backend
adicionales. CA y claves separadas, OpenAPI, Postman, diagramas de arquitectura
y ER, matriz de permisos/riesgos, pruebas reproducibles y sustentación T01–T12.
La revisión e integración conjunta conserva la autoría y responsabilidades de
cada componente; las pruebas con dobles se distinguen de las realizadas contra
AUTH, PostgreSQL y motores reales.

## Estado comprobado

El detector dejó de ser una dependencia pendiente: ya está integrado en el
STEGO activo, conservando JWT RS256, RBAC vigente y autorización por recurso.
Se comprobaron login, análisis ADMIN/ANALYST, rechazo USER/sin JWT, revocación
con el mismo token todavía válido, fallo seguro con AUTH detenido, propiedad
de resultados, motores reales, persistencia, SHA-256 y límite de imágenes.

La validación final contabiliza **332 pruebas/comprobaciones aprobadas y 0
fallidas**, más 14 subcasos históricos. Hubo tres fallos previos de ClamAV,
conservados en las evidencias; se corrigió su presupuesto de ejecución sin
modificar memoria, algoritmos ni umbrales LSB. Véanse la
[validación real del Backend V1](VALIDACION_BACKEND_V1.md) y el
[resumen de resultados](evidence/backend-v1-summary.json).

## Pendientes y límites

Completar la revisión académica y la sustentación de los entregables del equipo.
Antes de producción, revisar la actualización recomendada del motor ClamAV,
mantener firmas/dependencias y definir la operación y retención de auditoría.
Se mantienen las limitaciones LSB, la cobertura reducida de las reglas YARA y
la falta de detector esteganográfico JPEG/BMP; no se presentan como resultados
limpios ficticios ni como garantía de seguridad. El estado permite abrir el PR
de Diana para revisión, sin afirmar seguridad total o cumplimiento normativo integral.
