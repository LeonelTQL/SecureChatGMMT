# Matriz de riesgos y controles

Escala cualitativa para esta entrega; el riesgo residual requiere revisión al integrar el detector y antes de desplegar.

| Activo | Amenaza / vulnerabilidad | Riesgo inicial | Control implementado | Evidencia | Riesgo residual |
|---|---|---|---|---|---|
| Contraseñas | Filtración de texto claro | Alto | Argon2id, sal aleatoria, respuestas sin hash | Pruebas AUTH | Robo de base permite ataques offline; proteger backups |
| Login | Adivinación masiva | Alto | Límite por IP y correo, DTO estricto, hash ficticio | Prueba 429/401 | Contador local; despliegue con réplicas necesita almacén compartido |
| Identidades | Elevación por campos del cliente | Alto | Campos adicionales rechazados, registro sin roles, ADMIN para CRUD | HTTP 400/403 | Registro permite enumeración por duplicado 409 |
| Asignaciones | Roles falsos, duplicados o revocados | Alto | N:M persistida, FK/UNIQUE, consulta vigente | T05/T06/T07 | Permisos mal asignados por un ADMIN siguen siendo posibles |
| JWT | Falsificación o sesión cerrada reutilizada | Alto | RS256 fijo, claims, 15 min, sesión revocable | Pruebas JWT/logout | Token robado usable hasta revocación; no hay MFA |
| Claves | Divulgación al analizador o Git | Alto | Privada solo AUTH, archivos ignorados, pares JWT/TLS separados | Compose y revisión Git | Operador debe restringir ACL y rotar credenciales |
| Comunicación | Suplantación de AUTH/STEGO | Alto | TLS CA+hostname, token de servicio, endpoint interno bloqueado en proxy | T08 y pruebas de identidad | Compromiso de STEGO permite usar su credencial; rotarla |
| PostgreSQL | Acceso desde STEGO | Alto | Red identidad y credenciales solo AUTH | Compose | Administrador Docker tiene acceso privilegiado |
| Archivos | Formato falso, corrupción, bomba de imagen | Alto | MIME/extensión/formato, decodificación acotada, bytes/píxeles limitados | Pruebas 413/415 | Procesadores de imágenes requieren parches |
| Procesamiento | Agotamiento de CPU/memoria | Alto | Concurrencia, timeout, proceso hijo y límites Linux | Pruebas y contrato | Límite de disco es de aplicación; cuotas SO aconsejables |
| Almacenamiento | Traversal, exposición o integridad alterada | Alto | Nombres UUID, cuarentena privada, SHA-256, no descarga | Pruebas de archivos | No hay cifrado en reposo ni firma del registro |
| Resultados | Lectura ajena | Alto | Decisión por recurso y propietario leído de SQLite | T11 | ADMIN puede leer todos por política explícita |
| Auditoría | Fuga de secretos o falta de trazabilidad | Medio | JSON con sujeto/acción/recurso, sin JWT ni contraseñas | T12 | Logs locales requieren retención y centralización operativa |
| Dependencias | Vulnerabilidades conocidas | Alto | Lockfiles, Prisma 6.19.3, override acotado de deepmerge-ts 8 y pruebas de CLI/migración | npm audit sin alertas conocidas en la revisión | Repetir auditoría y aplicar parches; no afirmar riesgo cero |
| Detector | Clasificación ficticia, incompleta o evasión | Alto | LSB real, ClamAV/YARA y ExifTool; fallos/incompletos conservan cuarentena | [T09 y pila AUTH/BD real](VALIDACION_BACKEND_V1.md) | Falsos positivos/negativos, dos reglas YARA de prueba, técnicas JPEG/BMP no disponibles y actualización operativa del motor/firmas |

Zero Trust: el origen de red no concede permisos; cada operación pide decisión vigente y una falla deniega. Secure by Design: identidad separada, mínimo privilegio, almacenamiento privado y contratos estrictos. Shift Left Security: pruebas automáticas, validaciones, revisión de dependencias y riesgos documentados antes de integrar el detector.

Referencias de principios: ISO/IEC 27001 (acceso, criptografía, registro y gestión de riesgos), ISO/IEC 27034 (controles de seguridad de aplicaciones), [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207), [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html). Esto no es una declaración de cumplimiento normativo integral.
