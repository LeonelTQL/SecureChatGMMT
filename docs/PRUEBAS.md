# Pruebas y sustentación

**Revisión actual sin Alejandro:** los escenarios RBAC/N:M/autorización de la tabla siguiente quedan pendientes de reintegración. El reporte `docs/evidence/integration.json` comprueba autenticación y bloqueo seguro sin RBAC. El reporte `before-alejandro-removal.json` conserva evidencia histórica y NO describe las capacidades actuales. Los tests de Paul con dobles siguen verificando el contrato que Alejandro deberá implementar.

La evidencia distingue pruebas con dobles de persistencia/detector de integración real. No se presentan salidas de un doble como detección esteganográfica real.

| PDF | Escenario | Ejecución / evidencia |
|---|---|---|
| T01 | Iniciar/detener AUTH y STEGO por separado | Comandos stop/start del README; ambos publican health propio; T08 ejercita stop AUTH |
| T02 | Contraseña válida e inválida | AUTH unitario/HTTP e integración real |
| T03 | Sin JWT, manipulado o vencido | AUTH/STEGO automatizado; integración real sin token/manipulado |
| T04 | USER intenta analizar | Integración real: 403 |
| T05 | Dos roles por usuario, rol compartido | Integración real crea relación N:M en PostgreSQL |
| T06 | Asignación duplicada | Integración real: 409 por UNIQUE |
| T07 | Retirar rol, reutilizar JWT vigente | Integración real: primera carga autorizada; retiro; siguiente 403 |
| T08 | AUTH caído | `scripts/integration.py --failure-demo`: 503 sin procesar; prueba ASGI confirma cero lecturas de cuerpo |
| T09 | Original y muestra con carga LSB | Pendiente de Diana; no se sustituye por doble ni se inventan métricas |
| T10 | Archivo corrupto/excesivo | Unitario y real 415/413; validación de extensión/MIME/PNG/BMP y píxeles |
| T11 | Resultado ajeno | Integración real: ANALYST ajeno 403, propietario/ADMIN autorizado |
| T12 | Revisar bitácoras | `docker compose -f compose.yaml logs auth-service stego`; eventos con IDs, sin JWT ni claves |

Otros casos: usuario desactivado, logout revocable, emisor/audiencia incorrectos, algoritmo no autorizado, claims ausentes, campos extra, credencial de servicio incorrecta, filename con traversal, salida de detector inválida y error seguro sin detector.

Los artefactos de evidencia ejecutada se guardan en `docs/evidence/`. Comandos para reproducir desde raíz:

Validación histórica antes de retirar Alejandro: **9 pruebas AUTH, 31 pruebas STEGO y 33 verificaciones de integración real aprobadas**. La autenticación actual tiene **7 pruebas aprobadas**; la integración vigente se registra en `docs/evidence/integration.json`. Las dos migraciones compartidas se conservan. La evidencia histórica no implica que RBAC esté disponible ahora.

```powershell
npm.cmd --prefix apps/auth-service test
services/stego/.venv/Scripts/python.exe -m pytest services/stego/tests -q
services/stego/.venv/Scripts/python.exe scripts/integration.py --failure-demo
```

Para probar T01 de STEGO sin afectar identidad: `docker compose -f compose.yaml stop stego`; verifica `/health` de AUTH; luego `docker compose -f compose.yaml start stego`. No borres volúmenes.

El script de integración deshabilita sus cuentas al terminar, pero conserva asignaciones y registros como evidencia. Si falla, revisa las cuentas `test_*` y deshabilítalas mediante ADMIN. La carga de prueba sin detector genera intencionalmente un registro `error` en cuarentena y HTTP 503.

Para completar T09, Diana deberá aportar el algoritmo real, PNG/BMP original y modificado, procedimiento reproducible de inserción, métricas reales, umbrales y limitaciones; después se debe repetir la integración con resultados reales.
