# Validación de la entrega (Paul)

Fecha: 2026-11-04. Destino real: `http://localhost:8080/api`, servicios
levantados por el usuario mediante Docker Compose. No se usaron mocks HTTP.

## Colección Postman

Ejecutada desde la raíz del repositorio:

```powershell
postman collection run postman/Paul-files.postman_collection.json --no-report-events --timeout-request 10000 --timeout 60000 --delay-request 150
```

Resultado: **7 peticiones, 14 aserciones, 0 fallos, código de salida 0**.
La ejecución fue local; no se publicaron resultados en Postman.

| Caso | Resultado observado |
| --- | --- |
| Salud de archivos | 200, `file-analyzer`, `file-management` |
| Carga multipart PNG | 202, estado inicial PENDING, hash y tamaño presentes |
| Consulta de estado | 200, QUARANTINED / INCONCLUSIVE |
| Descarga de archivo en cuarentena | 423, `file_blocked` |
| Carga sin archivo | 422 |
| ID inválido | 422 |
| Archivo inexistente | 404 |

Adicionalmente se verificó que `/api/auth/health` devuelve 200.

## Comparación de integridad independiente

Se calculó el SHA-256 local de `postman/fixtures/pixel.png` con `hashlib` y se
comparó con la respuesta del endpoint de estado. Coinciden hash y tamaño:

- Archivo registrado: `8bcc8c57-7652-4082-8a21-90b082175b6f`.
- Tamaño: 69 bytes.
- SHA-256: `ca9b3f6a5185b96230396dca88491d802b92f983593f1c02f1c483ac67cca1ba`.
- Estado: `QUARANTINED`; motivo: `analyzer_not_configured`.

## Alcance de la evidencia

El servicio desplegado recibe y procesa la carga, conserva sus metadatos y
aplica el bloqueo por HTTP a través de Caddy. El adaptador predeterminado no
realiza análisis antimalware ni esteganográfico: devuelve INCONCLUSIVE.
La integración con el motor real de Diana permanece pendiente.

La suite local ejecutada previamente pasó sus 12 pruebas con unittest
(también descubribles por pytest), incluyendo resultados CLEAN/SUSPICIOUS
simulados, alteraciones de integridad y persistencia tras reiniciar la aplicación.
No se reiniciaron contenedores ni se verificaron sus logs en esta sesión:
el acceso al motor Docker está denegado para el entorno del agente.
