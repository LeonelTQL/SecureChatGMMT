# Contratos AUTH–STEGO y detector

La entrega de transferencia importada desde `main` mantiene su contrato original en `files.md`, `files.openapi.json` y `postman/Paul-files.postman_collection.json`. Esos endpoints pertenecen al componente `services/file-analyzer`, conservado sin despliegue activo. El Compose utiliza `services/stego`, que exige JWT y una decisión vigente; el contrato histórico de carga no sustituye esa autorización.

## Autorización por operación

STEGO verifica localmente RS256, issuer `ms-users-auth`, audience `chat-seguro`, expiración, vida máxima de 900 segundos, UUID de `sub` y `jti`. Luego invoca por HTTPS con validación de CA y hostname:

```http
POST /internal/authorization/check
X-Service-Token: <credencial exclusiva STEGO>
Content-Type: application/json
```

```json
{"subject_token":"<JWT>","action":"steganography.analyze","resource_id":null}
```

```json
{"subject_id":"<UUID>","action":"steganography.analyze","resource_id":null,"allowed":true,"reason":"active_role_grants_permission","scope":"own"}
```

Acciones permitidas: `steganography.analyze`, `steganography.results.read`. La segunda incluye UUID del análisis. AUTH consulta usuario, sesión y asignaciones actuales. Devuelve `scope=all` únicamente a ADMIN; a ANALYST le corresponde `own`. STEGO compara el propietario de SU registro SQLite con `subject_id`. No acepta propietarios ni permisos declarados por el cliente.

401: autenticación inválida. Decisión `allowed=false`: STEGO responde 403. Sin respuesta válida, TLS verificable o coincidencia de sujeto/acción/recurso: STEGO responde 503. No se cachean decisiones. AUTH caído implica denegación antes de leer el cuerpo. El token de servicio viaja solo sobre TLS, no se devuelve ni se imprime.

Caddy bloquea `/internal/*`; el puerto directo de AUTH está enlazado a loopback para evaluación y aun allí se exige credencial de servicio. En despliegue remoto restringir también puertos de administración/red.

## Detector de Diana — pendiente

Archivo de integración: `services/stego/app/detector.py`. Función síncrona `analyze(path: pathlib.Path) -> dict`:

```python
def analyze(path):
    # Calcular indicadores reales con la técnica implementada y justificada.
    return {
        "status": "no_concluyente",
        "technique": "nombre_de_tecnica_real",
        "indicators": {"metrica_real": 0.0},
        "limitations": "Limitaciones observadas de la técnica"
    }
```

El ejemplo describe el esquema, NO un detector ni valores que deban devolverse sin cálculo. Estados: `sin_indicios`, `sospechoso`, `no_concluyente`, `error`. Indicadores: hasta 50 métricas numéricas finitas. No imprimir texto adicional a stdout. El adaptador acepta solo campos del contrato y rechaza resultados sin métricas para clasificaciones distintas de error.

Paul aporta identificación, usuario, fecha, hash, almacenamiento y política. `sin_indicios` aplica advertencia y retiene archivo privado; los otros estados mantienen cuarentena. Diana aporta técnica, métricas, clasificación y limitaciones. El adaptador usa proceso hijo sin shell, timeout, salida acotada y límites CPU/memoria Linux.

Falta demostrar T09 con imágenes originales y alteradas, técnica real y parámetros justificados. Ninguna prueba del adaptador reemplaza esa evidencia.
