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

## Detector de Diana integrado

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

El ejemplo describe el esquema, NO valores que deban devolverse sin cálculo.
`services/stego/app/detector.py` ahora reutiliza los módulos de Diana conservados
en `services/file-analyzer/app`, sin iniciar su servicio histórico. En Docker se
copian esos mismos archivos como paquete `stego_diana`, sin reescribir algoritmos.
Estados: `sin_indicios`, `sospechoso`, `no_concluyente`, `error`. Indicadores: hasta
50 métricas numéricas finitas. Los canales RGB aportan X², grados de libertad,
p, cobertura y fracción LSB=1 reales; un p no calculable no se reemplaza por cero.
No imprimir texto adicional a stdout. Se aceptan además `reason` (código controlado)
y `reports` opcionales, compatibles con resultados anteriores. `reports` admite
únicamente `validation`, `antimalware`, `metadata`, `lsb`, hasta 32 KiB de JSON
finito. No se guardan rutas, salida cruda ni GPS. El adaptador rechaza resultados
sin métricas para clasificaciones distintas de error; para formatos no aplicables
se informa el tamaño medido del archivo, sin inventar métricas LSB.

Paul aporta identificación, usuario, fecha, hash, almacenamiento y política.
`sin_indicios` aplica advertencia y retiene archivo privado; los otros estados
mantienen cuarentena. No existe descarga ni aprobación automática. Diana aporta
técnica, métricas, clasificación y limitaciones. La integridad se verifica antes
y después del detector. Una verificación obligatoria no disponible produce
`no_concluyente`, aunque se conserven indicios individuales en los informes.
JPEG y BMP sin detector aplicable permanecen no concluyentes. El adaptador usa
proceso hijo sin shell, 90 s de timeout, 64 KiB de salida, 45 s de CPU y 3 GiB de
espacio virtual Linux; los motores mantienen sus límites propios más restrictivos.
El contenedor tiene 3 GiB y procesa una imagen a la vez para evitar multiplicar
la memoria de las firmas. No se envían credenciales AUTH al worker.

La evidencia T09 y de regresión está en `services/stego/INTEGRACION_DIANA.md`.
Las pruebas de decisiones autorizadas usan un decisor de prueba; se conserva
la comprobación real RS256 y existe una prueba con transporte AUTH inaccesible.
No sustituye una sustentación completa con AUTH/BD y revocación real de roles.
