# Integración de Diana en el STEGO protegido

Compose despliega únicamente `services/stego`, junto a AUTH e infraestructura.
`services/file-analyzer` se mantiene como código histórico y fuente reutilizable;
no se inicia como servicio adicional y no se elimina el trabajo de Paul.

## Flujo y contrato

1. `SecurityMiddleware` verifica JWT RS256, emisor, audiencia, vigencia y UUID.
   Consulta a AUTH por HTTPS con CA/hostname y exige una decisión vigente para
   la acción/recurso. Sin ella no consume el cuerpo ni invoca el detector.
2. La ruta protegida limita la recepción a 5 MiB y comprueba formato real,
   extensión y decodificación. Conserva BMP del contrato anterior y añade JPEG.
   No confía en el MIME declarado. Se guarda el archivo privado con UUID y SHA-256.
3. El adaptador comprueba integridad y ejecuta `app.detector.analyze(path)` en un
   proceso Linux aislado. Reutiliza la validación de Diana, ClamAV, YARA, ExifTool
   y el detector LSB sin cambiar fórmulas, umbrales ni sus módulos existentes.
4. El servicio vuelve a comprobar SHA-256 y persiste clasificación, métricas,
   limitaciones e informes. Una modificación de bytes impone error y cuarentena.
5. Cada lectura exige una nueva autorización y compara el propietario del registro
   con el sujeto verificado, salvo scope all autorizado para ADMIN. No se añade
   descarga, aprobación manual ni endpoint público de análisis.

No se modifican `security.py`, AUTH/RBAC ni la implementación del almacenamiento.
Las nuevas comprobaciones de hash completan la ruta activa, que anteriormente
sólo calculaba SHA-256 al recibir el archivo. La interfaz asíncrona del adaptador
existente y la función síncrona solicitada se conservan.

## Reutilización sin duplicar algoritmos

En desarrollo, el detector carga el paquete histórico desde una ruta fija del
repositorio bajo el nombre independiente `stego_diana`, evitando confundir los
dos paquetes llamados app. El único archivo añadido al directorio histórico es
`app/__init__.py`, sin iniciar ninguna aplicación.

Docker copia exactamente los módulos necesarios bajo ese mismo nombre. No copia
la antigua API ni almacenamiento de Paul. El contexto de la entrada stego cambia
a la raíz y usa `services/stego/Dockerfile`; una lista permitida en `.dockerignore`
evita enviar secretos, entornos virtuales u otros servicios. No se cambia la
configuración de AUTH ni se añade un microservicio.

El contrato admite los cuatro estados y hasta 50 indicadores numéricos finitos.
Se aplanan las métricas por R/G/B, conservando pares elegibles, X², grados de
libertad, p, cobertura, observaciones y fracción LSB=1. Los p no disponibles se
omiten del mapa numérico y permanecen null en el informe original. También se
informa tamaño medido y dimensiones disponibles, sin fabricar scores ni precisión.

`reason` y `reports` son opcionales para mantener compatibilidad. Este último
admite únicamente validation/antimalware/metadata/lsb y hasta 32 KiB de JSON.
El modelo HTTP admite esos campos y SQLite ya persistía un documento JSON, por
lo que no requiere migración. Los informes reutilizan la proyección de privacidad
de ExifTool; no contienen stdout, rutas internas, autores, seriales ni GPS.

## Política de clasificación

- Validación fallida: error; HTTP 503 del contrato activo y archivo en cuarentena.
  Los formatos/cargas rechazados antes del detector mantienen HTTP 415/413.
- Falta/fallo de una verificación obligatoria: no_concluyente, incluso si otra
  aporta indicios; éstos permanecen visibles en informes técnicos y se conserva
  cuarentena. No se confunde motor ausente con resultado limpio.
- Detección antimalware con verificaciones completas: sospechoso.
- Inconsistencias de metadatos: no_concluyente; no son prueba de malware/LSB.
- PNG con verificaciones completas: se conserva la clasificación estadística
  original en las cuatro etiquetas oficiales. SIN_INDICIOS no certifica seguridad.
- JPEG válido: se ejecutan validación, ClamAV/YARA y ExifTool, pero no hay detector
  LSB aplicable; no_concluyente. BMP se conserva como recepción histórica, sin
  pipeline Diana compatible: no_concluyente por técnica no aplicable, sin fingir
  verificaciones ni métricas LSB. Su indicador disponible es el tamaño real.

`sin_indicios` sólo aplica advertencia y conserva el objeto privado, como ya
definía el equipo. Los demás estados aplican cuarentena. No existe CLEAN ni
descarga automática en esta API. Se conservan falsos positivos/negativos y los
umbrales heurísticos documentados en `services/file-analyzer/STEGO_LSB.md`.

## Recursos y dependencias

El antiguo worker de 8 s CPU/384 MiB y timeout de 10 s no podía cargar el pipeline
que incluye ClamAV (hasta 45 s y 2 GiB). Se ajusta a 45 s CPU, 3 GiB de espacio
virtual y 90 s de tiempo total, manteniendo salida de 64 KiB. Los motores siguen
limitados por el ejecutor histórico y no se relajan sus límites. El contenedor
pasa de 768 MiB a 3 GiB y la concurrencia interna de dos a una imagen por worker.
No se deshabilitan read-only, cap_drop, no-new-privileges, pids_limit ni tmpfs.

Se restringen hilos BLAS y el entorno del worker: no recibe tokens ni credenciales
AUTH. Se mata el worker y sus descendientes ante timeout/cancelación; se lee la
salida hasta EOF, acotadamente, para evitar JSON parcial. Windows sin límites
Linux falla de forma cerrada. La imagen instala los tres motores/util-linux y
firmas oficiales al construir; deben renovarse operativamente para no quedar
vencidas. NumPy/SciPy se añaden con versiones fijadas a ambos manifiestos activos.

## Evidencia y pendientes

Las suites históricas y activas se ejecutan por separado porque ambas usan el
nombre de paquete app. Las 150 pruebas de Diana usan su entorno original; STEGO
usa su lock. Las pruebas autorizadas usan JWT RS256 reales y un decisor controlado
para aislar la integración. También se prueba una conexión HTTPS AUTH realmente
inaccesible. No equivale a levantar AUTH/PostgreSQL y demostrar revocación real
de roles persistidos: esa sustentación completa permanece pendiente.

Los resultados finales y comandos se registran en `VALIDACION_DIANA.md`.
La existencia de herramientas y ausencia de coincidencias no demuestra cobertura
universal ni seguridad para producción. YARA conserva sólo sus dos reglas de
prueba documentadas; JPEG/BMP no tienen detector estadístico. No se realizan
commits, push ni PR.
