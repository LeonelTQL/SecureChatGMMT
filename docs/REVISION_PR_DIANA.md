# Revisión de artefactos para el PR de Diana

Rama comprobada: `feature/stego-diana`. Revisión del 5 de noviembre de 2026.
No se realizaron commits, push, PR ni cambios al índice Git. El árbol ya tenía
cambios pendientes de la validación Backend V1; se conservaron.

## Cambios revisados

Se revisaron los cambios pendientes en README, contratos, arquitectura, riesgos,
distribución, OpenAPI, evidencias, documentación STEGO y scripts de integración.
Los ajustes funcionales previos de ClamAV y del adaptador (75/45 s y 120 s),
documentados en Backend V1, permanecen como estaban. Esta preparación no modifica
el código de ejecución del servicio, algoritmos, umbrales, AUTH, RBAC, almacenamiento
ni Compose. Sólo agrega documentación, herramientas de revisión/muestras y dos pruebas.

Las responsabilidades se contrastaron con el informe de distribución del equipo
y el PDF oficial del Primer Parcial (§2.1–2.5, rúbrica 5–6 y T09–T12). Diana aporta
el análisis; Paul conserva transferencia, hash, almacenamiento y política;
Leonel y Alejandro conservan autenticación y autorización. Se explicita la
precedencia de las cuatro clasificaciones oficiales sobre las tres etiquetas
del informe anterior del equipo.

## Auditoría de información sensible

Se inspeccionaron todos los JSON de `docs/evidence` y todas las colecciones JSON
de `postman`, incluidos cuerpos JSON serializados. No se encontraron JWT literales,
claves privadas, coordenadas GPS ni credenciales de servicio en esos artefactos.
Los UUID de cuentas y análisis sintéticos se conservan para mantener trazabilidad;
no son credenciales. No se alteraron métricas, resultados ni fallos históricos.

Se retiraron de la exportación adicional una ruta absoluta de usuario y los
identificadores/enlaces personales de exportación. Se renombró como
`postman/Backend-V1-demostracion.postman_collection.json`. Conserva sus doce
peticiones: las nueve originales y tres de demostración adicionales. Se usan
variables de URL, archivo y token autorizado independiente, todos sin credenciales
persistidas. Se parametrizaron las contraseñas literales de ejemplo de la
colección histórica de Leonel, sin cambiar sus endpoints ni aserciones.

Una comparación local adicional contra cinco valores sensibles de configuración
accesibles no encontró coincidencias en los archivos pendientes. El archivo
bootstrap tiene restricciones de lectura y no formó parte de esa comparación.
No se exportaron valores ni se alteraron secretos/ACL. La revisión heurística
estática no certifica ausencia absoluta de secretos ni audita el historial Git.
Puede repetirse sin acceso a credenciales:

```powershell
.venv-stego/Scripts/python.exe scripts/audit-pr-artifacts.py
```

## Verificaciones de esta revisión

- Detector real: 33 pruebas aprobadas, 0 fallidas (31 originales y dos nuevas).
- Se comprobó recuperación exacta de la imagen oculta en 2/4 bits; ambos casos
  devuelven SIN_INDICIOS. Se documentan como falsos negativos, sin cambiar PoV.
- Se conservaron la positiva LSB completa → SOSPECHOSO y el control original →
  SIN_INDICIOS, junto a sus métricas reales en `evidence/pr-lsb-samples.json`.
- OpenAPI contiene únicamente las rutas activas de salud, análisis y resultados;
  las dos operaciones de datos declaran BearerAuth. Conserva hash, métricas,
  clasificación, acción, motivo e informes técnicos.
- Las nueve solicitudes/aserciones originales de Postman permanecen compatibles
  con la colección canónica. Las tres adicionales no se presentan como probadas
  contra el servicio real durante esta revisión.
- Se verificó consistencia aritmética del resumen histórico: 332/0, más 14 subcasos.
  No se suman las nuevas pruebas a ese total ni se afirma haber repetido toda la pila.
- `git diff --check` sin errores de espacios; Git avisa sobre normalización LF/CRLF.

## Muestras y pendientes

Las muestras nuevas no necesitan imágenes externas. Se regeneran desde código
sintético versionado independiente del detector. Los comandos están en
`services/stego/VALIDACION_DIANA.md` y `postman/README.md`. No se atribuye una
licencia nueva a todo el repositorio. La procedencia/licencia de la muestra
histórica `postman/fixtures/pixel.png` no está documentada: se conserva el archivo
del equipo y no se usa para la nueva evidencia.

Quedan revisión del equipo, sustentación académica y decidir la documentación
de licencia/procedencia de esa muestra histórica. Se mantienen los límites PoV,
la cobertura reducida de YARA, la falta de técnica JPEG/BMP y el mantenimiento
de firmas/motores. El PR puede prepararse para revisión con estas limitaciones
declaradas; no implica seguridad completa ni aprobación académica automática.
