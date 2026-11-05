# Colecciones de pruebas

El backend activo es AUTH + `services/stego`. Importar la CA local y mantener
la verificación TLS. Nunca exportar contraseñas, JWT ni credenciales de servicio.
Usar únicamente cuentas de prueba; las colecciones hacen registros y logout.

| Archivo | Alcance |
| --- | --- |
| `Backend-V1.postman_collection.json` | Secuencia canónica generada por `scripts/generate-postman.cjs`: nueve solicitudes/aserciones verificadas en Backend V1. Comprueba registro, login, denegación por falta de roles, logout y revocación. |
| `Backend-V1-demostracion.postman_collection.json` | Exportación depurada: conserva las nueve solicitudes y tres adicionales de salud/análisis. Las tres adicionales no están incluidas en las nueve aserciones de la evidencia anterior. |
| `Leonel-auth.postman_collection.json` | Pruebas históricas de Leonel; contraseñas de ejemplo parametrizadas. Configurar `password` e `invalid_password` localmente con valores distintos. No sustituye la colección activa. |
| `Paul-files.postman_collection.json` | Contrato histórico de Paul, conservado; no corresponde a las rutas del STEGO activo. No iniciar file-analyzer para ejecutar la entrega actual. |

En ambas colecciones Backend V1, `password` y `access_token` se exportan vacíos;
los correos `example.com` son ejemplos. Configurar una cuenta nueva de prueba
para la secuencia de registro. El login captura su token durante la ejecución;
logout lo revoca. Limpiar las variables sensibles antes de volver a exportar.

Las peticiones de demostración adicionales se ejecutan por separado. Configurar
`analyst_token` localmente con un JWT vigente de ADMIN/ANALYST autorizado; no usar
el token que la secuencia anterior revocó. `image_path` apunta a una muestra
generada localmente; si Postman no resuelve variables en el selector de archivo,
seleccionar la imagen manualmente y retirar la ruta privada antes de exportar.
No enviar ni solicitar el token interno de servicio desde estas colecciones.

Desde la raíz, con el entorno de pruebas instalado:

```powershell
.venv-stego/Scripts/python.exe services/file-analyzer/tools/stego_samples.py .local/test-fixtures
.venv-stego/Scripts/python.exe scripts/audit-pr-artifacts.py
```

`original.png` y `lsb_full.png` son controles sintéticos reproducibles. Las
muestras de varios bits se regeneran con el comando documentado en
`services/stego/VALIDACION_DIANA.md`. No se incorporan imágenes externas.
`fixtures/pixel.png` se conserva como muestra histórica; no se encontró una
declaración de procedencia/licencia, por lo que no se usa como base de la nueva evidencia.
