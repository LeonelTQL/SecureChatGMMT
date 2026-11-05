# Evidencia local del detector LSB

Pruebas ejecutadas el 04/11/2026 desde la raíz del repositorio en Windows,
Python 3.12, Pillow 12.3.0, SciPy 1.18.1, NumPy 2.5.4 y pytest 9.2.0.

```powershell
.venv-stego/Scripts/python.exe -m pytest services/file-analyzer/tests/stego -q --basetemp=.venv-stego/pytest-run2
```

Resultado final: **31 passed in 2.22s**. El temporal elegido está dentro del entorno
virtual local ignorado. La primera ejecución con el temporal predeterminado tuvo
26 pruebas aprobadas y 3 errores de preparación por permisos en el temporal de
Windows; se corrigió la ubicación del temporal y la batería completa pasó.
No se modificaron cálculos ni umbrales para resolver ese problema del entorno.

Las métricas se obtuvieron invocando `analyze_png_bytes` sobre `samples()`;
también se imprimen completas con `pytest -s -k reproducible`. Orden de canales:
R / G / B. Cada canal de las muestras grandes tiene 65536 observaciones.

| Muestra | X² por canal | p por canal | Clasificación |
| --- | --- | --- | --- |
| Original sintético, valores pares | 65536 / 65536 / 65536 | 0 / 0 / 0 | SIN_INDICIOS |
| Carga LSB completa | 115.403805 / 107.165157 / 114.416650 | 0.780134 / 0.909573 / 0.799247 | SOSPECHOSO |
| Mensaje LSB corto, 20 bytes | 65440.219371 / 65436.226420 / 65452.207083 | 0 / 0 / 0 | SIN_INDICIOS |
| Ruido sin carga | 139.357692 / 148.679345 / 170.399194 | 0.232308 / 0.102059 / 0.007261 | SOSPECHOSO |
| Imagen pequeña, 16x16 | 0 / 0 / 0 | null / null / null | NO_CONCLUYENTE |
| Imagen plana, 256x256 | 65536 / 65536 / 65536 | 0 / 0 / 0 | NO_CONCLUYENTE |

Las cuatro primeras muestras tienen 128 pares elegibles por canal, df=128 y
cobertura=1. La pequeña no tiene pares elegibles; sus ceros de X² son sumas vacías,
sin contraste válido. La plana sólo tiene un par elegible por canal, por lo que no
satisface la política aunque sus valores p sean pequeños. Los p=0 representan
subdesbordamiento numérico de la cola; no certeza matemática ni ausencia probada.

En la inserción completa las fracciones de LSB=1 fueron 0.502884 / 0.501740 /
0.498917, frente a 0 en el original. El contraste cambió de manera reproducible.
La prueba analítica independiente confirmó X²=10, df=2, p=exp(-5) para conteos
(30,10)/(20,20). Pares exactamente equilibrados dieron X²=0 y p=1.

Se observaron un **falso positivo** (ruido sin carga) y un **falso negativo**
(mensaje corto conocido insertado en el portador). Se conservaron estas salidas
reales y se incluyeron pruebas que las documentan. La inserción completa fue
detectada en este portador artificial; no demuestra rendimiento en fotografías,
otros porcentajes de carga, otros algoritmos ni datos de producción. No se
estima precisión, sensibilidad ni especificidad con estas muestras.

La batería incluye firma falsa y contenido JPEG, CRC alterado, truncamiento,
ausencia de IEND, bytes posteriores a IEND, datos comprimidos corruptos con CRC
correcto, exceso de bytes/dimensiones/píxeles, lectura fallida, baja cobertura,
modos no soportados, APNG y alfa ignorado. No se ejecutaron pruebas HTTP de
integración ni de autenticación: no se añadieron rutas y la integración con el
contrato de Paul permanece pendiente.

Los archivos creados son `app/stego_lsb.py`, `tools/stego_samples.py`,
`tests/stego/conftest.py`, `tests/stego/test_lsb.py`, `requirements-stego.txt`,
`requirements-stego-dev.txt`, `STEGO_LSB.md` y este informe. No se editaron archivos
preexistentes, no se realizaron commits ni push. El entorno `.venv-stego` sólo
sirve para la verificación local y no forma parte de la entrega versionable.
