# Detector PNG LSB de Diana

Motor local reutilizable en `app/stego_lsb.py`, sin endpoints, carga, almacenamiento,
hash persistente ni cuarentena propios. Tras el rebase con main, el motor se conecta
al módulo de Paul mediante `app/stego_adapter.py`; ver [integración](STEGO_INTEGRACION.md).
El detector y sus 31 pruebas originales se mantienen sin cambios.

## Alcance frente a la consigna y al equipo

Se revisaron `Proyecto_Integrador_Primer_Parcial.pdf` (sección 2.3, criterio 5,
escenarios T09/T10) e `INFORME DE DISTRIBUCIÓN DE ACTIVIDADES.docx`, suministrados
en el directorio `P1/Proyecto`. La consigna del parcial prevalece sobre el resumen
general y sobre las tres etiquetas antiguas del informe. Este cambio implementa
el motor de Diana y sus evidencias locales; no constituye la entrega integral.
Las validaciones HTTP de extensión/MIME, identidad, autorización vigente, registro
con usuario/fecha/hash y política de gestión pertenecen a la integración del equipo.
El motor recibe bytes o una ruta local y verifica el contenido, sin confiar en nombres.

Antes de invocarlo desde HTTP deben comprobarse autenticación y autorización
vigente (pendiente en los endpoints actuales). El contrato original de Paul
(`app/analyzer.py`) esperaba `analyze(path, sha256)` y sólo
CLEAN/SUSPICIOUS/INCONCLUSIVE, sin indicadores.
El contrato ahora incluye `analysis` opcional para preservar los cuatro estados
originales, técnica, métricas, política y limitaciones. El adaptador no traduce
SIN_INDICIOS a una garantía de seguridad ni libera archivos; ERROR y NO_CONCLUYENTE
permanecen visibles en el informe. AUTH/RBAC no se modifican.

## Técnica y parámetros

Para cada canal R, G y B de un PNG estático RGB/RGBA de 8 bits se construye el
histograma de 256 valores. No se convierte una paleta ni una profundidad diferente,
porque podría cambiar el significado de sus LSB. Se excluye alfa, incluyendo los RGB
de píxeles transparentes. Otros PNG decodificables devuelven NO_CONCLUYENTE.

Cada par `(2j, 2j+1)` tiene conteos `a,b`, total `t=a+b` y esperado `t/2` por miembro.
Se usan pares con `t >= 10` (esperados >= 5). El estadístico de Pearson es:

`X² = sum((a-t/2)²/(t/2) + (b-t/2)²/(t/2)) = sum((a-b)²/t)`

Condicionado al total de cada par, hay una restricción de igualdad por par: se usa
`df = número de pares elegibles`, sin restar uno entre pares con totales fijados.
`p = scipy.stats.chi2.sf(X², df)` es la cola superior bajo la hipótesis de paridad
equiprobable. No es una probabilidad de que exista esteganografía. La fracción de
LSB=1 se informa descriptivamente; no determina la clasificación. Si no hay pares,
`p=null`, `df=0` y evidencia insuficiente. La cola puede subdesbordar a cero.

La sustitución LSB con carga aproximadamente aleatoria tiende a igualar las
frecuencias dentro de pares. El enfoque se apoya en
[Westfeld y Pfitzmann, Attacks on Steganographic Systems, sección 4.1](https://users.ece.cmu.edu/~adrian/487-s06/westfeld-pfitzmann-ihw99.pdf).
Esta implementación aplica un contraste condicionado por pares al histograma RGB
completo; no reproduce herramientas de extracción ni busca un mensaje.

Política V1, configurable mediante `LSBConfig` y devuelta íntegra en cada resultado:

| Condición, en orden | Clasificación |
| --- | --- |
| Firma/chunks/CRC/decodificación inválidos, lectura fallida o límites excedidos | ERROR |
| PNG fuera de alcance, menos de 4096 píxeles, menos de 32 pares por canal o cobertura < 0.90 en algún canal | NO_CONCLUYENTE |
| Evidencia suficiente en los tres canales y p >= 0.05 en al menos dos | SOSPECHOSO |
| Evidencia suficiente y p <= 0.001 en los tres canales | SIN_INDICIOS |
| Evidencia restante, intermedia o discordante | NO_CONCLUYENTE |

La cobertura es la fracción de muestras que pertenecen a pares elegibles. Los 32
pares evitan decidir a partir de una paleta estrecha; 4096 píxeles y 90% de cobertura
reducen decisiones sobre muestras escasas. La zona entre 0.001 y 0.05 y la exigencia
de varios canales son precauciones heurísticas, no umbrales calibrados sobre un corpus
representativo. Cambiar la política puede cambiar la clasificación sin cambiar métricas.

Límites por defecto: 10 MiB de archivo, 4096 por dimensión y 4 millones de píxeles.
La ruta lee como máximo `max_bytes+1`; bytes ya materializados deben acotarse también
en la capa que recibe la carga. Se inspecciona IHDR antes de decodificar y se verifican
longitudes, CRC de todos los chunks e IEND; se rechazan truncamientos y bytes posteriores
a IEND. Pillow verifica y luego decodifica la imagen. Se conservan las protecciones de
[Pillow](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html#png),
sin habilitar imágenes truncadas ni cambiar límites globales. No se ejecuta contenido.
Los límites no sustituyen aislamiento y límites de CPU/memoria del despliegue.

## Uso y pruebas

Desde `services/file-analyzer`, con Python 3.12:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-stego-dev.txt
.venv/Scripts/python.exe -m pytest tests/stego -q
.venv/Scripts/python.exe -m pytest tests/stego -q -s -k reproducible
.venv/Scripts/python.exe tools/stego_samples.py muestras-lsb
```

En Linux usar `.venv/bin/python`. `requirements-stego.txt` permite instalar el motor
independiente. El `requirements.txt` del servicio ahora lo incluye y el Dockerfile
copia ambos manifiestos. No se necesita FastAPI ni el módulo de carga para estas
31 pruebas independientes.

```python
import json
from app.stego_lsb import analyze_png, LSBConfig

result = analyze_png("muestras-lsb/lsb_full.png", LSBConfig(max_pixels=1_000_000))
print(json.dumps(result.to_dict(), ensure_ascii=False, allow_nan=False, indent=2))
```

`to_dict()` contiene técnica, clasificación, motivo, límites y umbrales aplicados,
dimensiones, indicadores por canal y limitaciones. No contiene identidad, hash,
fecha ni decisiones de almacenamiento; deben agregarse al registro de integración.

## Muestras y límites de la evidencia

`tools/stego_samples.py` no importa el detector. Genera un portador artificial
256x256 con valores pares y semilla 2026, carga pseudoaleatoria con semilla 7401
que ocupa toda su capacidad RGB (24576 bytes), un mensaje corto de 20 bytes y
ruido RGB sin carga con semilla 903. Inserta en orden raster/RGB, MSB primero
por byte; las pruebas recuperan exactamente el mensaje y verifican los bits altos.
También genera una imagen pequeña y otra plana. No son fotografías ni un corpus
de evaluación de precisión. Los PNG se regeneran, sin añadir binarios al repositorio.

Se compara el original con la inserción completa y se comprueba la fórmula contra
un caso analítico independiente: dos pares con conteos (30,10) y (20,20) dan
X²=10, df=2, p=exp(-5). Las pruebas cubren entradas falsas/corruptas, límites antes
de decodificar, modos no soportados, alfa, APNG y resultados insuficientes.

Falsos positivos esperables: ruido legítimo, tramados, imágenes sintéticas o
procesamiento que iguale pares. Falsos negativos esperables: cargas pequeñas,
inserción en un solo canal, regiones localizadas, bits sesgados, LSB matching,
métodos adaptativos o datos en alfa/metadatos. La correlación espacial debilita la
aproximación estadística y el histograma global pierde señales locales. No se
extrae contenido ni se detecta malware. No se declara porcentaje de precisión.
Los resultados observados se registran en `STEGO_LSB_RESULTADOS.md`.
