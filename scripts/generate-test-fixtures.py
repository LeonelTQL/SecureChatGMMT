"""Muestras inofensivas para validar archivos, límites y sustitución en Burp."""
import hashlib
import io
import json
from pathlib import Path
from PIL import Image

root = Path(__file__).resolve().parents[1]
output = root / '.local/test-fixtures'
output.mkdir(parents=True, exist_ok=True)


def image_bytes(format):
    buffer = io.BytesIO()
    Image.new('RGB', (32, 32), (40, 80, 120)).save(buffer, format=format)
    return buffer.getvalue()


png = image_bytes('PNG')
marker = b'UPLOAD_PROBE_INERTE_NO_EJECUTABLE\n'
samples = {
    'valida.png': png,
    'valida.bmp': image_bytes('BMP'),
    'no_admitida.jpg': image_bytes('JPEG'),
    'marcador.txt': marker,
    'texto_disfrazado.png': marker,
    'solo_firma.png': b'\x89PNG\r\n\x1a\n' + marker,
    'corrupta.png': png[:30],
    'vacia.png': b'',
    'bmp_disfrazado.png': image_bytes('BMP'),
    'png_con_marcador_extra.png': png + b'\n' + marker,
    'exactamente_5MiB.png': png + b'\0' * (5 * 1024 * 1024 - len(png)),
    'excede_5MiB.png': png + b'\0' * (5 * 1024 * 1024 + 1 - len(png)),
}
buffer = io.BytesIO()
# 20.005.000 píxeles: supera el límite sin crear un archivo gigante.
Image.new('1', (5000, 4001)).save(buffer, format='PNG')
samples['excede_pixeles.png'] = buffer.getvalue()
manifest = []
for filename, content in samples.items():
    target = output / filename
    if target.exists() and target.read_bytes() != content:
        raise RuntimeError(f'Se conserva la muestra modificada: {filename}; retírala manualmente para regenerar')
    target.write_bytes(content)
    manifest.append({'file': filename, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
(output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(f'{len(samples)} muestras inofensivas en .local/test-fixtures; ninguna abre conexiones ni ejecuta comandos')
