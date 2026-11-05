"""Muestras sintéticas propias de inserción en 2/4 bits; sin importar el detector.

Uso desde services/file-analyzer: python -m tools.stego_multibit_samples salida
No requiere imágenes externas. Los PNG se regeneran desde este código.
"""
import argparse
from pathlib import Path

from tools.stego_samples import carrier, encode


def hidden_image(size=(256, 256)) -> bytes:
    """Imagen RGB de bloques con valores 0/128, deliberadamente sesgada."""
    return bytes(128 * ((x // 16 + y // 16 + channel) % 2)
                 for y in range(size[1]) for x in range(size[0]) for channel in range(3))


def embed_image(raw: bytes, hidden: bytes, bits: int) -> bytes:
    if bits not in (2, 4) or len(raw) != len(hidden):
        raise ValueError("Se requieren imágenes de igual tamaño e inserción de 2/4 bits")
    mask = (1 << bits) - 1
    return bytes((value & (255 ^ mask)) | (secret >> (8 - bits))
                 for value, secret in zip(raw, hidden))


def samples() -> dict[str, bytes]:
    raw, hidden = carrier(), hidden_image()
    return {"hidden_source": encode(hidden),
            "hidden_2bit": encode(embed_image(raw, hidden, 2)),
            "hidden_4bit": encode(embed_image(raw, hidden, 4))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in samples().items():
        (args.output / f"{name}.png").write_bytes(data)
