"""Muestras sintéticas reproducibles. No importa ni consulta el detector."""
import argparse
from io import BytesIO
from pathlib import Path
import random

from PIL import Image


def encode(raw: bytes, size=(256, 256), mode="RGB") -> bytes:
    with Image.frombytes(mode, size, raw) as image:
        output = BytesIO()
        image.save(output, format="PNG")
        return output.getvalue()


def carrier(seed=2026, size=(256, 256)) -> bytes:
    """Portador artificial con todos los valores pares; sesgo conocido, no fotografía."""
    rng = random.Random(seed)
    return bytes(2 * rng.randrange(128) for _ in range(size[0] * size[1] * 3))


def embed_lsb(raw: bytes, payload: bytes) -> bytes:
    """Inserta bits de bytes en orden RGB/raster, MSB primero; falla si no caben."""
    if len(payload) * 8 > len(raw):
        raise ValueError("Carga mayor que la capacidad")
    output = bytearray(raw)
    for index in range(len(payload) * 8):
        bit = (payload[index // 8] >> (7 - index % 8)) & 1
        output[index] = (output[index] & 0xfe) | bit
    return bytes(output)


def samples() -> dict[str, bytes]:
    raw = carrier()
    rng = random.Random(7401)
    payload = rng.randbytes(len(raw) // 8)
    noise = random.Random(903).randbytes(len(raw))
    return {
        "original": encode(raw),
        "lsb_full": encode(embed_lsb(raw, payload)),
        "lsb_small": encode(embed_lsb(raw, b"Mensaje de prueba LSB")),
        "noise_without_payload": encode(noise),
        "tiny": encode(carrier(size=(16, 16)), size=(16, 16)),
        "flat": encode(bytes([128]) * len(raw)),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in samples().items():
        (args.output / f"{name}.png").write_bytes(data)
