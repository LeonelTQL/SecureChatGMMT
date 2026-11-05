"""Documenta falsos negativos reales, sin exigir detección que PoV no ofrece."""
from io import BytesIO

from PIL import Image
import pytest

from app.stego_lsb import analyze_png_bytes
from tools.stego_multibit_samples import hidden_image, samples


@pytest.mark.parametrize("bits", [2, 4])
def test_hidden_image_recovered_but_pov_has_no_indications(bits):
    data = samples()[f"hidden_{bits}bit"]
    with Image.open(BytesIO(data)) as image:
        raw = image.tobytes()
    # Recuperación independiente: la fuente 0/128 es exactamente representable.
    recovered = bytes((value % (2 ** bits)) * (2 ** (8 - bits)) for value in raw)
    assert recovered == hidden_image()
    result = analyze_png_bytes(data)
    assert result.classification.value == "SIN_INDICIOS"
    assert all(channel.p_value == 0 for channel in result.channels)
