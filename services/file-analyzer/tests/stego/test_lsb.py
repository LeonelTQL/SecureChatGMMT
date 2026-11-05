from dataclasses import replace
from io import BytesIO
import json
import math
import struct
import zlib

from PIL import Image
import pytest

from app.stego_lsb import Classification as C, LSBConfig, analyze_png, analyze_png_bytes
from tools.stego_samples import carrier, embed_lsb, encode, samples


@pytest.fixture(scope="module")
def corpus():
    return samples()


def test_original_and_embedded_comparison(corpus):
    original = analyze_png_bytes(corpus["original"])
    modified = analyze_png_bytes(corpus["lsb_full"])
    assert original.classification == C.SIN_INDICIOS
    assert modified.classification == C.SOSPECHOSO
    for a, b in zip(original.channels, modified.channels):
        assert a.chi_square == a.samples == 65536
        assert a.degrees_of_freedom == b.degrees_of_freedom == 128
        assert a.p_value == 0  # Underflow numérico de la cola, no certeza absoluta.
        assert b.chi_square < a.chi_square
        assert b.p_value > a.p_value
        assert 0.48 < b.lsb_one_fraction < 0.52


def test_embedding_is_independent_and_recoverable():
    original = carrier()
    payload = b"LSB: datos reproducibles"
    modified = embed_lsb(original, payload)
    recovered = bytes(sum((modified[i * 8 + j] & 1) << (7 - j) for j in range(8))
                      for i in range(len(payload)))
    assert recovered == payload
    assert all((a & 254) == (b & 254) for a, b in zip(original, modified))
    assert original[len(payload) * 8:] == modified[len(payload) * 8:]


def test_analytical_chi_square_two_pairs():
    # Por canal: par (0,1)=(30,10), par (2,3)=(20,20).
    # X²=20²/40+0²/40=10; df=2; sf=exp(-10/2).
    values = [0] * 30 + [1] * 10 + [2] * 20 + [3] * 20
    image = encode(bytes(v for x in values for v in (x, x, x)), size=(10, 8))
    result = analyze_png_bytes(image, LSBConfig(min_pixels=80, min_pairs=2))
    for channel in result.channels:
        assert channel.chi_square == 10
        assert channel.degrees_of_freedom == 2
        assert channel.p_value == pytest.approx(math.exp(-5))
        assert channel.coverage == 1
    assert result.classification == C.NO_CONCLUYENTE
    # Política configurable aplicada al mismo cálculo, sin alterar indicadores.
    changed = analyze_png_bytes(image, LSBConfig(min_pixels=80, min_pairs=2, suspicious_p=0.005))
    assert changed.classification == C.SOSPECHOSO
    assert changed.channels == result.channels


def test_fake_extension(tmp_path):
    path = tmp_path / "fake.png"
    path.write_bytes(b"No es una imagen")
    assert analyze_png(path).classification == C.ERROR


def test_other_real_format():
    output = BytesIO()
    Image.new("RGB", (64, 64)).save(output, format="JPEG")
    assert analyze_png_bytes(output.getvalue()).reason == "firma_no_png"


@pytest.mark.parametrize("damage", ["crc", "truncate", "iend", "trailing", "deflate"])
def test_corrupt_png(corpus, damage):
    data = bytearray(corpus["original"])
    if damage == "crc":
        data[29] ^= 1
    elif damage == "truncate":
        data = data[:50]
    elif damage == "iend":
        data = data[:-12]
    elif damage == "trailing":
        data += b"extra"
    else:
        offset = data.index(b"IDAT")
        length = int.from_bytes(data[offset - 4:offset], "big")
        data[offset + 4:offset + 4 + length] = b"\x00" * length
        data[offset + 4 + length:offset + 8 + length] = struct.pack(
            ">I", zlib.crc32(data[offset:offset + 4 + length]) & 0xffffffff)
    assert analyze_png_bytes(bytes(data)).classification == C.ERROR


def test_byte_limit_and_bounded_path_read(tmp_path, corpus):
    data = corpus["original"]
    path = tmp_path / "large.png"
    path.write_bytes(data)
    config = LSBConfig(max_bytes=len(data) - 1)
    assert analyze_png(path, config).reason == "limite_bytes"
    assert analyze_png_bytes(data, config).reason == "limite_bytes"
    assert analyze_png_bytes(data, replace(config, max_bytes=len(data))).classification != C.ERROR


@pytest.mark.parametrize("limit", ["max_width", "max_height", "max_pixels"])
def test_dimension_limits_before_decode(corpus, monkeypatch, limit):
    def forbidden(*args, **kwargs):
        pytest.fail("No debe decodificar una imagen que excede límites")
    monkeypatch.setattr(Image, "open", forbidden)
    assert analyze_png_bytes(corpus["original"], replace(LSBConfig(), **{limit: 100})).reason == "limite_dimensiones_o_pixeles"


@pytest.mark.parametrize("name", ["tiny", "flat"])
def test_insufficient_evidence(corpus, name):
    result = analyze_png_bytes(corpus[name])
    assert result.classification == C.NO_CONCLUYENTE
    assert not all(c.sufficient for c in result.channels)


def test_low_coverage():
    # Muchos pares escasos excluidos: 32 pares elegibles y cobertura <90%.
    values = [0] * 200 + [x for x in range(2, 64, 2) for _ in range(10)]
    values += [x for x in range(64, 256, 2) for _ in range(9)]
    raw = bytes(v for x in values for v in (x, x, x))
    image = encode(raw, size=(len(values), 1))
    result = analyze_png_bytes(image, LSBConfig(min_pixels=1, min_pairs=1))
    assert all(c.coverage < 0.9 and c.eligible_pairs >= 1 for c in result.channels)
    assert result.classification == C.NO_CONCLUYENTE


def test_exactly_balanced_pairs():
    # 128 pares con 32 observaciones de cada miembro: X²=0 y sf=1.
    raw = bytes(v for x in range(256) for _ in range(32) for v in (x, x, x))
    result = analyze_png_bytes(encode(raw, size=(128, 64)))
    assert result.classification == C.SOSPECHOSO
    assert all(c.chi_square == 0 and c.p_value == 1 for c in result.channels)


@pytest.mark.parametrize("mode", ["L", "P", "I;16"])
def test_unsupported_png_modes(mode):
    output = BytesIO()
    Image.new(mode, (128, 128)).save(output, format="PNG")
    assert analyze_png_bytes(output.getvalue()).classification == C.NO_CONCLUYENTE


def test_rgba_ignores_alpha(corpus):
    with Image.open(BytesIO(corpus["original"])) as image:
        rgba = image.convert("RGBA")
        rgba.putalpha(0)
        output = BytesIO()
        rgba.save(output, format="PNG")
    assert analyze_png_bytes(output.getvalue()).channels == analyze_png_bytes(corpus["original"]).channels


def test_animated_png():
    output = BytesIO()
    Image.new("RGB", (64, 64)).save(output, format="PNG", save_all=True,
        append_images=[Image.new("RGB", (64, 64), "white")])
    assert analyze_png_bytes(output.getvalue()).classification == C.NO_CONCLUYENTE


def test_observed_false_positive_and_false_negative(corpus):
    assert analyze_png_bytes(corpus["noise_without_payload"]).classification == C.SOSPECHOSO
    assert analyze_png_bytes(corpus["lsb_small"]).classification == C.SIN_INDICIOS


def test_reproducible_serializable_report(corpus):
    report = {name: analyze_png_bytes(data).to_dict() for name, data in corpus.items()}
    assert report == {name: analyze_png_bytes(data).to_dict() for name, data in samples().items()}
    print("\nLSB_REPORT=" + json.dumps(report, ensure_ascii=True, allow_nan=False))


def test_unreadable_file(tmp_path):
    assert analyze_png(tmp_path / "missing.png").reason == "archivo_no_legible"


@pytest.mark.parametrize("options", [dict(max_bytes=0), dict(min_pair_count=2),
    dict(min_pairs=129), dict(min_coverage=1.1), dict(suspicious_p=0.0001)])
def test_invalid_configuration(options):
    with pytest.raises(ValueError):
        LSBConfig(**options)
