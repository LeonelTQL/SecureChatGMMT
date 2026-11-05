from dataclasses import replace
from io import BytesIO
import hashlib
import struct
import zlib

from fastapi.testclient import TestClient
from PIL import Image, ImageFile
import pytest

from app.image_validation import ImageLimits, validate_image
from app.main import create_app
from tools.stego_samples import samples


@pytest.fixture(scope="module")
def images():
    output = BytesIO()
    Image.new("RGB", (64, 64), "blue").save(output, format="JPEG")
    return {**samples(), "jpeg": output.getvalue()}


def write_image(tmp_path, data):
    path = tmp_path / "private-uuid"
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("name,filename,mime", [
    ("original", "a.PNG", "image/png"), ("jpeg", "a.jpg", "image/jpeg"),
    ("jpeg", "a.JPEG", "image/jpeg")])
def test_valid_formats_and_content_mime(tmp_path, images, name, filename, mime):
    result = validate_image(write_image(tmp_path, images[name]), filename, ImageLimits())
    assert result.valid and result.mime == mime
    assert result.width > 0 and result.height > 0


@pytest.mark.parametrize("name,filename,reason", [
    ("original", "a.jpg", "image_extension_content_mismatch"),
    ("jpeg", "a.png", "image_extension_content_mismatch"),
    ("original", "a.gif", "unsupported_image_extension")])
def test_extension_agrees_with_content(tmp_path, images, name, filename, reason):
    result = validate_image(write_image(tmp_path, images[name]), filename, ImageLimits())
    assert not result.valid and result.reason == reason


@pytest.mark.parametrize("data", [b"<html>fake</html>", b"GIF89a", b"\xff\xd8not_jpeg"])
def test_forged_signature(tmp_path, data):
    result = validate_image(write_image(tmp_path, data), "fake.png", ImageLimits())
    assert not result.valid and result.reason == "unsupported_image_signature"


@pytest.mark.parametrize("kind", ["png_truncated", "png_crc", "png_deflate", "jpeg_truncated", "jpeg_entropy"])
def test_corrupt_and_truncated(tmp_path, images, kind):
    data = bytearray(images["jpeg"] if kind.startswith("jpeg") else images["original"])
    if kind.endswith("truncated"):
        data = data[:-25]
    elif kind == "png_crc":
        data[29] ^= 1
    elif kind == "png_deflate":
        offset = data.index(b"IDAT")
        length = int.from_bytes(data[offset - 4:offset], "big")
        data[offset + 4:offset + 4 + length] = bytes(length)
        data[offset + 4 + length:offset + 8 + length] = struct.pack(
            ">I", zlib.crc32(data[offset:offset + 4 + length]) & 0xffffffff)
    else:
        # Mantiene EOI, pero elimina el contenido comprimido tras SOS.
        offset = data.index(b"\xff\xda")
        data = data[:offset + 2] + b"\xff\xd9"
    suffix = ".jpg" if kind.startswith("jpeg") else ".png"
    result = validate_image(write_image(tmp_path, bytes(data)), "bad" + suffix, ImageLimits())
    assert not result.valid and result.reason == "image_malformed"


def test_size_boundaries_and_default_five_mib(tmp_path, images, monkeypatch):
    data = images["original"]
    path = write_image(tmp_path, data)
    assert ImageLimits().max_bytes == 5 * 1024 * 1024
    assert validate_image(path, "a.png", ImageLimits(max_bytes=len(data))).valid
    assert validate_image(path, "a.png", ImageLimits(max_bytes=len(data) - 1)).reason == "image_too_large"
    path.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
    def forbidden(*args, **kwargs):
        pytest.fail("No debe decodificar archivos excesivos")
    monkeypatch.setattr(Image, "open", forbidden)
    assert validate_image(path, "a.png", ImageLimits()).reason == "image_too_large"


@pytest.mark.parametrize("field", ["max_width", "max_height", "max_pixels"])
def test_dimensions_before_pixel_decode(tmp_path, images, monkeypatch, field):
    from PIL import PngImagePlugin, JpegImagePlugin
    def forbidden(*args, **kwargs):
        pytest.fail("No debe cargar píxeles que superen límites")
    monkeypatch.setattr(PngImagePlugin.PngImageFile, "load", forbidden)
    monkeypatch.setattr(JpegImagePlugin.JpegImageFile, "load", forbidden)
    limits = replace(ImageLimits(), **{field: 10})
    for name, suffix in [("original", ".png"), ("jpeg", ".jpg")]:
        result = validate_image(write_image(tmp_path, images[name]), "a" + suffix, limits)
        assert not result.valid and result.reason == "image_dimensions_exceeded"


@pytest.mark.parametrize("dimension", [10000, 20000])
def test_pillow_decompression_warning_and_error_are_rejected(tmp_path, images, dimension):
    # Modifica sólo el SOF: no genera ni descomprime una imagen gigante.
    data = bytearray(images["jpeg"])
    offset = data.index(b"\xff\xc0")
    data[offset + 5:offset + 9] = struct.pack(">HH", dimension, dimension)
    limits = ImageLimits(max_width=30000, max_height=30000, max_pixels=900_000_000)
    result = validate_image(write_image(tmp_path, bytes(data)), "bomb.jpg", limits)
    assert not result.valid and result.reason == "image_decompression_bomb"


def test_compressed_png_declaring_huge_dimensions(tmp_path, images, monkeypatch):
    data = bytearray(images["original"])
    data[16:24] = struct.pack(">II", 100000, 100000)
    data[29:33] = struct.pack(">I", zlib.crc32(data[12:29]) & 0xffffffff)
    def forbidden(*args, **kwargs):
        pytest.fail("La bomba PNG debe rechazarse antes de Pillow")
    monkeypatch.setattr(Image, "open", forbidden)
    result = validate_image(write_image(tmp_path, bytes(data)), "bomb.png", ImageLimits())
    assert result.reason == "image_dimensions_exceeded"


def test_unsafe_truncation_configuration_fails_closed(tmp_path, images, monkeypatch):
    monkeypatch.setattr(ImageFile, "LOAD_TRUNCATED_IMAGES", True)
    result = validate_image(write_image(tmp_path, images["original"]), "a.png", ImageLimits())
    assert result.reason == "unsafe_image_decoder_configuration"


@pytest.mark.parametrize("name,filename,declared,reason,mime", [
    ("original", "a.png", "application/x-executable", "additional_security_checks_required", "image/png"),
    ("jpeg", "a.jpg", "image/png", "jpeg_detector_not_available", "image/jpeg"),
    ("original", "a.jpg", "image/jpeg", "image_extension_content_mismatch", "image/png"),
    ("jpeg", "a.png", "image/png", "image_extension_content_mismatch", "image/jpeg"),
    ("lsb_full", "a.png", "image/png", "lsb_suspicious", "image/png"),
])
def test_http_content_validation_and_quarantine(tmp_path, images, name, filename, declared, reason, mime):
    data = images[name]
    with TestClient(create_app(tmp_path)) as client:
        response = client.post("/files/upload", files={"file": (filename, data, declared)})
        assert response.status_code == 202
        initial = response.json()
        record = client.get(f'/files/{initial["id"]}/status').json()
        assert record["sha256"] == hashlib.sha256(data).hexdigest()
        assert record["reason"] == reason
        assert record["analysis"]["validation"]["mime"] == mime
        assert record["status"] == "QUARANTINED"
        assert record["classification"] != "CLEAN"
        assert client.get(f'/files/{record["id"]}/content').status_code == 423


@pytest.mark.parametrize("name", ["jpeg", "bad", "oversize", "dimensions"])
def test_invalid_or_jpeg_never_reaches_even_clean_injected_engine(tmp_path, images, name):
    class MustNotRun:
        def analyze(self, path, sha256):
            pytest.fail("La validación debe bloquear antes del motor")
    data = images["jpeg"] if name == "jpeg" else images["original"]
    filename = "a.jpg" if name == "jpeg" else "a.png"
    limits = ImageLimits()
    if name == "bad":
        data = data[:50]
    elif name == "oversize":
        limits = replace(limits, max_bytes=len(data) - 1)
    elif name == "dimensions":
        limits = replace(limits, max_width=1)
    with TestClient(create_app(tmp_path, MustNotRun(), image_limits=limits)) as client:
        response = client.post("/files/upload", files={"file": (filename, data)})
        if name == "oversize":
            assert response.status_code == 413
            assert response.json()["detail"] == "image_too_large"
            assert list((tmp_path / "objects").iterdir()) == []
            return
        initial = response.json()
        record = client.get(f'/files/{initial["id"]}/status').json()
        assert record["classification"] == "INCONCLUSIVE"
        assert record["status"] == "QUARANTINED"
        assert client.get(f'/files/{record["id"]}/content').status_code == 423


def test_validation_policy_from_environment(tmp_path, images, monkeypatch):
    monkeypatch.setenv("IMAGE_MAX_BYTES", "100")
    monkeypatch.setenv("IMAGE_MAX_WIDTH", "1000")
    monkeypatch.setenv("IMAGE_MAX_HEIGHT", "1001")
    monkeypatch.setenv("IMAGE_MAX_PIXELS", "100000")
    assert ImageLimits.from_env() == ImageLimits(100, 1000, 1001, 100000)
    with TestClient(create_app(tmp_path)) as client:
        data = images["original"]
        response = client.post("/files/upload", files={"file": ("a.png", data)})
        assert response.status_code == 413
        assert response.json()["detail"] == "image_too_large"
        assert list((tmp_path / "objects").iterdir()) == []


def test_default_image_limit_does_not_change_global_transfer_limit(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        response = client.post("/files/upload", files={"file": (
            "large.png", b"x" * (5 * 1024 * 1024 + 1), "image/png")})
        # Menor que el límite global de 10 MiB, mayor que el de imágenes.
        assert response.status_code == 413
        assert response.json()["detail"] == "image_too_large"
        assert list((tmp_path / "objects").iterdir()) == []


@pytest.mark.parametrize("field", ["max_bytes", "max_width", "max_height", "max_pixels"])
def test_invalid_limit_configuration(field):
    with pytest.raises(ValueError):
        ImageLimits(**{field: 0})
