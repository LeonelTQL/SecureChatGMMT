import hashlib
import io
import time
from dataclasses import replace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from PIL import Image

from app.main import create_app
from app.security import Denied, Settings, SecurityMiddleware
from app.detector_adapter import validate_result


@pytest.fixture(scope="session")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())


def token(keys, **overrides):
    claims = {"sub": str(uuid4()), "jti": str(uuid4()), "iat": int(time.time()), "exp": int(time.time()) + 900,
        "iss": "ms-users-auth", "aud": "chat-seguro"}
    claims.update(overrides)
    return jwt.encode(claims, keys[0], algorithm="RS256")


def image(format="PNG"):
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), (80, 40, 10)).save(buffer, format=format)
    return buffer.getvalue()


@pytest.fixture
def setup(tmp_path, keys):
    settings = Settings("https://auth.test", "s" * 48, keys[1], "unused", tmp_path)
    state = {"allowed": True, "scope": "own", "calls": 0, "detector_calls": 0}
    async def decider(encoded, action, resource_id):
        state["calls"] += 1
        if state.get("down"): raise Denied(503, "AUTH no disponible")
        claims = jwt.decode(encoded, keys[1], algorithms=["RS256"], audience="chat-seguro", issuer="ms-users-auth")
        return {"subject_id": claims["sub"], "allowed": state["allowed"], "scope": state["scope"], "action": action, "resource_id": resource_id}
    async def detector(path):
        # Doble exclusivo de pruebas del contrato. No es evidencia de detección real.
        state["detector_calls"] += 1
        assert path.is_file()
        return {"status": "no_concluyente", "technique": "test_double", "indicators": {"sample": 1}, "limitations": "Solo prueba del contrato"}
    app = create_app(settings, decider, detector)
    with TestClient(app) as client:
        yield settings, state, app, client, decider


@pytest.mark.parametrize("header", [None, "Basic abc", "Bearer", "Bearer invalid"])
def test_missing_or_bad_auth(setup, header):
    settings, state, app, client, _ = setup
    response = client.post("/api/steganography/analyze", headers={"Authorization": header} if header else {}, files={"file": ("x.png", image(), "image/png")})
    assert response.status_code == 401
    assert state["detector_calls"] == 0
    assert not list(app.state.storage.quarantine.iterdir())


@pytest.mark.parametrize("claims", [{"exp": 1}, {"iss": "other"}, {"aud": "other"}, {"sub": "not-a-uuid"}, {"jti": None}, {"exp": int(time.time()) + 3600}])
def test_invalid_claims(setup, keys, claims):
    _, state, _, client, _ = setup
    response = client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + token(keys, **claims)})
    assert response.status_code == 401
    assert state["calls"] == 0


def test_different_signature_and_none(setup, keys):
    _, _, _, client, _ = setup
    different = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = different.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    for encoded in [token((private, keys[1])), jwt.encode({"sub": str(uuid4())}, "", algorithm="none")]:
        assert client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + encoded}).status_code == 401


def test_denial_revocation_and_auth_failure_do_not_process(setup, keys):
    _, state, app, client, _ = setup
    encoded = token(keys)
    headers = {"Authorization": "Bearer " + encoded, "X-Role": "ADMIN"}
    state["allowed"] = False
    assert client.post("/api/steganography/analyze", headers=headers).status_code == 403
    state["allowed"] = True
    good = client.post("/api/steganography/analyze", headers=headers, files={"file": ("x.png", image(), "image/png")})
    assert good.status_code == 200
    state["allowed"] = False
    assert client.post("/api/steganography/analyze", headers=headers).status_code == 403
    state["down"] = True
    assert client.post("/api/steganography/analyze", headers=headers).status_code == 503
    assert state["detector_calls"] == 1


@pytest.mark.parametrize("filename,mime,data", [("x.jpg", "image/jpeg", b"x"), ("x.png", "text/plain", b"x"),
    ("x.png", "image/png", b"not an image"), ("x.png", "image/png", b""), ("x.bmp", "image/bmp", image())])
def test_file_validation(setup, keys, filename, mime, data):
    _, state, _, client, _ = setup
    response = client.post("/api/steganography/analyze", headers={"Authorization": "Bearer " + token(keys)}, files={"file": (filename, data, mime)})
    assert response.status_code == 415
    assert state["detector_calls"] == 0


@pytest.mark.parametrize("format,mime", [("PNG", "image/png"), ("BMP", "image/bmp")])
def test_storage_hash_results_ownership_and_admin(setup, keys, format, mime):
    _, state, app, client, _ = setup
    owner = str(uuid4()); data = image(format)
    headers = {"Authorization": "Bearer " + token(keys, sub=owner)}
    response = client.post("/api/steganography/analyze", headers=headers, files={"file": ("../../original." + format.lower(), data, mime)})
    assert response.status_code == 200
    result = response.json(); analysis_id = result["analysis_id"]
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["user_id"] == owner
    assert "/" not in result["filename"]
    assert (app.state.storage.quarantine / analysis_id).read_bytes() == data
    assert result["action"] == "cuarentena"
    assert client.get("/api/steganography/results/" + analysis_id, headers=headers).status_code == 200
    other = {"Authorization": "Bearer " + token(keys)}
    assert client.get("/api/steganography/results/" + analysis_id, headers=other).status_code == 403
    state["scope"] = "all"
    assert client.get("/api/steganography/results/" + analysis_id, headers=other).status_code == 200
    assert client.get("/storage/quarantine/" + analysis_id, headers=headers).status_code == 404


def test_missing_detector_quarantines_never_marks_clean(tmp_path, setup, keys):
    from app.detector_adapter import DetectorUnavailable
    settings, _, _, _, decider = setup
    async def unavailable(path):
        raise DetectorUnavailable("test unavailable")
    app = create_app(replace(settings, storage=tmp_path / "without_detector"), decider, unavailable)
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer " + token(keys)}
        response = client.post("/api/steganography/analyze", headers=headers, files={"file": ("x.png", image(), "image/png")})
        assert response.status_code == 503
        assert response.json()["status"] == "error"
        assert response.json()["action"] == "cuarentena"
        assert client.get("/api/steganography/results/" + response.json()["analysis_id"], headers=headers).status_code == 200


def test_size_and_pixel_limits(setup, keys, tmp_path):
    settings, state, _, _, decider = setup
    app = create_app(replace(settings, storage=tmp_path / "limits", max_file_bytes=100, max_pixels=10), decider)
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer " + token(keys)}
        assert client.post("/api/steganography/analyze", headers=headers, files={"file": ("x.png", b"x" * 101, "image/png")}).status_code == 413
        assert client.post("/api/steganography/analyze", headers=headers, files={"file": ("x.png", image(), "image/png")}).status_code == 413
        assert client.post("/api/steganography/analyze", headers=headers, content=b"x" * 70000).status_code == 413


@pytest.mark.parametrize("result", [{}, {"status": "CLEAN"}, {"status": "sin_indicios", "technique": "x", "indicators": {}, "limitations": "x"},
    {"status": "sin_indicios", "technique": "x", "indicators": {"score": float('nan')}, "limitations": "x"}])
def test_reject_fake_or_invalid_detector_result(result):
    with pytest.raises(ValueError): validate_result(result)


def test_openapi_has_required_routes(setup):
    _, _, _, client, _ = setup
    schema = client.get("/openapi.json").json()
    assert "/api/steganography/analyze" in schema["paths"]
    assert "/api/steganography/results/{analysis_id}" in schema["paths"]
    assert "BearerAuth" in schema["components"]["securitySchemes"]


def test_chunked_upload_limit_without_content_length(setup, keys):
    _, _, _, client, _ = setup
    def chunks():
        yield b'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="big.png"\r\nContent-Type: image/png\r\n\r\n'
        for _ in range(90): yield b'x' * 65536
        yield b'\r\n--BOUND--\r\n'
    response = client.post('/api/steganography/analyze', headers={
        'Authorization': 'Bearer ' + token(keys), 'Content-Type': 'multipart/form-data; boundary=BOUND'}, content=chunks())
    assert response.status_code == 413


@pytest.mark.parametrize('failure', ['timeout', 'invalid'])
def test_failed_detector_keeps_quarantine(setup, keys, tmp_path, failure):
    settings, _, _, _, decider = setup
    async def broken(path):
        if failure == 'timeout': raise TimeoutError('no incluir detalles internos')
        return {'status': 'sin_indicios', 'technique': 'broken', 'indicators': {}, 'limitations': 'invalid'}
    app = create_app(replace(settings, storage=tmp_path / failure), decider, broken)
    with TestClient(app) as client:
        response = client.post('/api/steganography/analyze', headers={'Authorization': 'Bearer ' + token(keys)}, files={'file': ('x.png', image(), 'image/png')})
        assert response.status_code == 503
        assert response.json()['status'] == 'error'
        assert response.json()['action'] == 'cuarentena'
        assert 'no incluir' not in response.text
        assert (app.state.storage.quarantine / response.json()['analysis_id']).is_file()


def test_retention_purges_files_but_preserves_record(setup, keys):
    import os
    _, _, app, client, _ = setup
    response = client.post('/api/steganography/analyze', headers={'Authorization': 'Bearer ' + token(keys)}, files={'file': ('x.png', image(), 'image/png')})
    analysis_id = response.json()['analysis_id']
    path = app.state.storage.quarantine / analysis_id
    old = time.time() - 2 * 86400
    os.utime(path, (old, old))
    assert app.state.storage.purge(1) == 1
    assert not path.exists()
    assert app.state.storage.get(analysis_id)['analysis_id'] == analysis_id


def test_authorization_happens_before_any_body_read(keys, tmp_path):
    import asyncio
    calls = {"body": 0, "app": 0}
    async def app(scope, receive, send): calls["app"] += 1
    async def decider(token, action, resource_id): raise Denied(503, "AUTH unavailable")
    async def receive(): calls["body"] += 1; return {"type": "http.request", "body": b"sensitive"}
    messages = []
    async def send(message): messages.append(message)
    settings = Settings("https://auth.test", "s" * 48, keys[1], "unused", tmp_path)
    scope = {"type": "http", "method": "POST", "path": "/api/steganography/analyze",
        "headers": [(b"authorization", ("Bearer " + token(keys)).encode())]}
    asyncio.run(SecurityMiddleware(app, settings, decider)(scope, receive, send))
    assert messages[0]["status"] == 503
    assert calls == {"body": 0, "app": 0}
