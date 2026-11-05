import asyncio
import hashlib
import io
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from PIL import Image, UnidentifiedImageError

from .detector_adapter import DetectorUnavailable, analyze as run_detector, validate_result
from .security import AuthClient, Denied, SecurityMiddleware, Settings, audit
from .storage import Storage
from .models import AnalysisRecord


def load_settings():
    return Settings(auth_url=os.environ.get("AUTH_URL", "https://auth-service:3001"),
        service_token=os.environ["STEGO_SERVICE_TOKEN"],
        public_key=Path(os.environ.get("JWT_PUBLIC_KEY_PATH", "/run/public/jwt-public.pem")).read_text(),
        ca_file=os.environ.get("AUTH_CA_PATH", "/run/public/ca.pem"),
        storage=Path(os.environ.get("STORAGE_PATH", "/app/storage")))


def create_app(settings=None, decider=None, detector=None):
    settings = settings or load_settings()
    storage = Storage(settings.storage)
    detector = detector or run_detector
    app = FastAPI(title="STEGO — Transferencia y gestión segura", version="1.0.0")
    app.state.storage = storage
    app.add_middleware(SecurityMiddleware, settings=settings, decider=decider or AuthClient(settings))
    gate = asyncio.Semaphore(2)

    @app.exception_handler(Denied)
    async def denied_handler(request, error):
        return JSONResponse(status_code=error.status, content={"detail": error.detail})

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/health")
    def health():
        with storage.connect() as db: db.execute("SELECT 1")
        return {"service": "STEGO", "status": "ok", "detector": "external_component_required"}

    @app.post("/api/steganography/analyze", response_model=AnalysisRecord, responses={401: {}, 403: {}, 413: {}, 415: {}, 503: {}},
        openapi_extra={"security": [{"BearerAuth": []}]})
    async def analyze_image(request: Request, file: UploadFile = File(...)):
        identity = request.state.identity
        # Máximo dos archivos en validación/procesamiento simultáneos.
        if gate.locked(): raise HTTPException(503, "Capacidad de procesamiento ocupada")
        async with gate:
            if storage.bytes_used() >= settings.max_storage_bytes: raise HTTPException(503, "Almacenamiento lleno")
            filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
            extension = Path(filename).suffix.lower()
            expected = {".png": ("image/png", "PNG"), ".bmp": ("image/bmp", "BMP")}
            if extension not in expected or file.content_type != expected[extension][0]:
                raise HTTPException(415, "Solo PNG o BMP con MIME correspondiente")
            data = await file.read(settings.max_file_bytes + 1)
            await file.close()
            if len(data) > settings.max_file_bytes: raise HTTPException(413, "Imagen demasiado grande")
            if not data: raise HTTPException(415, "Imagen vacía")
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", Image.DecompressionBombWarning)
                    with Image.open(io.BytesIO(data)) as image:
                        if image.format != expected[extension][1]: raise ValueError("Formato discordante")
                        if image.width * image.height > settings.max_pixels: raise HTTPException(413, "Demasiados píxeles")
                        image.verify()
                    # verify no decodifica todos los formatos; forzar decodificación con límite de píxeles.
                    with Image.open(io.BytesIO(data)) as image: image.load()
            except HTTPException: raise
            except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombWarning, Image.DecompressionBombError):
                raise HTTPException(415, "Imagen corrupta o formato discordante") from None
            if storage.bytes_used() + len(data) > settings.max_storage_bytes: raise HTTPException(503, "Almacenamiento lleno")
            analysis_id = str(uuid4())
            path = storage.quarantine / analysis_id
            with path.open("xb") as stream:
                os.chmod(path, 0o600); stream.write(data)
            record = {"analysis_id": analysis_id, "user_id": identity["subject_id"], "filename": filename[:200],
                "sha256": hashlib.sha256(data).hexdigest(), "created_at": datetime.now(timezone.utc).isoformat(),
                "technique": "pending", "indicators": {}, "status": "pending", "action": "cuarentena", "limitations": "Pendiente de análisis"}
            storage.save(record)
            try:
                result = validate_result(await detector(path))
                record.update(result)
                record["action"] = "advertencia" if result["status"] == "sin_indicios" else "cuarentena"
                storage.save(record)
                audit("analysis.completed", analysis_id=analysis_id, user_id=identity["subject_id"], status=record["status"])
                if record["status"] == "error": return JSONResponse(status_code=503, content=record)
                return record
            except Exception as error:
                record.update(status="error", technique="unavailable" if isinstance(error, DetectorUnavailable) else "failed",
                    limitations="Detector no disponible o ejecución fallida; archivo permanece en cuarentena")
                storage.save(record)
                audit("analysis.failed", analysis_id=analysis_id, user_id=identity["subject_id"])
                return JSONResponse(status_code=503, content=record)

    @app.get("/api/steganography/results/{analysis_id}", response_model=AnalysisRecord, responses={401: {}, 403: {}, 404: {}, 503: {}},
        openapi_extra={"security": [{"BearerAuth": []}]})
    def result(analysis_id: str, request: Request):
        record = storage.get(analysis_id)
        if not record: raise HTTPException(404, "Análisis no encontrado")
        identity = request.state.identity
        if identity["scope"] != "all" and record["user_id"] != identity["subject_id"]:
            audit("result.denied", user_id=identity["subject_id"], analysis_id=analysis_id)
            raise HTTPException(403, "Acceso al resultado denegado")
        audit("result.read", user_id=identity["subject_id"], analysis_id=analysis_id)
        return record

    original_openapi = app.openapi
    def openapi():
        schema = original_openapi()
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["BearerAuth"] = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        return schema
    app.openapi = openapi
    return app
