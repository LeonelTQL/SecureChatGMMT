import hashlib
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException

from .analyzer import Analyzer, Classification, UnconfiguredAnalyzer
from .storage import Storage


class BodyTooLarge(MultiPartException):
    def __init__(self):
        super().__init__("file_too_large")


class BodyLimit:
    """Limita también cuerpos sin Content-Length, antes del parser multipart."""
    def __init__(self, app, limit: int):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "invalid_content_length"}, status_code=400)(scope, receive, send)
        if length > self.limit:
            return await JSONResponse({"detail": "file_too_large"}, status_code=413)(scope, receive, send)
        consumed = 0

        async def limited_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > self.limit:
                scope["body_too_large"] = True
                raise BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except BodyTooLarge:
            await JSONResponse({"detail": "file_too_large"}, status_code=413)(scope, receive, send)


class FileStatus(BaseModel):
    id: UUID
    filename: str
    size: int
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["PENDING", "ANALYZING", "APPROVED", "QUARANTINED"]
    classification: Classification | None
    reason: str | None
    created_at: str
    updated_at: str


def create_app(storage_root: Path | None = None, analyzer: Analyzer | None = None,
               max_file_bytes: int | None = None) -> FastAPI:
    root = storage_root if storage_root is not None else Path(os.getenv("FILE_STORAGE_ROOT", "storage"))
    limit = max_file_bytes if max_file_bytes is not None else int(os.getenv("MAX_FILE_BYTES", "10485760"))
    if limit <= 0:
        raise ValueError("MAX_FILE_BYTES must be positive")
    engine = analyzer if analyzer is not None else UnconfiguredAnalyzer()

    @asynccontextmanager
    async def lifespan(application):
        application.state.storage = Storage(root)
        yield

    application = FastAPI(title="SecureChat - Transferencia segura de archivos", lifespan=lifespan)
    application.add_middleware(BodyLimit, limit=limit + 65536)

    @application.exception_handler(StarletteHTTPException)
    async def http_error(request, exception):
        if request.scope.get("body_too_large"):
            return JSONResponse({"detail": "file_too_large"}, status_code=413)
        return await http_exception_handler(request, exception)

    @application.get("/health")
    def health():
        return {"service": "file-analyzer", "status": "ok", "implementation": "file-management"}

    @application.post("/files/upload", status_code=202, response_model=FileStatus,
                      responses={400: {"description": "Multipart inválido"},
                                 413: {"description": "Límite de tamaño excedido"},
                                 415: {"description": "Extensión no admitida"}},
                      openapi_extra={"requestBody": {"required": True, "content": {
                          "multipart/form-data": {"schema": {"type": "object",
                              "required": ["file"], "properties": {
                                  "file": {"type": "string", "format": "binary"}}}}}}})
    async def upload(request: Request, tasks: BackgroundTasks, response: Response):
        async with request.form(max_files=1, max_fields=0) as form:
            file = form.get("file")
            if len(form.multi_items()) != 1 or not isinstance(file, UploadFile):
                raise HTTPException(422, "one_file_required")
            filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1][:255]
            if Path(filename).suffix.lower() not in {".jpg", ".jpeg", ".png"}:
                raise HTTPException(415, "unsupported_file_extension")
            file_id = str(uuid4())
            store = request.app.state.storage
            path = store.path(file_id)
            size, sha = 0, hashlib.sha256()
            try:
                with path.open("xb") as destination:
                    os.chmod(path, 0o600)
                    while chunk := await file.read(65536):
                        size += len(chunk)
                        if size > limit:
                            raise HTTPException(413, "file_too_large")
                        sha.update(chunk)
                        destination.write(chunk)
                    if not size:
                        raise HTTPException(422, "empty_file")
                    destination.flush()
                    os.fsync(destination.fileno())
                record = store.add(file_id, filename, size, sha.hexdigest())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        tasks.add_task(store.process, file_id, engine)
        # Relativo al path de carga: funciona también tras /api del proxy.
        response.headers["Location"] = f"./{file_id}/status"
        return record

    @application.get("/files/{file_id}/status", response_model=FileStatus,
                     responses={404: {"description": "Archivo inexistente"}})
    def status(file_id: UUID, request: Request):
        record = request.app.state.storage.get(str(file_id))
        if record is None:
            raise HTTPException(404, "file_not_found")
        return record

    @application.get("/files/{file_id}/content", response_class=Response,
                     responses={200: {"content": {"application/octet-stream": {
                         "schema": {"type": "string", "format": "binary"}}}},
                         404: {"description": "Archivo inexistente"},
                         423: {"description": "Archivo bloqueado o integridad inválida"}})
    def content(file_id: UUID, request: Request):
        store = request.app.state.storage
        record = store.get(str(file_id))
        if record is None:
            raise HTTPException(404, "file_not_found")
        if record["status"] != "APPROVED":
            raise HTTPException(423, "file_blocked")
        try:
            # Servir los mismos bytes verificados evita reabrir un path después
            # del hash. La copia en memoria está acotada por el límite de carga.
            with store.path(str(file_id)).open("rb") as source:
                data = source.read(limit + 1)
            if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("integrity")
        except (OSError, ValueError):
            store.quarantine(str(file_id), "integrity_mismatch")
            raise HTTPException(423, "file_blocked") from None
        return Response(data, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{file_id}.bin"',
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        })

    return application


app = create_app()
