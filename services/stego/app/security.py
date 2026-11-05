"""JWT local + autorización remota antes de consumir el cuerpo de la petición."""
import json
import logging
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import httpx
import jwt
from starlette.exceptions import HTTPException as HttpError

log = logging.getLogger("stego.audit")


def audit(event, **data):
    log.warning(json.dumps({"service": "STEGO", "event": event, **data}))


class Denied(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail


@dataclass(frozen=True)
class Settings:
    auth_url: str
    service_token: str
    public_key: str
    ca_file: str
    storage: Path
    max_file_bytes: int = 5 * 1024 * 1024
    max_pixels: int = 20_000_000
    max_storage_bytes: int = 256 * 1024 * 1024

    def __post_init__(self):
        if not self.auth_url.startswith("https://") or len(self.service_token) < 32:
            raise ValueError("AUTH requiere HTTPS y credencial de servicio aleatoria")


class AuthClient:
    def __init__(self, settings):
        self.settings = settings

    async def __call__(self, token, action, resource_id):
        context = ssl.create_default_context(cafile=self.settings.ca_file)
        try:
            async with httpx.AsyncClient(verify=context, timeout=3, follow_redirects=False, trust_env=False) as client:
                response = await client.post(self.settings.auth_url + "/internal/authorization/check",
                    headers={"X-Service-Token": self.settings.service_token},
                    json={"subject_token": token, "action": action, "resource_id": resource_id})
            if response.status_code == 401:
                # Puede ser sesión revocada o credencial de servicio incorrecta: siempre denegar.
                raise Denied(401, "Autenticación no vigente")
            if response.status_code != 200:
                raise Denied(503, "No se pudo comprobar la autorización")
            return response.json()
        except (httpx.HTTPError, ValueError):
            raise Denied(503, "AUTH no disponible o respuesta inválida") from None


async def respond(send, status, detail):
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
        "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": body})


class SecurityMiddleware:
    def __init__(self, app, settings, decider):
        self.app, self.settings, self.decider = app, settings, decider

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        if not path.startswith("/api/steganography"):
            return await self.app(scope, receive, send)
        try:
            values = [v.decode("latin1") for k, v in scope["headers"] if k.lower() == b"authorization"]
            match = re.fullmatch(r"Bearer ([^\s]{1,4096})", values[0] if len(values) == 1 else "", re.I)
            if not match:
                raise Denied(401, "Se requiere un token Bearer")
            token = match.group(1)
            try:
                claims = jwt.decode(token, self.settings.public_key, algorithms=["RS256"],
                    audience="chat-seguro", issuer="ms-users-auth",
                    options={"require": ["sub", "jti", "exp", "iat", "iss", "aud"]})
                UUID(claims["sub"]); UUID(claims["jti"])
                if type(claims["exp"]) is not int or type(claims["iat"]) is not int or claims["exp"] - claims["iat"] > 900:
                    raise ValueError("Invalid lifetime")
            except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError):
                raise Denied(401, "Token inválido o expirado") from None
            resource_id = None
            if path == "/api/steganography/analyze" and scope["method"] == "POST":
                action = "steganography.analyze"
            elif path.startswith("/api/steganography/results/") and scope["method"] == "GET":
                try:
                    resource_id = str(UUID(path.rsplit("/", 1)[-1]))
                except ValueError:
                    raise Denied(404, "Recurso no encontrado") from None
                action = "steganography.results.read"
            else:
                raise Denied(404, "Ruta no disponible")
            decision = await self.decider(token, action, resource_id)
            if (not isinstance(decision, dict) or decision.get("subject_id") != claims["sub"] or
                decision.get("action") != action or decision.get("resource_id") != resource_id or
                type(decision.get("allowed")) is not bool or decision.get("scope") not in ("all", "own")):
                raise Denied(503, "Decisión de autorización inválida")
            if not decision["allowed"]:
                raise Denied(403, "Permisos insuficientes")
            scope.setdefault("state", {})["identity"] = decision
            # El cuerpo no se lee ni se analiza antes de la decisión vigente de AUTH.
            size = 0
            limit = self.settings.max_file_bytes + 64 * 1024
            lengths = [v for k, v in scope["headers"] if k.lower() == b"content-length"]
            if lengths:
                try:
                    if len(lengths) != 1 or int(lengths[0]) < 0: raise ValueError()
                    if int(lengths[0]) > limit: raise Denied(413, "Carga excesiva")
                except ValueError: raise Denied(400, "Content-Length inválido") from None
            async def bounded_receive():
                nonlocal size
                message = await receive()
                size += len(message.get("body", b""))
                if size > limit: raise HttpError(413, "Carga excesiva")
                return message
            await self.app(scope, bounded_receive, send)
        except Denied as error:
            audit("request.denied", status=error.status, path=path)
            await respond(send, error.status, error.detail)
