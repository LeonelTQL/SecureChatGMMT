import asyncio
import importlib.util
import json
import math
import os
import signal
import sys
from pathlib import Path


def validate_result(result):
    if not isinstance(result, dict) or result.get("status") not in {"sin_indicios", "sospechoso", "no_concluyente", "error"}:
        raise ValueError("Resultado del detector inválido")
    if not isinstance(result.get("technique"), str) or not 1 <= len(result["technique"]) <= 100:
        raise ValueError("Técnica ausente")
    indicators = result.get("indicators")
    if not isinstance(indicators, dict) or len(indicators) > 50:
        raise ValueError("Indicadores inválidos")
    for key, value in indicators.items():
        if not isinstance(key, str) or len(key) > 100 or type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError("Indicadores deben ser métricas numéricas finitas")
    if result["status"] != "error" and not indicators:
        raise ValueError("El detector debe aportar indicadores reales")
    if not isinstance(result.get("limitations"), str) or not 1 <= len(result["limitations"]) <= 2000:
        raise ValueError("Limitaciones ausentes")
    validated = {key: result[key] for key in ("status", "technique", "indicators", "limitations")}
    if "reason" in result:
        import re
        if not isinstance(result["reason"], str) or not re.fullmatch(r"[a-z_]{1,100}", result["reason"]):
            raise ValueError("Motivo inválido")
        validated["reason"] = result["reason"]
    if "reports" in result:
        reports = result["reports"]
        if (not isinstance(reports, dict) or not set(reports) <= {"validation", "antimalware", "metadata", "lsb"}
                or len(json.dumps(reports, allow_nan=False).encode()) > 32768):
            raise ValueError("Informes inválidos o excesivos")
        validated["reports"] = reports
    return validated


class DetectorUnavailable(Exception):
    pass


async def analyze(path: Path):
    if importlib.util.find_spec("app.detector") is None:
        raise DetectorUnavailable("Pendiente de integrar el detector de Diana")
    environment = {key: os.environ[key] for key in (
        "PATH", "PYTHONPATH", "LANG", "LC_ALL", "TMPDIR", "CLAMAV_DATABASE_DIR", "YARA_RULES_FILE"
    ) if key in os.environ}
    environment.update(OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1")
    process = await asyncio.create_subprocess_exec(sys.executable, "-m", "app.detector_worker", str(path),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        start_new_session=(sys.platform == "linux"), env=environment)
    async def read_bounded():
        output = bytearray()
        while chunk := await process.stdout.read(4096):
            output.extend(chunk)
            if len(output) > 65536:
                raise ValueError("Salida excesiva")
        return bytes(output)
    try:
        # Lectura acotada: un detector defectuoso tampoco puede inundar la memoria con stdout.
        output = await asyncio.wait_for(read_bounded(), timeout=90)
        await asyncio.wait_for(process.wait(), timeout=2)
        if process.returncode != 0: raise ValueError("Error de detector")
        return validate_result(json.loads(output))
    except BaseException:
        if process.returncode is None:
            if sys.platform == "linux":
                # Los motores usan grupos propios. Matar también descendientes
                # del worker antes de que se reparenten al terminar éste.
                def kill_children(pid):
                    try:
                        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
                    except OSError:
                        return
                    for child in children:
                        kill_children(int(child))
                        try: os.kill(int(child), signal.SIGKILL)
                        except ProcessLookupError: pass
                kill_children(process.pid)
            process.kill(); await process.wait()
        raise
