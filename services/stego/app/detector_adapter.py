import asyncio
import importlib.util
import json
import math
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
    return {key: result[key] for key in ("status", "technique", "indicators", "limitations")}


class DetectorUnavailable(Exception):
    pass


async def analyze(path: Path):
    if importlib.util.find_spec("app.detector") is None:
        raise DetectorUnavailable("Pendiente de integrar el detector de Diana")
    process = await asyncio.create_subprocess_exec(sys.executable, "-m", "app.detector_worker", str(path),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        # Lectura acotada: un detector defectuoso tampoco puede inundar la memoria con stdout.
        output = await asyncio.wait_for(process.stdout.read(65537), timeout=10)
        if len(output) > 65536: raise ValueError("Salida excesiva")
        await asyncio.wait_for(process.wait(), timeout=2)
        if process.returncode != 0: raise ValueError("Error de detector")
        return validate_result(json.loads(output))
    except BaseException:
        if process.returncode is None:
            process.kill(); await process.wait()
        raise
