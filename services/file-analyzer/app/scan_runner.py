"""Procesos Linux acotados: sin shell, sin preexec_fn y sin ejecutar la muestra."""
from dataclasses import dataclass
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time


@dataclass(frozen=True)
class ScanLimits:
    timeout_seconds: int = 45
    cpu_seconds: int = 30
    memory_bytes: int = 2 * 1024 ** 3
    max_bytes: int = 5 * 1024 ** 2
    output_bytes: int = 65536

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError("invalid_scan_limits")


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None = None
    output: str = ""
    error: str | None = None


_slot = threading.BoundedSemaphore(1)


def run_scan(argv: list[str], limits: ScanLimits) -> CommandResult:
    """Un motor a la vez por worker; salida privada acotada y descartada al interpretar."""
    if sys.platform != "linux" or not shutil.which("prlimit"):
        return CommandResult(error="resource_limits_unavailable")
    if not shutil.which(argv[0]):
        return CommandResult(error="engine_missing")
    if not _slot.acquire(timeout=0.25):
        return CommandResult(error="scanner_busy")
    process = None
    try:
        command = [shutil.which("prlimit"), f"--as={limits.memory_bytes}",
                   f"--cpu={limits.cpu_seconds}", "--core=0", "--nofile=64",
                   "--fsize=33554432", "--", *argv]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, env={"PATH": os.defpath,
                                   "LC_ALL": "C", "LANG": "C", "TMPDIR": "/tmp"})
        deadline = time.monotonic() + limits.timeout_seconds
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return CommandResult(error="scan_timeout")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(chunk) > limits.output_bytes:
                        return CommandResult(error="scan_output_limit")
                    else:
                        output.extend(chunk)
        try:
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return CommandResult(error="scan_timeout")
        return CommandResult(code, output.decode("utf-8", errors="replace"))
    except OSError:
        return CommandResult(error="engine_execution_failed")
    finally:
        if process is not None:
            # Elimina también descendientes que hayan heredado el grupo.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
        _slot.release()


def check_file(path: Path, limits: ScanLimits) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return "scan_invalid_file"
        if path.stat().st_size > limits.max_bytes:
            return "scan_file_limit"
    except OSError:
        return "scan_file_unreadable"
    return None
