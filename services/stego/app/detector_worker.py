"""Adaptador de ejecución aislada. El algoritmo app.detector corresponde a Diana."""
import json
import sys
from pathlib import Path


def main():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
        resource.setrlimit(resource.RLIMIT_AS, (3 * 1024 ** 3, 3 * 1024 ** 3))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except ImportError:
        raise SystemExit("Se requieren límites Linux")
    from app.detector import analyze
    print(json.dumps(analyze(Path(sys.argv[1])), allow_nan=False))


if __name__ == "__main__":
    main()
