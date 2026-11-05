"""Adaptador de ejecución aislada. El algoritmo app.detector corresponde a Diana."""
import json
import sys
from pathlib import Path


def main():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
    except ImportError:
        pass  # Windows: timeout del padre; aislamiento completo en el contenedor Linux.
    from app.detector import analyze
    print(json.dumps(analyze(Path(sys.argv[1])), allow_nan=False))


if __name__ == "__main__":
    main()
