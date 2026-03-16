"""
run_tests.py
────────────
Ejecutor de tests independiente. No requiere configuración de entorno.

Uso:
    python run_tests.py            # ejecuta todos los tests
    python run_tests.py -v         # salida detallada
    python run_tests.py -k kem     # solo tests que contengan "kem"
"""

import sys
import os

# ── Asegurar que mlkem_pkg es importable ──────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── Verificar que mlkem_pkg existe ────────────────────────────────────────
try:
    import mlkem_pkg
except ModuleNotFoundError:
    print("ERROR: No se encuentra 'mlkem_pkg'.")
    print(f"       Asegúrate de que existe la carpeta mlkem_pkg/ en: {ROOT}")
    sys.exit(1)

# ── Lanzar pytest ─────────────────────────────────────────────────────────
try:
    import pytest
except ModuleNotFoundError:
    print("ERROR: pytest no está instalado.")
    print("       Instálalo con:  pip install pytest")
    sys.exit(1)

TESTS_DIR = os.path.join(ROOT, "tests")

if __name__ == "__main__":
    # Pasa argumentos extra de la línea de comandos a pytest
    extra_args = sys.argv[1:]
    exit_code = pytest.main([TESTS_DIR, *extra_args])
    sys.exit(exit_code)