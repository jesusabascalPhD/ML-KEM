"""
tests/conftest.py
─────────────────
Fixtures compartidas para todos los tests de mlkem.
"""

import pytest
from mlkem_pkg.kem import MLKEM


@pytest.fixture(params=[512, 768, 1024])
def kem(request):
    """Instancia de MLKEM para cada nivel de seguridad."""
    return MLKEM(request.param)


@pytest.fixture(params=[512, 768, 1024])
def keypair(request):
    """Par de claves (ek, dk) para cada nivel de seguridad."""
    kem = MLKEM(request.param)
    ek, dk = kem.keygen()
    return kem, ek, dk
