"""
hash_utils.py
─────────────
Funciones hash y XOF requeridas por ML-KEM (FIPS 203 §4.1):

  G   SHA3-512   B* → B32 × B32
  H   SHA3-256   B* → B32
  J   SHAKE-256  B* → B32
  PRF SHAKE-256  (eta, s, b) → B^{64·eta}
  XOF SHAKE-128  (rho, i, j) → flujo infinito
"""

import hashlib
from typing import Tuple


def G(data: bytes) -> Tuple[bytes, bytes]:
    """G: B* → B32 × B32  (SHA3-512, salida dividida en dos mitades)."""
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]


def H(data: bytes) -> bytes:
    """H: B* → B32  (SHA3-256)."""
    return hashlib.sha3_256(data).digest()


def J(data: bytes) -> bytes:
    """J: B* → B32  (SHAKE-256, 32 bytes de salida)."""
    return hashlib.shake_256(data).digest(32)


def PRF(eta: int, s: bytes, b: int) -> bytes:
    """
    PRF_eta(s, b) = SHAKE-256(s ∥ b)  →  64·eta bytes.

    Parámetros
    ----------
    eta : parámetro de la distribución binomial centrada
    s   : semilla de 32 bytes
    b   : contador de un solo byte
    """
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def XOF(rho: bytes, i: int, j: int):
    """
    XOF(rho, i, j) = SHAKE-128(rho ∥ i ∥ j).

    Devuelve un objeto SHAKE-128 del que se puede extraer
    cualquier cantidad de bytes con .digest(n).
    """
    return hashlib.shake_128(rho + bytes([i, j]))
