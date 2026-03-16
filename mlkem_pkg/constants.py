"""
constants.py
────────────
Constantes globales de ML-KEM (FIPS 203):
  - Parámetros del anillo Z_q[X]/(X^N + 1)
  - Tablas de zetas precomputadas para NTT
  - Conjuntos de parámetros para cada nivel de seguridad
"""

# ── Parámetros del anillo ──────────────────────────────────────────────────
Q    = 3329   # Módulo primo
N    = 256    # Grado del polinomio
ZETA = 17     # Raíz primitiva 256-ésima de la unidad mod Q


# ── Utilidad: inversión de bits ────────────────────────────────────────────
def _bit_reverse(x: int, bits: int) -> int:
    """Invierte los 'bits' bits menos significativos de x."""
    result = 0
    for _ in range(bits):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


# ── Tablas de zetas (precomputadas en tiempo de importación) ───────────────
def _compute_ntt_zetas() -> list[int]:
    """
    ZETAS[i] = ZETA^(bitrev7(i)) mod Q
    Usadas dentro de NTT e INTT (butterfly).
    """
    return [pow(ZETA, _bit_reverse(i, 7), Q) for i in range(128)]


def _compute_basemul_zetas() -> list[int]:
    """
    BASEMUL_ZETAS[i] = ZETA^(2·bitrev7(i)+1) mod Q
    Usadas en la multiplicación base del dominio NTT (FIPS 203 §4.3).
    """
    return [pow(ZETA, 2 * _bit_reverse(i, 7) + 1, Q) for i in range(128)]


ZETAS         = _compute_ntt_zetas()
BASEMUL_ZETAS = _compute_basemul_zetas()


# ── Conjuntos de parámetros ────────────────────────────────────────────────
#   k    : dimensión del módulo
#   eta1 : parámetro CBD para s y e
#   eta2 : parámetro CBD para e1 y e2
#   du   : bits de compresión para u
#   dv   : bits de compresión para v
PARAMS: dict[int, dict] = {
    512:  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    768:  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    1024: {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}
