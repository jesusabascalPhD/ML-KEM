"""
sampling.py
───────────
Funciones de muestreo de ML-KEM (FIPS 203 §4.2.2):

  sample_ntt(rho, i, j)   Muestrea un polinomio uniforme en dominio NTT
                           usando XOF (SHAKE-128).  [Alg. 6]

  sample_cbd(eta, b)      Muestrea de la distribución binomial centrada
                           CBD_eta a partir de bytes pseudoaleatorios. [Alg. 7]
"""

from .constants import Q, N
from .hash_utils import XOF
from .poly import Poly


def sample_ntt(rho: bytes, i: int, j: int) -> Poly:
    """
    SampleNTT (Alg. 6).

    Genera un polinomio uniformemente distribuido en Z_q^N
    directamente en dominio NTT, usando el flujo XOF(rho, i, j).

    El método de rechazo extrae tripletas de bytes (b0, b1, b2) y
    produce hasta dos candidatos por tripleta:
        d1 = b0 + 256·(b1 mod 16)
        d2 = (b1 >> 4) + 16·b2
    Solo se aceptan valores < Q.
    """
    xof = XOF(rho, i, j)
    stream = xof.digest(840)   # suficiente para casi todos los casos
    a: Poly = []
    pos = 0

    while len(a) < N:
        # Ampliar el flujo si es necesario
        if pos + 3 > len(stream):
            stream += xof.digest(168)

        b0, b1, b2 = stream[pos], stream[pos+1], stream[pos+2]
        pos += 3

        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2

        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)

    return a


def sample_cbd(eta: int, b: bytes) -> Poly:
    """
    SamplePolyCBD_eta (Alg. 7).

    Muestrea de la distribución binomial centrada CBD_eta:
        f[i] = Σ_{j=0}^{eta-1} (a_j - b_j)   con a_j, b_j ∈ {0,1}

    Entrada: 64·eta bytes pseudoaleatorios.
    Salida:  polinomio en Z_q (coeficientes centrados reducidos mod Q).
    """
    assert len(b) == 64 * eta, (
        f"sample_cbd espera {64 * eta} bytes, recibió {len(b)}"
    )

    # Desempaquetar todos los bits en orden little-endian
    bits = []
    for byte in b:
        for k in range(8):
            bits.append((byte >> k) & 1)

    f: Poly = []
    for i in range(N):
        a_sum = sum(bits[2 * i * eta + j]       for j in range(eta))
        b_sum = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((a_sum - b_sum) % Q)

    return f
