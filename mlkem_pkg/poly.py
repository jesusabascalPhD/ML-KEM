"""
poly.py
───────
Aritmética de polinomios en Z_q[X]/(X^256 + 1):

  - Suma y resta de polinomios
  - NTT (Number Theoretic Transform) e INTT
  - Multiplicación pointwise en dominio NTT (base-case multiplication)
  - Operaciones sobre vectores y matrices de polinomios
"""

from typing import List
from .constants import Q, N, ZETAS, BASEMUL_ZETAS

# ── Tipos alias ───────────────────────────────────────────────────────────
Poly = List[int]   # N coeficientes en Z_q
Vec  = List[Poly]  # vector de polinomios
Mat  = List[Vec]   # matriz de polinomios


# ── Aritmética elemental ──────────────────────────────────────────────────

def poly_zero() -> Poly:
    """Polinomio cero."""
    return [0] * N


def poly_add(a: Poly, b: Poly) -> Poly:
    """Suma coeficiente a coeficiente mod Q."""
    return [(a[i] + b[i]) % Q for i in range(N)]


def poly_sub(a: Poly, b: Poly) -> Poly:
    """Resta coeficiente a coeficiente mod Q."""
    return [(a[i] - b[i]) % Q for i in range(N)]


# ── NTT e INTT ────────────────────────────────────────────────────────────

def ntt(f: Poly) -> Poly:
    """
    Number Theoretic Transform.
    Convierte un polinomio del dominio estándar al dominio NTT.
    Butterfly Cooley-Tukey con las zetas de FIPS 203.
    """
    a = f[:]
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j]          = (a[j] + t) % Q
        length //= 2
    return a


def ntt_inv(f: Poly) -> Poly:
    """
    Inverse NTT.
    Convierte del dominio NTT al dominio estándar.
    Butterfly Gentleman-Sande con escala 128^{-1} mod Q al final.
    """
    a = f[:]
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j]          = (t + a[j + length]) % Q
                a[j + length] = (zeta * (a[j + length] - t)) % Q
        length *= 2
    f_inv = pow(128, Q - 2, Q)   # 128^{-1} mod Q = 3303
    return [(x * f_inv) % Q for x in a]


def poly_mul_ntt(a: Poly, b: Poly) -> Poly:
    """
    Multiplicación pointwise en dominio NTT.

    Cada par (a[2i], a[2i+1]) representa un polinomio de grado 1
    en Z_q[X]/(X^2 - zeta_i). La multiplicación es:

        (a0 + a1·X)(b0 + b1·X) mod (X^2 - zeta)
        = (a0·b0 + a1·b1·zeta) + (a0·b1 + a1·b0)·X

    donde zeta = BASEMUL_ZETAS[i] = 17^(2·bitrev7(i)+1) mod Q.
    """
    c = [0] * N
    for i in range(128):
        a0, a1 = a[2*i], a[2*i+1]
        b0, b1 = b[2*i], b[2*i+1]
        zeta   = BASEMUL_ZETAS[i]
        c[2*i]   = (a0*b0 + a1*b1*zeta) % Q
        c[2*i+1] = (a0*b1 + a1*b0)      % Q
    return c


# ── Operaciones vectoriales y matriciales ─────────────────────────────────

def vec_add(u: Vec, v: Vec) -> Vec:
    """Suma elemento a elemento de dos vectores de polinomios."""
    return [poly_add(u[i], v[i]) for i in range(len(u))]


def mat_vec_mul(A: Mat, v: Vec) -> Vec:
    """
    Producto matriz-vector en dominio NTT: A @ v.
    Cada entrada de la salida es una suma de productos NTT.
    """
    k = len(A)
    result = []
    for i in range(k):
        acc = poly_zero()
        for j in range(k):
            acc = poly_add(acc, poly_mul_ntt(A[i][j], v[j]))
        result.append(acc)
    return result


def vec_dot(u: Vec, v: Vec) -> Poly:
    """Producto interno u · v en dominio NTT."""
    acc = poly_zero()
    for i in range(len(u)):
        acc = poly_add(acc, poly_mul_ntt(u[i], v[i]))
    return acc
