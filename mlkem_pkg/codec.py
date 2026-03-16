"""
codec.py
────────
Codificación, decodificación y compresión de polinomios (FIPS 203 §4.2):

  byte_encode(f, d)      Poly → bytes    (d bits por coeficiente)
  byte_decode(b, d)      bytes → Poly
  compress_poly(f, d)    Zq → Z_{2^d}   por coeficiente
  decompress_poly(f, d)  Z_{2^d} → Zq   por coeficiente
  encode_vec(v, d)       Vec → bytes     (comprime + codifica cada polinomio)
  decode_vec(b, k, d)    bytes → Vec     (decodifica + descomprime)
"""

from typing import List
from .constants import Q, N
from .poly import Poly, Vec


# ── Compresión / descompresión ────────────────────────────────────────────

def compress(x: int, d: int) -> int:
    """Comprime un coeficiente de Zq a Z_{2^d}."""
    return round(x * (2**d) / Q) % (2**d)


def decompress(y: int, d: int) -> int:
    """Descomprime de Z_{2^d} a Zq."""
    return round(y * Q / (2**d)) % Q


def compress_poly(f: Poly, d: int) -> Poly:
    """Aplica compress() a cada coeficiente del polinomio."""
    return [compress(c, d) for c in f]


def decompress_poly(f: Poly, d: int) -> Poly:
    """Aplica decompress() a cada coeficiente del polinomio."""
    return [decompress(c, d) for c in f]


# ── Codificación / decodificación de bytes ────────────────────────────────

def byte_encode(f: Poly, d: int) -> bytes:
    """
    ByteEncode_d (FIPS 203 Alg. 4):
    Empaqueta N coeficientes de d bits cada uno en un array de bytes.
    Los bits se escriben en orden little-endian dentro de cada coeficiente
    y los coeficientes se concatenan en orden.
    """
    bits: List[int] = []
    for c in f:
        val = int(c) % (2**d)
        for i in range(d):
            bits.append((val >> i) & 1)

    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        result.append(byte)
    return bytes(result)


def byte_decode(b: bytes, d: int) -> Poly:
    """
    ByteDecode_d (FIPS 203 Alg. 5):
    Recupera N coeficientes de d bits a partir de un array de bytes.
    """
    bits: List[int] = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> i) & 1)

    f: Poly = []
    for i in range(N):
        val = 0
        for j in range(d):
            val |= bits[i * d + j] << j
        f.append(val % Q)
    return f


# ── Codificación de vectores ──────────────────────────────────────────────

def encode_vec(v: Vec, d: int) -> bytes:
    """
    Comprime y codifica cada polinomio del vector.
    Produce k · (N·d/8) bytes en total.
    """
    return b"".join(byte_encode(compress_poly(p, d), d) for p in v)


def decode_vec(b: bytes, k: int, d: int) -> Vec:
    """
    Decodifica y descomprime k polinomios desde el array de bytes.
    Cada polinomio ocupa N·d/8 bytes.
    """
    size = (N * d) // 8
    return [
        decompress_poly(byte_decode(b[i*size:(i+1)*size], d), d)
        for i in range(k)
    ]
