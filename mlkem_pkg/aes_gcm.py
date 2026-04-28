"""
aes_gcm.py
──────────
Implementación de AES-256-GCM sin dependencias externas.
Solo usa la librería estándar de Python.

  aes_gcm_encrypt(key, plaintext) → (nonce, ciphertext_con_tag)
  aes_gcm_decrypt(key, nonce, ciphertext) → plaintext | None

Referencias: NIST SP 800-38D, FIPS 197.
"""

import os
import struct

# ─────────────────────────────────────────────────────────────────────────────
# AES (FIPS 197) — implementación pura en Python
# ─────────────────────────────────────────────────────────────────────────────

# S-box de AES
_SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]


# Multiplicación en GF(2^8) con polinomio reductor 0x11b
def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _sub_bytes(s):
    return [_SBOX[b] for b in s]


def _shift_rows(s):
    return [
        s[0],
        s[5],
        s[10],
        s[15],
        s[4],
        s[9],
        s[14],
        s[3],
        s[8],
        s[13],
        s[2],
        s[7],
        s[12],
        s[1],
        s[6],
        s[11],
    ]


def _mix_columns(s):
    out = []
    for c in range(4):
        a = s[c * 4 : (c + 1) * 4]
        out += [
            _gf_mul(2, a[0]) ^ _gf_mul(3, a[1]) ^ a[2] ^ a[3],
            a[0] ^ _gf_mul(2, a[1]) ^ _gf_mul(3, a[2]) ^ a[3],
            a[0] ^ a[1] ^ _gf_mul(2, a[2]) ^ _gf_mul(3, a[3]),
            _gf_mul(3, a[0]) ^ a[1] ^ a[2] ^ _gf_mul(2, a[3]),
        ]
    return out


def _add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


def _key_expansion(key: bytes) -> list[list[int]]:
    """Expansión de clave AES-256 → 15 round keys de 16 bytes."""
    assert len(key) == 32
    nk, nr = 8, 14
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    w = list(key)
    while len(w) < 16 * (nr + 1):
        t = w[-4:]
        if len(w) // 4 % nk == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= rcon[len(w) // 4 // nk - 1]
        elif len(w) // 4 % nk == 4:
            t = [_SBOX[b] for b in t]
        w += [w[-32 + i] ^ t[i] for i in range(4)]
    return [w[i : i + 16] for i in range(0, len(w), 16)]


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Cifra un bloque de 16 bytes con AES-256."""
    rks = _key_expansion(key)
    s = list(block)
    # El estado interno de AES usa orden columna-mayor, que coincide con
    # la lectura de bytes en orden: byte i → columna i//4, fila i%4.
    # ShiftRows opera sobre filas del estado, lo que en este layout
    # desplaza los índices correctamente sin reordenar la entrada ni la salida.
    s = _add_round_key(s, rks[0])
    for rnd in range(1, 15):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        if rnd < 14:
            s = _mix_columns(s)
        s = _add_round_key(s, rks[rnd])
    return bytes(s)


# ─────────────────────────────────────────────────────────────────────────────
# CTR mode  (para el keystream de GCM)
# ─────────────────────────────────────────────────────────────────────────────


def _gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    """GCTR: cifra 'data' en modo CTR a partir del contador inicial 'icb'."""
    if not data:
        return b""
    out = bytearray()
    cb = bytearray(icb)
    for i in range(0, len(data), 16):
        ks = aes_encrypt_block(key, bytes(cb))
        chunk = data[i : i + 16]
        out += bytes(a ^ b for a, b in zip(ks, chunk))
        # Incrementar los 32 bits menos significativos del contador
        ctr = struct.unpack_from(">I", cb, 12)[0]
        struct.pack_into(">I", cb, 12, (ctr + 1) & 0xFFFFFFFF)
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
# GHASH  (multiplicación en GF(2^128))
# ─────────────────────────────────────────────────────────────────────────────


def _gf128_mul(x: int, y: int) -> int:
    """Multiplicación en GF(2^128) con polinomio reductor x^128+x^7+x^2+x+1."""
    R = 0xE1 << 120
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        if x & 1:
            x = (x >> 1) ^ R
        else:
            x >>= 1
    return z


def _ghash(H: int, aad: bytes, ciphertext: bytes) -> bytes:
    """Calcula GHASH_H(A, C)."""

    def pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)

    data = pad16(aad) + pad16(ciphertext)
    data += struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)

    tag = 0
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i : i + 16], "big")
        tag = _gf128_mul(tag ^ block, H)
    return tag.to_bytes(16, "big")


# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM  (API pública)
# ─────────────────────────────────────────────────────────────────────────────


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Cifra con AES-256-GCM.

    Parámetros
    ----------
    key       : 32 bytes (AES-256)
    plaintext : mensaje a cifrar
    aad       : datos adicionales autenticados (opcional)

    Devuelve
    --------
    nonce (12 bytes), ciphertext + tag (16 bytes al final)
    """
    nonce = os.urandom(12)

    # H = AES_K(0^128)
    H = int.from_bytes(aes_encrypt_block(key, b"\x00" * 16), "big")

    # J0 = nonce ∥ 0^31 ∥ 1
    j0 = nonce + b"\x00\x00\x00\x01"

    # Cifrar
    icb = nonce + b"\x00\x00\x00\x02"  # J0 + 1
    ct = _gctr(key, icb, plaintext)

    # Tag
    s = _ghash(H, aad, ct)
    tag = _gctr(key, j0, s)

    return nonce, ct + tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes | None:
    """
    Descifra y verifica el tag AES-256-GCM.

    Devuelve el texto plano, o None si la autenticación falla.
    """
    if len(ciphertext) < 16:
        return None

    ct, tag_recv = ciphertext[:-16], ciphertext[-16:]

    H = int.from_bytes(aes_encrypt_block(key, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"

    # Verificar tag
    s = _ghash(H, aad, ct)
    tag_calc = _gctr(key, j0, s)

    # Comparación en tiempo constante
    diff = 0
    for a, b in zip(tag_calc, tag_recv):
        diff |= a ^ b
    if diff != 0:
        return None

    # Descifrar
    icb = nonce + b"\x00\x00\x00\x02"
    return _gctr(key, icb, ct)
