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
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
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
            a ^= 0x1b
        b >>= 1
    return p

def _sub_bytes(s):
    return [_SBOX[b] for b in s]

def _shift_rows(s):
    return [
        s[0],  s[5],  s[10], s[15],
        s[4],  s[9],  s[14], s[3],
        s[8],  s[13], s[2],  s[7],
        s[12], s[1],  s[6],  s[11],
    ]

def _mix_columns(s):
    out = []
    for c in range(4):
        a = s[c*4:(c+1)*4]
        out += [
            _gf_mul(2,a[0])^_gf_mul(3,a[1])^a[2]^a[3],
            a[0]^_gf_mul(2,a[1])^_gf_mul(3,a[2])^a[3],
            a[0]^a[1]^_gf_mul(2,a[2])^_gf_mul(3,a[3]),
            _gf_mul(3,a[0])^a[1]^a[2]^_gf_mul(2,a[3]),
        ]
    return out

def _add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]

def _key_expansion(key: bytes) -> list[list[int]]:
    """Expansión de clave AES-256 → 15 round keys de 16 bytes."""
    assert len(key) == 32
    nk, nr = 8, 14
    rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    w = list(key)
    while len(w) < 16 * (nr + 1):
        t = w[-4:]
        if len(w) // 4 % nk == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= rcon[len(w) // 4 // nk - 1]
        elif len(w) // 4 % nk == 4:
            t = [_SBOX[b] for b in t]
        w += [w[-32+i] ^ t[i] for i in range(4)]
    return [w[i:i+16] for i in range(0, len(w), 16)]

def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Cifra un bloque de 16 bytes con AES-256."""
    rks = _key_expansion(key)
    s = list(block)
    # Reorganizar en orden columna-mayor
    s = [s[r + 4*c] for c in range(4) for r in range(4)]
    s = _add_round_key(s, rks[0])
    for rnd in range(1, 15):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        if rnd < 14:
            s = _mix_columns(s)
        s = _add_round_key(s, rks[rnd])
    # Volver a orden fila-mayor
    out = [s[c*4 + r] for r in range(4) for c in range(4)]
    return bytes(out)


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
        chunk = data[i:i+16]
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
        block = int.from_bytes(data[i:i+16], "big")
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
    icb = nonce + b"\x00\x00\x00\x02"   # J0 + 1
    ct  = _gctr(key, icb, plaintext)

    # Tag
    s   = _ghash(H, aad, ct)
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

    H  = int.from_bytes(aes_encrypt_block(key, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"

    # Verificar tag
    s        = _ghash(H, aad, ct)
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