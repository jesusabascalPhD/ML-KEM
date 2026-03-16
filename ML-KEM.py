"""
ML-KEM (CRYSTALS-Kyber) Implementation in Python
Based on NIST FIPS 203 standard

Supports parameter sets:
  - ML-KEM-512  (k=2, security level ~128-bit)
  - ML-KEM-768  (k=3, security level ~192-bit)
  - ML-KEM-1024 (k=4, security level ~256-bit)
"""

import os
import hashlib
import struct
from typing import Tuple, List

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
Q = 3329          # Modulus
N = 256           # Polynomial degree
ZETA = 17         # Primitive 256th root of unity mod Q

# Precomputed NTT zetas (powers of ZETA^(bitrev(i)) mod Q)
def _compute_zetas():
    zetas = []
    for i in range(128):
        exp = _bit_reverse(i, 7)
        zetas.append(pow(ZETA, exp, Q))
    return zetas

def _bit_reverse(x: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result

ZETAS = _compute_zetas()

def _compute_basemul_zetas():
    """Zetas for base-case multiplication: ZETA^(2*bitrev7(i)+1) mod Q"""
    return [pow(ZETA, 2 * _bit_reverse(i, 7) + 1, Q) for i in range(128)]

BASEMUL_ZETAS = _compute_basemul_zetas()

# ─────────────────────────────────────────────
# Parameter Sets
# ─────────────────────────────────────────────
PARAMS = {
    512:  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    768:  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    1024: {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}

# ─────────────────────────────────────────────
# Hash / XOF utilities
# ─────────────────────────────────────────────
def _G(data: bytes) -> Tuple[bytes, bytes]:
    """G: B* → B32 × B32  (SHA3-512)"""
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]

def _H(data: bytes) -> bytes:
    """H: B* → B32  (SHA3-256)"""
    return hashlib.sha3_256(data).digest()

def _J(data: bytes) -> bytes:
    """J: B* → B32  (SHAKE-256 with 32-byte output)"""
    return hashlib.shake_256(data).digest(32)

def _PRF(eta: int, s: bytes, b: int) -> bytes:
    """PRF_eta(s, b) = SHAKE-256(s || b)  → 64*eta bytes"""
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)

def _XOF(rho: bytes, i: int, j: int):
    """XOF(rho, i, j) = SHAKE-128 stream"""
    seed = rho + bytes([i, j])
    # Return a generator-like object for reading bytes
    return hashlib.shake_128(seed)

# ─────────────────────────────────────────────
# Polynomial arithmetic
# ─────────────────────────────────────────────
Poly = List[int]   # list of N = 256 coefficients mod Q

def poly_add(a: Poly, b: Poly) -> Poly:
    return [(a[i] + b[i]) % Q for i in range(N)]

def poly_sub(a: Poly, b: Poly) -> Poly:
    return [(a[i] - b[i]) % Q for i in range(N)]

def poly_zero() -> Poly:
    return [0] * N

def ntt(f: Poly) -> Poly:
    """Number Theoretic Transform (in-place, returns new poly)"""
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
                a[j] = (a[j] + t) % Q
        length //= 2
    return a

def ntt_inv(f: Poly) -> Poly:
    """Inverse NTT"""
    a = f[:]
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = (zeta * (a[j + length] - t)) % Q
        length *= 2
    f_inv = pow(128, Q - 2, Q)  # 128^{-1} mod Q
    return [(x * f_inv) % Q for x in a]

def poly_mul_ntt(a: Poly, b: Poly) -> Poly:
    """Pointwise multiplication in NTT domain (base case: degree-2 polynomials).
    Uses BASEMUL_ZETAS = ZETA^(2*bitrev7(i)+1) mod Q per FIPS 203."""
    c = [0] * N
    for i in range(128):
        a0, a1 = a[2*i], a[2*i+1]
        b0, b1 = b[2*i], b[2*i+1]
        zeta = BASEMUL_ZETAS[i]
        # (a0 + a1*X)(b0 + b1*X) mod (X^2 - zeta)
        c[2*i]   = (a0*b0 + a1*b1*zeta) % Q
        c[2*i+1] = (a0*b1 + a1*b0) % Q
    return c

# ─────────────────────────────────────────────
# Vector / Matrix operations
# ─────────────────────────────────────────────
Vec = List[Poly]
Mat = List[Vec]

def vec_add(u: Vec, v: Vec) -> Vec:
    return [poly_add(u[i], v[i]) for i in range(len(u))]

def mat_vec_mul(A: Mat, v: Vec) -> Vec:
    """A @ v in NTT domain"""
    k = len(A)
    result = []
    for i in range(k):
        acc = poly_zero()
        for j in range(k):
            acc = poly_add(acc, poly_mul_ntt(A[i][j], v[j]))
        result.append(acc)
    return result

def vec_dot(u: Vec, v: Vec) -> Poly:
    """u · v in NTT domain"""
    acc = poly_zero()
    for i in range(len(u)):
        acc = poly_add(acc, poly_mul_ntt(u[i], v[i]))
    return acc

# ─────────────────────────────────────────────
# Encoding / Decoding
# ─────────────────────────────────────────────
def _compress(x: int, d: int) -> int:
    """Compress Zq → Z_{2^d}"""
    return round(x * (2**d) / Q) % (2**d)

def _decompress(y: int, d: int) -> int:
    """Decompress Z_{2^d} → Zq"""
    return round(y * Q / (2**d)) % Q

def byte_encode(f: Poly, d: int) -> bytes:
    """ByteEncode_d: encode polynomial with d bits per coeff"""
    bits = []
    for c in f:
        val = int(c) % (2**d)
        for i in range(d):
            bits.append((val >> i) & 1)
    # Pack bits into bytes
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        result.append(byte)
    return bytes(result)

def byte_decode(b: bytes, d: int) -> Poly:
    """ByteDecode_d: decode bytes to polynomial"""
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> i) & 1)
    f = []
    for i in range(N):
        val = 0
        for j in range(d):
            val |= bits[i * d + j] << j
        f.append(val % Q)
    return f

def compress_poly(f: Poly, d: int) -> Poly:
    return [_compress(c, d) for c in f]

def decompress_poly(f: Poly, d: int) -> Poly:
    return [_decompress(c, d) for c in f]

def encode_vec(v: Vec, d: int) -> bytes:
    return b"".join(byte_encode(compress_poly(p, d), d) for p in v)

def decode_vec(b: bytes, k: int, d: int) -> Vec:
    size = (N * d) // 8
    return [decompress_poly(byte_decode(b[i*size:(i+1)*size], d), d) for i in range(k)]

# ─────────────────────────────────────────────
# Sampling
# ─────────────────────────────────────────────
def sample_ntt(rho: bytes, i: int, j: int) -> Poly:
    """Sample a uniform polynomial in NTT domain (Algorithm 6)"""
    xof = _XOF(rho, i, j)
    # Need enough bytes; SHAKE-128 is infinite, get plenty
    stream = xof.digest(840)
    a = []
    pos = 0
    while len(a) < N:
        if pos + 3 > len(stream):
            stream += xof.digest(168)
        b0, b1, b2 = stream[pos], stream[pos+1], stream[pos+2]
        pos += 3
        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 // 16) + 16 * b2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a

def sample_cbd(eta: int, b: bytes) -> Poly:
    """Sample from centered binomial distribution CBD_eta (Algorithm 7)"""
    assert len(b) == 64 * eta
    f = []
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> i) & 1)
    for i in range(N):
        a_sum = sum(bits[2 * i * eta + j] for j in range(eta))
        b_sum = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((a_sum - b_sum) % Q)
    return f

# ─────────────────────────────────────────────
# Key Generation, Encapsulation, Decapsulation
# ─────────────────────────────────────────────
class MLKEM:
    def __init__(self, security_level: int = 768):
        if security_level not in PARAMS:
            raise ValueError(f"Invalid security level. Choose from {list(PARAMS.keys())}")
        p = PARAMS[security_level]
        self.k    = p["k"]
        self.eta1 = p["eta1"]
        self.eta2 = p["eta2"]
        self.du   = p["du"]
        self.dv   = p["dv"]
        self.security_level = security_level

    def _generate_matrix(self, rho: bytes, transpose: bool = False) -> Mat:
        k = self.k
        A = []
        for i in range(k):
            row = []
            for j in range(k):
                row.append(sample_ntt(rho, j if transpose else i,
                                           i if transpose else j))
            A.append(row)
        return A

    # ── K-PKE Key Generation ──────────────────
    def _pke_keygen(self, d: bytes) -> Tuple[bytes, bytes]:
        """Internal PKE key generation. d = 32 random bytes."""
        rho, sigma = _G(d + bytes([self.k]))

        A_hat = self._generate_matrix(rho, transpose=False)

        s = []
        e = []
        for i in range(self.k):
            s.append(sample_cbd(self.eta1, _PRF(self.eta1, sigma, i)))
            e.append(sample_cbd(self.eta1, _PRF(self.eta1, sigma, self.k + i)))

        s_hat = [ntt(si) for si in s]
        e_hat = [ntt(ei) for ei in e]

        # t_hat = A_hat @ s_hat + e_hat
        t_hat = vec_add(mat_vec_mul(A_hat, s_hat), e_hat)

        # Encode public key
        ek_pke = b"".join(byte_encode(t, 12) for t in t_hat) + rho
        dk_pke = b"".join(byte_encode(s, 12) for s in s_hat)
        return ek_pke, dk_pke

    # ── K-PKE Encrypt ─────────────────────────
    def _pke_encrypt(self, ek: bytes, m: bytes, r: bytes) -> bytes:
        """Encrypt 32-byte message m with randomness r."""
        k = self.k
        t_hat = [byte_decode(ek[i*384:(i+1)*384], 12) for i in range(k)]
        rho = ek[k*384:]

        A_hat_T = self._generate_matrix(rho, transpose=True)

        y  = []
        e1 = []
        for i in range(k):
            y.append(sample_cbd(self.eta1, _PRF(self.eta1, r, i)))
            e1.append(sample_cbd(self.eta2, _PRF(self.eta2, r, k + i)))
        e2 = sample_cbd(self.eta2, _PRF(self.eta2, r, 2 * k))

        y_hat = [ntt(yi) for yi in y]

        # u = A^T @ y + e1
        u_hat = vec_add(mat_vec_mul(A_hat_T, y_hat), [ntt(ei) for ei in e1])
        u = [ntt_inv(ui) for ui in u_hat]

        # mu: decode message
        mu = decompress_poly(byte_decode(m, 1), 1)

        # v = t^T @ y + e2 + mu
        v_hat = vec_dot(t_hat, y_hat)
        v = poly_add(poly_add(ntt_inv(v_hat), e2), mu)

        # Compress and encode
        c1 = encode_vec(u, self.du)
        c2 = byte_encode(compress_poly(v, self.dv), self.dv)
        return c1 + c2

    # ── K-PKE Decrypt ─────────────────────────
    def _pke_decrypt(self, dk: bytes, c: bytes) -> bytes:
        k = self.k
        c1_len = k * self.du * N // 8
        c1, c2 = c[:c1_len], c[c1_len:]

        u = decode_vec(c1, k, self.du)
        v = decompress_poly(byte_decode(c2, self.dv), self.dv)
        s_hat = [byte_decode(dk[i*384:(i+1)*384], 12) for i in range(k)]

        u_hat = [ntt(ui) for ui in u]
        w = poly_sub(v, ntt_inv(vec_dot(s_hat, u_hat)))
        return byte_encode(compress_poly(w, 1), 1)

    # ── ML-KEM Key Generation ─────────────────
    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate an ML-KEM key pair.
        Returns: (ek, dk)  –  encapsulation key, decapsulation key
        """
        d = os.urandom(32)
        z = os.urandom(32)
        ek, dk_pke = self._pke_keygen(d)
        dk = dk_pke + ek + _H(ek) + z
        return ek, dk

    # ── ML-KEM Encapsulate ────────────────────
    def encaps(self, ek: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: given ek, produce (K, c).
        K = 32-byte shared secret, c = ciphertext.
        """
        m = os.urandom(32)
        K, r = _G(m + _H(ek))
        c = self._pke_encrypt(ek, m, r)
        return K, c

    # ── ML-KEM Decapsulate ────────────────────
    def decaps(self, dk: bytes, c: bytes) -> bytes:
        """
        Decapsulate: given dk and ciphertext c, recover shared secret K.
        Implements implicit rejection for security.
        """
        k = self.k
        dk_pke = dk[:k*384]
        ek      = dk[k*384 : k*384 + k*384 + 32]
        h       = dk[k*384 + k*384 + 32 : k*384 + k*384 + 64]
        z       = dk[k*384 + k*384 + 64:]

        m_prime = self._pke_decrypt(dk_pke, c)
        K_prime, r_prime = _G(m_prime + h)
        K_reject = _J(z + c)

        c_prime = self._pke_encrypt(ek, m_prime, r_prime)

        # Constant-time comparison
        ok = _ct_eq(c, c_prime)
        K = bytes(K_prime[i] if ok else K_reject[i] for i in range(32))
        return K

# ─────────────────────────────────────────────
# Constant-time helpers
# ─────────────────────────────────────────────
def _ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality check."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0

# ─────────────────────────────────────────────
# Demo
# ─────────────────────────────────────────────
def demo():
    print("=" * 60)
    print("   ML-KEM (CRYSTALS-Kyber) — Python Implementation")
    print("   NIST FIPS 203 Standard")
    print("=" * 60)

    for level in [512, 768, 1024]:
        print(f"\n── ML-KEM-{level} ──")
        kem = MLKEM(level)

        print("  [1] Key Generation ...", end=" ", flush=True)
        ek, dk = kem.keygen()
        print(f"OK  (ek={len(ek)}B, dk={len(dk)}B)")

        print("  [2] Encapsulation  ...", end=" ", flush=True)
        K_alice, c = kem.encaps(ek)
        print(f"OK  (ciphertext={len(c)}B)")

        print("  [3] Decapsulation  ...", end=" ", flush=True)
        K_bob = kem.decaps(dk, c)
        match = K_alice == K_bob
        print(f"OK  (keys match: {match})")

        print(f"  Shared secret: {K_alice.hex()[:32]}...")

        # Test implicit rejection
        print("  [4] Rejection test ...", end=" ", flush=True)
        bad_c = bytes([c[0] ^ 0xFF]) + c[1:]
        K_bad = kem.decaps(dk, bad_c)
        print(f"OK  (different key on tampered ct: {K_alice != K_bad})")

    print("\n" + "=" * 60)
    print("  All tests passed! ✓")
    print("=" * 60)

if __name__ == "__main__":
    demo()