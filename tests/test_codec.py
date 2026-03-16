"""
tests/test_codec.py
───────────────────
Tests unitarios para mlkem_pkg/codec.py:
  - compress / decompress
  - byte_encode / byte_decode
  - encode_vec / decode_vec
"""

import pytest
from mlkem_pkg.constants import Q, N
from mlkem_pkg.codec import (
    compress, decompress,
    compress_poly, decompress_poly,
    byte_encode, byte_decode,
    encode_vec, decode_vec,
)


# ── Utilidades ────────────────────────────────────────────────────────────

def _rand_poly(seed: int) -> list[int]:
    import hashlib
    b = hashlib.shake_256(seed.to_bytes(4, "big")).digest(N * 2)
    return [int.from_bytes(b[i*2:(i+1)*2], "big") % Q for i in range(N)]


# ── compress / decompress ─────────────────────────────────────────────────

class TestCompressDecompress:
    @pytest.mark.parametrize("d", [1, 4, 5, 10, 11, 12])
    def test_output_in_range(self, d):
        for x in [0, Q//4, Q//2, 3*Q//4, Q-1]:
            c = compress(x, d)
            assert 0 <= c < 2**d

    @pytest.mark.parametrize("d", [1, 4, 5, 10, 11, 12])
    def test_decompress_output_in_range(self, d):
        for y in range(2**d):
            v = decompress(y, d)
            assert 0 <= v < Q

    def test_compress_zero(self):
        assert compress(0, 12) == 0

    def test_roundtrip_12bits(self):
        """compress/decompress con 12 bits es prácticamente sin pérdida."""
        for x in range(0, Q, 100):
            c = compress(x, 12)
            d = decompress(c, 12)
            assert abs(d - x) <= 1 or abs(d - x) >= Q - 1

    def test_compress_poly_length(self):
        f = _rand_poly(0)
        assert len(compress_poly(f, 10)) == N

    def test_decompress_poly_length(self):
        f = [i % 1024 for i in range(N)]
        assert len(decompress_poly(f, 10)) == N


# ── byte_encode / byte_decode ─────────────────────────────────────────────

class TestByteEncodeDecode:
    @pytest.mark.parametrize("d", [1, 4, 5, 10, 11, 12])
    def test_roundtrip(self, d):
        """byte_decode(byte_encode(f, d), d) == f para coeficientes en rango."""
        f = [i % (2**d) for i in range(N)]
        assert byte_decode(byte_encode(f, d), d) == f

    @pytest.mark.parametrize("d", [1, 4, 5, 10, 11, 12])
    def test_output_length(self, d):
        f = [0] * N
        encoded = byte_encode(f, d)
        assert len(encoded) == (N * d) // 8

    def test_encode_zeros(self):
        for d in [1, 4, 12]:
            result = byte_encode([0] * N, d)
            assert all(b == 0 for b in result)

    def test_encode_deterministic(self):
        f = _rand_poly(1)
        f_clamped = [c % (2**12) for c in f]
        assert byte_encode(f_clamped, 12) == byte_encode(f_clamped, 12)

    def test_different_polys_different_encoding(self):
        f1 = [0] * N
        f2 = [1] + [0] * (N - 1)
        assert byte_encode(f1, 12) != byte_encode(f2, 12)

    def test_decode_coefficients_in_range(self):
        import os
        b = os.urandom((N * 12) // 8)
        f = byte_decode(b, 12)
        assert all(0 <= c < Q for c in f)
        assert len(f) == N


# ── encode_vec / decode_vec ───────────────────────────────────────────────

class TestEncodeDecodeVec:
    @pytest.mark.parametrize("k,d", [(2, 10), (3, 10), (4, 11), (3, 4)])
    def test_output_length(self, k, d):
        v = [_rand_poly(i) for i in range(k)]
        encoded = encode_vec(v, d)
        assert len(encoded) == k * (N * d) // 8

    @pytest.mark.parametrize("k,d", [(2, 10), (3, 10), (4, 11)])
    def test_decode_length(self, k, d):
        v = [_rand_poly(i) for i in range(k)]
        encoded = encode_vec(v, d)
        decoded = decode_vec(encoded, k, d)
        assert len(decoded) == k
        assert all(len(p) == N for p in decoded)

    def test_roundtrip_approximate(self):
        """
        encode_vec comprime antes de codificar, por lo que hay pérdida.
        Verificamos que el error de redondeo es pequeño (< Q/2^du).
        """
        k, d = 3, 10
        from mlkem_pkg.codec import compress_poly, decompress_poly
        v = [_rand_poly(i) for i in range(k)]
        encoded = encode_vec(v, d)
        decoded = decode_vec(encoded, k, d)

        tol = Q // (2**d) + 2
        for pi, po in zip(v, decoded):
            for ci, co in zip(pi, po):
                err = min(abs(ci - co), Q - abs(ci - co))
                assert err <= tol, f"Error {err} supera tolerancia {tol}"
