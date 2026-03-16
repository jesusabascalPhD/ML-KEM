"""
tests/test_poly.py
──────────────────
Tests unitarios para mlkem_pkg/poly.py:
  - poly_add, poly_sub, poly_zero
  - ntt / ntt_inv (transformada y su inversa)
  - poly_mul_ntt (multiplicación en dominio NTT)
  - vec_add, mat_vec_mul, vec_dot
"""

import pytest
from mlkem_pkg.constants import Q, N
from mlkem_pkg.poly import (
    poly_zero, poly_add, poly_sub,
    ntt, ntt_inv, poly_mul_ntt,
    vec_add, mat_vec_mul, vec_dot,
)


# ── Utilidades de test ────────────────────────────────────────────────────

def _rand_poly(seed: int) -> list[int]:
    """Polinomio pseudoaleatorio reproducible."""
    import hashlib
    b = hashlib.shake_256(seed.to_bytes(4, "big")).digest(N * 2)
    return [int.from_bytes(b[i*2:(i+1)*2], "big") % Q for i in range(N)]


# ── poly_zero ─────────────────────────────────────────────────────────────

class TestPolyZero:
    def test_length(self):
        assert len(poly_zero()) == N

    def test_all_zeros(self):
        assert all(c == 0 for c in poly_zero())


# ── poly_add / poly_sub ───────────────────────────────────────────────────

class TestPolyAddSub:
    def test_add_commutative(self):
        a = _rand_poly(0)
        b = _rand_poly(1)
        assert poly_add(a, b) == poly_add(b, a)

    def test_add_zero(self):
        a = _rand_poly(2)
        assert poly_add(a, poly_zero()) == a

    def test_sub_self_is_zero(self):
        a = _rand_poly(3)
        result = poly_sub(a, a)
        assert all(c == 0 for c in result)

    def test_add_sub_inverse(self):
        a = _rand_poly(4)
        b = _rand_poly(5)
        assert poly_sub(poly_add(a, b), b) == a

    def test_coefficients_in_range(self):
        a = _rand_poly(6)
        b = _rand_poly(7)
        result = poly_add(a, b)
        assert all(0 <= c < Q for c in result)

    def test_length_preserved(self):
        a = _rand_poly(8)
        b = _rand_poly(9)
        assert len(poly_add(a, b)) == N
        assert len(poly_sub(a, b)) == N


# ── NTT e INTT ────────────────────────────────────────────────────────────

class TestNTT:
    def test_roundtrip(self):
        """ntt_inv(ntt(f)) == f para cualquier polinomio."""
        f = _rand_poly(10)
        assert ntt_inv(ntt(f)) == f

    def test_roundtrip_zero(self):
        z = poly_zero()
        assert ntt_inv(ntt(z)) == z

    def test_roundtrip_constant(self):
        f = [1] + [0] * (N - 1)
        assert ntt_inv(ntt(f)) == f

    def test_ntt_not_identity(self):
        """NTT no debe ser la identidad (salvo coincidencia extrema)."""
        f = _rand_poly(11)
        assert ntt(f) != f

    def test_output_length(self):
        f = _rand_poly(12)
        assert len(ntt(f)) == N
        assert len(ntt_inv(f)) == N

    def test_coefficients_in_range(self):
        f = _rand_poly(13)
        assert all(0 <= c < Q for c in ntt(f))
        assert all(0 <= c < Q for c in ntt_inv(f))

    def test_linearity(self):
        """NTT es lineal: NTT(a+b) == NTT(a) + NTT(b)."""
        a = _rand_poly(14)
        b = _rand_poly(15)
        lhs = ntt(poly_add(a, b))
        rhs = poly_add(ntt(a), ntt(b))
        assert lhs == rhs


# ── poly_mul_ntt ──────────────────────────────────────────────────────────

class TestPolyMulNTT:
    def test_multiply_by_one(self):
        """f * 1 = f en dominio NTT."""
        f = _rand_poly(16)
        f_hat = ntt(f)
        one_hat = ntt([1] + [0] * (N - 1))
        result = ntt_inv(poly_mul_ntt(f_hat, one_hat))
        assert result == f

    def test_multiply_by_zero(self):
        """f * 0 = 0 en dominio NTT."""
        f_hat = ntt(_rand_poly(17))
        zero_hat = ntt(poly_zero())
        result = poly_mul_ntt(f_hat, zero_hat)
        assert ntt_inv(result) == poly_zero()

    def test_commutative(self):
        """Multiplicación conmutativa: a*b == b*a."""
        a_hat = ntt(_rand_poly(18))
        b_hat = ntt(_rand_poly(19))
        assert poly_mul_ntt(a_hat, b_hat) == poly_mul_ntt(b_hat, a_hat)

    def test_output_length(self):
        a_hat = ntt(_rand_poly(20))
        b_hat = ntt(_rand_poly(21))
        assert len(poly_mul_ntt(a_hat, b_hat)) == N

    def test_coefficients_in_range(self):
        a_hat = ntt(_rand_poly(22))
        b_hat = ntt(_rand_poly(23))
        result = poly_mul_ntt(a_hat, b_hat)
        assert all(0 <= c < Q for c in result)

    def test_distributive(self):
        """a*(b+c) == a*b + a*c en dominio NTT."""
        a_hat = ntt(_rand_poly(24))
        b_hat = ntt(_rand_poly(25))
        c_hat = ntt(_rand_poly(26))
        lhs = poly_mul_ntt(a_hat, poly_add(b_hat, c_hat))
        rhs = poly_add(poly_mul_ntt(a_hat, b_hat), poly_mul_ntt(a_hat, c_hat))
        assert lhs == rhs


# ── Operaciones vectoriales ───────────────────────────────────────────────

class TestVecOps:
    def _make_vec(self, k: int, seed_offset: int) -> list:
        return [_rand_poly(seed_offset + i) for i in range(k)]

    def test_vec_add_commutative(self):
        u = self._make_vec(3, 0)
        v = self._make_vec(3, 3)
        assert vec_add(u, v) == vec_add(v, u)

    def test_vec_add_zero(self):
        u = self._make_vec(3, 10)
        zero = [poly_zero() for _ in range(3)]
        assert vec_add(u, zero) == u

    def test_mat_vec_mul_identity(self):
        """Multiplicar por la matriz identidad (en NTT) debe ser la identidad."""
        k = 2
        one_hat = ntt([1] + [0] * (N - 1))
        zero_hat = poly_zero()
        # Identidad en NTT
        I = [[one_hat if i == j else zero_hat for j in range(k)] for i in range(k)]
        v = [ntt(_rand_poly(i)) for i in range(k)]
        result = mat_vec_mul(I, v)
        assert result == v

    def test_mat_vec_mul_zero_matrix(self):
        k = 2
        zero_hat = poly_zero()
        Z = [[zero_hat] * k for _ in range(k)]
        v = [ntt(_rand_poly(i)) for i in range(k)]
        result = mat_vec_mul(Z, v)
        expected = [poly_zero()] * k
        assert result == expected

    def test_vec_dot_commutative(self):
        k = 3
        u = [ntt(_rand_poly(i))   for i in range(k)]
        v = [ntt(_rand_poly(k+i)) for i in range(k)]
        assert vec_dot(u, v) == vec_dot(v, u)

    def test_vec_dot_zero(self):
        k = 3
        u = [ntt(_rand_poly(i)) for i in range(k)]
        z = [poly_zero()] * k
        assert vec_dot(u, z) == poly_zero()
