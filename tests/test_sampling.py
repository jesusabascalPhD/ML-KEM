"""
tests/test_sampling.py
──────────────────────
Tests unitarios para mlkem_pkg/sampling.py:
  - sample_ntt: uniformidad, determinismo, rango
  - sample_cbd: distribución binomial centrada, rango
"""

import pytest
from mlkem_pkg.constants import Q, N
from mlkem_pkg.hash_utils import PRF
from mlkem_pkg.sampling import sample_ntt, sample_cbd


class TestSampleNTT:
    def test_output_length(self):
        assert len(sample_ntt(bytes(32), 0, 0)) == N

    def test_coefficients_in_range(self):
        f = sample_ntt(bytes(32), 0, 0)
        assert all(0 <= c < Q for c in f)

    def test_deterministic(self):
        rho = bytes(range(32))
        assert sample_ntt(rho, 0, 0) == sample_ntt(rho, 0, 0)

    def test_different_i_different_poly(self):
        rho = bytes(32)
        assert sample_ntt(rho, 0, 0) != sample_ntt(rho, 1, 0)

    def test_different_j_different_poly(self):
        rho = bytes(32)
        assert sample_ntt(rho, 0, 0) != sample_ntt(rho, 0, 1)

    def test_different_rho_different_poly(self):
        assert sample_ntt(bytes(32), 0, 0) != sample_ntt(bytes([1]*32), 0, 0)

    def test_all_ij_pairs_differ(self):
        """Para k=4, las 16 entradas de la matriz deben ser distintas."""
        rho = bytes(32)
        polys = [sample_ntt(rho, i, j) for i in range(4) for j in range(4)]
        assert len(set(map(tuple, polys))) == 16

    def test_approximate_uniformity(self):
        """
        Con suficientes muestras, la media debe acercarse a Q/2.
        Test estadístico muy relajado.
        """
        f = sample_ntt(bytes(32), 0, 0)
        mean = sum(f) / N
        assert Q * 0.3 < mean < Q * 0.7


class TestSampleCBD:
    @pytest.mark.parametrize("eta", [2, 3])
    def test_output_length(self, eta):
        b = PRF(eta, bytes(32), 0)
        assert len(sample_cbd(eta, b)) == N

    @pytest.mark.parametrize("eta", [2, 3])
    def test_coefficients_in_range(self, eta):
        b = PRF(eta, bytes(32), 0)
        f = sample_cbd(eta, b)
        assert all(0 <= c < Q for c in f)

    @pytest.mark.parametrize("eta", [2, 3])
    def test_deterministic(self, eta):
        b = PRF(eta, bytes(32), 0)
        assert sample_cbd(eta, b) == sample_cbd(eta, b)

    @pytest.mark.parametrize("eta", [2, 3])
    def test_centered_values(self, eta):
        """
        CBD produce coeficientes en [-eta, eta] mod Q.
        Representados en Zq, los negativos aparecen como valores >= Q - eta.
        """
        b = PRF(eta, bytes(32), 0)
        f = sample_cbd(eta, b)
        for c in f:
            assert c <= eta or c >= Q - eta, f"Coeficiente {c} fuera de rango CBD_{eta}"

    @pytest.mark.parametrize("eta", [2, 3])
    def test_small_norm(self, eta):
        """Los coeficientes deben ser pequeños (norma infinito ≤ eta)."""
        b = PRF(eta, bytes(32), 0)
        f = sample_cbd(eta, b)
        for c in f:
            centered = c if c < Q // 2 else c - Q
            assert abs(centered) <= eta

    def test_wrong_length_raises(self):
        with pytest.raises(AssertionError):
            sample_cbd(2, bytes(100))  # debería ser 128 bytes

    @pytest.mark.parametrize("eta", [2, 3])
    def test_different_counters_differ(self, eta):
        b0 = PRF(eta, bytes(32), 0)
        b1 = PRF(eta, bytes(32), 1)
        assert sample_cbd(eta, b0) != sample_cbd(eta, b1)
