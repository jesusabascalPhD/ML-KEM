"""
tests/test_hash_utils.py
────────────────────────
Tests unitarios para mlkem_pkg/hash_utils.py:
  - G, H, J: longitud de salida y determinismo
  - PRF: longitud según eta, determinismo
  - XOF: flujo reproducible
"""

import pytest
from mlkem_pkg.hash_utils import G, H, J, PRF, XOF


class TestG:
    def test_output_lengths(self):
        rho, sigma = G(b"test")
        assert len(rho) == 32
        assert len(sigma) == 32

    def test_deterministic(self):
        a1, b1 = G(b"hello")
        a2, b2 = G(b"hello")
        assert a1 == a2
        assert b1 == b2

    def test_different_inputs_different_outputs(self):
        a1, b1 = G(b"input_a")
        a2, b2 = G(b"input_b")
        assert a1 != a2
        assert b1 != b2

    def test_two_halves_are_different(self):
        rho, sigma = G(b"data")
        assert rho != sigma

    def test_empty_input(self):
        rho, sigma = G(b"")
        assert len(rho) == 32
        assert len(sigma) == 32


class TestH:
    def test_output_length(self):
        assert len(H(b"test")) == 32

    def test_deterministic(self):
        assert H(b"hello") == H(b"hello")

    def test_different_inputs(self):
        assert H(b"a") != H(b"b")

    def test_empty_input(self):
        assert len(H(b"")) == 32


class TestJ:
    def test_output_length(self):
        assert len(J(b"test")) == 32

    def test_deterministic(self):
        assert J(b"hello") == J(b"hello")

    def test_different_inputs(self):
        assert J(b"a") != J(b"b")

    def test_differs_from_H(self):
        """J y H usan primitivas distintas: sus salidas deben diferir."""
        data = b"same input"
        assert H(data) != J(data)


class TestPRF:
    @pytest.mark.parametrize("eta", [2, 3])
    def test_output_length(self, eta):
        s = bytes(32)
        assert len(PRF(eta, s, 0)) == 64 * eta

    def test_deterministic(self):
        s = bytes(32)
        assert PRF(2, s, 5) == PRF(2, s, 5)

    def test_different_counter_different_output(self):
        s = bytes(32)
        assert PRF(2, s, 0) != PRF(2, s, 1)

    def test_different_seed_different_output(self):
        assert PRF(2, bytes(32), 0) != PRF(2, bytes([1]*32), 0)

    def test_counter_range(self):
        """Debe funcionar con contadores de 0 a 255."""
        s = bytes(32)
        outputs = {PRF(2, s, b) for b in range(256)}
        assert len(outputs) == 256


class TestXOF:
    def test_reproducible(self):
        rho = bytes(32)
        s1 = XOF(rho, 0, 0).digest(64)
        s2 = XOF(rho, 0, 0).digest(64)
        assert s1 == s2

    def test_different_ij_different_stream(self):
        rho = bytes(32)
        assert XOF(rho, 0, 0).digest(64) != XOF(rho, 0, 1).digest(64)
        assert XOF(rho, 0, 0).digest(64) != XOF(rho, 1, 0).digest(64)

    def test_different_rho_different_stream(self):
        assert XOF(bytes(32), 0, 0).digest(64) != XOF(bytes([1]*32), 0, 0).digest(64)

    def test_output_length(self):
        for n in [16, 64, 256, 840]:
            assert len(XOF(bytes(32), 0, 0).digest(n)) == n
