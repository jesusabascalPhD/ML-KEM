"""
tests/test_constants.py
───────────────────────
Tests unitarios para mlkem_pkg/constants.py:
  - Valores de Q, N, ZETA
  - Tablas ZETAS y BASEMUL_ZETAS
  - Conjuntos de parámetros PARAMS
"""

import pytest
from mlkem_pkg.constants import Q, N, ZETA, ZETAS, BASEMUL_ZETAS, PARAMS, _bit_reverse


class TestBasicConstants:
    def test_Q_value(self):
        assert Q == 3329

    def test_N_value(self):
        assert N == 256

    def test_ZETA_value(self):
        assert ZETA == 17

    def test_ZETA_is_primitive_root(self):
        """17 debe ser raíz primitiva 256-ésima de la unidad mod Q."""
        # 17^256 ≡ 1 (mod Q)
        assert pow(ZETA, 256, Q) == 1
        # Ninguna potencia menor debe ser 1 (orden exactamente 256)
        for exp in [1, 2, 4, 8, 16, 32, 64, 128]:
            assert pow(ZETA, exp, Q) != 1


class TestBitReverse:
    def test_zero(self):
        assert _bit_reverse(0, 7) == 0

    def test_one(self):
        # 0b0000001 invertido en 7 bits → 0b1000000 = 64
        assert _bit_reverse(1, 7) == 64

    def test_full(self):
        # 0b1111111 = 127 invertido → 127
        assert _bit_reverse(127, 7) == 127

    def test_known_value(self):
        # 0b0000010 = 2 → 0b0100000 = 32
        assert _bit_reverse(2, 7) == 32

    def test_involution(self):
        """Aplicar dos veces debe devolver el valor original."""
        for i in range(128):
            assert _bit_reverse(_bit_reverse(i, 7), 7) == i


class TestZetas:
    def test_length(self):
        assert len(ZETAS) == 128

    def test_all_in_range(self):
        assert all(0 <= z < Q for z in ZETAS)

    def test_first_element(self):
        # ZETAS[0] = 17^bitrev7(0) = 17^0 = 1
        assert ZETAS[0] == 1

    def test_known_value(self):
        # ZETAS[1] = 17^bitrev7(1) = 17^64 mod 3329
        assert ZETAS[1] == pow(17, _bit_reverse(1, 7), Q)

    def test_formula(self):
        """Verificar toda la tabla contra la fórmula."""
        for i in range(128):
            assert ZETAS[i] == pow(ZETA, _bit_reverse(i, 7), Q)


class TestBasemulZetas:
    def test_length(self):
        assert len(BASEMUL_ZETAS) == 128

    def test_all_in_range(self):
        assert all(0 <= z < Q for z in BASEMUL_ZETAS)

    def test_first_element(self):
        # BASEMUL_ZETAS[0] = 17^(2*0+1) = 17
        assert BASEMUL_ZETAS[0] == 17

    def test_formula(self):
        """Verificar toda la tabla contra la fórmula FIPS 203."""
        for i in range(128):
            expected = pow(ZETA, 2 * _bit_reverse(i, 7) + 1, Q)
            assert BASEMUL_ZETAS[i] == expected

    def test_distinct_from_ntt_zetas(self):
        """BASEMUL_ZETAS y ZETAS deben ser diferentes (salvo coincidencias)."""
        assert BASEMUL_ZETAS != ZETAS


class TestParams:
    def test_valid_levels(self):
        assert set(PARAMS.keys()) == {512, 768, 1024}

    @pytest.mark.parametrize("level,expected", [
        (512,  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4}),
        (768,  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4}),
        (1024, {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5}),
    ])
    def test_param_values(self, level, expected):
        assert PARAMS[level] == expected

    def test_k_increases_with_level(self):
        assert PARAMS[512]["k"] < PARAMS[768]["k"] < PARAMS[1024]["k"]
