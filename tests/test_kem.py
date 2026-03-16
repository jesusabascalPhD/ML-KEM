"""
tests/test_kem.py
─────────────────
Tests unitarios para mlkem_pkg/kem.py (clase MLKEM):
  - keygen: tamaños de clave
  - encaps: tamaño de cápsula y secreto
  - decaps: corrección, rechazo implícito
  - K-PKE interno: cifrado/descifrado simétrico
"""

import pytest
from mlkem_pkg.kem import MLKEM, _ct_eq


# ── Parámetros esperados por nivel ────────────────────────────────────────
# (ek_size, dk_size, ct_size)  según FIPS 203 Tabla 2
EXPECTED = {
    512:  (800,  1632,  768),
    768:  (1184, 2400,  1088),
    1024: (1568, 3168,  1568),
}


# ── Constructor ───────────────────────────────────────────────────────────

class TestMLKEMInit:
    def test_valid_levels(self):
        for level in [512, 768, 1024]:
            kem = MLKEM(level)
            assert kem.security_level == level

    def test_default_level(self):
        kem = MLKEM()
        assert kem.security_level == 768

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError):
            MLKEM(256)

    def test_invalid_level_raises_message(self):
        with pytest.raises(ValueError, match="512"):
            MLKEM(999)

    @pytest.mark.parametrize("level,k", [(512, 2), (768, 3), (1024, 4)])
    def test_k_parameter(self, level, k):
        assert MLKEM(level).k == k


# ── keygen ────────────────────────────────────────────────────────────────

class TestKeyGen:
    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_key_sizes(self, level):
        ek_exp, dk_exp, _ = EXPECTED[level]
        ek, dk = MLKEM(level).keygen()
        assert len(ek) == ek_exp, f"ek size: {len(ek)} != {ek_exp}"
        assert len(dk) == dk_exp, f"dk size: {len(dk)} != {dk_exp}"

    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_keys_are_random(self, level):
        kem = MLKEM(level)
        ek1, _ = kem.keygen()
        ek2, _ = kem.keygen()
        assert ek1 != ek2

    def test_keygen_returns_bytes(self):
        ek, dk = MLKEM(768).keygen()
        assert isinstance(ek, bytes)
        assert isinstance(dk, bytes)


# ── encaps ────────────────────────────────────────────────────────────────

class TestEncaps:
    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_output_sizes(self, level):
        _, _, ct_exp = EXPECTED[level]
        kem = MLKEM(level)
        ek, _ = kem.keygen()
        K, c = kem.encaps(ek)
        assert len(K) == 32,      f"Shared secret size: {len(K)}"
        assert len(c) == ct_exp,  f"Ciphertext size: {len(c)} != {ct_exp}"

    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_encaps_is_random(self, level):
        kem = MLKEM(level)
        ek, _ = kem.keygen()
        K1, c1 = kem.encaps(ek)
        K2, c2 = kem.encaps(ek)
        assert K1 != K2
        assert c1 != c2

    def test_returns_bytes(self):
        kem = MLKEM(768)
        ek, _ = kem.keygen()
        K, c = kem.encaps(ek)
        assert isinstance(K, bytes)
        assert isinstance(c, bytes)


# ── decaps: corrección ────────────────────────────────────────────────────

class TestDecapsCorrectness:
    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_shared_secret_matches(self, level):
        """El secreto compartido debe coincidir entre emisor y receptor."""
        kem = MLKEM(level)
        ek, dk = kem.keygen()
        K_sender, c = kem.encaps(ek)
        K_receiver  = kem.decaps(dk, c)
        assert K_sender == K_receiver

    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_multiple_rounds(self, level):
        """Varias encapsulaciones con la misma clave deben funcionar."""
        kem = MLKEM(level)
        ek, dk = kem.keygen()
        for _ in range(3):
            K_s, c = kem.encaps(ek)
            K_r    = kem.decaps(dk, c)
            assert K_s == K_r

    def test_output_is_32_bytes(self):
        kem = MLKEM(768)
        ek, dk = kem.keygen()
        _, c = kem.encaps(ek)
        K = kem.decaps(dk, c)
        assert len(K) == 32
        assert isinstance(K, bytes)


# ── decaps: rechazo implícito ─────────────────────────────────────────────

class TestImplicitRejection:
    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_tampered_ciphertext_gives_different_key(self, level):
        """Con cápsula manipulada, decaps devuelve una clave distinta."""
        kem = MLKEM(level)
        ek, dk = kem.keygen()
        K_good, c = kem.encaps(ek)
        c_bad = bytes([c[0] ^ 0xFF]) + c[1:]
        K_bad = kem.decaps(dk, c_bad)
        assert K_good != K_bad

    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_rejection_key_is_deterministic(self, level):
        """La clave de rechazo para una cápsula dada siempre es la misma."""
        kem = MLKEM(level)
        ek, dk = kem.keygen()
        _, c = kem.encaps(ek)
        c_bad = bytes([c[0] ^ 0xFF]) + c[1:]
        K1 = kem.decaps(dk, c_bad)
        K2 = kem.decaps(dk, c_bad)
        assert K1 == K2

    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_rejection_key_length(self, level):
        kem = MLKEM(level)
        ek, dk = kem.keygen()
        _, c = kem.encaps(ek)
        c_bad = c[:-1] + bytes([c[-1] ^ 0x01])
        K_bad = kem.decaps(dk, c_bad)
        assert len(K_bad) == 32


# ── K-PKE interno ─────────────────────────────────────────────────────────

class TestKPKE:
    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_pke_encrypt_decrypt_roundtrip(self, level):
        """El PKE subyacente debe ser correcto."""
        import os
        kem = MLKEM(level)
        ek, dk_pke_full = kem.keygen()
        dk_pke = dk_pke_full[:kem.k * 384]

        m = os.urandom(32)
        r = os.urandom(32)
        c = kem._pke_encrypt(ek, m, r)
        m2 = kem._pke_decrypt(dk_pke, c)
        assert m == m2

    def test_pke_ciphertext_size_512(self):
        import os
        kem = MLKEM(512)
        ek, _ = kem.keygen()
        c = kem._pke_encrypt(ek, bytes(32), bytes(32))
        assert len(c) == 768

    def test_pke_ciphertext_size_768(self):
        import os
        kem = MLKEM(768)
        ek, _ = kem.keygen()
        c = kem._pke_encrypt(ek, bytes(32), bytes(32))
        assert len(c) == 1088


# ── _ct_eq ────────────────────────────────────────────────────────────────

class TestCtEq:
    def test_equal_bytes(self):
        assert _ct_eq(b"hello", b"hello") is True

    def test_different_bytes(self):
        assert _ct_eq(b"hello", b"world") is False

    def test_different_lengths(self):
        assert _ct_eq(b"abc", b"ab") is False

    def test_empty(self):
        assert _ct_eq(b"", b"") is True

    def test_single_bit_difference(self):
        a = bytes(32)
        b = bytes([0] * 31 + [1])
        assert _ct_eq(a, b) is False
