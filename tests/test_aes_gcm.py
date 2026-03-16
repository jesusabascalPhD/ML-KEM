"""
tests/test_aes_gcm.py
─────────────────────
Tests unitarios para mlkem_pkg/aes_gcm.py:
  - aes_encrypt_block: bloque único AES-256
  - aes_gcm_encrypt / aes_gcm_decrypt: cifrado autenticado
"""

import os
import pytest
from mlkem_pkg.aes_gcm import aes_encrypt_block, aes_gcm_encrypt, aes_gcm_decrypt


KEY_32 = bytes(range(32))
KEY_B  = bytes([0xAB] * 32)


class TestAESBlock:
    def test_output_length(self):
        assert len(aes_encrypt_block(KEY_32, bytes(16))) == 16

    def test_deterministic(self):
        block = bytes(range(16))
        assert aes_encrypt_block(KEY_32, block) == aes_encrypt_block(KEY_32, block)

    def test_different_keys_different_output(self):
        block = bytes(16)
        assert aes_encrypt_block(KEY_32, block) != aes_encrypt_block(KEY_B, block)

    def test_different_blocks_different_output(self):
        block_a = bytes(16)
        block_b = bytes([1] + [0] * 15)
        assert aes_encrypt_block(KEY_32, block_a) != aes_encrypt_block(KEY_32, block_b)

    def test_nist_known_answer(self):
        """
        Vector NIST AES-256:
        key  = 000102...1f
        pt   = 00112233...ff (primeros 16 bytes)
        ct   = 8ea2b7ca516745bfeafc49904b496089  (conocido)
        """
        key = bytes(range(32))
        pt  = bytes(range(16))
        # Valor de referencia del NIST AESAVS
        expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        assert aes_encrypt_block(key, pt) == expected


class TestAESGCM:
    def test_encrypt_returns_nonce_and_ciphertext(self):
        nonce, ct = aes_gcm_encrypt(KEY_32, b"hello")
        assert len(nonce) == 12
        assert len(ct) > 0

    def test_ciphertext_length(self):
        """ct = plaintext + 16 bytes de tag."""
        msg = b"mensaje de prueba"
        _, ct = aes_gcm_encrypt(KEY_32, msg)
        assert len(ct) == len(msg) + 16

    def test_roundtrip(self):
        msg = b"Texto secreto con ML-KEM"
        nonce, ct = aes_gcm_encrypt(KEY_32, msg)
        assert aes_gcm_decrypt(KEY_32, nonce, ct) == msg

    @pytest.mark.parametrize("msg", [
        b"",
        b"a",
        b"A" * 16,
        b"B" * 17,
        b"C" * 100,
        "Hola mundo, esto es un secreto 🔐".encode(),
    ])
    def test_roundtrip_varios_mensajes(self, msg):
        nonce, ct = aes_gcm_encrypt(KEY_32, msg)
        assert aes_gcm_decrypt(KEY_32, nonce, ct) == msg

    def test_nonce_is_random(self):
        """Cada llamada debe generar un nonce distinto."""
        nonces = {aes_gcm_encrypt(KEY_32, b"test")[0] for _ in range(20)}
        assert len(nonces) == 20

    def test_ciphertext_differs_per_nonce(self):
        """Mismo mensaje, distinto nonce → distinto ciphertext."""
        ct_set = {aes_gcm_encrypt(KEY_32, b"test")[1] for _ in range(10)}
        assert len(ct_set) == 10

    def test_wrong_key_returns_none(self):
        nonce, ct = aes_gcm_encrypt(KEY_32, b"secreto")
        assert aes_gcm_decrypt(KEY_B, nonce, ct) is None

    def test_tampered_ciphertext_returns_none(self):
        nonce, ct = aes_gcm_encrypt(KEY_32, b"secreto")
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        assert aes_gcm_decrypt(KEY_32, nonce, tampered) is None

    def test_tampered_tag_returns_none(self):
        nonce, ct = aes_gcm_encrypt(KEY_32, b"secreto")
        tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        assert aes_gcm_decrypt(KEY_32, nonce, tampered) is None

    def test_tampered_nonce_returns_none(self):
        nonce, ct = aes_gcm_encrypt(KEY_32, b"secreto")
        bad_nonce = bytes([nonce[0] ^ 0xFF]) + nonce[1:]
        assert aes_gcm_decrypt(KEY_32, bad_nonce, ct) is None

    def test_too_short_ciphertext_returns_none(self):
        assert aes_gcm_decrypt(KEY_32, bytes(12), bytes(15)) is None

    def test_aad_roundtrip(self):
        msg = b"payload"
        aad = b"cabecera autenticada"
        nonce, ct = aes_gcm_encrypt(KEY_32, msg, aad=aad)
        assert aes_gcm_decrypt(KEY_32, nonce, ct, aad=aad) == msg

    def test_wrong_aad_returns_none(self):
        msg = b"payload"
        aad = b"cabecera correcta"
        nonce, ct = aes_gcm_encrypt(KEY_32, msg, aad=aad)
        assert aes_gcm_decrypt(KEY_32, nonce, ct, aad=b"cabecera falsa") is None
