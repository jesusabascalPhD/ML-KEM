"""
kem.py
──────
Implementación principal de ML-KEM (FIPS 203):

  Clase MLKEM
  ├── keygen()            → (ek, dk)
  ├── encaps(ek)          → (K, c)
  └── decaps(dk, c)       → K

Internamente delega en K-PKE (cifrado de clave pública subyacente):
  _pke_keygen(d)          → (ek_pke, dk_pke)
  _pke_encrypt(ek, m, r)  → c
  _pke_decrypt(dk, c)     → m
"""

import os
from typing import Tuple

from .constants import Q, N, PARAMS
from .hash_utils import G, H, J, PRF
from .poly      import ntt, ntt_inv, vec_add, mat_vec_mul, vec_dot, poly_add, poly_sub
from .codec     import byte_encode, byte_decode, compress_poly, decompress_poly, encode_vec, decode_vec
from .sampling  import sample_ntt, sample_cbd


class MLKEM:
    """
    ML-KEM — Key Encapsulation Mechanism post-cuántico.

    Implementa NIST FIPS 203 para los tres conjuntos de parámetros:
      - ML-KEM-512   (~128 bits de seguridad)
      - ML-KEM-768   (~192 bits de seguridad)  ← por defecto
      - ML-KEM-1024  (~256 bits de seguridad)

    Uso básico
    ----------
    >>> kem = MLKEM(768)
    >>> ek, dk = kem.keygen()
    >>> K_alice, c = kem.encaps(ek)
    >>> K_bob = kem.decaps(dk, c)
    >>> assert K_alice == K_bob
    """

    def __init__(self, security_level: int = 768) -> None:
        if security_level not in PARAMS:
            raise ValueError(
                f"Nivel de seguridad inválido: {security_level}. "
                f"Opciones válidas: {sorted(PARAMS)}"
            )
        p = PARAMS[security_level]
        self.security_level = security_level
        self.k    = p["k"]
        self.eta1 = p["eta1"]
        self.eta2 = p["eta2"]
        self.du   = p["du"]
        self.dv   = p["dv"]

    # ── Generación de la matriz pública A ─────────────────────────────────

    def _generate_matrix(self, rho: bytes, transpose: bool = False):
        """
        Genera la matriz pública A (o Aᵀ) en dominio NTT.
        A[i][j] = SampleNTT(rho, i, j)   (o A[i][j] = SampleNTT(rho, j, i) si transpuesta)
        """
        k = self.k
        return [
            [
                sample_ntt(rho, j if transpose else i,
                                i if transpose else j)
                for j in range(k)
            ]
            for i in range(k)
        ]

    # ── K-PKE: Generación de claves ───────────────────────────────────────

    def _pke_keygen(self, d: bytes) -> Tuple[bytes, bytes]:
        """
        K-PKE.KeyGen (FIPS 203 Alg. 12).

        Entrada: d — 32 bytes aleatorios.
        Salida:  (ek_pke, dk_pke)
        """
        k = self.k
        rho, sigma = G(d + bytes([k]))

        A_hat = self._generate_matrix(rho, transpose=False)

        # Muestrear s y e de la distribución CBD_eta1
        s = [sample_cbd(self.eta1, PRF(self.eta1, sigma, i))     for i in range(k)]
        e = [sample_cbd(self.eta1, PRF(self.eta1, sigma, k + i)) for i in range(k)]

        s_hat = [ntt(si) for si in s]
        e_hat = [ntt(ei) for ei in e]

        # t̂ = Â·ŝ + ê
        t_hat = vec_add(mat_vec_mul(A_hat, s_hat), e_hat)

        # Serializar
        ek_pke = b"".join(byte_encode(t, 12) for t in t_hat) + rho
        dk_pke = b"".join(byte_encode(s, 12) for s in s_hat)
        return ek_pke, dk_pke

    # ── K-PKE: Cifrado ────────────────────────────────────────────────────

    def _pke_encrypt(self, ek: bytes, m: bytes, r: bytes) -> bytes:
        """
        K-PKE.Encrypt (FIPS 203 Alg. 13).

        Parámetros
        ----------
        ek : clave de encapsulación (clave pública PKE)
        m  : mensaje de 32 bytes
        r  : aleatoridad de 32 bytes
        """
        k = self.k

        # Decodificar clave pública
        t_hat = [byte_decode(ek[i*384:(i+1)*384], 12) for i in range(k)]
        rho   = ek[k*384:]

        A_hat_T = self._generate_matrix(rho, transpose=True)

        # Muestrear y, e1, e2
        y  = [sample_cbd(self.eta1, PRF(self.eta1, r, i))      for i in range(k)]
        e1 = [sample_cbd(self.eta2, PRF(self.eta2, r, k + i))  for i in range(k)]
        e2 =  sample_cbd(self.eta2, PRF(self.eta2, r, 2 * k))

        y_hat = [ntt(yi) for yi in y]

        # u = Aᵀ·y + e1  (en dominio normal)
        u_hat = vec_add(mat_vec_mul(A_hat_T, y_hat), [ntt(ei) for ei in e1])
        u     = [ntt_inv(ui) for ui in u_hat]

        # mu: descodificar el mensaje de 1 bit por coeficiente
        mu = decompress_poly(byte_decode(m, 1), 1)

        # v = tᵀ·y + e2 + mu
        v = poly_add(
            poly_add(ntt_inv(vec_dot(t_hat, y_hat)), e2),
            mu
        )

        # Comprimir y serializar
        c1 = encode_vec(u, self.du)
        c2 = byte_encode(compress_poly(v, self.dv), self.dv)
        return c1 + c2

    # ── K-PKE: Descifrado ─────────────────────────────────────────────────

    def _pke_decrypt(self, dk: bytes, c: bytes) -> bytes:
        """
        K-PKE.Decrypt (FIPS 203 Alg. 14).

        Parámetros
        ----------
        dk : clave privada PKE (ŝ serializado)
        c  : texto cifrado
        """
        k = self.k
        c1_len = k * self.du * N // 8
        c1, c2 = c[:c1_len], c[c1_len:]

        u     = decode_vec(c1, k, self.du)
        v     = decompress_poly(byte_decode(c2, self.dv), self.dv)
        s_hat = [byte_decode(dk[i*384:(i+1)*384], 12) for i in range(k)]

        # w = v − ŝᵀ·û
        u_hat = [ntt(ui) for ui in u]
        w = poly_sub(v, ntt_inv(vec_dot(s_hat, u_hat)))
        return byte_encode(compress_poly(w, 1), 1)

    # ── ML-KEM: API pública ───────────────────────────────────────────────

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        ML-KEM.KeyGen (FIPS 203 Alg. 15).

        Genera un par de claves frescas.

        Devuelve
        --------
        ek : clave de encapsulación (pública)
        dk : clave de desencapsulación (privada)
        """
        d = os.urandom(32)
        z = os.urandom(32)
        ek, dk_pke = self._pke_keygen(d)
        dk = dk_pke + ek + H(ek) + z
        return ek, dk

    def encaps(self, ek: bytes) -> Tuple[bytes, bytes]:
        """
        ML-KEM.Encaps (FIPS 203 Alg. 16).

        Parámetros
        ----------
        ek : clave de encapsulación del destinatario

        Devuelve
        --------
        K : secreto compartido de 32 bytes
        c : texto cifrado (encapsulación)
        """
        m    = os.urandom(32)
        K, r = G(m + H(ek))
        c    = self._pke_encrypt(ek, m, r)
        return K, c

    def decaps(self, dk: bytes, c: bytes) -> bytes:
        """
        ML-KEM.Decaps (FIPS 203 Alg. 17).

        Implementa rechazo implícito: si el texto cifrado ha sido
        manipulado, devuelve una clave pseudoaleatoria derivada de z,
        indistinguible de una clave legítima para un atacante.

        Parámetros
        ----------
        dk : clave de desencapsulación privada
        c  : texto cifrado recibido

        Devuelve
        --------
        K : secreto compartido de 32 bytes
        """
        k = self.k

        # Desempaquetar dk = dk_pke ∥ ek ∥ H(ek) ∥ z
        dk_pke = dk[:k*384]
        ek     = dk[k*384      : k*384 + k*384 + 32]
        h      = dk[k*384 + k*384 + 32 : k*384 + k*384 + 64]
        z      = dk[k*384 + k*384 + 64:]

        m_prime      = self._pke_decrypt(dk_pke, c)
        K_prime, r_prime = G(m_prime + h)
        K_reject     = J(z + c)

        c_prime = self._pke_encrypt(ek, m_prime, r_prime)

        # Selección en tiempo constante
        ok = _ct_eq(c, c_prime)
        return bytes(K_prime[i] if ok else K_reject[i] for i in range(32))


# ── Comparación en tiempo constante ──────────────────────────────────────

def _ct_eq(a: bytes, b: bytes) -> bool:
    """
    Compara dos arrays de bytes en tiempo constante.
    Evita ataques de temporización en la comprobación de integridad.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
