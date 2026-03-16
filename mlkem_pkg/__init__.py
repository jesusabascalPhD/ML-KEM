"""
mlkem — ML-KEM (CRYSTALS-Kyber) en Python
==========================================
Implementación de NIST FIPS 203.

Uso rápido
----------
>>> from mlkem import MLKEM
>>> kem = MLKEM(768)          # o 512 / 1024
>>> ek, dk = kem.keygen()
>>> K_alice, c = kem.encaps(ek)
>>> K_bob = kem.decaps(dk, c)
>>> assert K_alice == K_bob

Módulos
-------
constants   Constantes del anillo, tablas NTT y parámetros
hash_utils  Funciones G, H, J, PRF, XOF  (FIPS 203 §4.1)
poly        Aritmética de polinomios, NTT / INTT
codec       Codificación, compresión y serialización
sampling    SampleNTT y SampleCBD
kem         Clase MLKEM  (K-PKE + ML-KEM completo)
"""

from .kem import MLKEM

__all__ = ["MLKEM"]
__version__ = "1.0.0"
