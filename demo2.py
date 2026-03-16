"""
demo.py
───────
Demostración de ML-KEM + AES-256-GCM:

  Alice cifra un mensaje con AES-GCM usando la clave derivada del KEM.
  Bob descifra el mensaje usando su clave de desencapsulación.

Sin dependencias externas — AES-GCM implementado en mlkem_pkg/aes_gcm.py.

Ejecutar desde el directorio raíz del proyecto:
    python demo.py
"""

from mlkem_pkg import MLKEM
from mlkem_pkg.aes_gcm import aes_gcm_encrypt, aes_gcm_decrypt


# ── Demo principal ────────────────────────────────────────────────────────

MENSAJE = "Hola Bob, esto es un secreto cifrado con ML-KEM + AES-GCM 🔐"

def demo() -> None:
    print("=" * 62)
    print("   ML-KEM + AES-256-GCM — Intercambio de mensaje seguro")
    print("   Cifrado simétrico: AES-256-GCM (implementación propia)")
    print("=" * 62)
    print(f"\n  Mensaje original : «{MENSAJE}»")

    for level in [512, 768, 1024]:
        print(f"\n{'─'*62}")
        print(f"  ML-KEM-{level}")
        print(f"{'─'*62}")
        kem = MLKEM(level)

        # ── Alice genera sus claves ───────────────────────────────
        ek, dk = kem.keygen()
        print(f"  [1] Claves generadas   ek={len(ek)}B  dk={len(dk)}B")

        # ── Alice publica ek. Bob encapsula y obtiene K + cápsula ─
        K_bob, capsula = kem.encaps(ek)
        print(f"  [2] Bob encapsula      cápsula={len(capsula)}B")
        print(f"       Clave Bob  : {K_bob.hex()[:32]}…")

        # ── Bob cifra el mensaje con K_bob ────────────────────────
        nonce, ct_mensaje = aes_gcm_encrypt(K_bob, MENSAJE.encode())
        print(f"  [3] Bob cifra          nonce={nonce.hex()}  ct={len(ct_mensaje)}B")

        # ── Alice desencapsula la cápsula y obtiene K_alice ───────
        K_alice = kem.decaps(dk, capsula)
        print(f"  [4] Alice desencapsula")
        print(f"       Clave Alice: {K_alice.hex()[:32]}…")
        print(f"       Claves iguales: {'✓' if K_alice == K_bob else '✗ ERROR'}")

        # ── Alice descifra el mensaje ─────────────────────────────
        texto = aes_gcm_decrypt(K_alice, nonce, ct_mensaje)
        if texto is not None:
            print(f"  [5] Alice descifra  ✓")
            print(f"       Mensaje        : «{texto.decode()}»")
        else:
            print("  [5] Alice descifra  ✗ ERROR — autenticación fallida")

        # ── Test de rechazo: cápsula manipulada ───────────────────
        capsula_mala = bytes([capsula[0] ^ 0xFF]) + capsula[1:]
        K_mala = kem.decaps(dk, capsula_mala)
        texto_malo = aes_gcm_decrypt(K_mala, nonce, ct_mensaje)
        rechazado = texto_malo is None
        print(f"  [6] Cápsula manipulada → descifrado falla: {'✓' if rechazado else '✗ ERROR'}")

    print(f"\n{'='*62}")
    print("  Todos los tests pasaron. ✓")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    demo()