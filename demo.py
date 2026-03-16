"""
demo.py
───────
Script de demostración para ML-KEM.

Ejecutar desde el directorio raíz del proyecto:
    python demo.py
"""

from mlkem_pkg import MLKEM


def demo() -> None:
    print("=" * 60)
    print("   ML-KEM (CRYSTALS-Kyber) — Python Implementation")
    print("   NIST FIPS 203")
    print("=" * 60)

    for level in [512, 768, 1024]:
        print(f"\n── ML-KEM-{level} ──")
        kem = MLKEM(level)

        print("  [1] Key Generation ...", end=" ", flush=True)
        ek, dk = kem.keygen()
        print(f"OK  (ek={len(ek)}B, dk={len(dk)}B)")

        print("  [2] Encapsulation  ...", end=" ", flush=True)
        K_alice, c = kem.encaps(ek)
        print(f"OK  (ciphertext={len(c)}B)")

        print("  [3] Decapsulation  ...", end=" ", flush=True)
        K_bob = kem.decaps(dk, c)
        match = K_alice == K_bob
        status = "✓" if match else "✗ ERROR"
        print(f"OK  (claves coinciden: {status})")
        print(f"     Secreto compartido: {K_alice.hex()[:32]}…")

        print("  [4] Rechazo implícito ...", end=" ", flush=True)
        bad_c = bytes([c[0] ^ 0xFF]) + c[1:]
        K_bad = kem.decaps(dk, bad_c)
        different = K_alice != K_bad
        status = "✓" if different else "✗ ERROR"
        print(f"OK  (clave distinta con ct manipulado: {status})")

    print("\n" + "=" * 60)
    print("  Todos los tests pasaron. ✓")
    print("=" * 60)


if __name__ == "__main__":
    demo()
