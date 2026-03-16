# ML-KEM — Post-Quantum Key Encapsulation in Python

> Implementación en Python del algoritmo **ML-KEM** (Module Lattice-based Key Encapsulation Mechanism), estándar PQC aprobado por el NIST (FIPS 203).

---

## ¿Qué es ML-KEM?

ML-KEM (antes conocido como CRYSTALS-Kyber) es un algoritmo de **encapsulación de claves resistente a ataques cuánticos**, basado en el problema de aprendizaje con errores sobre módulos (Module-LWE). Forma parte de la primera ronda de estándares post-cuánticos publicados por el NIST en 2024.

Este proyecto implementa ML-KEM en Python puro con fines educativos y de prueba, siguiendo la especificación oficial **FIPS 203**.

---

## Características

- ✅ Implementación de los tres niveles de seguridad: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`
- ✅ Generación de par de claves (`KeyGen`)
- ✅ Encapsulación de clave compartida (`Encaps`)
- ✅ Desencapsulación (`Decaps`)
- ✅ Código legible y comentado, orientado al aprendizaje

---

## Requisitos

- Python 3.10 o superior
- No requiere dependencias externas (solo biblioteca estándar)

> Opcionalmente, puedes instalar `pytest` para ejecutar los tests.

---

## Instalación

```bash
# Clona el repositorio
git clone https://github.com/tu-usuario/ml-kem.git
cd ml-kem
```

Si quieres ejecutar los tests:

```bash
pip install pytest
```

---

## Uso

### Ejemplo básico

```python
from mlkem import MLKEM

# Selecciona el nivel de seguridad: 512, 768 o 1024
kem = MLKEM(level=768)

# 1. Generación de claves
ek, dk = kem.keygen()

# 2. Encapsulación (lado del emisor)
ciphertext, shared_secret_sender = kem.encaps(ek)

# 3. Desencapsulación (lado del receptor)
shared_secret_receiver = kem.decaps(dk, ciphertext)

# Verificación
assert shared_secret_sender == shared_secret_receiver
print("✅ Clave compartida establecida correctamente")
print(f"   Clave (hex): {shared_secret_sender.hex()}")
```

### Ejecutar los tests

```bash
pytest tests/
```

---

## Estructura del proyecto

```
ml-kem/
├── mlkem/
│   ├── __init__.py
│   ├── mlkem.py          # Clase principal ML-KEM
│   ├── ntt.py            # Transformada de número teórico (NTT)
│   ├── sampling.py       # Funciones de muestreo
│   └── utils.py          # Funciones auxiliares (XOF, PRF, KDF)
├── tests/
│   └── test_mlkem.py     # Tests unitarios
├── README.md
└── main.py               # Script de demostración
```

---

## Niveles de seguridad

| Variante      | Seguridad NIST | Tamaño clave pública | Tamaño ciphertext |
|---------------|:--------------:|---------------------:|------------------:|
| ML-KEM-512    | Nivel 1        | 800 bytes            | 768 bytes         |
| ML-KEM-768    | Nivel 3        | 1184 bytes           | 1088 bytes        |
| ML-KEM-1024   | Nivel 5        | 1568 bytes           | 1568 bytes        |

---

## Referencias

- [NIST FIPS 203 — ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [CRYSTALS-Kyber (origen del algoritmo)](https://pq-crystals.org/kyber/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## Aviso

> ⚠️ Esta implementación es **educativa y experimental**. No ha sido auditada para uso en producción. Para aplicaciones reales, utiliza bibliotecas criptográficas certificadas como [liboqs](https://github.com/open-quantum-safe/liboqs).

---

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el archivo `LICENSE` para más detalles.