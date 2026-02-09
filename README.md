

## 🔐 ElGamal Performance Benchmark (2048-bit)

**Benchmark context:** Modular exponentiation performance for ElGamal cryptographic operations using a **2048-bit prime**.

### 📌 Configuration

* **Prime size (p):** 2048 bits
* **Iterations per test:** 50

---

### ⏱️ Average Execution Time

| Operation              | Avg Time (ms) | Notes                       |
| ---------------------- | ------------- | --------------------------- |
| Key Generation         | 81.92         | ( g^x \bmod p )             |
| Encryption             | 101.08        | 2 Modular Exponentiations   |
| Decryption             | 28.97         | 1 ModExp + Modular Inverse  |
| Digital Signing        | 30.66         | 1 Modular Exponentiation    |
| Signature Verification | 59.99         | 2 ModExps (Relatively Slow) |

---

### 🧪 Notes

* All results are **averaged over 50 iterations**.
* Timings highlight the **cost dominance of modular exponentiation** in public-key cryptographic operations.
* Signature verification is slower due to **multiple exponentiations**, which is expected for ElGamal-based schemes.

---

**Environment:**

```bash
(.crypto2) satyajit-priyadarshi@satyajit-Ubuntu
```
