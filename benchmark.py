import time
import secrets
from crypto_utils import Helper, Elgamal, Hash

# ---------------------------------------------------------
# Configuration: Use the exact 2048-bit Prime from MCC.py
# ---------------------------------------------------------
G = 2
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

ITERATIONS = 50  # Number of runs to average (keep low for 2048-bit math)

def run_benchmark():
    print(f"\n[*] Starting Benchmark for 2048-bit ElGamal Operations")
    print(f"[*] Prime P size: {P.bit_length()} bits")
    print(f"[*] Iterations per test: {ITERATIONS}")
    print("=" * 65)
    print(f"{'OPERATION':<25} | {'AVG TIME (ms)':<15} | {'NOTES':<20}")
    print("-" * 65)

    # -----------------------------------------------------
    # 1. Key Generation
    # -----------------------------------------------------
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        x, y = Elgamal.keygen(P, G)
    end_time = time.perf_counter()
    
    avg_keygen = ((end_time - start_time) / ITERATIONS) * 1000
    print(f"{'Key Generation':<25} | {avg_keygen:.2f} ms {'':<5} | {'g^x mod p':<20}")

    # Prepare keys for next steps
    priv, pub = Elgamal.keygen(P, G)
    message_int = 123456789
    message_bytes = b"UAV-COMMAND-TEST"

    # -----------------------------------------------------
    # 2. Encryption
    # -----------------------------------------------------
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        c1, c2 = Elgamal.encrypt(message_int, pub, P, G)
    end_time = time.perf_counter()

    avg_enc = ((end_time - start_time) / ITERATIONS) * 1000
    print(f"{'Encryption':<25} | {avg_enc:.2f} ms {'':<5} | {'2 ModExps':<20}")

    # Prepare cipher for decryption test
    c1, c2 = Elgamal.encrypt(message_int, pub, P, G)

    # -----------------------------------------------------
    # 3. Decryption
    # -----------------------------------------------------
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        m = Elgamal.decrypt(c1, c2, priv, P)
    end_time = time.perf_counter()

    avg_dec = ((end_time - start_time) / ITERATIONS) * 1000
    print(f"{'Decryption':<25} | {avg_dec:.2f} ms {'':<5} | {'1 ModExp + Inv':<20}")

    # -----------------------------------------------------
    # 4. Digital Signing
    # -----------------------------------------------------
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        r, s = Elgamal.sign(message_bytes, priv, P, G)
    end_time = time.perf_counter()

    avg_sign = ((end_time - start_time) / ITERATIONS) * 1000
    print(f"{'Digital Signing':<25} | {avg_sign:.2f} ms {'':<5} | {'1 ModExp':<20}")

    # Prepare signature for verification test
    r, s = Elgamal.sign(message_bytes, priv, P, G)

    # -----------------------------------------------------
    # 5. Signature Verification
    # -----------------------------------------------------
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        Elgamal.verify(message_bytes, r, s, pub, P, G)
    end_time = time.perf_counter()

    avg_verify = ((end_time - start_time) / ITERATIONS) * 1000
    print(f"{'Signature Verification':<25} | {avg_verify:.2f} ms {'':<5} | {'2 ModExps (Slow)':<20}")
    
    print("=" * 65)
    print("[*] Done. Copy these values to your README.md.")

if __name__ == "__main__":
    run_benchmark()