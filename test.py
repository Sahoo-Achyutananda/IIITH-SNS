from crypto_utils import Helper, Elgamal, Hash

def test_elgamal_standalone():
    print("--- STARTING STANDALONE CRYPTO TEST ---")

    # 1. Setup Parameters (Using a small 2048-bit style safe prime for testing)
    # This is a standard RFC 3526 2048-bit prime (same as in your mcc.py)
    print("\n[Step 1] Initializing Parameters...")
    # P = int(
    #     "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    #     "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    #     "4FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
    #     "07D32BD18426C51A1AD174FD124E5E02580556209800974E7984852086438D9E"
    #     "40E5E7A81434914F59A15F333E332E9D40454316302EB45D997F296D56E7CD43"
    #     "D7B1B6191E09C0D3962F74ED238A827B665241961A340331D45A0079C3110E6F"
    #     "D03A2E7092F26330960F174987E136E7B99D0F5486C9081B45F678912E351710"
    #     "79E50C07D7F84F868953C3C005391696D268159E443B14392C1D614E15684C2F"
    #     "FFFFFFFFFFFFFFFF", 16
    # )

    # RFC 3526 - 2048-bit MODP Group
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
    G = 2
    print(f"    Prime P bit-length: {P.bit_length()}")

    # 2. Test Key Generation
    print("\n[Step 2] Testing Key Generation...")
    try:
        priv_x, pub_y = Elgamal.keygen(P, G)
        print(f"    Private Key generated.")
        print(f"    Public Key generated.")
        
        # Validation: y == g^x mod p
        calc_y = Helper.modexp(G, priv_x, P)
        if calc_y != pub_y:
            print("    [FAIL] Key generation math mismatch!")
            return
        else:
            print("    [PASS] Key pair mathematically valid.")
    except Exception as e:
        print(f"    [FAIL] Crash during keygen: {e}")
        return

    # 3. Test Encryption / Decryption
    print("\n[Step 3] Testing Encryption & Decryption...")
    original_message_int = 12345678901234567890
    print(f"    Original Message (int): {original_message_int}")

    try:
        c1, c2 = Elgamal.encrypt(original_message_int, pub_y, P, G)
        decrypted_int = Elgamal.decrypt(c1, c2, priv_x, P)
        
        if decrypted_int == original_message_int:
            print(f"    [PASS] Decrypted message matches original.")
        else:
            print(f"    [FAIL] Decrypted message {decrypted_int} != Original")
            return
    except Exception as e:
        print(f"    [FAIL] Crash during Enc/Dec: {e}")
        return

    # 4. Test Signing / Verification
    print("\n[Step 4] Testing Signature & Verification...")
    # This mimics the exact payload structure you might have
    test_payload = b"INIT_PARAM_PAYLOAD_DATA_EXAMPLE_123"
    print(f"    Signing payload: {test_payload}")

    try:
        # Sign
        r, s = Elgamal.sign(test_payload, priv_x, P, G)
        print("    Signature generated (r, s).")

        # Verify Positive Case
        valid = Elgamal.verify(test_payload, r, s, pub_y, P, G)
        if valid:
            print("    [PASS] Signature verified successfully on correct data.")
        else:
            print("    [FAIL] Signature verification returned False on correct data.")
            return

        # Verify Negative Case (Tampering)
        tampered_payload = b"INIT_PARAM_PAYLOAD_DATA_EXAMPLE_124" # Changed last digit
        valid_tampered = Elgamal.verify(tampered_payload, r, s, pub_y, P, G)
        if not valid_tampered:
            print("    [PASS] Signature verification correctly rejected tampered data.")
        else:
            print("    [FAIL] Signature accepted bad data! (Security Flaw)")
            return

    except Exception as e:
        print(f"    [FAIL] Crash during Sign/Verify: {e}")
        return

    print("\n--- ALL TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_elgamal_standalone()