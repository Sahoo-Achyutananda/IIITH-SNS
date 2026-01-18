from crypto_utils import aes_encrypt, aes_decrypt, compute_hmac, verify_hmac, evolve_key

def test_system():
    # 1. Setup
    master_key = b"this_is_16_bytes"
    data = b"Hello, secure world!"
    header = b"OPCODE:10|ROUND:0"
    
    # 2. Test Encryption & Padding
    print("Testing Encryption...")
    iv, ciphertext = aes_encrypt(master_key, data)
    decrypted = aes_decrypt(master_key, iv, ciphertext)
    assert data == decrypted
    print("Success: Encryption/Decryption and Padding work.")

    # 3. Test Integrity (HMAC)
    print("\nTesting HMAC...")
    mac_key = b"mac_key_16_bytes"
    payload = header + ciphertext
    tag = compute_hmac(mac_key, payload)
    is_valid = verify_hmac(mac_key, payload, tag)
    assert is_valid == True
    
    # Simulate an attack (modify one bit) [cite: 116]
    tampered_payload = payload[:-1] + b'\x00'
    is_valid_after_attack = verify_hmac(mac_key, tampered_payload, tag)
    assert is_valid_after_attack == False
    print("Success: HMAC catches tampered data.")

    # 4. Test Key Evolution
    print("\nTesting Key Evolution...")
    next_key = evolve_key(master_key, ciphertext)
    assert len(next_key) == 16
    assert next_key != master_key
    print("Success: Key evolved correctly.")

if __name__ == "__main__":
    test_system()