#!/usr/bin/env python3
# test_crypto.py
# Test file to demonstrate all the refactored crypto classes

from crypto_utils import (
    ModularArithmetic, 
    PKCS7Padding, 
    AESCipher, 
    Schnorr, 
    ThresholdSchnorr,
    generate_schnorr_params
)
import os

def test_modular_arithmetic():
    print("=" * 50)
    print("Testing ModularArithmetic class")
    print("=" * 50)
    
    # Test recursive modular exponentiation
    base, exp, mod = 5, 8, 47
    result = ModularArithmetic.mod_pow(base, exp, mod)
    print(f"Recursive mod_pow: {base}^{exp} mod {mod} = {result}")
    
    # Compare with Python's built-in
    builtin_result = pow(base, exp, mod)
    print(f"Built-in pow: {base}^{exp} mod {mod} = {builtin_result}")
    print(f"Match: {result == builtin_result}")
    print()

def test_padding():
    print("=" * 50)
    print("Testing PKCS7Padding class")
    print("=" * 50)
    
    data = b"Hello World"
    print(f"Original data: {data}")
    print(f"Original length: {len(data)} bytes")
    
    padded = PKCS7Padding.pad(data, 16)
    print(f"Padded data: {padded}")
    print(f"Padded length: {len(padded)} bytes")
    
    unpadded = PKCS7Padding.unpad(padded)
    print(f"Unpadded data: {unpadded}")
    print(f"Match: {data == unpadded}")
    print()

def test_aes():
    print("=" * 50)
    print("Testing AESCipher class")
    print("=" * 50)
    
    key = os.urandom(32)  # 256-bit key
    plaintext = b"This is a secret message!"
    
    cipher = AESCipher(key)
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Encrypted (hex): {encrypted.hex()[:60]}...")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")
    print()

def test_schnorr():
    print("=" * 50)
    print("Testing Schnorr class")
    print("=" * 50)
    
    p, q, g = generate_schnorr_params()
    schnorr = Schnorr(p, q, g)
    
    # Generate keypair
    x, y = schnorr.generate_keypair()
    print(f"Private key: {x}")
    print(f"Public key: {y}")
    
    # Sign and verify
    message = "Test message"
    signature = schnorr.sign(message, x)
    print(f"Signature: {signature}")
    
    valid = schnorr.verify(message, signature, y)
    print(f"Signature valid: {valid}")
    print()

def test_threshold_schnorr():
    print("=" * 50)
    print("Testing ThresholdSchnorr class")
    print("=" * 50)
    
    p, q, g = generate_schnorr_params()
    threshold = ThresholdSchnorr(p, q, g)
    
    # Generate master key and shares
    x, y = threshold.generate_keypair()
    shares = threshold.generate_shares(x, 3)
    print(f"Master private key: {x}")
    print(f"Public key: {y}")
    print(f"Key shares: {shares}")
    
    # Verify shares sum to master key
    shares_sum = sum(shares) % q
    print(f"Shares sum: {shares_sum}")
    print(f"Shares valid: {shares_sum == x}")
    print()

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("CRYPTO UTILITIES TEST SUITE")
    print("=" * 50 + "\n")
    
    test_modular_arithmetic()
    test_padding()
    test_aes()
    test_schnorr()
    test_threshold_schnorr()
    
    print("=" * 50)
    print("ALL TESTS COMPLETED")
    print("=" * 50)
