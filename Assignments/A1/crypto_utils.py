import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct

# 1. PKCS#7 PADDING
# AES works only with data in blocks of 16 bytes.
# If data is not exactly 16-byte multiple, we add extra bytes to fill the block.
def pkcs7_pad(data: bytes) -> bytes:
    block_size = 16
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

# After decryption, we remove the extra padding bytes to get original data back.
def pkcs7_unpad(padded_data: bytes) -> bytes:
    if not padded_data:
        raise ValueError("Data is empty")
    padding_len = padded_data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding length")
    if padded_data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid PKCS#7 padding detected")
    return padded_data[:-padding_len]

# 2. AES-128-CBC
# Encrypt data using AES with 128-bit key and CBC mode.
# A random IV is generated every time for security.
def aes_encrypt(key: bytes, plaintext: bytes) -> tuple:
    iv = os.urandom(16)
    padded_data = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

# Decrypt AES-CBC encrypted data using the same key and IV.
# After decryption, padding is removed.
def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded_plaintext)

# 3. HMAC-SHA256
# Create message authentication code to check if data was modified or not.
def compute_hmac(key: bytes, message: bytes) -> bytes:
    h = hmac.new(key, message, hashlib.sha256)
    return h.digest()

# Compare received HMAC with freshly computed one to verify integrity.
def verify_hmac(key: bytes, message: bytes, received_hmac: bytes) -> bool:
    expected = compute_hmac(key, message)
    return hmac.compare_digest(expected, received_hmac)

# 4. KEY EVOLUTION (RATCHETING)
# After every message, new keys are created from old key and some message data.
# This way, even if one key is leaked, past and future messages stay safe.
def evolve_key(current_key: bytes, evolution_data: bytes) -> bytes:
    new_hash = hashlib.sha256(current_key + evolution_data).digest()
    return new_hash[:16]

# 5. HEADER PACKING
# Combine protocol fields into fixed-size binary header for sending over network.
def pack_header(opcode, client_id, round_no, direction):
    return struct.pack("!BBIB", opcode, client_id, round_no, direction)
