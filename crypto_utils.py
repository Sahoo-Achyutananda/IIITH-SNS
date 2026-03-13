# crypto_utils.py
# This file contains utility functions for cryptographic operations
# We implement Schnorr signatures and threshold versions manually
# All classes are separated for better modularity

import hashlib
import json
import os
import random
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class ModularArithmetic:
    """Helper class for modular arithmetic operations"""
    
    @staticmethod
    def mod_pow(base, exp, mod):
        """
        Recursive modular exponentiation: base^exp mod mod
        Uses divide-and-conquer approach for efficiency
        """
        # Base cases
        if mod == 1:
            return 0
        if exp == 0:
            return 1
        if exp == 1:
            return base % mod
        
        # Recursive case: divide exponent by 2
        if exp % 2 == 0:
            # If exp is even: base^exp = (base^(exp/2))^2
            half = ModularArithmetic.mod_pow(base, exp // 2, mod)
            return (half * half) % mod
        else:
            # If exp is odd: base^exp = base * base^(exp-1)
            return (base * ModularArithmetic.mod_pow(base, exp - 1, mod)) % mod


class PKCS7Padding:
    """Class for PKCS#7 padding operations"""
    
    @staticmethod
    def pad(data, block_size=16):
        """
        Add PKCS#7 padding to data
        Padding length is stored in each padding byte
        """
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len]) * padding_len
        return data + padding
    
    @staticmethod
    def unpad(padded_data):
        """
        Remove PKCS#7 padding from data
        Read the last byte to know padding length
        """
        padding_len = padded_data[-1]
        return padded_data[:-padding_len]


class AESCipher:
    """Class for AES encryption and decryption operations"""
    
    def __init__(self, key):
        """Initialize with a 256-bit key"""
        self.key = key
        self.block_size = 16  # AES block size is 16 bytes
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-256-CBC
        Returns: IV + ciphertext
        """
        # Generate random IV (Initialization Vector)
        iv = os.urandom(self.block_size)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad plaintext to block size
        padded = PKCS7Padding.pad(plaintext, self.block_size)
        
        # Encrypt
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        # Return IV + ciphertext (IV needed for decryption)
        return iv + ciphertext
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using AES-256-CBC
        Input: IV + ciphertext
        """
        # Extract IV from the beginning
        iv = ciphertext[:self.block_size]
        actual_ciphertext = ciphertext[self.block_size:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = PKCS7Padding.unpad(padded)
        
        return plaintext


class Schnorr:
    """Schnorr signature scheme implementation"""
    
    def __init__(self, p, q, g):
        """
        Initialize with Schnorr parameters
        p: large prime
        q: prime divisor of (p-1)
        g: generator of order q
        """
        self.p = p
        self.q = q
        self.g = g
        self.mod_arith = ModularArithmetic()

    def hash_message(self, message, R):
        """
        Hash function: SHA-256 of message || R
        Returns hash value mod q
        """
        data = message.encode() + str(R).encode()
        return int(hashlib.sha256(data).hexdigest(), 16) % self.q

    def generate_keypair(self):
        """
        Generate Schnorr keypair
        Private key x: random in [1, q-1]
        Public key y: g^x mod p
        """
        x = random.randint(1, self.q - 1)
        y = self.mod_arith.mod_pow(self.g, x, self.p)
        return x, y

    def sign(self, message, x):
        """
        Sign message with private key x
        Returns: (R, s) signature
        """
        # Generate random nonce k
        k = random.randint(1, self.q - 1)
        
        # Compute R = g^k mod p
        R = self.mod_arith.mod_pow(self.g, k, self.p)
        
        # Compute challenge e = H(m || R)
        e = self.hash_message(message, R)
        
        # Compute signature s = k + e*x mod q
        s = (k + e * x) % self.q
        
        return (R, s)

    def verify(self, message, signature, y):
        """
        Verify signature with public key y
        Checks if g^s = R * y^e (mod p)
        """
        R, s = signature
        
        # Compute challenge
        e = self.hash_message(message, R)
        
        # Compute left side: g^s mod p
        left = self.mod_arith.mod_pow(self.g, s, self.p)
        
        # Compute right side: R * y^e mod p
        y_e = self.mod_arith.mod_pow(y, e, self.p)
        right = (R * y_e) % self.p
        
        return left == right


class ThresholdSchnorr(Schnorr):
    """Threshold Schnorr signature (2-of-3 scheme)"""
    
    def generate_shares(self, x, n=3):
        """
        Split private key x into n shares for a 2-of-n threshold scheme
        using a degree-1 Shamir polynomial: f(i) = x + a*i (mod q)
        where x = f(0) is the master secret.
        """
        a = random.randint(1, self.q - 1)
        shares = []
        for i in range(1, n + 1):
            share = (x + a * i) % self.q
            shares.append(share)

        return shares

    def partial_sign(self, message, x_i):
        """
        Generate partial signature with key share x_i
        Returns: R_i, k_i, x_i (for later computation)
        """
        k_i = random.randint(1, self.q - 1)
        R_i = self.mod_arith.mod_pow(self.g, k_i, self.p)
        return R_i, k_i, x_i

    def compute_partial_s(self, R_list, message, k_i, x_i):
        """
        Compute partial s_i after collecting all R's
        s_i = k_i + e * x_i (mod q)
        """
        # Combine all R values
        R_combined = 1
        for R in R_list:
            R_combined = (R_combined * R) % self.p
        
        # Compute challenge
        e = self.hash_message(message, R_combined)
        
        # Compute partial signature
        s_i = (k_i + e * x_i) % self.q
        
        return s_i

    def combine_partial_sigs(self, partials):
        """
        Combine 2 partial signatures into full signature
        Input: [(R1, s1), (R2, s2)]
        Output: (R, s) where R = R1*R2 mod p, s = s1+s2 mod q
        """
        R1, s1 = partials[0]
        R2, s2 = partials[1]
        
        # Combine R values (multiplicative)
        R = (R1 * R2) % self.p
        
        # Combine s values (additive)
        s = (s1 + s2) % self.q
        
        return (R, s)


class Ticket:
    """
    Ticket structure containing all required fields
    - Client ID: identifier for the client
    - Service ID: identifier for the service
    - Issue Timestamp: when ticket was created
    - Lifetime: how long ticket is valid (seconds)
    - Session Key: encrypted session key for communication
    - Authority Metadata: which authorities signed
    - Key Version: version of signing key (for rotation)
    """
    
    def __init__(self, client_id, service_id, session_key, lifetime=3600, key_version=1):
        self.client_id = client_id
        self.service_id = service_id
        self.session_key = session_key
        self.issue_timestamp = int(time.time())
        self.lifetime = lifetime
        self.key_version = key_version
        self.authority_metadata = []
        self.signature = None
    
    def get_payload(self):
        """Get ticket payload for signing"""
        session_key_hex = self.session_key.hex() if self.session_key is not None else ''
        return f"{self.client_id}|{self.service_id}|{self.issue_timestamp}|{self.lifetime}|{session_key_hex}|{self.key_version}"
    
    def is_expired(self):
        """Check if ticket has expired"""
        current_time = int(time.time())
        expiry_time = self.issue_timestamp + self.lifetime
        return current_time > expiry_time
    
    def set_signature(self, signature, authority_ids):
        """Set the threshold signature and which authorities signed"""
        self.signature = signature
        self.authority_metadata = authority_ids
    
    def to_dict(self):
        """Convert ticket to dictionary for transmission"""
        return {
            'client_id': self.client_id,
            'service_id': self.service_id,
            'issue_timestamp': self.issue_timestamp,
            'lifetime': self.lifetime,
            'session_key': self.session_key.hex() if self.session_key is not None else None,
            'key_version': self.key_version,
            'authority_metadata': self.authority_metadata,
            'signature': {
                'R': self.signature[0] if self.signature else None,
                's': self.signature[1] if self.signature else None
            }
        }
    
    @staticmethod
    def from_dict(data):
        """Create ticket from dictionary"""
        ticket = Ticket(
            data['client_id'],
            data['service_id'],
            bytes.fromhex(data['session_key']) if data.get('session_key') else None,
            data['lifetime'],
            data['key_version']
        )
        ticket.issue_timestamp = data['issue_timestamp']
        ticket.authority_metadata = data['authority_metadata']
        if data['signature']['R'] and data['signature']['s']:
            ticket.signature = (data['signature']['R'], data['signature']['s'])
        return ticket
    
    def encrypt_with_key(self, key):
        """Encrypt ticket data with given key"""
        cipher = AESCipher(key)
        json_data = json.dumps(self.to_dict()).encode()
        return cipher.encrypt(json_data)
    
    @staticmethod
    def decrypt_with_key(encrypted_data, key):
        """Decrypt ticket data"""
        cipher = AESCipher(key)
        json_data = cipher.decrypt(encrypted_data)
        data = json.loads(json_data.decode())
        return Ticket.from_dict(data)


class PartialSignature:
    """Represents a partial signature from one authority"""
    
    def __init__(self, authority_id, R_i, s_i=None, k_i=None):
        self.authority_id = authority_id
        self.R_i = R_i
        self.s_i = s_i
        self.k_i = k_i
    
    def to_dict(self):
        return {
            'authority_id': self.authority_id,
            'R_i': self.R_i,
            's_i': self.s_i
        }
    
    @staticmethod
    def from_dict(data):
        return PartialSignature(data['authority_id'], data['R_i'], data['s_i'])


def generate_schnorr_params():
    """
    Generate Schnorr parameters p, q, g
    For demo: using small primes
    In production: use large cryptographic primes
    """
    q = 23  # small prime
    p = 47  # p = 2*q + 1 = 47, q divides p-1
    g = 5   # generator of order q
    return p, q, g


# Legacy wrapper functions for backward compatibility
def aes_encrypt(key, plaintext):
    """Encrypt plaintext with AES-256-CBC"""
    cipher = AESCipher(key)
    return cipher.encrypt(plaintext)


def aes_decrypt(key, ciphertext):
    """Decrypt ciphertext with AES-256-CBC"""
    cipher = AESCipher(key)
    return cipher.decrypt(ciphertext)