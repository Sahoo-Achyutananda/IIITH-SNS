# crypto_utils.py


import secrets
import hashlib
import hmac
from Crypto.Cipher import AES as _AES
from Crypto.Random import get_random_bytes


class Helper:
    """
    Helper class for basic math operations used in cryptography.
    All methods are static because they do not depend on any object state.
    """

    @staticmethod
    def modexp(base, exp, mod):
        """
        Computes (base^exp) % mod using fast exponentiation.
        This is much faster than using pow(base, exp) directly.
        """
        result = 1
        base = base % mod

        # Square-and-multiply method
        while exp > 0:
            if exp & 1:              # if current bit of exp is 1
                result = (result * base) % mod
            base = (base * base) % mod
            exp >>= 1               # shift exp to right (divide by 2)

        return result

    @staticmethod
    def extended_euclidean(a, b):
        """
        Extended Euclidean Algorithm (Iterative version to avoid stack overflow).
        Returns gcd(a, b) and coefficients x, y such that:
        a*x + b*y = gcd(a, b)
        """
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        
        # old_r is the GCD
        # old_s and old_t are the coefficients
        return old_r, old_s, old_t

    @staticmethod
    def modular_inverse(a, mod):
        """
        Finds modular inverse of a modulo mod.
        Inverse exists only if gcd(a, mod) = 1.
        """
        gcd, x, _ = Helper.extended_euclidean(a, mod)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % mod

    @staticmethod
    def int_to_bytes(n: int) -> bytes:
        """
        Converts an integer to big-endian byte representation.
        Used when integers need to be encrypted or hashed.
        """
        if n == 0:
            return b'\x00'
        return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    @staticmethod
    def bytes_to_int(b: bytes) -> int:
        """
        Converts big-endian bytes back to integer.
        """
        return int.from_bytes(b, byteorder='big')


class Hash:
    """
    Hash-related utilities.
    SHA-256 is used as required by the assignment.
    """

    @staticmethod
    def hash_bytes(data: bytes) -> bytes:
        """
        Computes SHA-256 hash and returns raw bytes.
        """
        return hashlib.sha256(data).digest()

    @staticmethod
    def hash_int(data: bytes) -> int:
        """
        Computes SHA-256 hash and converts it to an integer.
        Useful for signature algorithms.
        """
        return int.from_bytes(Hash.hash_bytes(data), 'big')


class Elgamal:
    """
    Manual implementation of ElGamal cryptosystem.
    Includes key generation, encryption, decryption,
    digital signature and verification.
    """

    @staticmethod
    def keygen(p, g):
        """
        Generates ElGamal key pair.
        x -> private key
        y -> public key (g^x mod p)
        """
        x = secrets.randbelow(p - 2) + 1
        y = Helper.modexp(g, x, p)
        return x, y

    @staticmethod
    def encrypt(m: int, y: int, p: int, g: int):
        """
        Encrypts message m using receiver's public key y.
        Returns ciphertext (c1, c2).
        """
        k = secrets.randbelow(p - 2) + 1
        c1 = Helper.modexp(g, k, p)
        c2 = (m * Helper.modexp(y, k, p)) % p
        return c1, c2

    @staticmethod
    def decrypt(c1: int, c2: int, x: int, p: int):
        """
        Decrypts ElGamal ciphertext using private key x.
        """
        s = Helper.modexp(c1, x, p)
        s_inv = Helper.modular_inverse(s, p)
        m = (c2 * s_inv) % p
        return m

    @staticmethod
    def sign(message: bytes, x: int, p: int, g: int):
        """
        Generates ElGamal digital signature for a message.
        Returns signature pair (r, s).
        
        Standard ElGamal signature:
        1. Choose random k with gcd(k, p-1) = 1
        2. r = g^k mod p
        3. s = k^(-1) * (H(m) - x*r) mod (p-1)
        
        Verification: g^H(m) ≡ y^r * r^s (mod p)
        """
        h = Hash.hash_int(message)

        # Choose k such that gcd(k, p-1) = 1
        while True:
            k = secrets.randbelow(p - 2) + 1
            gcd, _, _ = Helper.extended_euclidean(k, p - 1)
            if gcd == 1:
                break

        r = Helper.modexp(g, k, p)
        k_inv = Helper.modular_inverse(k, p - 1)
        s = (k_inv * (h - x * r)) % (p - 1)

        return r, s

    @staticmethod
    def verify(message: bytes, r: int, s: int, y: int, p: int, g: int) -> bool:
        """
        Verifies ElGamal signature.
        Returns True if signature is valid, else False.
        
        Verification equation: g^H(m) ≡ y^r * r^s (mod p)
        where:
        - y is the public key (g^x mod p)
        - r, s is the signature
        - H(m) is the hash of the message
        """
        if r <= 0 or r >= p:
            return False

        h = Hash.hash_int(message)

        left = Helper.modexp(g, h, p)
        right = (Helper.modexp(y, r, p) * Helper.modexp(r, s, p)) % p

        return left == right


class AES:
    """
    AES-256-CBC implementation (used in Phase 3).
    Padding is done manually using PKCS-style padding.
    """

    @staticmethod
    def aes_encrypt(key: bytes, plaintext: bytes):
        """
        Encrypts plaintext using AES-256-CBC.
        Returns IV and ciphertext.
        """
        iv = get_random_bytes(16)
        cipher = _AES.new(key, _AES.MODE_CBC, iv)

        # Padding to make plaintext multiple of 16 bytes
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad_len]) * pad_len

        ciphertext = cipher.encrypt(plaintext)
        return iv, ciphertext

    @staticmethod
    def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
        """
        Decrypts AES-256-CBC ciphertext and removes padding.
        """
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        pad_len = plaintext[-1]
        return plaintext[:-pad_len]


class HMAC:
    """
    HMAC utility using SHA-256.
    Used for message authentication and integrity.
    """

    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        """
        Computes HMAC-SHA256 for given key and data.
        """
        return hmac.new(key, data, hashlib.sha256).digest()