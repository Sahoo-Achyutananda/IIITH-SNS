class Helper:

    def modexp(base, exp, mod):
        pass

    def extended_euclidean(a,b):
        pass

    def modular_inverse(a, mod):
        pass

    def int_to_bytes(n: int) -> bytes:
        pass

    def bytes_to_int(b: bytes) -> int:
        pass


class Hash:
    
    def hash_bytes(data : bytes) -> bytes:
        pass

    def hash_int(data : bytes) -> int:
        pass

class Elgamal:
    
    def keygen(p,g):
        """
        returns (private key, public key)
        """
        pass

    def encrypt(m : int, y : int, p : int, g : int):
        pass

    def decrypt(c1 : int, c2 : int, x : int, p : int):
        pass

    def sign(message: bytes, x: int, p: int, g: int):
        pass

    def verify(message: bytes, r: int, s: int, y: int, p: int, g: int) -> bool:
        pass


class AES:

    def aes_encrypt(key: bytes, plaintext: bytes):
        pass

    def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
        pass

class HMAC :
    
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        pass




