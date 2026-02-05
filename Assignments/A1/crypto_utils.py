import os
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16

def add_padding(data : bytes) -> bytes:
    # This ensures that the data length is a multiple of 16.
    pad_len = BLOCK_SIZE - (len(data)%BLOCK_SIZE)
    # eg : len(data) = 35, pad_len = 16 - 35%16 = 16 - 3 = 13 => 13 bytes have to be added
    padding = bytes([pad_len]*pad_len)
    # here, we append the pad_len value pad_len times | we can do something else too LOL
    # there is a reason why we do it -> we can extract the length of the data we appened using simple indexing
    return data + padding

def remove_padding(data : bytes) -> bytes:
    data_len = len(data)
    if data_len == 0 or data_len%BLOCK_SIZE != 0:
        # a preliminary check to ensure that the data is a multiple of 16
        raise ValueError("Invalid Message")  

    pad_len = data[-1] # extracting padding_length using simple indexing

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        # only values from 1 to 15 are accepted as padding length
        raise ValueError("Invalid padding length")
    
    # padding veriication -
    received_padding = data[-pad_len:] # extracts the padded data
    expected_padding = bytes([pad_len]*pad_len)

    if(received_padding != expected_padding):
        raise ValueError("Invalid padding")
    
    data_without_padding = data[:-pad_len]

    return data_without_padding  

def encrypt(key: bytes, plaintext:bytes) -> tuple[bytes, bytes]:
    if len(key) != 16:
        raise ValueError("Key must be exactly of 16 bytes")
    
    iv = os.urandom(16) #initialization vector
    padded_data = add_padding(plaintext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    """
    Cipher Block Chaining (CBC) mode is a block cipher mode of operation that enhances 
    security by XORing each plaintext block with the previous ciphertext block (or an 
    Initialization Vector (IV) for the first block) before encryption, creating a "chain" 
    that hides plaintext patterns and ensures identical plaintext blocks produce different 
    ciphertexts. 

    a good resource : https://www.geeksforgeeks.org/ethical-hacking/block-cipher-modes-of-operation/
    """
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext
    # we return the iv coz it is needed for decrypting

def decrypt(key : bytes, iv : bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    plaintext = remove_padding(padded_plaintext)

    return plaintext

def compute_hmac(key : bytes, data : bytes) -> bytes:
    """
    Hash based message authentication code
    In simple terms, it is a way to verify both the integrity and the authenticity of a message. 
    It ensures that the message hasn't been tampered with and that it definitely came from someone 
    who knows a specific secret key.

    Why not use SHA-2 ? => coz it is prone to length extension attack

    HMAC doesn't just "add" the key to the message. It uses a specific nested structure to prevent certain types of attacks (like "length-extension attacks").
    Inner Pass: The secret key is mixed with some padding (called ipad) and hashed along with the message.
    Outer Pass: That result is then mixed with different padding (opad) and hashed again with the secret key.
    HMAC(k,m)=H((k⊕opad) ∥ H((k⊕ipad) ∥ m))

    The hashing function can be SHA2 or SHA3 etc ..
    """ 
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(key: bytes, data: bytes, received_mac : bytes) -> bool:
    expected = compute_hmac(key,data)
    return hmac.compare_digest(expected, received_mac)

def evolve_key(current_key: bytes, evolution_data: bytes) -> bytes:
    """
    Derive a new 16-byte key from the current key and evolution data.
    Yeh hash karke hota hai
    new_key = SHA256(old_key || evolution_data)[:16]
    """
    return hashlib.sha256(current_key + evolution_data).digest()[:16]

def pack_header(opcode: int, client_id: int, round_no: int, direction: int) -> bytes:
    """
    Pack protocol header into bytes.
    Format: | Opcode (1) | ClientID (1) | Round (4) | Direction (1) |
    """
    return struct.pack("!BBIB", opcode, client_id, round_no, direction)

def unpack_header(header_bytes: bytes):
    """
    Unpack protocol header fields.
    """
    return struct.unpack("!BBIB", header_bytes)

    """
    What dies !BBIB mean - 
    ! => signifies netwrok byte order - usually big endian .. we can use > too equivalently
    B => Unsgined Char
    I => Unsigned Int

    BBIB represents the header
    """

"""
In Python, struct.pack and struct.unpack are tools used to convert between Python objects (like integers, floats, and strings) and C-style binary data (bytes).

When you are writing low-level code like the SHA-1 implementation, you can't just send a Python integer into a hash function. You need to turn that 
integer into a specific sequence of bytes (e.g., 4 bytes or 8 bytes) so the math works correctly.

Struct pack converts Object -> BYtes
eg : 
# Convert the number 1024 into a 4-byte integer (Big-Endian)
binary_data = struct.pack('>I', 1024) // here  > denotes Big ENdian and I denotes treating the input as an unsigned integer
print(binary_data) // 
# Output: b'\x00\x00\x04\x00'
number = struct.unpack('>I', data)
print(number)
# Output: (1024,)

"""