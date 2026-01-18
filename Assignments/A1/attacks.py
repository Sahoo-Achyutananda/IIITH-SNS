import socket
import struct
import time
from crypto_utils import (
    aes_encrypt, compute_hmac, evolve_key, pack_header
)

# Server details (must be same as server.py)
HOST = '127.0.0.1'
PORT = 8080
MASTER_KEY = b"this_is_16_bytes"
CLIENT_ID = 1

def setup_initial_keys():
    # Create starting encryption and MAC keys same as normal client
    c2s_enc = evolve_key(MASTER_KEY, b"C2S-ENC")
    c2s_mac = evolve_key(MASTER_KEY, b"C2S-MAC")
    return c2s_enc, c2s_mac

def attack_bit_flip():
    """Change one byte of encrypted data to check if HMAC detects tampering"""
    print("\n--- Starting Attack: Bit-Flipping (Integrity) ---")
    c2s_enc, c2s_mac = setup_initial_keys()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Create a normal valid HELLO message
    header = pack_header(10, CLIENT_ID, 0, 0)
    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")
    
    # ATTACK: Flip last byte of ciphertext to corrupt the message
    tampered_ciphertext = ciphertext[:-1] + bytes([(ciphertext[-1] ^ 0xFF)])
    
    msg_out = header + iv + tampered_ciphertext
    mac_out = compute_hmac(c2s_mac, msg_out)
    
    print("Sending tampered ciphertext...")
    s.sendall(msg_out + mac_out)
    
    response = s.recv(1024)
    print(f"Server response: {response.decode('utf-8', 'ignore')}")
    s.close()

def attack_replay():
    """Send same valid message again to test replay protection"""
    print("\n--- Starting Attack: Message Replay ---")
    c2s_enc, c2s_mac = setup_initial_keys()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Create correct Round 0 message
    header = pack_header(10, CLIENT_ID, 0, 0)
    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")
    msg = header + iv + ciphertext + compute_hmac(c2s_mac, header + iv + ciphertext)
    
    print("Sending valid Round 0 message...")
    s.sendall(msg)
    time.sleep(1) # Give server time to process first message
    
    print("Replaying same Round 0 message...")
    s.sendall(msg)
    
    response = s.recv(1024)
    print(f"Server response after replay: {response.decode('utf-8', 'ignore')}")
    s.close()

def attack_invalid_round():
    """Send message with wrong round number to break FSM rules"""
    print("\n--- Starting Attack: Round Mismatch ---")
    c2s_enc, c2s_mac = setup_initial_keys()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # ATTACK: Send round number 5 instead of expected 0
    header = pack_header(10, CLIENT_ID, 5, 0)
    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")
    msg = header + iv + ciphertext + compute_hmac(c2s_mac, header + iv + ciphertext)
    
    print("Sending message with Round 5 (Expected 0)...")
    s.sendall(msg)
    
    response = s.recv(1024)
    print(f"Server response: {response.decode('utf-8', 'ignore')}")
    s.close()

if __name__ == "__main__":
    # Make sure server.py is running before testing attacks
    try:
        attack_bit_flip()
        time.sleep(2)
        attack_replay()
        time.sleep(2)
        attack_invalid_round()
    except ConnectionRefusedError:
        print("Error: Server is not running on 127.0.0.1:8080")
