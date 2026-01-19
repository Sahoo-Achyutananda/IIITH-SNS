import socket
import struct
import time
from crypto_utils import (
    aes_encrypt, compute_hmac, evolve_key, pack_header
)

# Server address and port (must match server.py)
HOST = '127.0.0.1'
PORT = 8080

# Shared master key known to both client and server
MASTER_KEY = b"this_is_16_bytes"
CLIENT_ID = 1


def setup_initial_keys():
    # Generate first encryption and MAC keys from master key
    # This is same logic as normal client, so server expects these keys
    c2s_enc = evolve_key(MASTER_KEY, b"C2S-ENC")
    c2s_mac = evolve_key(MASTER_KEY, b"C2S-MAC")
    return c2s_enc, c2s_mac


def attack_bit_flip():
    # Modify encrypted data slightly and check if server detects tampering
    print("\nStarting Bit-Flip Attack")

    c2s_enc, c2s_mac = setup_initial_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    header = pack_header(10, CLIENT_ID, 0, 0)
    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")

    # Change last byte of ciphertext so encrypted data becomes corrupted
    tampered_ciphertext = ciphertext[:-1] + bytes([(ciphertext[-1] ^ 0xFF)])

    msg_out = header + iv + tampered_ciphertext
    mac_out = compute_hmac(c2s_mac, msg_out)

    print("Sending message with changed ciphertext")
    s.sendall(msg_out + mac_out)

    response = s.recv(1024)
    print("Server response:", response.decode("utf-8", "ignore"))
    s.close()


def attack_hmac_tamper():
    # Send wrong HMAC value to see if server rejects message
    print("\nStarting HMAC Tampering Attack")

    c2s_enc, c2s_mac = setup_initial_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    header = pack_header(10, CLIENT_ID, 0, 0)
    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")

    msg_body = header + iv + ciphertext

    # Send fake MAC instead of correct one
    invalid_mac = b"A" * 32

    print("Sending message with fake HMAC")
    s.sendall(msg_body + invalid_mac)

    response = s.recv(1024)
    print("Server response:", response.decode("utf-8", "ignore"))
    s.close()


def attack_replay():
    # Send the same valid message again to check replay protection
    print("\nStarting Replay Attack")

    c2s_enc, c2s_mac = setup_initial_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    header = pack_header(10, CLIENT_ID, 0, 0)
    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")

    msg = header + iv + ciphertext + compute_hmac(c2s_mac, header + iv + ciphertext)

    print("Sending valid message first time")
    s.sendall(msg)

    time.sleep(0.5)

    print("Sending same message again (replay)")
    s.sendall(msg)

    response = s.recv(1024)
    print("Server response:", response.decode("utf-8", "ignore"))
    s.close()


def attack_invalid_round():
    # Send message with wrong round number to break protocol order
    print("\nStarting Invalid Round Attack")

    c2s_enc, c2s_mac = setup_initial_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Server expects round 0 but we send round 5
    header = pack_header(10, CLIENT_ID, 5, 0)

    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")
    msg = header + iv + ciphertext + compute_hmac(c2s_mac, header + iv + ciphertext)

    print("Sending message with wrong round number")
    s.sendall(msg)

    response = s.recv(1024)
    print("Server response:", response.decode("utf-8", "ignore"))
    s.close()


def attack_reflection():
    # Send message with server-to-client direction back to server
    print("\nStarting Reflection Attack")

    c2s_enc, c2s_mac = setup_initial_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Direction 1 means server-to-client, but server should accept only client-to-server
    header = pack_header(10, CLIENT_ID, 0, 1)

    iv, ciphertext = aes_encrypt(c2s_enc, b"HELLO")
    msg = header + iv + ciphertext + compute_hmac(c2s_mac, header + iv + ciphertext)

    print("Sending reflected message back to server")
    s.sendall(msg)

    response = s.recv(1024)
    print("Server response:", response.decode("utf-8", "ignore"))
    s.close()


if __name__ == "__main__":
    try:
        attack_bit_flip()
        time.sleep(1)

        attack_hmac_tamper()
        time.sleep(1)

        attack_replay()
        time.sleep(1)

        attack_invalid_round()
        time.sleep(1)

        attack_reflection()

    except ConnectionRefusedError:
        print("Server is not running on given port")
