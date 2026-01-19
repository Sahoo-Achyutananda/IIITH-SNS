import socket
import sys
import struct
from crypto_utils import (
    aes_encrypt, aes_decrypt, compute_hmac,
    verify_hmac, evolve_key, pack_header
)

# ---------------- ARGUMENT CHECK ----------------
if len(sys.argv) != 5:
    print("Usage : python client.py <IP> <PORT> <CLIENT_ID> <MASTER_KEY>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])
CLIENT_ID = int(sys.argv[3])

# Make sure master key is exactly 16 bytes for AES-128
MASTER_KEY = sys.argv[4].encode().ljust(16, b'\0')[:16]

# ---------------- KEY INITIALIZATION ----------------
# Create first encryption and MAC keys from master key

c2s_enc = evolve_key(MASTER_KEY, b"C2S-ENC")
c2s_mac = evolve_key(MASTER_KEY, b"C2S-MAC")
s2c_enc = evolve_key(MASTER_KEY, b"S2C-ENC")
s2c_mac = evolve_key(MASTER_KEY, b"S2C-MAC")

# ---------------- CONNECT TO SERVER ----------------
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

round_no = 0
phase = "INIT"

print(f"Connected to {HOST}:{PORT} as Client {CLIENT_ID}. Phase: {phase}")

try:
    while True:

        # ---------------- BUILD MESSAGE ----------------
        if phase == "INIT":
            input(">> Press Enter to send CLIENT_HELLO...")
            opcode = 10
            payload = b"HELLO"
        else:
            op_input = input(">> Action (DATA/EXIT): ").strip().upper()
            if op_input == "EXIT":
                opcode = 60
                payload = b"TERMINATE"
            else:
                opcode = 30
                payload = input(">> Enter numeric data: ").encode()

        # Create protocol header
        header = pack_header(opcode, CLIENT_ID, round_no, 0)  # 0 = client to server

        # Encrypt payload
        iv, ciphertext = aes_encrypt(c2s_enc, payload)

        # Combine header + IV + ciphertext
        msg_out = header + iv + ciphertext

        # Create HMAC for integrity
        mac_out = compute_hmac(c2s_mac, msg_out)

        # Send full secured message
        client.sendall(msg_out + mac_out)

        # ---------------- RECEIVE SERVER RESPONSE ----------------
        data = client.recv(4096)
        if not data:
            break

        rx_header = data[:7]
        rx_iv = data[7:23]
        rx_mac = data[-32:]
        rx_ciphertext = data[23:-32]

        # Verify HMAC before decrypting
        if not verify_hmac(s2c_mac, data[:-32], rx_mac):
            print("!!! SECURITY ALERT: HMAC Mismatch. Terminating.")
            break

        try:
            decrypted_payload = aes_decrypt(s2c_enc, rx_iv, rx_ciphertext)
            print(f"Server Response: {decrypted_payload.decode()}")

            rx_opcode = rx_header[0]
            if rx_opcode == 60:
                break

        except Exception as e:
            print(f"Decryption Error: {e}")
            break

        # ---------------- KEY EVOLUTION (RATCHETING) ----------------

        # Update client-to-server keys using sent ciphertext
        c2s_enc = evolve_key(c2s_enc, ciphertext)
        c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE")

        # Update server-to-client keys using received ciphertext
        s2c_enc = evolve_key(s2c_enc, rx_ciphertext)
        s2c_mac = evolve_key(s2c_mac, b"CONSTANT_NONCE")

        round_no += 1
        phase = "ACTIVE"

except KeyboardInterrupt:
    print("\nShutting down.")

finally:
    client.close()
    print("Connection closed.")
