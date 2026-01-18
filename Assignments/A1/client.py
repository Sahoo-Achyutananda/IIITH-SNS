import socket
import sys
import struct
from crypto_utils import (
    aes_encrypt, aes_decrypt, compute_hmac, 
    verify_hmac, evolve_key, pack_header
)

if len(sys.argv) != 4:
    print("Usage : python client.py <IP> <PORT> <MASTER_KEY>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

# Make sure master key is exactly 16 bytes for AES-128
MASTER_KEY = sys.argv[3].encode().ljust(16, b'\0')[:16] 
CLIENT_ID = 1  

# --- 1. Key Initialization ---
# Create first encryption and MAC keys from master key
c2s_enc = evolve_key(MASTER_KEY, b"C2S-ENC")
c2s_mac = evolve_key(MASTER_KEY, b"C2S-MAC")
s2c_enc = evolve_key(MASTER_KEY, b"S2C-ENC")
s2c_mac = evolve_key(MASTER_KEY, b"S2C-MAC")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

round_no = 0
phase = "INIT"

print(f"Connected to {HOST}:{PORT}. Phase: {phase}")

try:
    while True:
        # First message must be HELLO to start protocol
        if phase == "INIT":
            input(">> Press Enter to send CLIENT_HELLO...")
            opcode = 10 
            payload = b"HELLO"
        else:
            # After handshake, user can send data or exit
            op_input = input(">> Action (DATA/EXIT): ").strip().upper()
            if op_input == "EXIT":
                opcode = 60 
                payload = b"TERMINATE"
            else:
                opcode = 30 
                payload = input(">> Enter numeric data: ").encode()

        # --- 2. Sender Side: Build and Encrypt Message ---
        # Create protocol header
        header = pack_header(opcode, CLIENT_ID, round_no, 0) # 0 means client to server
        
        # Encrypt payload using current client-to-server key
        iv, ciphertext = aes_encrypt(c2s_enc, payload)
        
        # Combine header, IV and encrypted data
        msg_out = header + iv + ciphertext
        
        # Generate HMAC for integrity check
        mac_out = compute_hmac(c2s_mac, msg_out)
        
        # Send full secured packet
        client.sendall(msg_out + mac_out)

        # --- 3. Receiver Side: Receive and Verify Reply ---
        data = client.recv(4096)
        if not data:
            break
            
        # Split received message into parts
        rx_header = data[:7]
        rx_iv = data[7:23]
        rx_mac = data[-32:]
        rx_ciphertext = data[23:-32]
        
        # Always check HMAC before decrypting to prevent attacks
        if not verify_hmac(s2c_mac, data[:-32], rx_mac):
            print("!!! SECURITY ALERT: HMAC Mismatch. Terminating.")
            break

        try:
            # Decrypt server message after integrity check
            decrypted_payload = aes_decrypt(s2c_enc, rx_iv, rx_ciphertext)
            print(f"Server Response: {decrypted_payload.decode()}")
            
            # If server sends close opcode, stop communication
            rx_opcode = rx_header[0]
            if rx_opcode == 60: 
                break
                
        except Exception as e:
            print(f"Decryption Error: {e}")
            break

        # --- 4. Key Evolution (Ratcheting) ---
        # Create new keys so next message uses fresh keys
        
        # Update client-to-server keys using sent ciphertext
        c2s_enc = evolve_key(c2s_enc, ciphertext)
        c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE") 
        
        # Update server-to-client keys using received ciphertext
        s2c_enc = evolve_key(s2c_enc, rx_ciphertext)
        s2c_mac = evolve_key(s2c_mac, b"CONSTANT_NONCE")

        # Move to next message round
        round_no += 1
        phase = "ACTIVE"
        
except KeyboardInterrupt:
    print("\nShutting down.")
finally:
    client.close()
