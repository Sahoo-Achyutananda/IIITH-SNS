import socket
import sys
import threading
import struct
from protocol_fsm import ProtocolError, ProtocolFSM
from crypto_utils import (
    aes_encrypt, aes_decrypt, compute_hmac, 
    verify_hmac, evolve_key, pack_header
)

if len(sys.argv) != 3:
    print("Usage : python server.py <IP> <PORT>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

# Master key for each client (must be same as what client is using)
MASTER_KEYS = {1: b"this_is_16_bytes"} 

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)
print(f"Server listening on {HOST}:{PORT}...")

def handle_client(conn, addr):
    print(f"New connection from {addr}")

    try:
        cid = 1
        mk = MASTER_KEYS[cid]

        c2s_enc = evolve_key(mk, b"C2S-ENC")
        c2s_mac = evolve_key(mk, b"C2S-MAC")
        s2c_enc = evolve_key(mk, b"S2C-ENC")
        s2c_mac = evolve_key(mk, b"S2C-MAC")

        fsm = ProtocolFSM(cid)

        while True:
            data = conn.recv(4096)
            if not data:
                break

            header_bytes = data[:7]
            iv = data[7:23]
            received_mac = data[-32:]
            ciphertext = data[23:-32]

            # 1. Verify HMAC first
            if not verify_hmac(c2s_mac, data[:-32], received_mac):
                raise ProtocolError("HMAC Verification Failed")

            # 2. FSM validation
            opcode, rx_cid, rx_round, direction = struct.unpack("!BBIB", header_bytes)
            fsm.validate_and_update(opcode, rx_round)

            # 3. Decrypt
            plaintext = aes_decrypt(c2s_enc, iv, ciphertext)
            print(f"Round {rx_round} | From Client {rx_cid}: {plaintext.decode()}")

            # 4. Prepare response
            res_opcode = 40 if opcode == 30 else 20
            res_payload = b"SERVER_ACK: " + plaintext

            res_header = pack_header(res_opcode, cid, rx_round, 1)
            res_iv, res_ciphertext = aes_encrypt(s2c_enc, res_payload)
            res_msg = res_header + res_iv + res_ciphertext
            res_mac = compute_hmac(s2c_mac, res_msg)

            conn.sendall(res_msg + res_mac)

            # 5. Key ratcheting (local to this thread)
            c2s_enc = evolve_key(c2s_enc, ciphertext)
            c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE")
            s2c_enc = evolve_key(s2c_enc, res_ciphertext)
            s2c_mac = evolve_key(s2c_mac, b"CONSTANT_NONCE")

            fsm.increment_round()

            if opcode == 60:
                break

    except (ProtocolError, ValueError) as e:
        print(f"[{addr}] Protocol violation:", e)
    finally:
        conn.close()
        print(f"Connection closed: {addr}")


while True:
    conn, addr = server.accept()
    t = threading.Thread(
        target=handle_client,
        args=(conn, addr),
        daemon=True
    )
    t.start()


server.close()
