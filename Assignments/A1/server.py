import socket
import sys
import threading

from protocol_fsm import ProtocolError, ProtocolFSM
from crypto_utils import *

if len(sys.argv) != 3:
    print("Usage: python server.py <IP> <PORT>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

MASTER_KEYS = {
    1 : b"client1_master__",
    2 : b"client2_master__",
}

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    fsm = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            header = data[:7]
            iv = data[7:23]
            ciphertext = data[23:-32]
            mac = data[-32:]

            opcode, cid, rnd, direction = unpack_header(header)
            
            if fsm is None:
                if cid not in MASTER_KEYS:
                    raise ProtocolError("Unknown Client ID")
                
                fsm = ProtocolFSM(cid, MASTER_KEYS[cid])
                print(f"FSM created for client {cid}")
            
            # FSM validation - 
            fsm.validate_message(opcode, rnd, direction)

            # HMAC check
            if not verify_hmac(fsm.c2s_mac, data[:-32], mac):
                raise ProtocolError("Bad HMAC")
            
            # decrypt
            plaintext = decrypt(fsm.c2s_enc, iv, ciphertext)
            print(f"[SERVER:{cid}] Round {rnd} → {plaintext.decode()}")
            
            # update keys
            fsm.update_keys_after_c2s(ciphertext)

            # respond to client
            response = b"ACK"

            # build the response
            resp_header = pack_header(40, cid, rnd, 1) # opcode 40, direction 1 (s2c)
            resp_iv, resp_ct = encrypt(fsm.s2c_enc, response)
            resp_msg = resp_header + resp_iv + resp_ct
            resp_mac = compute_hmac(fsm.s2c_mac, resp_msg)

            conn.sendall(resp_msg + resp_mac)

            # update the keys and update round
            fsm.update_keys_after_s2c(resp_ct)
            fsm.advance_round()
    
    except ProtocolError as e:
        print(f"[SERVER:{addr}] Protocol violation:", e)

    finally:
        conn.close()
        print(f"[SERVER] Closed {addr}")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)

print(f"[SERVER] Listening on {HOST}:{PORT}")

while True:
    conn, addr = server.accept()
    threading.Thread(
        target=handle_client,
        args=(conn, addr),
        daemon=True
    ).start()