import socket
import sys
import struct
import threading
from protocol_fsm import ProtocolError, ProtocolFSM
from crypto_utils import (
    aes_encrypt, aes_decrypt, compute_hmac,
    verify_hmac, evolve_key, pack_header
)

# ---------------- ARG CHECK ----------------
if len(sys.argv) != 3:
    print("Usage : python server.py <IP> <PORT>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

# ---------------- MASTER KEYS ----------------
MASTER_KEYS = {
    1: b"this_is_16_byte1",
    2: b"this_is_16_byte2",
    3: b"this_is_16_byte3",
    4: b"this_is_16_byte4",
}

# ---------------- AGGREGATION STATE ----------------
round_values = {}      # { round_no: [values] }
round_clients = {}    # { round_no: [connections] }
agg_lock = threading.Lock()

EXPECTED_CLIENTS = 3   # number of active clients in demo

# ---------------- CLIENT HANDLER ----------------
def handle_client(conn, addr):
    print(f"New connection from {addr}")

    try:
        # First packet to get client ID
        data = conn.recv(4096)
        if not data:
            return

        header_bytes = data[:7]
        opcode, rx_cid, rx_round, direction = struct.unpack("!BBIB", header_bytes)

        if rx_cid not in MASTER_KEYS:
            raise ProtocolError("Unknown Client ID")

        cid = rx_cid
        mk = MASTER_KEYS[cid]

        # Initial keys
        c2s_enc = evolve_key(mk, b"C2S-ENC")
        c2s_mac = evolve_key(mk, b"C2S-MAC")
        s2c_enc = evolve_key(mk, b"S2C-ENC")
        s2c_mac = evolve_key(mk, b"S2C-MAC")

        fsm = ProtocolFSM(cid)

        pending_data = data

        while True:
            if pending_data:
                data = pending_data
                pending_data = None
            else:
                data = conn.recv(4096)

            if not data:
                break

            header_bytes = data[:7]
            iv = data[7:23]
            received_mac = data[-32:]
            ciphertext = data[23:-32]

            # ---- HMAC CHECK ----
            if not verify_hmac(c2s_mac, data[:-32], received_mac):
                raise ProtocolError("HMAC Verification Failed")

            opcode, rx_cid, rx_round, direction = struct.unpack("!BBIB", header_bytes)

            # ---- FSM CHECK ----
            fsm.validate_and_update(opcode, rx_round, direction)


            # ---- DECRYPT ----
            plaintext = aes_decrypt(c2s_enc, iv, ciphertext)
            msg = plaintext.decode()
            print(f"[Client {cid}] Round {rx_round}: {msg}")

            # ======================================================
            # HANDSHAKE RESPONSE
            # ======================================================
            if opcode == 10:  # CLIENT_HELLO
                res_header = pack_header(20, cid, rx_round, 1)  # SERVER_CHALLENGE
                res_iv, res_ciphertext = aes_encrypt(s2c_enc, b"SERVER_CHALLENGE")
                res_msg = res_header + res_iv + res_ciphertext
                res_mac = compute_hmac(s2c_mac, res_msg)
                conn.sendall(res_msg + res_mac)

                # key evolution after handshake
                c2s_enc = evolve_key(c2s_enc, ciphertext)
                c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE")
                s2c_enc = evolve_key(s2c_enc, res_ciphertext)
                s2c_mac = evolve_key(s2c_mac, b"CONSTANT_NONCE")

                fsm.increment_round()
                continue

            # ======================================================
            # AGGREGATION COLLECTION
            # ======================================================
            aggregate_ready = False
            agg_result = None

            if opcode == 30:  # CLIENT DATA
                try:
                    value = int(msg)
                except:
                    value = 0

                with agg_lock:
                    if rx_round not in round_values:
                        round_values[rx_round] = []
                        round_clients[rx_round] = []

                    round_values[rx_round].append(value)
                    round_clients[rx_round].append(conn)

                    if len(round_values[rx_round]) == EXPECTED_CLIENTS:
                        agg_result = sum(round_values[rx_round])
                        aggregate_ready = True

            # ======================================================
            # SEND AGGREGATED RESULT
            # ======================================================
            if aggregate_ready:
                result_msg = f"AGG_RESULT: {agg_result}".encode()

                with agg_lock:
                    targets = list(round_clients[rx_round])

                for c in targets:
                    res_header = pack_header(40, cid, rx_round, 1)
                    res_iv, res_ciphertext = aes_encrypt(s2c_enc, result_msg)
                    res_msg = res_header + res_iv + res_ciphertext
                    res_mac = compute_hmac(s2c_mac, res_msg)
                    c.sendall(res_msg + res_mac)

            # ======================================================
            # KEY EVOLUTION
            # ======================================================
            c2s_enc = evolve_key(c2s_enc, ciphertext)
            c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE")

            if aggregate_ready:
                s2c_enc = evolve_key(s2c_enc, str(agg_result).encode())
            else:
                s2c_enc = evolve_key(s2c_enc, ciphertext)

            s2c_mac = evolve_key(s2c_mac, b"CONSTANT_NONCE")

            fsm.increment_round()

            if opcode == 60:
                break

    except (ProtocolError, ValueError) as e:
        print(f"[{addr}] Protocol/Security Violation: {e}")

    finally:
        conn.close()
        print(f"Connection closed: {addr}")

# ---------------- MAIN SERVER LOOP ----------------
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)

print(f"Server listening on {HOST}:{PORT}...")

while True:
    conn, addr = server.accept()
    t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
    t.start()
