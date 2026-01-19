import socket
import sys
import threading
import struct
import threading
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

# Master key per client (you can add more clients here)
MASTER_KEYS = {
    1: b"this_is_16_byte1",
    2: b"this_is_16_byte2" , # must be 16 bytes
    3: b"this_is_16_byte3" ,
    4: b"this_is_16_byte4" , # must be 16 bytes

}

<<<<<<< HEAD

=======
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
def handle_client(conn, addr):
    print(f"New connection from {addr}")

    try:
<<<<<<< HEAD
        # Receive first packet to know client ID
        data = conn.recv(4096)
        if not data:
            return

        header_bytes = data[:7]
        opcode, rx_cid, rx_round, direction = struct.unpack("!BBIB", header_bytes)

        if rx_cid not in MASTER_KEYS:
            raise ProtocolError("Unknown Client ID")

        cid = rx_cid
        mk = MASTER_KEYS[cid]

        # Initialize keys
=======
        cid = 1
        mk = MASTER_KEYS[cid]

>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
        c2s_enc = evolve_key(mk, b"C2S-ENC")
        c2s_mac = evolve_key(mk, b"C2S-MAC")
        s2c_enc = evolve_key(mk, b"S2C-ENC")
        s2c_mac = evolve_key(mk, b"S2C-MAC")

        fsm = ProtocolFSM(cid)
<<<<<<< HEAD

        # Put first packet back into processing
        pending_data = data
=======
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232

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

<<<<<<< HEAD
            # Verify HMAC first
            if not verify_hmac(c2s_mac, data[:-32], received_mac):
                raise ProtocolError("HMAC Verification Failed")

=======
            # 1. Verify HMAC first
            if not verify_hmac(c2s_mac, data[:-32], received_mac):
                raise ProtocolError("HMAC Verification Failed")

            # 2. FSM validation
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
            opcode, rx_cid, rx_round, direction = struct.unpack("!BBIB", header_bytes)

            # Validate protocol state
            fsm.validate_and_update(opcode, rx_round)

<<<<<<< HEAD
            # Decrypt after validation
=======
            # 3. Decrypt
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
            plaintext = aes_decrypt(c2s_enc, iv, ciphertext)
            print(f"[Client {cid}] Round {rx_round}: {plaintext.decode()}")

<<<<<<< HEAD
            # Prepare reply
=======
            # 4. Prepare response
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
            res_opcode = 40 if opcode == 30 else 20
            res_payload = b"SERVER_ACK: " + plaintext

            res_header = pack_header(res_opcode, cid, rx_round, 1)
            res_iv, res_ciphertext = aes_encrypt(s2c_enc, res_payload)
<<<<<<< HEAD

=======
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
            res_msg = res_header + res_iv + res_ciphertext
            res_mac = compute_hmac(s2c_mac, res_msg)

            conn.sendall(res_msg + res_mac)

<<<<<<< HEAD
            # Key evolution
            c2s_enc = evolve_key(c2s_enc, ciphertext)
            c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE")

=======
            # 5. Key ratcheting (local to this thread)
            c2s_enc = evolve_key(c2s_enc, ciphertext)
            c2s_mac = evolve_key(c2s_mac, b"CONSTANT_NONCE")
>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232
            s2c_enc = evolve_key(s2c_enc, res_ciphertext)
            s2c_mac = evolve_key(s2c_mac, b"CONSTANT_NONCE")

            fsm.increment_round()

            if opcode == 60:
                break

    except (ProtocolError, ValueError) as e:
<<<<<<< HEAD
        print(f"[{addr}] Protocol/Security Violation: {e}")

    finally:
        conn.close()
        print(f"Connection closed: {addr}")
=======
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

>>>>>>> 97af8ddb6e94496acc4520afe043a9586268f232


# ----------- MAIN SERVER LOOP -----------

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)

print(f"Server listening on {HOST}:{PORT}...")

while True:
    conn, addr = server.accept()

    # Start new thread for each client
    t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
    t.start()
