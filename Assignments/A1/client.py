import socket
import sys

from protocol_fsm import ProtocolFSM
from crypto_utils import *

if len(sys.argv) != 5:
    print("Usage: python client.py <IP> <PORT> <CLIENT_ID> <MASTER_KEY>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])
CLIENT_ID = int(sys.argv[3])
MASTER_KEY = sys.argv[4].encode().ljust(16, b'\0')[:16]

sock = socket.socket()
sock.connect((HOST, PORT))

fsm = ProtocolFSM(CLIENT_ID, MASTER_KEY)

print("[CLIENT] Connected")

try:
    while True:
        msg = input("Enter message (or quit): ")
        if msg.lower() == "quit":
            break

        opcode = 10 if fsm.phase == "INIT" else 30

        header = pack_header(opcode, CLIENT_ID, fsm.round, 0)
        iv, ct = encrypt(fsm.c2s_enc, msg.encode())
        sent_ct = ct
        packet = header + iv + ct
        mac = compute_hmac(fsm.c2s_mac, packet)

        sock.sendall(packet + mac)

        data = sock.recv(4096)
        if not data:
            break

        h = data[:7]
        iv = data[7:23]
        ct = data[23:-32]
        mac = data[-32:]

        if not verify_hmac(fsm.s2c_mac, data[:-32], mac):
            print("Bad MAC from server")
            break

        reply = decrypt(fsm.s2c_enc, iv, ct)
        print("Server:", reply.decode())

        fsm.update_keys_after_c2s(sent_ct)
        fsm.update_keys_after_s2c(ct)
        fsm.advance_round()

except Exception as e:
    print("[CLIENT] Error:", e)

finally:
    sock.close()
