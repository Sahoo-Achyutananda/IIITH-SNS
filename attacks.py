# attacks.py
# Attack Demonstrations against MCC–Drone Protocol
#
# Attacks demonstrated:
# 1. Replay Attack
# 2. MITM Parameter Tampering
# 3. Unauthorized Drone ID Attack

import socket
import struct
import time

from crypto_utils import Helper


# MCC connection details
HOST = "127.0.0.1"
PORT = 9000

# Required opcodes
OPCODE_PARAM_INIT = 10
OPCODE_AUTH_REQ   = 20


def replay_attack():
    """
    Replay Attack:
    Re-sends an old or previously captured AUTH_REQ message.
    Expected result: MCC should reject it due to stale timestamp or nonce reuse.
    """
    print("\n[ATTACK 1] Replay Attack")

    s = socket.socket()
    s.connect((HOST, PORT))

    # Receive Phase 0 parameters (ignored for this attack)
    s.recv(1)
    plen = struct.unpack("!I", s.recv(4))[0]
    s.recv(plen)
    s.recv(256)
    s.recv(256)

    # Construct a fake old authentication request
    fake_ts = int(time.time()) - 1000   # deliberately old timestamp
    fake_rn = 12345678
    fake_id = b"DRONE-REPLAY-ATTK"

    fake_msg = (
        struct.pack("!B", OPCODE_AUTH_REQ) +
        struct.pack("!Q", fake_ts) +
        struct.pack("!Q", fake_rn) +
        fake_id.ljust(16, b'\x00') +
        b"\x00" * 256 +
        b"\x00" * 256 +
        b"\x00" * 256 +
        b"\x00" * 256
    )

    s.sendall(fake_msg)
    print("[✔] Replayed old authentication packet")

    s.close()


def mitm_parameter_attack():
    """
    MITM Parameter Tampering Attack:
    Modifies cryptographic parameters (prime p) during Phase 0.
    Expected result: drone should detect weak or inconsistent parameters.
    """
    print("\n[ATTACK 2] MITM Parameter Tampering")

    s = socket.socket()
    s.connect((HOST, PORT))

    # Receive Phase 0 message
    opcode = struct.unpack("!B", s.recv(1))[0]
    plen = struct.unpack("!I", s.recv(4))[0]
    payload = bytearray(s.recv(plen))

    # Replace prime p with a very small value (p = 23)
    print("[*] Tampering prime p")
    payload[0:4] = b"\x00\x00\x00\x17"

    # Discard MCC signature
    s.recv(256)
    s.recv(256)

    # Send modified parameters back (simulated MITM behavior)
    s.sendall(
        struct.pack("!B", opcode) +
        struct.pack("!I", len(payload)) +
        payload
    )

    print("[✔] Tampered parameters sent")

    s.close()


def unauthorized_drone_attack():
    """
    Unauthorized Drone ID Attack:
    Attempts authentication using a fake or unregistered drone ID.
    Expected result: MCC should reject the authentication.
    """
    print("\n[ATTACK 3] Unauthorized Drone ID")

    s = socket.socket()
    s.connect((HOST, PORT))

    # Receive Phase 0 parameters
    s.recv(1)
    plen = struct.unpack("!I", s.recv(4))[0]
    s.recv(plen)
    s.recv(256)
    s.recv(256)

    fake_id = b"HACKER-DRONE-999"

    # Construct fake authentication request
    msg = (
        struct.pack("!B", OPCODE_AUTH_REQ) +
        struct.pack("!Q", int(time.time())) +
        struct.pack("!Q", 99999999) +
        fake_id.ljust(16, b'\x00') +
        b"\x00" * 256 +
        b"\x00" * 256 +
        b"\x00" * 256 +
        b"\x00" * 256
    )

    s.sendall(msg)
    print("[✔] Unauthorized drone attempted authentication")

    s.close()


if __name__ == "__main__":
    replay_attack()
    time.sleep(1)

    mitm_parameter_attack()
    time.sleep(1)

    unauthorized_drone_attack()
