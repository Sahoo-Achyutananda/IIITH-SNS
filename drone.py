import socket
import struct
import time
import secrets
import sys 

from crypto_utils import Helper, Elgamal, Hash, HMAC, AES

HOST = "127.0.0.1"
DEFAULT_PORT = 9000

# 1. Parse Drone ID
if len(sys.argv) > 1:
    DRONE_ID_RAW = sys.argv[1].encode()
else:
    DRONE_ID_RAW = b"DRONE-001"

# Pad to 16 bytes
DRONE_ID = DRONE_ID_RAW[:16].ljust(16, b'\x00')

# 2. Parse Port Number (New!)
if len(sys.argv) > 2:
    try:
        PORT = int(sys.argv[2])
    except ValueError:
        print(f"[ERROR] Invalid port '{sys.argv[2]}'. Using default {DEFAULT_PORT}.")
        PORT = DEFAULT_PORT
else:
    PORT = DEFAULT_PORT

print(f"[*] Drone ID: {DRONE_ID_RAW.decode()}")
print(f"[*] Target: {HOST}:{PORT}")

class Connection:
    def __init__(self, host, port):
        print(f"[DEBUG] Connecting to {host}:{port}...")
        self.sock = socket.socket()
        try:
            self.sock.connect((host, port))
            print("[DEBUG] Connection established.")
        except ConnectionRefusedError:
            print(f"[FATAL] Could not connect to {host}:{port}. Is the server (or proxy) running?")
            sys.exit(1)

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            part = self.sock.recv(n - len(data))
            if not part:
                raise ConnectionError
            data += part
        return data

    def send(self, data):
        self.sock.sendall(data)

    def recv_opcode(self):
        op = self.recv_exact(1)
        return struct.unpack("!B", op)[0]

    def close(self):
        self.sock.close()

class Phase0:
    def __init__(self, conn):
        self.conn = conn

    def receive(self):
        print("\n--- PHASE 0 START ---")
        opcode = self.conn.recv_opcode()
        if opcode != 10:
            raise Exception("Invalid Phase 0 opcode")

        plen = struct.unpack("!I", self.conn.recv_exact(4))[0]
        payload = self.conn.recv_exact(plen)
        r = Helper.bytes_to_int(self.conn.recv_exact(256))
        s = Helper.bytes_to_int(self.conn.recv_exact(256))
        
        print("[DEBUG] Phase 0 Payload received.")
        return payload, r, s

    def parse(self, payload):
        offset = 0
        p_len = struct.unpack("!I", payload[offset:offset+4])[0]
        offset += 4
        p = Helper.bytes_to_int(payload[offset:offset+p_len])
        offset += p_len

        g_len = struct.unpack("!I", payload[offset:offset+4])[0]
        offset += 4
        g = Helper.bytes_to_int(payload[offset:offset+g_len])
        offset += g_len

        sl = struct.unpack("!I", payload[offset:offset+4])[0]
        offset += 4
        ts = struct.unpack("!Q", payload[offset:offset+8])[0]
        offset += 8
        mcc_id = payload[offset:offset+9]
        offset += 9

        pub_len = struct.unpack("!I", payload[offset:offset+4])[0]
        offset += 4
        pub = Helper.bytes_to_int(payload[offset:offset+pub_len])

        print(f"[DEBUG] Parsed Parameters:\n   > P (bits): {p.bit_length()}\n   > G: {g}\n   > MCC Public Key: {str(pub)[:20]}...")
        return p, g, sl, ts, mcc_id, pub

    def verify(self, payload, r, s, p, g, pub, sl):
        if p.bit_length() < sl:
            raise Exception("Weak parameters detected!")
        if not Elgamal.verify(payload, r, s, pub, p, g):
            raise Exception("Bad MCC signature in Phase 0")
        print("[DEBUG] Phase 0 Signature Verified. MCC is trusted.")

class Phase1:
    def __init__(self, conn, p, g, mcc_pub):
        self.conn = conn
        self.p = p
        self.g = g
        self.mcc_pub = mcc_pub
        self.priv, self.pub = Elgamal.keygen(p, g)
        self.K = secrets.randbits(256)
        print(f"[DEBUG] Generated Ephemeral Key K: {str(self.K)[:10]}...")

    def send_auth(self):
        print("\n--- PHASE 1 START ---")
        # Encrypt K with MCC's Public Key
        c1, c2 = Elgamal.encrypt(self.K, self.mcc_pub, self.p, self.g)
        
        self.ts_d = int(time.time())
        self.rn_d = secrets.randbits(64)

        body = (
            struct.pack("!Q", self.ts_d) +
            struct.pack("!Q", self.rn_d) +
            DRONE_ID +
            Helper.int_to_bytes(self.pub).rjust(256, b'\x00') +
            Helper.int_to_bytes(c1).rjust(256, b'\x00') +
            Helper.int_to_bytes(c2).rjust(256, b'\x00')
        )

        r, s = Elgamal.sign(body, self.priv, self.p, self.g)
        
        msg = (
            struct.pack("!B", 20) +
            body +
            Helper.int_to_bytes(r).rjust(256, b'\x00') +
            Helper.int_to_bytes(s).rjust(256, b'\x00')
        )
        self.conn.send(msg)
        print("[DEBUG] Auth Request Sent (Phase 1A).")

    def receive_response(self):
        opcode = self.conn.recv_opcode()
        if opcode != 30:
            raise Exception("Auth failed or rejected")

        data = self.conn.recv_exact(537)
        r = Helper.bytes_to_int(self.conn.recv_exact(256))
        s = Helper.bytes_to_int(self.conn.recv_exact(256))

        if not Elgamal.verify(data, r, s, self.mcc_pub, self.p, self.g):
            raise Exception("Bad MCC response signature")

        ts_m = struct.unpack("!Q", data[0:8])[0]
        rn_m = struct.unpack("!Q", data[8:16])[0]
        c1 = Helper.bytes_to_int(data[25:281])
        c2 = Helper.bytes_to_int(data[281:537])

        # Decrypt K sent back by MCC
        K2 = Elgamal.decrypt(c1, c2, self.priv, self.p)

        if K2 != self.K:
            raise Exception("Key mismatch! MCC did not decrypt correctly.")
        
        print("[DEBUG] MCC Response Verified (Phase 1B). Keys match.")
        return ts_m, rn_m

class Phase2:
    def __init__(self, conn, K, ts_d, ts_m, rn_d, rn_m):
        self.conn = conn
        self.sk = Hash.hash_bytes(
            Helper.int_to_bytes(K) +
            struct.pack("!QQQQ", ts_d, ts_m, rn_d, rn_m)
        )
        print(f"[DEBUG] Session Key Derived: {self.sk.hex()[:10]}...")

    def confirm(self):
        print("\n--- PHASE 2 START ---")
        ts = int(time.time())
        
        # FIX: Strip the null bytes so it matches what MCC verifies
        clean_id = DRONE_ID.strip(b'\x00') 
        data = clean_id + struct.pack("!Q", ts)
        
        tag = HMAC.hmac_sha256(self.sk, data)
        self.conn.send(struct.pack("!B", 40) + tag)
        print("[DEBUG] Confirmation HMAC sent.")

        op = self.conn.recv_opcode()
        if op == 50:
            print("[DEBUG] MCC Confirmed Session. Secure Channel Open.")
        else:
            print(f"[ERROR] MCC Rejected Confirmation. Opcode: {op}")
            raise Exception("Confirmation failed")
        return self.sk

class Phase3:
    def __init__(self, conn, sk):
        self.conn = conn
        self.sk = sk
        self.gk = None

    # def listen(self):
    #     print("\n--- PHASE 3 (LISTENING) ---")
    #     print("Waiting for broadcasts...")
    #     while True:
    #         try:
    #             op = self.conn.recv_opcode()
                
    #             if op == 70: # Group Key Update
    #                 iv = self.conn.recv_exact(16)
    #                 ct = self.conn.recv_exact(48)
    #                 self.gk = AES.aes_decrypt(self.sk, iv, ct)
    #                 print(f"\n[BROADCAST] Received new Group Key: {self.gk.hex()[:10]}...")

    #             elif op == 80: # Encrypted Command
    #                 iv = self.conn.recv_exact(16)
    #                 ct = self.conn.recv_exact(1024)
    #                 tag = self.conn.recv_exact(32)

    #                 if not self.gk:
    #                     print("[WARN] Received command but no Group Key set.")
    #                     continue
                        
    #                 if HMAC.hmac_sha256(self.gk, iv + ct) != tag:
    #                     print("[WARN] Command Integrity Check Failed!")
    #                     continue

    #                 msg = AES.aes_decrypt(self.gk, iv, ct)
    #                 msg_clean = msg.rstrip(b'\x00')
    #                 print(f"[COMMAND] >>> {msg_clean.decode('utf-8').strip()}")

    #             elif op == 90:
    #                 print("Shutdown signal received.")
    #                 break
    #         except Exception as e:
    #             print(f"Connection error: {e}")
    #             break

    def listen(self):
        print("\n--- PHASE 3 (LISTENING) ---")
        print("Waiting for broadcasts...")
        while True:
            try:
                op = self.conn.recv_opcode()
                
                if op == 70: # Group Key Update
                    iv = self.conn.recv_exact(16)
                    ct = self.conn.recv_exact(48) # GK (32 bytes) + Padding (16 bytes) = 48 bytes
                    self.gk = AES.aes_decrypt(self.sk, iv, ct)
                    print(f"\n[BROADCAST] Received new Group Key: {self.gk.hex()[:10]}...")

                elif op == 80: # Encrypted Command
                    # FIX: Read exact length of ciphertext
                    ct_len = struct.unpack("!I", self.conn.recv_exact(4))[0]
                    
                    iv = self.conn.recv_exact(16)
                    ct = self.conn.recv_exact(ct_len)
                    tag = self.conn.recv_exact(32)

                    if not self.gk:
                        print("[WARN] Received command but no Group Key set.")
                        continue
                        
                    # Verify HMAC
                    if HMAC.hmac_sha256(self.gk, iv + ct) != tag:
                        print("[WARN] Command Integrity Check Failed!")
                        continue

                    # Decrypt
                    msg = AES.aes_decrypt(self.gk, iv, ct)
                    
                    # Because aes_decrypt handles unpadding, we just decode
                    try:
                        print(f"[COMMAND] >>> {msg.decode('utf-8')}")
                    except UnicodeDecodeError:
                        print(f"[ERROR] Decryption produced garbage: {msg}")

                elif op == 90:
                    print("Shutdown signal received.")
                    break
            except Exception as e:
                print(f"Connection error: {e}")
                break

def main():
    conn = Connection(HOST, PORT)
    try:
        p0 = Phase0(conn)
        payload, r, s = p0.receive()
        p, g, sl, ts0, mcc_id, mcc_pub = p0.parse(payload)
        p0.verify(payload, r, s, p, g, mcc_pub, sl)

        p1 = Phase1(conn, p, g, mcc_pub)
        p1.send_auth()
        ts_m, rn_m = p1.receive_response()

        p2 = Phase2(conn, p1.K, p1.ts_d, ts_m, p1.rn_d, rn_m)
        sk = p2.confirm()

        p3 = Phase3(conn, sk)
        p3.listen()

    except Exception as e:
        print(f"[FATAL] Drone Crash: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()