import socket
import struct
import threading
import time
import secrets

from crypto_utils import Helper, Elgamal, Hash, HMAC, AES

HOST = "127.0.0.1"
PORT = 9000
MCC_ID = b"MCC-ALPHA"
SECURITY_LEVEL = 2048
G = 2

# Standard RFC 3526 2048-bit Prime (safe for this lab)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

class Connection:
    def __init__(self, sock):
        self.sock = sock

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            part = self.sock.recv(n - len(data))
            if not part:
                raise ConnectionError
            data += part
        return data

    def recv_opcode(self):
        return struct.unpack("!B", self.recv_exact(1))[0]

    def send(self, data):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()

class Phase0:
    def __init__(self, mcc_priv, mcc_pub):
        self.mcc_priv = mcc_priv
        self.mcc_pub = mcc_pub

    def send(self, conn):
        print("  [Phase 0] Sending Parameters...")
        ts = int(time.time())
        p_bytes = Helper.int_to_bytes(P)
        g_bytes = Helper.int_to_bytes(G)
        pub_bytes = Helper.int_to_bytes(self.mcc_pub)

        payload = (
            struct.pack("!I", len(p_bytes)) + p_bytes +
            struct.pack("!I", len(g_bytes)) + g_bytes +
            struct.pack("!I", SECURITY_LEVEL) +
            struct.pack("!Q", ts) +
            MCC_ID +
            struct.pack("!I", len(pub_bytes)) + pub_bytes
        )

        r, s = Elgamal.sign(payload, self.mcc_priv, P, G)

        msg = (
            struct.pack("!B", 10) +
            struct.pack("!I", len(payload)) +
            payload +
            Helper.int_to_bytes(r).rjust(256, b'\x00') +
            Helper.int_to_bytes(s).rjust(256, b'\x00')
        )
        conn.send(msg)

class Phase1:
    def __init__(self, conn, mcc_priv):
        self.conn = conn
        self.mcc_priv = mcc_priv

    def receive_auth(self):
        print("  [Phase 1] Waiting for Drone Auth...")
        header = self.conn.recv_exact(1 + 8 + 8 + 16 + 256)
        opcode, ts_d, rn_d, d_id, drone_pub_bytes = struct.unpack("!BQQ16s256s", header)

        if opcode != 20:
            raise Exception("Invalid AUTH_REQ Opcode")

        # adding some extra code for security check -
        current_time = int(time.time())
        
        # Calculate the difference (allow for small clock drift)
        time_diff = abs(current_time - ts_d)
        
        print(f"  [SECURITY] Timestamp Check: Packet Time={ts_d}, Server Time={current_time}, Diff={time_diff}s")

        # Reject if older than 10 seconds
        if time_diff > 10:
            print(f"  [SECURITY ALERT] REPLAY ATTACK DETECTED! Timestamp expired by {time_diff}s")
            # Send Error Opcode 60 to tell attacker to go away
            self.conn.send(struct.pack("!B", 60))
            raise Exception("Replay Attack Blocked: Timestamp expired")
        
        drone_id = d_id.strip(b'\x00')
        drone_pub = Helper.bytes_to_int(drone_pub_bytes)

        c1 = Helper.bytes_to_int(self.conn.recv_exact(256))
        c2 = Helper.bytes_to_int(self.conn.recv_exact(256))
        r = Helper.bytes_to_int(self.conn.recv_exact(256))
        s = Helper.bytes_to_int(self.conn.recv_exact(256))

        sig_data = (
            struct.pack("!Q", ts_d) +
            struct.pack("!Q", rn_d) +
            d_id +
            drone_pub_bytes +
            Helper.int_to_bytes(c1).rjust(256, b'\x00') +
            Helper.int_to_bytes(c2).rjust(256, b'\x00')
        )

        if not Elgamal.verify(sig_data, r, s, drone_pub, P, G):
            raise Exception("Drone signature invalid")

        K = Elgamal.decrypt(c1, c2, self.mcc_priv, P)
        print(f"  [Phase 1] Authenticated {drone_id.decode()}. Shared secret K decrypted.")
        return drone_id, drone_pub, K, ts_d, rn_d

    def send_response(self, drone_pub, K):
        ts_m = int(time.time())
        rn_m = secrets.randbits(64)
        c1, c2 = Elgamal.encrypt(K, drone_pub, P, G)

        payload = (
            struct.pack("!QQ", ts_m, rn_m) +
            MCC_ID +
            Helper.int_to_bytes(c1).rjust(256, b'\x00') +
            Helper.int_to_bytes(c2).rjust(256, b'\x00')
        )

        r, s = Elgamal.sign(payload, self.mcc_priv, P, G)
        msg = (
            struct.pack("!B", 30) +
            payload +
            Helper.int_to_bytes(r).rjust(256, b'\x00') +
            Helper.int_to_bytes(s).rjust(256, b'\x00')
        )
        self.conn.send(msg)
        return ts_m, rn_m

class Phase2:
    def __init__(self, conn):
        self.conn = conn

    def verify(self, drone_id, sk):
        print(f"  [Phase 2] Waiting for confirmation from {drone_id.decode()}...")
        opcode = self.conn.recv_opcode()
        if opcode != 40:
            print("  [Phase 2] FAILED. Wrong opcode.")
            return False

        received_tag = self.conn.recv_exact(32)
        now = int(time.time())
                
        verified = False
        for delta in range(-10, 11): # 20 second window
            ts = now + delta
            data = drone_id + struct.pack("!Q", ts)

            if HMAC.hmac_sha256(sk, data) == received_tag:
                verified = True
                break

        if verified:
            self.conn.send(struct.pack("!B", 50)) # Success
            print("  [Phase 2] SUCCESS. HMAC Verified.")
            return True
        else:
            self.conn.send(struct.pack("!B", 60)) # Fail
            print("  [Phase 2] FAILED. HMAC Mismatch.")
            return False

class DroneRegistry:
    def __init__(self):
        self.drones = {}
        self.lock = threading.Lock()

    def add(self, drone_id, conn, sk, addr):
        with self.lock:
            self.drones[drone_id] = {
                "conn": conn,
                "sk": sk,
                "addr": addr,
                "time": time.time()
            }
            print(f"[REGISTRY] Added {drone_id.decode()}. Total Drones: {len(self.drones)}")

    def remove(self, drone_id):
        with self.lock:
            if drone_id in self.drones:
                del self.drones[drone_id]
                print(f"[REGISTRY] Removed {drone_id.decode()}")

    def list(self):
        with self.lock:
            return dict(self.drones)

    def broadcast(self, command, mcc_priv):
        with self.lock:
            if not self.drones:
                print("[BROADCAST] No drones connected.")
                return

            print(f"[BROADCAST] Generating Group Key for {len(self.drones)} drones...")
            
            # 1. Generate Group Key (GK)
            # Sort keys by Drone ID to ensure consistent order if needed, though dict order is usually preserved
            material = b"".join(d["sk"] for d in self.drones.values()) + Helper.int_to_bytes(mcc_priv)
            gk = Hash.hash_bytes(material)

            # 2. Send GK to all drones
            for d_id, d in self.drones.items():
                try:
                    iv, ct = AES.aes_encrypt(d["sk"], gk)
                    # Send Opcode 70 + IV + Ciphertext
                    d["conn"].send(struct.pack("!B", 70) + iv + ct)
                except Exception as e:
                    print(f"  [BROADCAST ERROR] Could not send GK to {d_id}: {e}")

            time.sleep(0.5) # Allow drones to process GK

            # 3. Send Encrypted Command
            print(f"[BROADCAST] Sending encrypted command: '{command}'")
            for d_id, d in self.drones.items():
                try:
                    iv, ct = AES.aes_encrypt(gk, command.encode())
                    
                    # Packet: Opcode(1) + Length(4) + IV(16) + Ciphertext(N) + Tag(32)
                    
                    header = struct.pack("!BI", 80, len(ct)) # Opcode 80, Length of CT
                    tag = HMAC.hmac_sha256(gk, iv + ct)
                    
                    d["conn"].send(header + iv + ct + tag)
                except Exception as e:
                     print(f"  [BROADCAST ERROR] Could not send CMD to {d_id}: {e}")
    
class DroneHandler(threading.Thread):
    def __init__(self, sock, addr, mcc_priv, mcc_pub, registry):
        super().__init__(daemon=True)
        self.conn = Connection(sock)
        self.addr = addr
        self.mcc_priv = mcc_priv
        self.mcc_pub = mcc_pub
        self.registry = registry
        self.drone_id = None

    def run(self):
        try:
            print(f"[{self.addr}] Starting Handshake...")
            Phase0(self.mcc_priv, self.mcc_pub).send(self.conn)

            p1 = Phase1(self.conn, self.mcc_priv)
            self.drone_id, drone_pub, K, ts_d, rn_d = p1.receive_auth()
            
            ts_m, rn_m = p1.send_response(drone_pub, K)

            sk = Hash.hash_bytes(
                Helper.int_to_bytes(K) +
                struct.pack("!QQQQ", ts_d, ts_m, rn_d, rn_m)
            )

            if not Phase2(self.conn).verify(self.drone_id, sk):
                return

            self.registry.add(self.drone_id, self.conn, sk, self.addr)

            # Keep thread alive to maintain connection
            while True:
                time.sleep(1)
        except Exception as e:
            print(f"[{self.addr}] Handler Error: {e}")
        finally:
            if self.drone_id:
                self.registry.remove(self.drone_id)
            self.conn.close()

class MCCServer:
    def __init__(self):
        print("Initializing MCC... Generating Keys (this might take a second)...")
        self.priv, self.pub = Elgamal.keygen(P, G)
        self.registry = DroneRegistry()
        print(f"MCC Ready. Public Key: {str(self.pub)[:20]}...")

    def start(self):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"MCC listening on {HOST}:{PORT}")

        threading.Thread(target=self.cli, daemon=True).start()

        while True:
            sock, addr = server.accept()
            print(f"\n[NEW CONNECTION] {addr}")
            DroneHandler(sock, addr, self.priv, self.pub, self.registry).start()

    def cli(self):
        time.sleep(1) # Wait for startup prints
        print("\n--- COMMAND CENTER READY ---")
        print("Type 'help' for commands.")
        
        while True:
            cmd = input("\nMCC> ").strip()
            if cmd == "list":
                drones = self.registry.list()
                if not drones:
                    print("No drones connected")
                else:
                    print("\nConnected Drones:")
                    for d, info in drones.items():
                        print(f"  - {d.decode()} @ {info['addr']}")
            elif cmd.startswith("broadcast "):
                msg = cmd[10:]
                self.registry.broadcast(msg, self.priv)
            elif cmd == "shutdown":
                print("Shutting down...")
                break
            elif cmd == "help":
                 print("Commands: list | broadcast <message> | shutdown")
            else:
                print("Unknown command.")

if __name__ == "__main__":
    MCCServer().start()