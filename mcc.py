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
        ts = int(time.time())
        p_bytes = Helper.int_to_bytes(P)
        g_bytes = Helper.int_to_bytes(G)
        pub_bytes = Helper.int_to_bytes(self.mcc_pub)

        print(Helper.bytes_to_int(p_bytes))
        print(self.mcc_pub)
        payload = (
            struct.pack("!I", len(p_bytes)) +
            p_bytes +
            struct.pack("!I", len(g_bytes)) +
            g_bytes +
            struct.pack("!I", SECURITY_LEVEL) +
            struct.pack("!Q", ts) +
            MCC_ID +
            struct.pack("!I", len(pub_bytes)) +
            pub_bytes
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
        header = self.conn.recv_exact(1 + 8 + 8 + 16)
        opcode, ts_d, rn_d, d_id = struct.unpack("!BQQ16s", header)

        if opcode != 20:
            raise Exception("Invalid AUTH_REQ")

        drone_id = d_id.strip(b'\x00')

        c1 = Helper.bytes_to_int(self.conn.recv_exact(256))
        c2 = Helper.bytes_to_int(self.conn.recv_exact(256))
        r = Helper.bytes_to_int(self.conn.recv_exact(256))
        s = Helper.bytes_to_int(self.conn.recv_exact(256))

        drone_pub = Helper.modexp(G, Helper.bytes_to_int(d_id), P)

        sig_data = (
            struct.pack("!Q", ts_d) +
            struct.pack("!Q", rn_d) +
            d_id +
            Helper.int_to_bytes(c1).rjust(256, b'\x00') +
            Helper.int_to_bytes(c2).rjust(256, b'\x00')
        )

        if not Elgamal.verify(sig_data, r, s, drone_pub, P, G):
            raise Exception("Drone signature invalid")

        K = Elgamal.decrypt(c1, c2, self.mcc_priv, P)

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
        opcode = self.conn.recv_opcode()
        if opcode != 40:
            raise Exception("Expected SK_CONFIRM")

        received = self.conn.recv_exact(32)

        now = int(time.time())
        for delta in range(-10, 11):
            ts = now + delta
            data = drone_id + struct.pack("!Q", ts)
            if HMAC.hmac_sha256(sk, data) == received:
                self.conn.send(struct.pack("!B", 50))
                return True

        self.conn.send(struct.pack("!B", 60))
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

    def remove(self, drone_id):
        with self.lock:
            self.drones.pop(drone_id, None)

    def list(self):
        with self.lock:
            return dict(self.drones)

    def broadcast(self, command, mcc_priv):
        with self.lock:
            if not self.drones:
                return

            material = b"".join(d["sk"] for d in self.drones.values()) + Helper.int_to_bytes(mcc_priv)
            gk = Hash.hash_bytes(material)

            for d in self.drones.values():
                iv, ct = AES.aes_encrypt(d["sk"], gk)
                d["conn"].send(struct.pack("!B", 70) + iv + ct)

            time.sleep(0.2)

            for d in self.drones.values():
                iv, ct = AES.aes_encrypt(gk, command.encode())
                ct = ct.ljust(1024, b'\x00')
                tag = HMAC.hmac_sha256(gk, iv + ct)
                d["conn"].send(struct.pack("!B", 80) + iv + ct + tag)


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

            while True:
                time.sleep(1)

        except Exception:
            pass
        finally:
            if self.drone_id:
                self.registry.remove(self.drone_id)
            self.conn.close()


class MCCServer:
    def __init__(self):
        self.priv, self.pub = Elgamal.keygen(P, G)
        self.registry = DroneRegistry()

    def start(self):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        threading.Thread(target=self.cli, daemon=True).start()

        while True:
            sock, addr = server.accept()
            DroneHandler(sock, addr, self.priv, self.pub, self.registry).start()

    def cli(self):
        while True:
            cmd = input("MCC> ").strip()
            if cmd == "list":
                for d, info in self.registry.list().items():
                    print(d.decode(), info["addr"])
            elif cmd.startswith("broadcast "):
                self.registry.broadcast(cmd[10:], self.priv)
            elif cmd == "shutdown":
                break


def main():
    MCCServer().start()


if __name__ == "__main__":
    main()
