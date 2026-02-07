import socket
import struct
import time
import secrets

from crypto_utils import Helper, Elgamal, Hash, HMAC, AES


HOST = "127.0.0.1"
PORT = 9000
DRONE_ID = b"DRONE-001"


class Connection:
    def __init__(self, host, port):
        self.sock = socket.socket()
        self.sock.connect((host, port))

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
        return struct.unpack("!B", self.recv_exact(1))[0]

    def close(self):
        self.sock.close()


class Phase0:
    def __init__(self, conn):
        self.conn = conn

    def receive(self):
        opcode = self.conn.recv_opcode()
        if opcode != 10:
            raise Exception("Invalid Phase 0 opcode")

        plen = struct.unpack("!I", self.conn.recv_exact(4))[0]
        payload = self.conn.recv_exact(plen)

        r = Helper.bytes_to_int(self.conn.recv_exact(256))
        s = Helper.bytes_to_int(self.conn.recv_exact(256))

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

        return p, g, sl, ts, mcc_id, pub

    def verify(self, payload, r, s, p, g, pub, sl):
        if p.bit_length() < sl:
            raise Exception("Weak parameters")

        if not Elgamal.verify(payload, r, s, pub, p, g):
            raise Exception("Bad MCC signature")


class Phase1:
    def __init__(self, conn, p, g, mcc_pub):
        self.conn = conn
        self.p = p
        self.g = g
        self.mcc_pub = mcc_pub
        self.priv, self.pub = Elgamal.keygen(p, g)
        self.K = secrets.randbits(256)

    def send_auth(self):
        c1, c2 = Elgamal.encrypt(self.K, self.mcc_pub, self.p, self.g)

        self.ts_d = int(time.time())
        self.rn_d = secrets.randbits(64)

        body = (
            struct.pack("!Q", self.ts_d) +
            struct.pack("!Q", self.rn_d) +
            DRONE_ID.ljust(16, b'\x00') +
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

    def receive_response(self):
        opcode = self.conn.recv_opcode()
        if opcode != 30:
            raise Exception("Auth failed")

        data = self.conn.recv_exact(537)
        r = Helper.bytes_to_int(self.conn.recv_exact(256))
        s = Helper.bytes_to_int(self.conn.recv_exact(256))

        if not Elgamal.verify(data, r, s, self.mcc_pub, self.p, self.g):
            raise Exception("Bad MCC response signature")

        ts_m = struct.unpack("!Q", data[0:8])[0]
        rn_m = struct.unpack("!Q", data[8:16])[0]

        c1 = Helper.bytes_to_int(data[25:281])
        c2 = Helper.bytes_to_int(data[281:537])

        K2 = Elgamal.decrypt(c1, c2, self.priv, self.p)

        if K2 != self.K:
            raise Exception("Key mismatch")

        return ts_m, rn_m


class Phase2:
    def __init__(self, conn, K, ts_d, ts_m, rn_d, rn_m):
        self.conn = conn
        self.sk = Hash.hash_bytes(
            Helper.int_to_bytes(K) +
            struct.pack("!QQQQ", ts_d, ts_m, rn_d, rn_m)
        )

    def confirm(self):
        ts = int(time.time())
        data = DRONE_ID + struct.pack("!Q", ts)
        tag = HMAC.hmac_sha256(self.sk, data)

        self.conn.send(struct.pack("!B", 40) + tag)

        if self.conn.recv_opcode() != 50:
            raise Exception("Confirmation failed")

        return self.sk


class Phase3:
    def __init__(self, conn, sk):
        self.conn = conn
        self.sk = sk
        self.gk = None

    def listen(self):
        while True:
            op = self.conn.recv_opcode()

            if op == 70:
                iv = self.conn.recv_exact(16)
                ct = self.conn.recv_exact(48)
                self.gk = AES.aes_decrypt(self.sk, iv, ct)

            elif op == 80:
                iv = self.conn.recv_exact(16)
                ct = self.conn.recv_exact(1024)
                tag = self.conn.recv_exact(32)

                if HMAC.hmac_sha256(self.gk, iv + ct) != tag:
                    continue

                msg = AES.aes_decrypt(self.gk, iv, ct)
                print(msg.decode().strip())

            elif op == 90:
                break


def main():
    conn = Connection(HOST, PORT)

    p0 = Phase0(conn)
    payload, r, s = p0.receive()
    p, g, sl, ts0, mcc_id, mcc_pub = p0.parse(payload)
    print(p, "\n")
    print(g, "\n")
    print(mcc_pub)
    p0.verify(payload, r, s, p, g, mcc_pub, sl)

    p1 = Phase1(conn, p, g, mcc_pub)
    p1.send_auth()
    ts_m, rn_m = p1.receive_response()

    p2 = Phase2(conn, p1.K, p1.ts_d, ts_m, p1.rn_d, rn_m)
    sk = p2.confirm()

    p3 = Phase3(conn, sk)
    p3.listen()

    conn.close()


if __name__ == "__main__":
    main()
