import socket, struct, time, secrets
from crypto_utils import Helper, Elgamal, Hash, HMAC, AES

HOST, PORT = "127.0.0.1", 9000
DRONE_ID = b"DRONE-001"

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def main():
    sock = socket.socket()
    sock.connect((HOST, PORT))
    print(f"[DRONE] Connected to MCC at {HOST}:{PORT}")
    
    # Phase 0: Parameter Init
    print("[DRONE] Phase 0: Receiving parameters...")
    opcode = struct.unpack("!B", recv_exact(sock, 1))[0]
    if opcode != 10:
        raise Exception(f"Expected PARAM_INIT (10), got {opcode}")
    
    plen = struct.unpack("!I", recv_exact(sock, 4))[0]
    payload = recv_exact(sock, plen)
    r_m = Helper.bytes_to_int(recv_exact(sock, 256))
    s_m = Helper.bytes_to_int(recv_exact(sock, 256))

    # Parse parameters
    p_len = struct.unpack("!I", payload[0:4])[0]
    p = Helper.bytes_to_int(payload[4:4+p_len])
    
    # G is variable length - find where it ends
    g_start = 4 + p_len
    g_bytes_len = 1  # G=2 is 1 byte
    g = Helper.bytes_to_int(payload[g_start:g_start+g_bytes_len])
    
    sl_start = g_start + g_bytes_len
    sl = struct.unpack("!I", payload[sl_start:sl_start+4])[0]
    
    ts_start = sl_start + 4
    ts_0 = struct.unpack("!Q", payload[ts_start:ts_start+8])[0]
    
    id_start = ts_start + 8
    mcc_id = payload[id_start:id_start+9]
    
    pubkey_len_start = id_start + 9
    mcc_pub_len = struct.unpack("!I", payload[pubkey_len_start:pubkey_len_start+4])[0]
    
    pubkey_start = pubkey_len_start + 4
    mcc_pub_key = Helper.bytes_to_int(payload[pubkey_start:pubkey_start+mcc_pub_len])
    
    print(f"[DRONE] Received: SL={sl}, p={p.bit_length()} bits, g={g}")
    print(f"[DRONE] MCC_PUB = {str(mcc_pub_key)[:60]}...")
    print(f"[DRONE] DEBUG: p_len={p_len}, pub_len={mcc_pub_len}, payload_len={len(payload)}")
    
    # Verify parameters
    if p.bit_length() < sl:
        raise Exception(f"Security violation! p has {p.bit_length()} bits but SL={sl}")
    
    # Verify MCC signature using the provided public key
    if not Elgamal.verify(payload, r_m, s_m, mcc_pub_key, p, g):
        print(f"[DRONE] DEBUG: Signature verification details:")
        print(f"  - payload hash: {Hash.hash_int(payload) % 10000}")
        print(f"  - r: {str(r_m)[:50]}...")
        print(f"  - s: {str(s_m)[:50]}...")
        print(f"  - pub_key: {str(mcc_pub_key)[:50]}...")
        raise Exception("MCC signature verification failed!")
    
    print("[DRONE] Phase 0: Parameters verified ✓")

    # Phase 1A: Generate keys and send authentication request
    print("[DRONE] Phase 1A: Generating keys and authenticating...")
    priv_d, pub_d = Elgamal.keygen(p, g)
    K = secrets.randbits(256)
    
    # Encrypt K with MCC's public key
    c1, c2 = Elgamal.encrypt(K, mcc_pub_key, p, g)
    
    ts_d = int(time.time())
    rn_d = secrets.randbits(64)
    
    # Build authentication message
    header = struct.pack("!Q", ts_d) + struct.pack("!Q", rn_d) + DRONE_ID.ljust(16, b'\x00')
    auth_body = header + Helper.int_to_bytes(c1).rjust(256, b'\x00') + Helper.int_to_bytes(c2).rjust(256, b'\x00')
    
    # Sign the authentication
    r_d, s_d = Elgamal.sign(auth_body, priv_d, p, g)
    
    auth_msg = (struct.pack("!B", 20) + auth_body + 
                Helper.int_to_bytes(r_d).rjust(256, b'\x00') + 
                Helper.int_to_bytes(s_d).rjust(256, b'\x00'))
    
    sock.sendall(auth_msg)
    print(f"[DRONE] Sent AUTH_REQ with K={K}")

    # Phase 1B: Receive MCC Response
    print("[DRONE] Phase 1B: Waiting for MCC response...")
    opcode = struct.unpack("!B", recv_exact(sock, 1))[0]
    if opcode != 30:
        raise Exception(f"Expected AUTH_RES (30), got {opcode}")
    
    # Read response data: ts(8) + rn(8) + id(9) + c1(256) + c2(256) = 537 bytes
    res_data = recv_exact(sock, 537)
    r_m_sig = Helper.bytes_to_int(recv_exact(sock, 256))
    s_m_sig = Helper.bytes_to_int(recv_exact(sock, 256))
    
    ts_m = struct.unpack("!Q", res_data[0:8])[0]
    rn_m = struct.unpack("!Q", res_data[8:16])[0]
    mcc_id_resp = res_data[16:25]
    c1b = Helper.bytes_to_int(res_data[25:281])
    c2b = Helper.bytes_to_int(res_data[281:537])
    
    # Verify MCC signature on response
    if not Elgamal.verify(res_data, r_m_sig, s_m_sig, mcc_pub_key, p, g):
        raise Exception("MCC response signature verification failed!")
    
    # Decrypt and verify K
    K_received = Elgamal.decrypt(c1b, c2b, priv_d, p)
    if K_received != K:
        raise Exception(f"Key mismatch! Sent {K}, received {K_received}")
    
    print(f"[DRONE] Phase 1B: MCC proved knowledge of K ✓")

    # Phase 2: Session Key Confirmation
    print("[DRONE] Phase 2: Deriving session key...")
    sk = Hash.hash_bytes(Helper.int_to_bytes(K) + 
                         struct.pack("!QQQQ", ts_d, ts_m, rn_d, rn_m))
    
    # Send confirmation with timestamp
    ts_final = int(time.time())
    confirm_data = DRONE_ID.strip(b'\x00') + struct.pack("!Q", ts_final)
    hmac_tag = HMAC.hmac_sha256(sk, confirm_data)
    
    confirm_msg = struct.pack("!B", 40) + hmac_tag
    sock.sendall(confirm_msg)
    print("[DRONE] Sent SK_CONFIRM")
    
    # Wait for confirmation
    opcode = struct.unpack("!B", recv_exact(sock, 1))[0]
    if opcode == 50:
        print("[DRONE] ✓✓✓ FULLY AUTHENTICATED ✓✓✓")
    elif opcode == 60:
        raise Exception("MCC rejected: HMAC mismatch")
    else:
        raise Exception(f"Unexpected opcode: {opcode}")

    # Phase 3: Listen for group commands
    print("[DRONE] Phase 3: Listening for commands...")
    gk = None
    
    while True:
        try:
            op = struct.unpack("!B", recv_exact(sock, 1))[0]
            
            if op == 70:  # GROUP_KEY
                print("[DRONE] Receiving group key...")
                iv = recv_exact(sock, 16)
                ct = recv_exact(sock, 48)  # 32 bytes key + 16 bytes padding
                gk = AES.aes_decrypt(sk, iv, ct)
                print(f"[DRONE] Group key received: {gk.hex()[:32]}...")
                
            elif op == 80:  # GROUP_CMD
                if gk is None:
                    print("[DRONE] Warning: Received GROUP_CMD before GROUP_KEY")
                    continue
                    
                iv = recv_exact(sock, 16)
                ct = recv_exact(sock, 1024)
                tag = recv_exact(sock, 32)
                
                # Verify HMAC
                expected_tag = HMAC.hmac_sha256(gk, iv + ct)
                if expected_tag != tag:
                    print("[DRONE] ERROR: HMAC verification failed!")
                    continue
                
                # Decrypt command
                plaintext = AES.aes_decrypt(gk, iv, ct)
                command = plaintext.decode().strip()
                print(f"[DRONE] ✓ COMMAND RECEIVED: '{command}'")
                
            elif op == 90:  # SHUTDOWN
                print("[DRONE] Shutdown command received")
                break
                
            else:
                print(f"[DRONE] Unknown opcode: {op}")
                
        except Exception as e:
            print(f"[DRONE] Error in command loop: {e}")
            break
    
    sock.close()
    print("[DRONE] Connection closed")

if __name__ == "__main__":
    main()