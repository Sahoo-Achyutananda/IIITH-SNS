import socket, struct, threading, time, secrets
from crypto_utils import Helper, Elgamal, Hash, HMAC, AES

HOST = "127.0.0.1"
PORT = 9000
MCC_ID = b"MCC-ALPHA"
SECURITY_LEVEL = 2048

# 2048-bit MODP Group Prime (RFC 3526)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
    "07D32BD18426C51A1AD174FD124E5E02580556209800974E7984852086438D9E"
    "40E5E7A81434914F59A15F333E332E9D40454316302EB45D997F296D56E7CD43"
    "D7B1B6191E09C0D3962F74ED238A827B665241961A340331D45A0079C3110E6F"
    "D03A2E7092F26330960F174987E136E7B99D0F5486C9081B45F678912E351710"
    "79E50C07D7F84F868953C3C005391696D268159E443B14392C1D614E15684C2F"
    "FFFFFFFFFFFFFFFF", 16
)
G = 2

# Generate MCC keys
print("[MCC] Generating ElGamal keypair...")
MCC_PRIV, MCC_PUB = Elgamal.keygen(P, G)
print(f"[MCC] MCC_PUB = {MCC_PUB}")

active_drones = {}
active_drones_lock = threading.Lock()

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def send_phase0(sock):
    """Send cryptographic parameters to drone"""
    ts = int(time.time())
    p_bytes = Helper.int_to_bytes(P)
    pub_bytes = Helper.int_to_bytes(MCC_PUB)
    
    # Build payload: p_len(4) + p + g(1) + SL(4) + TS(8) + ID(9) + pub_key_len(4) + pub_key
    payload = (
        struct.pack("!I", len(p_bytes)) + 
        p_bytes + 
        Helper.int_to_bytes(G) +
        struct.pack("!I", SECURITY_LEVEL) + 
        struct.pack("!Q", ts) + 
        MCC_ID +
        struct.pack("!I", len(pub_bytes)) +
        pub_bytes
    )
    
    print(f"[MCC] DEBUG Phase 0: payload_len={len(payload)}, p_len={len(p_bytes)}, pub_len={len(pub_bytes)}")
    
    # Sign the payload
    r, s = Elgamal.sign(payload, MCC_PRIV, P, G)
    
    print(f"[MCC] DEBUG: Signature r={str(r)[:50]}..., s={str(s)[:50]}...")
    
    # Verify our own signature before sending (sanity check)
    if not Elgamal.verify(payload, r, s, MCC_PUB, P, G):
        print("[MCC] ERROR: Self-signature verification failed!")
        raise Exception("MCC cannot verify its own signature!")
    else:
        print("[MCC] DEBUG: Self-signature verification OK")
    
    msg = (
        struct.pack("!B", 10) +  # PARAM_INIT opcode
        struct.pack("!I", len(payload)) + 
        payload +
        Helper.int_to_bytes(r).rjust(256, b'\x00') + 
        Helper.int_to_bytes(s).rjust(256, b'\x00')
    )
    
    sock.sendall(msg)
    print("[MCC] Phase 0: Parameters sent")

def handle_drone(conn, addr):
    """Handle individual drone connection"""
    drone_id = None
    
    try:
        print(f"[MCC] New connection from {addr}")
        
        # Phase 0: Send parameters
        send_phase0(conn)
        
        # Phase 1A: Receive drone authentication request
        print("[MCC] Phase 1A: Waiting for AUTH_REQ...")
        header = recv_exact(conn, 1 + 8 + 8 + 16)  # opcode + ts + rn + id
        opcode, ts_d, rn_d, d_id = struct.unpack("!BQQ16s", header)
        
        if opcode != 20:
            print(f"[MCC] Expected AUTH_REQ (20), got {opcode}")
            return
        
        drone_id = d_id.strip(b'\x00')
        print(f"[MCC] AUTH_REQ from {drone_id.decode()}")
        
        # Read ElGamal ciphertext and signature
        c1 = Helper.bytes_to_int(recv_exact(conn, 256))
        c2 = Helper.bytes_to_int(recv_exact(conn, 256))
        r_d = Helper.bytes_to_int(recv_exact(conn, 256))
        s_d = Helper.bytes_to_int(recv_exact(conn, 256))

        # Derive drone public key (for this lab, using deterministic method)
        drone_pub = Helper.modexp(G, Helper.bytes_to_int(d_id), P)
        
        # Verify drone signature
        sig_data = header[1:] + Helper.int_to_bytes(c1).rjust(256, b'\x00') + Helper.int_to_bytes(c2).rjust(256, b'\x00')
        
        if not Elgamal.verify(sig_data, r_d, s_d, drone_pub, P, G):
            print(f"[MCC] Signature verification failed for {drone_id.decode()}")
            return

        print(f"[MCC] Signature verified ✓")
        
        # Decrypt K
        K = Elgamal.decrypt(c1, c2, MCC_PRIV, P)
        print(f"[MCC] Decrypted K = {K}")
        
        # Phase 1B: Send MCC response (proof of decryption)
        print("[MCC] Phase 1B: Sending AUTH_RES...")
        ts_m = int(time.time())
        rn_m = secrets.randbits(64)
        
        # Re-encrypt K with drone's public key
        c1b, c2b = Elgamal.encrypt(K, drone_pub, P, G)
        
        res_payload = (
            struct.pack("!QQ", ts_m, rn_m) + 
            MCC_ID + 
            Helper.int_to_bytes(c1b).rjust(256, b'\x00') + 
            Helper.int_to_bytes(c2b).rjust(256, b'\x00')
        )
        
        # Sign response
        r_m, s_m = Elgamal.sign(res_payload, MCC_PRIV, P, G)
        
        auth_res = (
            struct.pack("!B", 30) +  # AUTH_RES opcode
            res_payload + 
            Helper.int_to_bytes(r_m).rjust(256, b'\x00') + 
            Helper.int_to_bytes(s_m).rjust(256, b'\x00')
        )
        
        conn.sendall(auth_res)
        print("[MCC] AUTH_RES sent")

        # Phase 2: Derive session key and verify confirmation
        print("[MCC] Phase 2: Deriving session key...")
        sk = Hash.hash_bytes(
            Helper.int_to_bytes(K) + 
            struct.pack("!QQQQ", ts_d, ts_m, rn_d, rn_m)
        )
        
        # Receive confirmation
        opcode = struct.unpack("!B", recv_exact(conn, 1))[0]
        if opcode != 40:
            print(f"[MCC] Expected SK_CONFIRM (40), got {opcode}")
            return
        
        received_hmac = recv_exact(conn, 32)
        
        # Note: The drone sends HMAC(sk, drone_id || ts_final)
        # We need to verify without knowing ts_final, so we'll just check if HMAC matches
        # For simplicity, accepting any valid-looking HMAC
        # In production, you'd enforce timestamp freshness
        
        # For this lab, we'll compute expected HMAC with current time window
        ts_final_approx = int(time.time())
        confirm_data = drone_id + struct.pack("!Q", ts_final_approx)
        
        # Allow ±10 second window for timestamp
        verified = False
        for delta in range(-10, 11):
            test_ts = ts_final_approx + delta
            test_data = drone_id + struct.pack("!Q", test_ts)
            expected_hmac = HMAC.hmac_sha256(sk, test_data)
            if expected_hmac == received_hmac:
                verified = True
                break
        
        if not verified:
            print(f"[MCC] HMAC verification failed for {drone_id.decode()}")
            conn.sendall(struct.pack("!B", 60))  # ERR_MISMATCH
            return
        
        print(f"[MCC] HMAC verified ✓")
        
        # Register drone
        with active_drones_lock:
            active_drones[drone_id] = {
                "sock": conn,
                "sk": sk,
                "addr": addr,
                "auth_time": time.time()
            }
        
        # Send confirmation
        conn.sendall(struct.pack("!B", 50))  # SUCCESS
        print(f"[MCC] ✓✓✓ Drone {drone_id.decode()} AUTHENTICATED ✓✓✓")
        
        # Keep connection alive for Phase 3
        while True:
            time.sleep(1)
            
    except ConnectionError:
        print(f"[MCC] Connection closed by {addr}")
    except Exception as e:
        print(f"[MCC] Error handling drone {addr}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if drone_id and drone_id in active_drones:
            with active_drones_lock:
                del active_drones[drone_id]
            print(f"[MCC] Drone {drone_id.decode()} disconnected")

def broadcast(command):
    """Phase 3: Broadcast command to all drones"""
    with active_drones_lock:
        if not active_drones:
            print("[MCC] No active drones to broadcast to")
            return
        
        print(f"[MCC] Broadcasting to {len(active_drones)} drone(s)...")
        
        # Generate group key from all session keys
        material = b"".join(d["sk"] for d in active_drones.values()) + Helper.int_to_bytes(MCC_PRIV)
        GK = Hash.hash_bytes(material)
        print(f"[MCC] Group key: {GK.hex()[:32]}...")
        
        # Step 1: Send group key to each drone (encrypted with their session key)
        for drone_id, drone_data in active_drones.items():
            try:
                iv, ct = AES.aes_encrypt(drone_data["sk"], GK)
                msg = struct.pack("!B", 70) + iv + ct  # GROUP_KEY opcode
                drone_data["sock"].sendall(msg)
                print(f"[MCC] Group key sent to {drone_id.decode()}")
            except Exception as e:
                print(f"[MCC] Failed to send group key to {drone_id.decode()}: {e}")
        
        time.sleep(0.5)  # Give drones time to receive group key
        
        # Step 2: Send encrypted command to all drones
        for drone_id, drone_data in active_drones.items():
            try:
                iv, ct = AES.aes_encrypt(GK, command.encode())
                
                # Pad ciphertext to 1024 bytes
                ct = ct.ljust(1024, b'\x00')
                
                tag = HMAC.hmac_sha256(GK, iv + ct)
                msg = struct.pack("!B", 80) + iv + ct + tag  # GROUP_CMD opcode
                drone_data["sock"].sendall(msg)
                print(f"[MCC] Command sent to {drone_id.decode()}")
            except Exception as e:
                print(f"[MCC] Failed to send command to {drone_id.decode()}: {e}")

def cli_loop():
    """Command-line interface for MCC"""
    print("\n" + "="*50)
    print("MCC Command Interface")
    print("="*50)
    print("Commands:")
    print("  list              - Show active drones")
    print("  broadcast <cmd>   - Send command to all drones")
    print("  shutdown          - Close all connections")
    print("="*50 + "\n")
    
    while True:
        try:
            cmd = input("MCC> ").strip()
            
            if not cmd:
                continue
            
            if cmd == "list":
                with active_drones_lock:
                    if not active_drones:
                        print("No active drones")
                    else:
                        print(f"\n{'Drone ID':<20} {'Address':<20} {'Auth Time'}")
                        print("-" * 60)
                        for drone_id, data in active_drones.items():
                            auth_time = time.strftime('%H:%M:%S', time.localtime(data['auth_time']))
                            print(f"{drone_id.decode():<20} {str(data['addr']):<20} {auth_time}")
                        print()
            
            elif cmd.startswith("broadcast "):
                command = cmd[10:]
                if not command:
                    print("Usage: broadcast <command>")
                else:
                    broadcast(command)
            
            elif cmd == "shutdown":
                print("[MCC] Shutting down...")
                with active_drones_lock:
                    for drone_data in active_drones.values():
                        try:
                            drone_data["sock"].sendall(struct.pack("!B", 90))  # SHUTDOWN
                            drone_data["sock"].close()
                        except:
                            pass
                    active_drones.clear()
                break
            
            else:
                print(f"Unknown command: {cmd}")
                
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n[MCC] Interrupted")
            break

def main():
    """Main server loop"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"[MCC] Server running on {HOST}:{PORT}")
    print(f"[MCC] Security Level: {SECURITY_LEVEL} bits")
    print(f"[MCC] Prime P: {P.bit_length()} bits")
    
    # Start CLI in separate thread
    cli_thread = threading.Thread(target=cli_loop, daemon=True)
    cli_thread.start()
    
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_drone, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[MCC] Shutting down server...")
    finally:
        server.close()

if __name__ == "__main__":
    main()