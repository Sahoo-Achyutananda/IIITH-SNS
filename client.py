# client.py
# Client implementation with complete two-phase threshold signature protocol

import socket
import json
import os
import uuid
import time
from crypto_utils import ThresholdSchnorr, AESCipher, Ticket

class Client:
    """Client that interacts with AS, TGS, and Service servers"""
    
    def __init__(self, client_id, password):
        self.client_id = client_id
        self.password = password
        self.tgt = None
        self.session_key = None
        
        # Load Schnorr parameters
        with open('params.json', 'r') as f:
            self.params = json.load(f)
        p, q, g, y = self.params['p'], self.params['q'], self.params['g'], self.params['y']
        self.schnorr = ThresholdSchnorr(p, q, g)
        self.y = y
    
    def request_from_authorities(self, ports, request_data, phase_name):
        """Send request to multiple authorities and collect responses"""
        responses = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(('localhost', port))
                sock.send(json.dumps(request_data).encode())
                response = json.loads(sock.recv(4096).decode())
                sock.close()
                
                if response.get('status') == 'error':
                    print(f"  {phase_name} - Port {port} error: {response.get('message')}")
                else:
                    responses.append(response)
            except Exception as e:
                print(f"  {phase_name} - Port {port} failed: {e}")
        
        return responses
    
    def request_tgt(self, service_id='TGS'):
        """
        Request TGT from AS cluster using two-phase threshold protocol
        Returns: True if successful, False otherwise
        """
        print(f"\n[Client {self.client_id}] Requesting TGT...")
        
        as_ports = [8001, 8002, 8003]
        session_id = str(uuid.uuid4())
        ticket_issue_timestamp = int(time.time())
        ticket_session_key = os.urandom(32)
        
        # Phase 1: Collect R_i values from AS nodes
        print("  Phase 1: Collecting R_i commitments from AS nodes...")
        phase1_request = {
            'type': 'phase1',
            'client_id': self.client_id,
            'password': self.password,
            'service_id': service_id,
            'session_id': session_id,
            'ticket_issue_timestamp': ticket_issue_timestamp,
            'ticket_session_key': ticket_session_key.hex()
        }
        
        phase1_responses = self.request_from_authorities(as_ports, phase1_request, "AS Phase 1")
        
        if len(phase1_responses) < 2:
            print(f"  Authentication could not proceed because fewer than 2 AS nodes responded ({len(phase1_responses)} received).")
            return False
        
        # Use first 2 responses for 2-of-3 threshold
        selected_responses = phase1_responses[:2]
        R_combined = 1
        for resp in selected_responses:
            R_combined = (R_combined * resp['R_i']) % self.schnorr.p
        
        print(f"  Received {len(phase1_responses)} responses. Partial signatures from AS{selected_responses[0]['node_id']} and AS{selected_responses[1]['node_id']} will be combined.")
        print(f"  Combined R = {R_combined}")
        
        # Get ticket info and session key from first response
        ticket_info = selected_responses[0]['ticket_info']
        encrypted_key = bytes.fromhex(selected_responses[0]['encrypted_session_key'])
        
        # Decrypt session key
        cipher = AESCipher(self.password.encode().ljust(32)[:32])
        self.session_key = cipher.decrypt(encrypted_key)
        
        # Phase 2: Collect s_i values
        print("  Phase 2: Collecting partial signatures s_i...")
        phase2_request = {
            'type': 'phase2',
            'session_id': session_id,
            'R_combined': R_combined,
            'participants': [resp['node_id'] for resp in selected_responses]
        }
        
        # Only request from authorities we used in phase 1
        selected_ports = [as_ports[resp['node_id']-1] for resp in selected_responses]
        phase2_responses = self.request_from_authorities(selected_ports, phase2_request, "AS Phase 2")
        
        if len(phase2_responses) < 2:
            print(f"  Signature generation could not be completed because only {len(phase2_responses)} partial signatures were obtained.")
            return False
        
        # Combine partial signatures
        s_combined = 0
        for resp in phase2_responses:
            s_combined = (s_combined + resp['s_i']) % self.schnorr.q
        
        print(f"  Combined signature component s = {s_combined}")
        
        # Create TGT with signature
        self.tgt = Ticket.from_dict(ticket_info)
        self.tgt.set_signature((R_combined, s_combined), 
                               [resp['node_id'] for resp in selected_responses])
        
        # Verify signature
        payload = self.tgt.get_payload()
        if self.schnorr.verify(payload, (R_combined, s_combined), self.y):
            print(f"  The TGT signature was verified successfully.")
            return True
        else:
            print(f"  The TGT signature verification failed.")
            return False
    
    def request_service_ticket(self, service_id):
        """
        Request service ticket from TGS cluster
        Returns: service ticket if successful, None otherwise
        """
        if not self.tgt:
            print("  No TGT is available. A TGT must be obtained before requesting a service ticket.")
            return None
        
        print(f"\n[Client {self.client_id}] Requesting service ticket for {service_id}...")
        
        tgs_ports = [9001, 9002, 9003]
        session_id = str(uuid.uuid4())
        ticket_issue_timestamp = int(time.time())
        ticket_session_key = os.urandom(32)
        
        # Phase 1: Collect R_i values
        print("  Phase 1: Collecting R_i from TGS nodes...")
        phase1_request = {
            'type': 'phase1',
            'client_id': self.client_id,
            'service_id': service_id,
            'tgt': self.tgt.to_dict(),
            'session_id': session_id,
            'ticket_issue_timestamp': ticket_issue_timestamp,
            'ticket_session_key': ticket_session_key.hex()
        }
        
        phase1_responses = self.request_from_authorities(tgs_ports, phase1_request, "TGS Phase 1")
        
        if len(phase1_responses) < 2:
            print(f"  Service ticket issuance could not proceed because fewer than 2 TGS nodes responded ({len(phase1_responses)} received).")
            return None
        
        # Use first 2 responses
        selected_responses = phase1_responses[:2]
        R_combined = 1
        for resp in selected_responses:
            R_combined = (R_combined * resp['R_i']) % self.schnorr.p
        
        print(f"  Combined commitment R = {R_combined}")
        
        ticket_info = selected_responses[0]['ticket_info']
        service_session_key = bytes.fromhex(selected_responses[0]['service_session_key'])
        
        # Phase 2: Collect s_i values
        print("  Phase 2: Collecting s_i from TGS nodes...")
        phase2_request = {
            'type': 'phase2',
            'session_id': session_id,
            'R_combined': R_combined,
            'participants': [resp['node_id'] for resp in selected_responses]
        }
        
        selected_ports = [tgs_ports[resp['node_id']-1] for resp in selected_responses]
        phase2_responses = self.request_from_authorities(selected_ports, phase2_request, "TGS Phase 2")
        
        if len(phase2_responses) < 2:
            print(f"  Service ticket signature generation could not be completed because insufficient partial signatures were received.")
            return None
        
        # Combine signatures
        s_combined = 0
        for resp in phase2_responses:
            s_combined = (s_combined + resp['s_i']) % self.schnorr.q
        
        # Create service ticket
        service_ticket = Ticket.from_dict(ticket_info)
        service_ticket.set_signature((R_combined, s_combined),
                                    [resp['node_id'] for resp in selected_responses])
        
        # Verify
        payload = service_ticket.get_payload()
        if self.schnorr.verify(payload, (R_combined, s_combined), self.y):
            print(f"  The service ticket was verified successfully.")
            return service_ticket
        else:
            print(f"  The service ticket verification failed.")
            return None
    
    def access_service(self, service_port, service_ticket):
        """Access service with service ticket"""
        print(f"\n[Client {self.client_id}] Accessing service...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('localhost', service_port))
            
            request = {
                'client_id': self.client_id,
                'ticket': service_ticket.to_dict()
            }
            
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(4096).decode())
            sock.close()
            
            if response.get('status') == 'authenticated':
                print(f"  Service access was granted.")
                return True
            else:
                print(f"  Service access denied: {response.get('message', 'Unknown')}")
                return False
        except Exception as e:
            print(f"  Service access failed due to the following error: {e}")
            return False


# Entry point for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python3 client.py <client_id> <password> <service_id>")
        print("Example: python3 client.py alice alice123 file_service")
        sys.exit(1)
    
    client_id = sys.argv[1]
    password = sys.argv[2]
    service_id = sys.argv[3]
    
    client = Client(client_id, password)
    
    # Get TGT
    if client.request_tgt():
        # Get service ticket
        service_ticket = client.request_service_ticket(service_id)
        
        if service_ticket:
            # Access service
            client.access_service(10001, service_ticket)