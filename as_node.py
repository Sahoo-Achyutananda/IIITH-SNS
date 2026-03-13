# as_node.py
# Authentication Server (AS) node implementing threshold signatures
# Handles Phase 1 (R_i generation) and Phase 2 (s_i computation)

import socket
import json
import threading
import os
from crypto_utils import ThresholdSchnorr, AESCipher, Ticket, PartialSignature

class ASNode:
    """Authentication Server node with threshold signing capability"""
    
    def __init__(self, node_id, port, share_file, key_version=1):
        # Load Schnorr parameters
        with open('params.json', 'r') as f:
            self.params = json.load(f)
        p, q, g, y = self.params['p'], self.params['q'], self.params['g'], self.params['y']
        self.schnorr = ThresholdSchnorr(p, q, g)
        self.y = y

        # Load private key share
        with open(share_file, 'r') as f:
            self.x_i = json.load(f)['x_i']

        self.node_id = node_id
        self.port = port
        self.key_version = key_version
        
        # Store client credentials (simplified - in real system use password hashing)
        self.user_db = {
            'user1': 'password1',
            'user2': 'password2',
            'alice': 'alice123',
            'bob': 'bob123'
        }
        
        # Storage for nonces during two-phase signing
        self.pending_nonces = {}  # {session_id: (k_i, ticket_payload)}
        
        # Setup server socket
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('localhost', port))
        self.server.listen(5)
        print(f"AS{node_id} listening on port {port} with key version {key_version}")

    def lagrange_coefficient(self, signer_id, participants):
        """Compute Lagrange coefficient at x=0 for signer_id over given participants"""
        q = self.schnorr.q
        numerator = 1
        denominator = 1

        for participant_id in participants:
            if participant_id == signer_id:
                continue
            numerator = (numerator * participant_id) % q
            denominator = (denominator * (participant_id - signer_id)) % q

        return (numerator * pow(denominator % q, -1, q)) % q

    def verify_client(self, client_id, password):
        """Verify client credentials"""
        if client_id in self.user_db:
            return self.user_db[client_id] == password
        return False

    def handle_phase1_request(self, request):
        """
        Phase 1: Generate R_i (commitment)
        Client sends authentication request
        AS responds with R_i and session key
        """
        client_id = request['client_id']
        password = request.get('password', '')
        service_id = request['service_id']
        session_id = request['session_id']
        ticket_issue_timestamp = request.get('ticket_issue_timestamp')
        ticket_session_key = request.get('ticket_session_key')

        # Verify client credentials
        if not self.verify_client(client_id, password):
            return {
                'status': 'error',
                'message': 'Authentication failed'
            }

        print(f"AS{self.node_id}: Phase 1 - Client {client_id} authenticated")

        # Use the same session key across participating AS nodes for this request
        session_key = bytes.fromhex(ticket_session_key) if ticket_session_key else os.urandom(32)

        # Create ticket structure
        ticket = Ticket(client_id, service_id, session_key, 
                       lifetime=3600, key_version=self.key_version)
        if ticket_issue_timestamp is not None:
            ticket.issue_timestamp = int(ticket_issue_timestamp)
        ticket_payload = ticket.get_payload()

        # Generate nonce k_i and commitment R_i
        k_i = self.schnorr.q - self.node_id  # Simplified for demo
        R_i = self.schnorr.mod_arith.mod_pow(self.schnorr.g, k_i, self.schnorr.p)

        # Store nonce for Phase 2
        self.pending_nonces[session_id] = (k_i, ticket_payload)

        # Encrypt session key for client
        cipher = AESCipher(password.encode().ljust(32)[:32])  # Simplified key derivation
        encrypted_session_key = cipher.encrypt(session_key)

        response = {
            'status': 'phase1_complete',
            'node_id': self.node_id,
            'R_i': R_i,
            'encrypted_session_key': encrypted_session_key.hex(),
            'ticket_info': ticket.to_dict()
        }
        
        return response

    def handle_phase2_request(self, request):
        """
        Phase 2: Compute s_i after receiving all R values
        Client sends combined R and list of participating authorities
        AS computes partial signature s_i
        """
        session_id = request['session_id']
        R_combined = request['R_combined']
        participants = request['participants']

        # Retrieve stored nonce
        if session_id not in self.pending_nonces:
            return {
                'status': 'error',
                'message': 'No pending session'
            }

        k_i, ticket_payload = self.pending_nonces[session_id]

        # Compute challenge e = H(payload || R_combined)
        e = self.schnorr.hash_message(ticket_payload, R_combined)

        if self.node_id not in participants:
            return {
                'status': 'error',
                'message': 'Node not selected as participant'
            }

        lambda_i = self.lagrange_coefficient(self.node_id, participants)

        # Compute threshold partial signature s_i = k_i + lambda_i * e * x_i mod q
        s_i = (k_i + (lambda_i * e * self.x_i)) % self.schnorr.q

        print(f"AS{self.node_id}: Phase 2 - Computed s_i = {s_i}")

        # Clean up
        del self.pending_nonces[session_id]

        response = {
            'status': 'phase2_complete',
            'node_id': self.node_id,
            's_i': s_i
        }

        return response

    def handle_request(self, conn):
        """Route requests to appropriate handler"""
        try:
            data = conn.recv(4096).decode()
            request = json.loads(data)
            
            request_type = request.get('type', 'phase1')
            
            if request_type == 'phase1':
                response = self.handle_phase1_request(request)
            elif request_type == 'phase2':
                response = self.handle_phase2_request(request)
            else:
                response = {'status': 'error', 'message': 'Unknown request type'}
            
            conn.send(json.dumps(response).encode())
        except Exception as e:
            error_response = {'status': 'error', 'message': str(e)}
            conn.send(json.dumps(error_response).encode())
        finally:
            conn.close()

    def run(self):
        """Main server loop"""
        print(f"AS{self.node_id} ready to accept connections")
        while True:
            conn, addr = self.server.accept()
            threading.Thread(target=self.handle_request, args=(conn,), daemon=True).start()


# Entry point
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python3 as_node.py <node_id> <port> <share_file> [key_version]")
        sys.exit(1)
    
    node_id = int(sys.argv[1])
    port = int(sys.argv[2])
    share_file = sys.argv[3]
    key_version = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    
    as_node = ASNode(node_id, port, share_file, key_version)
    as_node.run()