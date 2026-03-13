# service_server.py
# Service Server with proper ticket verification

import socket
import json
import threading
from crypto_utils import ThresholdSchnorr, Ticket

class ServiceServer:
    """Service server that verifies threshold-signed tickets"""
    
    def __init__(self, service_id, port, key_version=1):
        self.service_id = service_id
        self.port = port
        self.key_version = key_version
        
        # Load Schnorr parameters
        with open('params.json', 'r') as f:
            self.params = json.load(f)
        p, q, g, y = self.params['p'], self.params['q'], self.params['g'], self.params['y']
        self.schnorr = ThresholdSchnorr(p, q, g)
        self.y = y
        
        # Setup server socket
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('localhost', port))
        self.server.listen(5)
        print(f"Service '{service_id}' listening on port {port}")

    def verify_ticket(self, ticket_dict):
        """
        Verify service ticket
        Checks: signature validity, expiration, key version, service ID
        """
        try:
            ticket = Ticket.from_dict(ticket_dict)
            
            # Check if ticket is for this service
            if ticket.service_id != self.service_id:
                print(f"  Service mismatch: expected {self.service_id}, got {ticket.service_id}")
                return False, "Service ID mismatch"
            
            # Check expiration
            if ticket.is_expired():
                print(f"  Ticket expired")
                return False, "Ticket expired"
            
            # Check key version (reject outdated keys)
            if ticket.key_version != self.key_version:
                print(f"  Key version mismatch: expected {self.key_version}, got {ticket.key_version}")
                return False, "Outdated key version"
            
            # Verify threshold signature
            payload = ticket.get_payload()
            if not ticket.signature:
                print(f"  No signature present")
                return False, "Missing signature"
            
            if self.schnorr.verify(payload, ticket.signature, self.y):
                print(f"  The ticket signature is valid.")
                return True, "Valid"
            else:
                print(f"  The ticket signature is invalid.")
                return False, "Invalid signature"
                
        except Exception as e:
            print(f"  Verification error: {e}")
            return False, f"Verification error: {str(e)}"

    def handle_request(self, conn):
        """Handle client service access request"""
        try:
            data = conn.recv(4096).decode()
            request = json.loads(data)
            client_id = request['client_id']
            ticket_dict = request['ticket']
            
            print(f"\n[Service {self.service_id}] Request from {client_id}")
            
            # Verify ticket
            valid, message = self.verify_ticket(ticket_dict)
            
            if valid:
                print(f"  Access has been granted to {client_id}.")
                response = {
                    'status': 'authenticated',
                    'message': 'Access granted',
                    'service': self.service_id
                }
            else:
                print(f"  Access has been denied to {client_id}: {message}")
                response = {
                    'status': 'denied',
                    'message': message
                }
            
            conn.send(json.dumps(response).encode())
        except Exception as e:
            error_response = {
                'status': 'error',
                'message': f"Server error: {str(e)}"
            }
            conn.send(json.dumps(error_response).encode())
        finally:
            conn.close()

    def run(self):
        """Main server loop"""
        print(f"Service {self.service_id} ready to accept connections\n")
        while True:
            conn, addr = self.server.accept()
            threading.Thread(target=self.handle_request, args=(conn,), daemon=True).start()


# Entry point
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python3 service_server.py <service_id> <port> [key_version]")
        print("Example: python3 service_server.py file_service 10001")
        sys.exit(1)
    
    service_id = sys.argv[1]
    port = int(sys.argv[2])
    key_version = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    
    service = ServiceServer(service_id, port, key_version)
    service.run()