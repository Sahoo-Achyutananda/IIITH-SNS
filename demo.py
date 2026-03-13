#!/usr/bin/env python3
# demo.py
# Comprehensive demonstration of the Kerberos threshold signature system

import subprocess
import time
import signal
import sys
import os

class SystemDemo:
    """Orchestrates complete system demonstration"""
    
    def __init__(self):
        self.processes = []
        self.as_ports = [8001, 8002, 8003]
        self.tgs_ports = [9001, 9002, 9003]
        self.service_port = 10001
        
    def cleanup(self, signum=None, frame=None):
        """Clean up running processes"""
        print("\n\n[Demo] Cleaning up processes...")
        for p in self.processes:
            try:
                p.terminate()
                p.wait(timeout=2)
            except:
                try:
                    p.kill()
                except:
                    pass
        print("[Demo] Cleanup complete")
        sys.exit(0)
    
    def start_as_nodes(self):
        """Start all AS nodes"""
        print("\n" + "=" * 70)
        print("Starting Authentication Servers (AS1, AS2, AS3)")
        print("=" * 70)
        
        for i in range(1, 4):
            port = self.as_ports[i-1]
            share_file = f'share_{i}.json'
            cmd = ['python3', 'as_node.py', str(i), str(port), share_file]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(p)
            print(f"  Started AS{i} on port {port}")
        
        time.sleep(1)  # Wait for servers to start
        print("  All AS nodes have been started successfully.\n")
    
    def start_tgs_nodes(self):
        """Start all TGS nodes"""
        print("=" * 70)
        print("Starting Ticket Granting Servers (TGS1, TGS2, TGS3)")
        print("=" * 70)
        
        for i in range(1, 4):
            port = self.tgs_ports[i-1]
            share_file = f'share_{i}.json'
            cmd = ['python3', 'tgs_node.py', str(i), str(port), share_file]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(p)
            print(f"  Started TGS{i} on port {port}")
        
        time.sleep(1)
        print("  All TGS nodes have been started successfully.\n")
    
    def start_service(self):
        """Start service server"""
        print("=" * 70)
        print("Starting Service Server")
        print("=" * 70)
        
        cmd = ['python3', 'service_server.py', 'file_service', str(self.service_port)]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(p)
        print(f"  Started service 'file_service' on port {self.service_port}")
        
        time.sleep(1)
        print("  The service server has been started successfully.\n")
    
    def run_client_test(self, client_id, password, service_id):
        """Run client authentication test"""
        print("=" * 70)
        print(f"Client Test: {client_id} accessing {service_id}")
        print("=" * 70)
        
        cmd = ['python3', 'client.py', client_id, password, service_id]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
        
        return result.returncode == 0
    
    def run_attack_demos(self):
        """Run attack demonstrations"""
        print("\n" + "=" * 70)
        print("Running Attack Scenario Demonstrations")
        print("=" * 70)
        
        cmd = ['python3', 'attacks.py']
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
    
    def run_full_demo(self):
        """Run complete system demonstration"""
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)
        
        print("\n" + "=" * 70)
        print("KERBEROS THRESHOLD SIGNATURE SYSTEM - FULL DEMONSTRATION")
        print("=" * 70)
        print("\nThis demo will:")
        print("  1. Start all authentication authorities (AS1, AS2, AS3)")
        print("  2. Start all ticket granting authorities (TGS1, TGS2, TGS3)")
        print("  3. Start a service server")
        print("  4. Run client authentication tests")
        print("  5. Demonstrate attack scenarios")
        print("\nPress Ctrl+C anytime to stop\n")
        
        input("Press Enter to begin...")
        
        try:
            # Check if keys exist
            if not os.path.exists('params.json'):
                print("\n[Demo] Generating cryptographic keys...")
                subprocess.run(['python3', 'master_keygen.py'], check=True)
                print("\n")
            
            # Start all servers
            self.start_as_nodes()
            self.start_tgs_nodes()
            self.start_service()
            
            print("\n" + "=" * 70)
            print("All servers are running. Starting client tests...")
            print("=" * 70)
            
            time.sleep(2)
            
            # Test 1: Alice accesses file_service
            success1 = self.run_client_test('alice', 'alice123', 'file_service')
            
            time.sleep(2)
            
            # Test 2: Bob accesses file_service
            success2 = self.run_client_test('bob', 'bob123', 'file_service')
            
            time.sleep(2)
            
            # Run attack demonstrations
            self.run_attack_demos()
            
            # Summary
            print("\n\n" + "=" * 70)
            print("DEMONSTRATION SUMMARY")
            print("=" * 70)
            print(f"  Alice authentication result: {'successful' if success1 else 'failed'}")
            print(f"  Bob authentication result: {'successful' if success2 else 'failed'}")
            print(f"  Attack demonstrations: completed")
            print("=" * 70)
            
            print("\n[Demo] Servers will keep running. Press Ctrl+C to stop.\n")
            
            # Keep running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            
        except Exception as e:
            print(f"\n[Demo] Error: {e}")
        finally:
            self.cleanup()


def main():
    demo = SystemDemo()
    demo.run_full_demo()


if __name__ == "__main__":
    main()
