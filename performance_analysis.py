#!/usr/bin/env python3
# performance_analysis.py
# Performance measurement and analysis for threshold signature system

import time
import statistics
from crypto_utils import ThresholdSchnorr, generate_schnorr_params, AESCipher, Ticket
import os

class PerformanceAnalyzer:
    """Measure and analyze system performance"""
    
    def __init__(self):
        # Generate test parameters
        self.p, self.q, self.g = generate_schnorr_params()
        self.schnorr = ThresholdSchnorr(self.p, self.q, self.g)
        self.x, self.y = self.schnorr.generate_keypair()
        self.shares = self.schnorr.generate_shares(self.x, 3)
        
    def time_operation(self, func, iterations=100):
        """Time an operation over multiple iterations"""
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms
        
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'min': min(times),
            'max': max(times)
        }
    
    def test_modular_exponentiation(self):
        """Measure modular exponentiation performance"""
        def op():
            self.schnorr.mod_arith.mod_pow(self.g, self.x, self.p)
        
        return self.time_operation(op)
    
    def test_signature_generation(self):
        """Measure full signature generation"""
        message = "test message"
        
        def op():
            self.schnorr.sign(message, self.x)
        
        return self.time_operation(op)
    
    def test_signature_verification(self):
        """Measure signature verification"""
        message = "test message"
        sig = self.schnorr.sign(message, self.x)
        
        def op():
            self.schnorr.verify(message, sig, self.y)
        
        return self.time_operation(op)
    
    def test_partial_signature(self):
        """Measure partial signature generation"""
        message = "test message"
        
        def op():
            self.schnorr.partial_sign(message, self.shares[0])
        
        return self.time_operation(op)
    
    def test_threshold_signing(self):
        """Measure complete 2-of-3 threshold signing"""
        message = "test message"
        
        def op():
            # Phase 1: Generate R values
            k1 = self.q - 1
            k2 = self.q - 2
            R1 = self.schnorr.mod_arith.mod_pow(self.g, k1, self.p)
            R2 = self.schnorr.mod_arith.mod_pow(self.g, k2, self.p)
            R_combined = (R1 * R2) % self.p
            
            # Phase 2: Compute s values
            e = self.schnorr.hash_message(message, R_combined)
            s1 = (k1 + e * self.shares[0]) % self.q
            s2 = (k2 + e * self.shares[1]) % self.q
            s_combined = (s1 + s2) % self.q
        
        return self.time_operation(op)
    
    def test_aes_encryption(self):
        """Measure AES encryption"""
        key = os.urandom(32)
        cipher = AESCipher(key)
        plaintext = b"This is a test message for encryption performance"
        
        def op():
            cipher.encrypt(plaintext)
        
        return self.time_operation(op)
    
    def test_aes_decryption(self):
        """Measure AES decryption"""
        key = os.urandom(32)
        cipher = AESCipher(key)
        plaintext = b"This is a test message for encryption performance"
        ciphertext = cipher.encrypt(plaintext)
        
        def op():
            cipher.decrypt(ciphertext)
        
        return self.time_operation(op)
    
    def test_ticket_creation(self):
        """Measure ticket creation and signing"""
        def op():
            ticket = Ticket("user1", "service1", os.urandom(32))
            payload = ticket.get_payload()
            sig = self.schnorr.sign(payload, self.x)
            ticket.set_signature(sig, [1, 2])
        
        return self.time_operation(op)
    
    def print_results(self, name, results):
        """Print performance results"""
        print(f"\n{name}")
        print(f"  Mean:   {results['mean']:.4f} ms")
        print(f"  Median: {results['median']:.4f} ms")
        print(f"  StdDev: {results['stdev']:.4f} ms")
        print(f"  Min:    {results['min']:.4f} ms")
        print(f"  Max:    {results['max']:.4f} ms")
    
    def run_analysis(self):
        """Run complete performance analysis"""
        print("=" * 70)
        print("PERFORMANCE ANALYSIS")
        print("=" * 70)
        print(f"\nTest Configuration:")
        print(f"  Schnorr parameters: p={self.p}, q={self.q}, g={self.g}")
        print(f"  Iterations per test: 100")
        print(f"  Time unit: milliseconds (ms)")
        
        print("\n" + "-" * 70)
        print("CRYPTOGRAPHIC OPERATIONS")
        print("-" * 70)
        
        # Modular exponentiation
        results = self.test_modular_exponentiation()
        self.print_results("Modular Exponentiation (g^x mod p)", results)
        
        # Signature operations
        results = self.test_signature_generation()
        self.print_results("Full Signature Generation", results)
        
        results = self.test_signature_verification()
        self.print_results("Signature Verification", results)
        
        results = self.test_partial_signature()
        self.print_results("Partial Signature Generation", results)
        
        results = self.test_threshold_signing()
        self.print_results("Complete Threshold Signing (2-of-3)", results)
        
        print("\n" + "-" * 70)
        print("SYMMETRIC ENCRYPTION")
        print("-" * 70)
        
        results = self.test_aes_encryption()
        self.print_results("AES-256-CBC Encryption", results)
        
        results = self.test_aes_decryption()
        self.print_results("AES-256-CBC Decryption", results)
        
        print("\n" + "-" * 70)
        print("TICKET OPERATIONS")
        print("-" * 70)
        
        results = self.test_ticket_creation()
        self.print_results("Ticket Creation + Signing", results)
        
        # Analysis summary
        print("\n" + "=" * 70)
        print("OVERHEAD ANALYSIS")
        print("=" * 70)
        
        single_sig = self.test_signature_generation()['mean']
        threshold_sig = self.test_threshold_signing()['mean']
        overhead = threshold_sig - single_sig
        overhead_pct = (overhead / single_sig) * 100
        
        print(f"\nSingle Authority Signature:   {single_sig:.4f} ms")
        print(f"Threshold (2-of-3) Signature: {threshold_sig:.4f} ms")
        print(f"Overhead:                     {overhead:.4f} ms ({overhead_pct:.1f}%)")
        print(f"\nConclusion:")
        print(f"  The threshold scheme introduces ~{overhead_pct:.0f}% performance overhead")
        print(f"  This is acceptable for the security benefit of distributed trust")
        
        # Network considerations
        print("\n" + "=" * 70)
        print("NETWORK OVERHEAD")
        print("=" * 70)
        print(f"\nSingle Authority System:")
        print(f"  - Client → AS: 1 round trip")
        print(f"  - Total: 1 network round trip")
        print(f"\nThreshold System (2-of-3):")
        print(f"  - Client → AS (Phase 1): 3 parallel requests")
        print(f"  - Client → AS (Phase 2): 2 parallel requests")
        print(f"  - Total: 2 network round trips (with parallelization)")
        print(f"\nNote: Threshold system requires 2x round trips but provides:")
        print(f"  - Resilience against compromise of a single authority")
        print(f"  - Availability despite failure of one authority")
        print(f"  - A distributed trust model")
        
        print("\n" + "=" * 70)


def main():
    analyzer = PerformanceAnalyzer()
    analyzer.run_analysis()


if __name__ == "__main__":
    main()
