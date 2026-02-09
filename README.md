# UAV Command and Control System

## Project Overview

Secure UAV (Unmanned Aerial Vehicle) Command and Control system implementing a custom cryptographic protocol with manual ElGamal encryption, digital signatures, and secure group broadcasting.

---

## Performance Benchmarks (2048-bit ElGamal Operations)

### Test Configuration
- **Prime Size:** 2048 bits (RFC 3526 MODP Group)
- **Iterations:** 50 per operation
- **Implementation:** Manual ElGamal using Python's built-in arbitrary precision integers

### Benchmark Results

```
[*] Starting Benchmark for 2048-bit ElGamal Operations
[*] Prime P size: 2048 bits
[*] Iterations per test: 50
=================================================================
OPERATION                 | AVG TIME (ms)   | NOTES               
-----------------------------------------------------------------
Key Generation            | 81.92 ms       | g^x mod p           
Encryption                | 101.08 ms      | 2 ModExps           
Decryption                | 28.97 ms       | 1 ModExp + Inv      
Digital Signing           | 30.66 ms       | 1 ModExp            
Signature Verification    | 59.99 ms       | 2 ModExps (Slow)    
=================================================================
```

### Performance Analysis

| Operation | Avg Time (ms) | Modular Exponentiations | Description |
|-----------|---------------|-------------------------|-------------|
| **Key Generation** | 81.92 | 1 | Compute y = g^x mod p |
| **Encryption** | 101.08 | 2 | Compute c1 = g^k, c2 = m·y^k |
| **Decryption** | 28.97 | 1 + Inverse | Compute s = c1^x, m = c2·s^(-1) |
| **Digital Signing** | 30.66 | 1 | Compute r = g^k mod p |
| **Signature Verification** | 59.99 | 2 | Compute g^H(m) and y^r·r^s |

**Key Observations:**
- **Modular Exponentiation** with 2048-bit primes averages **~30-82ms** per operation
- **Encryption** takes longer (101ms) due to two exponentiations (c1 and c2 computation)
- **Decryption** is faster (29ms) with only one exponentiation plus modular inverse
- **Signature Verification** (60ms) requires two exponentiations, making it the slowest per-operation task
- **Total authentication time** (Phase 0-2) is approximately **300-400ms per drone**

**Implementation Details:**
- Square-and-multiply algorithm for fast modular exponentiation
- Iterative Extended Euclidean Algorithm for modular inverse
- No external libraries (GMP/OpenSSL) used for arithmetic operations
- Suitable for real-time UAV authentication scenarios

---

## How to Run

### 1. Setup Environment

```bash
# Activate virtual environment
source .crypto2/bin/activate

# Install dependencies
pip install pycryptodome
```

### 2. Run Performance Benchmark

```bash
python3 benchmark.py
```

### 3. Start MCC Server

**Terminal 1:**
```bash
python3 mcc.py
```

### 4. Connect Drones

**Terminal 2:**
```bash
python3 drone.py DRONE-001
```

**Terminal 3:**
```bash
python3 drone.py DRONE-002
```

**Terminal 4:**
```bash
python3 drone.py DRONE-003
```

### 5. MCC Commands

```
MCC> list                          # Show connected drones
MCC> broadcast RETURN_TO_BASE      # Send encrypted command to all drones
MCC> shutdown                      # Close all connections
```

---

## Running Security Tests

```bash
python3 attacks.py
```

**Available Attacks:**
1. **MitM Parameter Tampering** - Intercepts and modifies Phase 0 prime
2. **Replay Attack** - Captures and replays authentication packets
3. **Unauthorized Access** - Attempts connection with fake credentials

**Expected Results:**
- Replay attacks are blocked (timestamp validation)
- Parameter tampering detected (signature verification fails)
- Unauthorized access rejected (invalid signatures)

---

## Running Unit Tests

```bash
python3 test.py
```

Tests verify:
- Key generation correctness (y = g^x mod p)
- Encryption/Decryption integrity (m' = m)
- Digital signature validity
- Signature rejection on tampered data

---

## File Structure

```
├── crypto_utils.py    # Manual ElGamal, modular math, AES/HMAC
├── mcc.py             # Mission Control Center server
├── drone.py           # Drone client
├── attacks.py         # Security attack demonstrations
├── benchmark.py       # Performance measurement
├── test.py            # Unit tests
├── SECURITY.md        # Freshness & Forward Secrecy analysis
└── README.md          # This file
```

---

## Security Features

**Freshness (Replay Protection):**
- Timestamp validation (10-second window)
- Random nonces in every session
- Session key includes timestamps and nonces

**Forward Secrecy:**
- Ephemeral session keys (new random K per session)
- Long-term keys never used directly for encryption
- Past sessions remain secure if private key compromised

See [SECURITY.md](SECURITY.md) for detailed analysis.

---

## Requirements

- Python 3.7+
- pycryptodome (for AES-256-CBC)
- All ElGamal operations manually implemented

---

## Authors

**Course:** System and Network Security (CS8.403)  
**Institution:** IIIT Hyderabad  
**Assignment:** Lab 2 - Secure UAV Command and Control System