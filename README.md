# Kerberos with Threshold Signatures Lab

Advanced authentication system implementing Kerberos-inspired protocol with 2-of-3 threshold Schnorr signatures for compromise resilience.

## 📋 Overview

This project implements a distributed authentication system where:
- **No single authority** can issue valid tickets alone
- System remains secure if **1 authority is compromised**
- **2-of-3 threshold** signature scheme ensures distributed trust
- Tickets contain cryptographic proofs requiring cooperation

## 🏗️ Architecture

```
Client → AS Cluster (AS1, AS2, AS3) → TGT with threshold signature
       → TGS Cluster (TGS1, TGS2, TGS3) → Service Ticket
       → Service Server → Access Granted
```

### Components
- **3 Authentication Servers (AS)**: Issue TGTs via threshold signatures
- **3 Ticket Granting Servers (TGS)**: Issue service tickets
- **Service Servers**: Verify tickets and grant access
- **Clients**: Request tickets and access services

## 📦 Files

### Core Implementation
- `crypto_utils.py` - Cryptographic primitives, threshold logic, and ticket structures
- `as_node.py` - Authentication Server implementation
- `tgs_node.py` - Ticket Granting Server implementation
- `service_server.py` - Service server with verification
- `client.py` - Client with two-phase protocol

### Utilities
- `master_keygen.py` - Key generation, distribution, and key rotation
- `attacks.py` - Attack scenario demonstrations
- `performance_analysis.py` - Performance measurements
- `demo.py` - Automated system demonstration
- `test_crypto.py` - Cryptographic unit tests

### Documentation
- `README.md` - This file
- `SECURITY.md` - Security analysis

## 🚀 Quick Start

### Prerequisites
```bash
python3 -m pip install cryptography
```

### Method 1: Automated Demo
```bash
python3 demo.py
```
This starts all servers and runs client tests automatically.

### Method 2: Manual Setup

#### Step 1: Generate Keys
```bash
python3 master_keygen.py
```
Generates:
- `params.json` - Public parameters (p, q, g, y)
- `share_1.json`, `share_2.json`, `share_3.json` - Private key shares

#### Step 2: Start Authentication Servers
```bash
# Terminal 1
python3 as_node.py 1 8001 share_1.json

# Terminal 2
python3 as_node.py 2 8002 share_2.json

# Terminal 3
python3 as_node.py 3 8003 share_3.json
```

#### Step 3: Start Ticket Granting Servers
```bash
# Terminal 4
python3 tgs_node.py 1 9001 share_1.json

# Terminal 5
python3 tgs_node.py 2 9002 share_2.json

# Terminal 6
python3 tgs_node.py 3 9003 share_3.json
```

#### Step 4: Start Service Server
```bash
# Terminal 7
python3 service_server.py file_service 10001
```

#### Step 5: Run Client
```bash
# Terminal 8
python3 client.py alice alice123 file_service
```

## 🔐 Protocol Flow

### Phase 1: TGT Acquisition

1. **Client → AS Cluster (Phase 1)**
   - Client sends credentials to all 3 AS nodes
   - Each AS verifies and generates R_i (commitment)
   - Client receives R_1, R_2, R_3 and encrypted session keys

2. **Client → AS Cluster (Phase 2)**
   - Client combines R values: R = R_1 * R_2 mod p
   - Client requests s_i from selected AS nodes
   - Each AS computes s_i = k_i + e*x_i mod q
   - Client combines: s = s_1 + s_2 mod q

3. **Client Verifies TGT**
   - Checks: g^s ≡ R * y^e mod p
   - If valid, TGT is authentic

### Phase 2: Service Ticket Acquisition
Same threshold protocol with TGS cluster, presents TGT first.

### Phase 3: Service Access
Client presents service ticket to service server for verification.

## 🧪 Testing

### Run All Tests
```bash
# Cryptographic primitives
python3 test_crypto.py

# Attack demonstrations
python3 attacks.py

# Performance analysis
python3 performance_analysis.py
```

### Default User Credentials
- alice / alice123
- bob / bob123
- user1 / password1
- user2 / password2

## 🔄 Key Rotation

```bash
python3 master_keygen.py --rotate
```

This will:
1. Backup current keys
2. Generate new master key and shares
3. Update version number
4. Require restart of all authorities

⚠️ All existing tickets become invalid after rotation.

## 🛡️ Security Features

### Threshold Cryptography
- **2-of-3 threshold**: Any 2 authorities can sign, 1 cannot
- **Additive secret sharing**: x = x_1 + x_2 + x_3 mod q
- **No key reconstruction**: Authorities never share private data

### Compromise Resistance
- Single compromised authority cannot forge tickets
- Attacker needs 2+ authorities to break system
- Key share leakage of 1 authority is insufficient

### Attack Prevention
- **Replay protection**: Nonces prevent replay attacks
- **Integrity**: Signatures bound to payload via hash
- **Expiration**: Tickets have limited lifetime
- **Version checking**: Reject tickets with old keys

## 📊 Performance

Typical measurements (small primes for demo):
- Modular exponentiation: ~0.01 ms
- Full signature: ~0.02 ms
- Threshold signature: ~0.03 ms (50% overhead)
- Network overhead: 2 round trips vs 1 in classical system

**Trade-off**: ~50% computation overhead + 1 extra network round trip

**Benefit**: Resilience to authority compromise and failure

## 🎓 Educational Features

### Beginner-Friendly Design
- **Separated classes**: Each class has single responsibility
- **Detailed comments**: Every function documented
- **Manual implementations**: No black-box crypto libraries
- **Small parameters**: Easy to verify calculations by hand

### Cryptographic Implementations
- Recursive modular exponentiation (divide-and-conquer)
- Schnorr signature from scratch
- Threshold signature combination
- PKCS#7 padding manual implementation

## 📝 Assignment Requirements

- ✅ Threshold Schnorr signature (2-of-3)
- ✅ Distributed AS and TGS nodes
- ✅ Ticket generation and validation
- ✅ Authority compromise simulation
- ✅ Attack containment demonstration
- ✅ Performance analysis
- ✅ Key rotation mechanism
- ✅ Comprehensive documentation

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find and kill process
lsof -ti:8001 | xargs kill -9
```

### Connection Refused
- Ensure all servers are running
- Check firewall settings
- Verify correct port numbers

### Signature Verification Failed
- Regenerate keys: `python3 master_keygen.py`
- Ensure same key version across all nodes
- Check parameter files exist

## 📚 References

- Kerberos Protocol: RFC 4120
- Schnorr Signature: Schnorr, C.P. (1991)
- Threshold Cryptography: Desmedt, Y. (1994)
- Secret Sharing: Shamir, A. (1979)

## 👥 Authors

CS5.470 System and Network Security Lab Assignment 3
IIIT Hyderabad, Spring 2026

## 📄 License

Educational use only.