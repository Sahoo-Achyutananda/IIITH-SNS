# SECURITY.md

## How the Protocol Ensures Security

This document explains how the UAV Command and Control protocol protects against common attacks through **Freshness** and **Forward Secrecy**.

---

## 1. Freshness (Replay Attack Protection)

**What is Freshness?**  
Freshness ensures that old messages cannot be reused by an attacker. Without it, an attacker could capture a valid authentication packet and replay it later to gain unauthorized access.

**How We Implement Freshness:**

### Timestamps (Phase 1)
- Every authentication request includes a timestamp (`TS_d`) from the drone
- The MCC checks if the timestamp is within 10 seconds of the current time
- If the packet is older than 10 seconds, it is rejected immediately
- This prevents attackers from replaying captured packets after they expire

**Code Implementation (mcc.py, Phase 1):**
```python
current_time = int(time.time())
time_diff = abs(current_time - ts_d)

if time_diff > 10:
    print("[SECURITY ALERT] REPLAY ATTACK DETECTED!")
    self.conn.send(struct.pack("!B", 60))  # Send error opcode
    raise Exception("Replay Attack Blocked: Timestamp expired")
```

### Random Nonces (Phase 1)
- Drone generates a random nonce `RN_d` (64-bit random number)
- MCC generates its own random nonce `RN_MCC`
- Both nonces are included in the session key derivation
- Even if timestamps were identical, different nonces ensure different session keys

**Session Key Formula:**
```
SK = SHA-256(K || TS_d || TS_MCC || RN_d || RN_MCC)
```

### Why This Works:
1. **Timestamps expire** - Old packets are rejected
2. **Nonces are unique** - Each session has different random values
3. **Combined protection** - Even if one mechanism fails, the other provides backup

---

## 2. Forward Secrecy

**What is Forward Secrecy?**  
Forward Secrecy ensures that if a private key is compromised in the future, past communications remain secure. An attacker cannot decrypt old messages even if they steal the server's private key later.

**How We Implement Forward Secrecy:**

### Ephemeral Session Keys (Phase 1-2)
- Each drone generates a fresh random secret `K` for every connection
- `K` is a 256-bit random number that changes with each session
- `K` is encrypted using ElGamal and sent to the MCC
- After deriving the session key, `K` is discarded

**Code Implementation (drone.py, Phase 1):**
```python
self.K = secrets.randbits(256)  # New random key every time
c1, c2 = Elgamal.encrypt(self.K, self.mcc_pub, self.p, self.g)
```

### Session Key Derivation
- Both parties derive `SK` from the ephemeral `K` plus timestamps and nonces
- `SK` is used for all subsequent encryption (Phase 2 HMAC, Phase 3 AES)
- Once the session ends, `SK` is lost forever

**Key Points:**
```
SK_session1 = SHA-256(K1 || TS1 || TS_MCC1 || RN1 || RN_MCC1)
SK_session2 = SHA-256(K2 || TS2 || TS_MCC2 || RN2 || RN_MCC2)
```
These are completely different because K, timestamps, and nonces change.

### Why This Works:
1. **Ephemeral K** - A new random secret is generated for each session
2. **No key reuse** - Long-term private keys (MCC's `x`) are never directly used for encryption
3. **Perfect forward secrecy** - Compromising MCC's private key `x` does NOT reveal past values of `K`
4. **Session isolation** - Each session has independent cryptographic material

### What an Attacker CANNOT Do:
- If an attacker steals MCC's private key **today**, they cannot:
  - Decrypt yesterday's session keys
  - Decrypt yesterday's messages
  - Recover the ephemeral `K` values from past sessions

- Why? Because `K` was randomly generated, used once, and destroyed

---

## 3. Combined Security Properties

| Attack Type | Defense Mechanism | Location |
|-------------|------------------|----------|
| Replay Attack | Timestamp validation (10s window) | Phase 1 (mcc.py) |
| Replay Attack | Random nonces | Phase 1 (both sides) |
| Session Hijacking | Session key derivation with unique inputs | Phase 2 |
| Key Compromise | Ephemeral secrets (K) | Phase 1 |
| Past Traffic Decryption | Forward Secrecy via session-specific keys | Phase 1-2 |
| Parameter Tampering | Digital signatures on Phase 0 | Phase 0 |

---

## 4. Attack Demonstrations (attacks.py)

### Replay Attack (Attack #2)
- **What it does:** Captures a valid AUTH_REQ packet and replays it
- **Expected result:** MCC rejects with Opcode 60 (timestamp expired)
- **Protection:** Timestamp check in Phase 1

### MITM Parameter Tampering (Attack #1)
- **What it does:** Replaces the 2048-bit prime with a weak 23-bit prime
- **Expected result:** Drone detects weak parameters OR signature fails
- **Protection:** Security level validation + digital signatures

### Unauthorized Access (Attack #3)
- **What it does:** Sends fake AUTH_REQ with garbage data
- **Expected result:** MCC rejects due to invalid signature
- **Protection:** Digital signature verification

---

## Summary

**Freshness is achieved by:**
- Timestamp validation (10-second window)
- Random nonces in every session
- Combined use in session key derivation

**Forward Secrecy is achieved by:**
- Ephemeral random secrets (K) generated per session
- Session keys derived from ephemeral values
- No reuse of long-term keys for encryption
- Immediate destruction of session material after use

This design ensures that even if the MCC's long-term private key is compromised, all past communications remain secure, and old authentication packets cannot be reused.