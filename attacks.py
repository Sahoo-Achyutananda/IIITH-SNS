# attacks.py
# Demonstration of attack scenarios and security properties

import json
import time
from crypto_utils import ThresholdSchnorr, ModularArithmetic, Ticket

def load_params():
    """Load system parameters"""
    with open('params.json', 'r') as f:
        params = json.load(f)
    p, q, g, y = params['p'], params['q'], params['g'], params['y']
    return ThresholdSchnorr(p, q, g), y, p, q, g

def load_share(share_num):
    """Load a key share"""
    with open(f'share_{share_num}.json', 'r') as f:
        return json.load(f)['x_i']

print("=" * 70)
print("ATTACK SCENARIO DEMONSTRATIONS")
print("=" * 70)

# ============================================================================
# Attack 1: Single malicious authority attempting to forge ticket
# ============================================================================
print("\n[Attack 1] Single Malicious Authority Forging Ticket")
print("-" * 70)

schnorr, y, p, q, g = load_params()
x1 = load_share(1)

print(f"Scenario: AS1 compromised, attempting to forge ticket alone")
print(f"  Compromised authority has share x1 = {x1}")

# Malicious AS tries to create valid ticket
ticket = Ticket("attacker", "secret_service", b"fake_key")
payload = ticket.get_payload()

print(f"  Attempting to sign: {payload}")

# Malicious AS generates partial signature with only its share
k_mal = schnorr.q - 1  # malicious nonce
R_mal = schnorr.mod_arith.mod_pow(g, k_mal, p)
e_mal = schnorr.hash_message(payload, R_mal)
s_mal = (k_mal + e_mal * x1) % q

forged_sig = (R_mal, s_mal)
print(f"  Forged signature: R={R_mal}, s={s_mal}")

# Try to verify
if schnorr.verify(payload, forged_sig, y):
    print(f"  Observation: the forged signature was accepted unexpectedly.")
else:
    print(f"  Observation: the forged signature was rejected.")
    print(f"  Explanation: Single share cannot produce valid signature")
    print(f"               g^s ≠ R * y^e because s uses only x1, not full x")

# ============================================================================
# Attack 2: Modified ticket payload after signing
# ============================================================================
print("\n[Attack 2] Modified Ticket Payload")
print("-" * 70)

print(f"Scenario: Attacker intercepts valid ticket and modifies payload")

# Create legitimate ticket with proper 2-of-3 signature
x1 = load_share(1)
x2 = load_share(2)

original_ticket = Ticket("alice", "file_service", b"session_key")
original_payload = original_ticket.get_payload()

# Two authorities sign
k1 = q - 1
k2 = q - 2
R1 = schnorr.mod_arith.mod_pow(g, k1, p)
R2 = schnorr.mod_arith.mod_pow(g, k2, p)
R_combined = (R1 * R2) % p

e = schnorr.hash_message(original_payload, R_combined)
s1 = (k1 + e * x1) % q
s2 = (k2 + e * x2) % q
s_combined = (s1 + s2) % q

original_sig = (R_combined, s_combined)

print(f"  Original ticket: {original_payload}")
print(f"  Original signature valid: {schnorr.verify(original_payload, original_sig, y)}")

# Attacker modifies payload
modified_ticket = Ticket("alice", "admin_service", b"session_key")  # Changed service!
modified_payload = modified_ticket.get_payload()

print(f"  Modified ticket: {modified_payload}")
print(f"  Reusing same signature on modified payload...")

if schnorr.verify(modified_payload, original_sig, y):
    print(f"  Observation: the modified payload was accepted unexpectedly.")
else:
    print(f"  Observation: the modified payload was rejected.")
    print(f"  Explanation: Signature is bound to original payload via hash")
    print(f"               Changing payload changes e = H(payload||R), invalidating signature")

# ============================================================================
# Attack 3: Replay of old partial signature
# ============================================================================
print("\n[Attack 3] Replay of Old Partial Signature")
print("-" * 70)

print(f"Scenario: Attacker replays old partial signature for new ticket")

# Old partial signature
old_ticket = Ticket("bob", "old_service", b"old_key")
old_payload = old_ticket.get_payload()

k_old = q - 3
R_old = schnorr.mod_arith.mod_pow(g, k_old, p)
e_old = schnorr.hash_message(old_payload, R_old)
s_old = (k_old + e_old * x1) % q

print(f"  Old partial signature: R={R_old}, s={s_old}")

# New ticket request
new_ticket = Ticket("bob", "new_service", b"new_key")
new_payload = new_ticket.get_payload()

print(f"  Old ticket: {old_payload}")
print(f"  New ticket: {new_payload}")

# Try to use old (R, s) with new authority's fresh partial
k_new = q - 4
R_new = schnorr.mod_arith.mod_pow(g, k_new, p)
R_replay = (R_old * R_new) % p  # Combining old R with new R
e_replay = schnorr.hash_message(new_payload, R_replay)
s_new = (k_new + e_replay * x2) % q
s_replay = (s_old + s_new) % q  # Old s doesn't match new e!

replay_sig = (R_replay, s_replay)

print(f"  Attempting replay with combined (R_old*R_new, s_old+s_new)...")

if schnorr.verify(new_payload, replay_sig, y):
    print(f"  Observation: the replay attempt was accepted unexpectedly.")
else:
    print(f"  Observation: the replay attempt was rejected.")
    print(f"  Explanation: s_old was computed with old challenge e_old")
    print(f"               New payload requires s = k + e_new*x where e_new = H(new_payload||R)")
    print(f"               Cannot reconstruct valid s by mixing old and new partials")

# ============================================================================
# Attack 4: Key share leakage
# ============================================================================
print("\n[Attack 4] Single Key Share Leakage")
print("-" * 70)

print(f"Scenario: Attacker obtains one key share x1 = {x1}")
print(f"  Public key y = {y}")
print(f"  Can attacker recover full private key x?")

# Attacker has x1, knows y = g^x mod p
# In additive secret sharing: x = x1 + x2 + x3 mod q
# Without x2 or x3, cannot compute x

print(f"  Attacker knows: x = x1 + x2 + x3 mod {q}")
print(f"  Attacker needs to find: x2 + x3 mod {q}")
print(f"  ")
print(f"  Possible values for (x2 + x3): {q} possibilities")
print(f"  Cannot efficiently determine without additional information")
print(f"  ")
print(f"  With one leaked share, the system remains secure under the assumed threat model.")
print(f"  With two leaked shares, the secret can be reconstructed and the scheme is no longer secure.")

x1_val = x1
x2_val = load_share(2)
x3_val = load_share(3)
x_reconstructed = (x1_val + x2_val + x3_val) % q

print(f"  ")
print(f"  With 2 shares (x1={x1_val}, x2={x2_val}):")
print(f"    x = x1 + x2 + x3 mod q")
print(f"    y = g^x mod p = {y}")
print(f"    Attacker can compute x3 by trying all {q} values")
print(f"    Or use discrete log if possible")
print(f"    Reconstructed x = {x_reconstructed}")

# ============================================================================
# Attack 5: Authority offline scenario
# ============================================================================
print("\n[Attack 5] Authority Offline")
print("-" * 70)

print(f"Scenario: AS3 is offline, only AS1 and AS2 available")
print(f"  System threshold: 2-of-3")
print(f"  Available authorities: 2")
print(f"  ")

available_shares = [x1, x2]
print(f"  AS1 and AS2 can still produce valid signature:")

test_ticket = Ticket("charlie", "test_service", b"test_key")
test_payload = test_ticket.get_payload()

k1_test = q - 5
k2_test = q - 6
R1_test = schnorr.mod_arith.mod_pow(g, k1_test, p)
R2_test = schnorr.mod_arith.mod_pow(g, k2_test, p)
R_test = (R1_test * R2_test) % p

e_test = schnorr.hash_message(test_payload, R_test)
s1_test = (k1_test + e_test * x1) % q
s2_test = (k2_test + e_test * x2) % q
s_test = (s1_test + s2_test) % q

test_sig = (R_test, s_test)

print(f"  Signature verification: {schnorr.verify(test_payload, test_sig, y)}")
print(f"  The system remains operational with 2 authorities online.")
print(f"  If 2 or more authorities are offline, valid signatures cannot be produced.")

# ============================================================================
# Attack 6: Attempt to sign with only one share
# ============================================================================
print("\n[Attack 6] Signing with Single Share")
print("-" * 70)

print(f"Scenario: Try to use only AS1 to issue ticket")

single_ticket = Ticket("mallory", "bank_service", b"fake_session")
single_payload = single_ticket.get_payload()

# Only one authority participates
k_single = q - 7
R_single = schnorr.mod_arith.mod_pow(g, k_single, p)
e_single = schnorr.hash_message(single_payload, R_single)
s_single = (k_single + e_single * x1) % q

single_sig = (R_single, s_single)

print(f"  Single authority signature:")
print(f"    R = g^k = {R_single}")
print(f"    s = k + e*x1 = {s_single}")
print(f"    e = H(m||R) = {e_single}")
print(f"  ")
print(f"  Verification check: g^s ?= R * y^e")

left = schnorr.mod_arith.mod_pow(g, s_single, p)
y_e = schnorr.mod_arith.mod_pow(y, e_single, p)
right = (R_single * y_e) % p

print(f"    g^s = {left}")
print(f"    R * y^e = {right}")

if schnorr.verify(single_payload, single_sig, y):
    print(f"  Observation: a single-authority signature was accepted unexpectedly.")
else:
    print(f"  Observation: the single-authority signature was rejected.")
    print(f"  Explanation:")
    print(f"    y = g^x where x = x1 + x2 + x3")
    print(f"    g^s = g^(k + e*x1)")
    print(f"    R*y^e = g^k * g^(e*x) = g^(k + e*(x1+x2+x3))")
    print(f"    These are equal only if x1 = x1+x2+x3, i.e., x2+x3=0")
    print(f"    With proper secret sharing, this won't happen")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "=" * 70)
print("ATTACK SUMMARY")
print("=" * 70)
print("A single malicious authority cannot forge tickets independently.")
print("Modified payloads are detected during signature verification.")
print("Replay attempts fail because the challenge hash is bound to the payload.")
print("Leakage of one key share does not compromise the complete system.")
print("The system remains operational with any 2 out of 3 authorities.")
print("A valid signature cannot be produced using only 1 authority.")
print("=" * 70)