# master_keygen.py
# This script generates and rotates the master key and shares for the system

from crypto_utils import generate_schnorr_params, ThresholdSchnorr
import json
import os
import shutil


def reconstruct_secret(q, indexed_shares):
    """Reconstruct secret at x=0 from two Shamir shares (index, share)."""
    secret = 0

    for i, share_i in indexed_shares:
        numerator = 1
        denominator = 1

        for j, _ in indexed_shares:
            if i == j:
                continue
            numerator = (numerator * (-j)) % q
            denominator = (denominator * (i - j)) % q

        lagrange = (numerator * pow(denominator % q, -1, q)) % q
        secret = (secret + share_i * lagrange) % q

    return secret


def generate_and_save_keys(version=None):
    """Generate parameters, master key, shares, and save them to disk."""
    p, q, g = generate_schnorr_params()
    print(f"Generated parameters: p={p}, q={q}, g={g}")

    schnorr = ThresholdSchnorr(p, q, g)

    x, y = schnorr.generate_keypair()
    print(f"Master private key: {x}")
    print(f"Master public key: {y}")

    shares = schnorr.generate_shares(x, 3)
    print(f"Key shares: {shares}")

    reconstructed = reconstruct_secret(q, [(1, shares[0]), (2, shares[1])])
    if reconstructed != x:
        raise ValueError("Share verification failed during key generation")

    params = {'p': p, 'q': q, 'g': g, 'y': y}
    if version is not None:
        params['version'] = version

    with open('params.json', 'w') as f:
        json.dump(params, f, indent=2)

    for i, share in enumerate(shares, start=1):
        share_data = {'x_i': share}
        if version is not None:
            share_data['version'] = version
        with open(f'share_{i}.json', 'w') as f:
            json.dump(share_data, f, indent=2)

    print("Keys and params saved.")


class KeyRotationManager:
    """Manages key rotation for the threshold signature system."""

    def __init__(self):
        self.params_file = 'params.json'
        self.share_prefix = 'share_'

    def backup_current_keys(self, version):
        """Backup current keys before rotation."""
        backup_dir = f'keys_backup_v{version}'
        os.makedirs(backup_dir, exist_ok=True)

        if os.path.exists(self.params_file):
            shutil.copy(self.params_file, f'{backup_dir}/{self.params_file}')

        for i in range(1, 4):
            share_file = f'{self.share_prefix}{i}.json'
            if os.path.exists(share_file):
                shutil.copy(share_file, f'{backup_dir}/{share_file}')

        print(f"Existing key material has been backed up to {backup_dir}/")

    def rotate_keys(self):
        """Perform complete key rotation."""
        print("=" * 70)
        print("KEY ROTATION PROCESS")
        print("=" * 70)

        current_version = 1
        if os.path.exists(self.params_file):
            with open(self.params_file, 'r') as f:
                params = json.load(f)
                current_version = params.get('version', 1)

        new_version = current_version + 1

        print(f"Current key version: {current_version}")
        print(f"New key version: {new_version}")

        print(f"\nStep 1: Backing up current keys...")
        self.backup_current_keys(current_version)

        print(f"\nStep 2: Generating new keys...")
        generate_and_save_keys(version=new_version)

        print(f"\nStep 3: Key rotation complete!")
        print(f"\nImportant:")
        print(f"  - Restart all AS and TGS nodes with new key version")
        print(f"  - Old tickets (version {current_version}) will be rejected")
        print(f"  - Clients must request new tickets")
        return True

def main():
    import sys

    if '--rotate' in sys.argv:
        manager = KeyRotationManager()
        if '--auto' in sys.argv:
            manager.rotate_keys()
            return

        print("This will rotate all cryptographic keys.")
        print("All authorities must be restarted with new keys.")
        print("All existing tickets will become invalid.")
        response = input("\nProceed with key rotation? (yes/no): ")

        if response.lower() == 'yes':
            manager.rotate_keys()
        else:
            print("Key rotation cancelled.")
        return

    generate_and_save_keys()

if __name__ == "__main__":
    main()