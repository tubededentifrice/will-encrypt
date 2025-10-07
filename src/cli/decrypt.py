"""Decrypt command implementation."""
import base64
import sys

from src.crypto.bip39 import decode_share, validate_checksum
from src.crypto.encryption import EncryptedMessage, decrypt_message
from src.crypto.keypair import decrypt_private_keys
from src.crypto.shamir import reconstruct_secret
from src.crypto.keypair import HybridKeypair
from src.storage.vault import load_vault


def decrypt_command(vault_path: str, shares: list = None) -> int:
    """Decrypt messages using K shares."""
    import os

    # Check vault exists
    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    try:
        # Load vault
        vault = load_vault(vault_path)
        k = vault.manifest.k

        # Collect shares
        if shares is None:
            print(f"\\nEnter {k} shares (24-word BIP39 mnemonics):\\n")
            shares = []
            for i in range(k):
                share_str = input(f"Share {i+1}: ").strip()
                shares.append(share_str)

        # Validate shares
        if len(shares) < k:
            print(f"Error: Insufficient shares (need {k}, got {len(shares)})", file=sys.stderr)
            return 3

        # Validate BIP39 checksums
        for i, share_str in enumerate(shares[:k], 1):
            if not validate_checksum(share_str):
                print(f"Error: Invalid BIP39 checksum in share {i}", file=sys.stderr)
                return 4

        # Decode shares
        share_bytes = []
        for i, share_str in enumerate(shares[:k], 1):
            decoded = decode_share(share_str)  # Returns 32 bytes
            # Prepend sequential index (1-based) to make 33-byte share
            share_bytes.append(bytes([i]) + decoded)

        # Reconstruct passphrase
        passphrase = reconstruct_secret(share_bytes)

        # Decrypt private keys
        keypair_obj = HybridKeypair(
            rsa_public=vault.keys.rsa_public.encode(),
            rsa_private_encrypted=base64.b64decode(vault.keys.rsa_private_encrypted),
            kyber_public=base64.b64decode(vault.keys.kyber_public),
            kyber_private_encrypted=base64.b64decode(
                vault.keys.kyber_private_encrypted
            ),
            kdf_salt=base64.b64decode(vault.keys.kdf_salt),
            kdf_iterations=vault.keys.kdf_iterations,
        )

        rsa_private, kyber_private = decrypt_private_keys(keypair_obj, passphrase)

        # Decrypt messages
        print(f"\\n✓ Decrypting {len(vault.messages)} message(s)...\\n")
        for msg in vault.messages:
            encrypted = EncryptedMessage(
                ciphertext=base64.b64decode(msg.ciphertext),
                rsa_wrapped_kek=base64.b64decode(msg.rsa_wrapped_kek),
                kyber_wrapped_kek=base64.b64decode(msg.kyber_wrapped_kek),
                nonce=base64.b64decode(msg.nonce),
                auth_tag=base64.b64decode(msg.auth_tag),
            )

            plaintext = decrypt_message(
                encrypted, rsa_private, kyber_private, msg.title
            )

            print(f"Message {msg.id}: {msg.title}")
            print(f"Created: {msg.created}")
            print(f"Content:\\n{plaintext.decode('utf-8')}\\n")
            print("-" * 60 + "\\n")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 7
