"""Rotate command implementation."""
import base64
import sys
from datetime import datetime, timezone

from src.crypto.bip39 import decode_share, encode_share, validate_checksum
from src.crypto.keypair import (
    HybridKeypair,
    decrypt_private_keys,
    encrypt_key_with_passphrase,
    generate_hybrid_keypair,
)
from src.crypto.passphrase import generate_passphrase
from src.crypto.shamir import reconstruct_secret, split_secret
from src.storage.manifest import append_rotation_event, compute_fingerprints
from src.storage.models import RotationEvent
from src.storage.vault import load_vault, save_vault, update_manifest


def rotate_command(
    vault_path: str,
    mode: str,
    new_k: int = None,
    new_n: int = None,
    shares: list = None,
) -> int:
    """
    Rotate shares or passphrase.

    Args:
        vault_path: Path to vault file
        mode: "shares" or "passphrase"
        new_k: New threshold (for share rotation)
        new_n: New total shares (for share rotation)
        shares: List of share mnemonics (K shares to reconstruct passphrase)

    Returns:
        Exit code (0 = success)
    """
    import os

    # Check vault exists
    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    try:
        # Load vault
        vault = load_vault(vault_path)
        k = vault.manifest.k

        # Collect shares if not provided
        if shares is None:
            print(f"\\nEnter {k} shares to authorize rotation:\\n")
            shares = []
            for i in range(k):
                share_str = input(f"Share {i+1}: ").strip()
                shares.append(share_str)

        # Validate shares
        if len(shares) < k:
            print(
                f"Error: Insufficient shares (need {k}, got {len(shares)})",
                file=sys.stderr,
            )
            return 3

        # Validate BIP39 checksums
        for i, share_str in enumerate(shares[:k], 1):
            if not validate_checksum(share_str):
                print(f"Error: Invalid BIP39 checksum in share {i}", file=sys.stderr)
                return 4

        # Decode shares
        share_bytes = []
        for i, share_str in enumerate(shares[:k], 1):
            decoded = decode_share(share_str)
            share_bytes.append(bytes([i]) + decoded)

        # Reconstruct current passphrase
        current_passphrase = reconstruct_secret(share_bytes)

        # Verify passphrase works (by decrypting private keys)
        keypair_obj = HybridKeypair(
            rsa_public=vault.keys.rsa_public.encode(),
            rsa_private_encrypted=base64.b64decode(
                vault.keys.rsa_private_encrypted
            ),
            kyber_public=base64.b64decode(vault.keys.kyber_public),
            kyber_private_encrypted=base64.b64decode(
                vault.keys.kyber_private_encrypted
            ),
            kdf_salt=base64.b64decode(vault.keys.kdf_salt),
            kdf_iterations=vault.keys.kdf_iterations,
        )

        rsa_private, kyber_private = decrypt_private_keys(keypair_obj, current_passphrase)

        if mode == "shares":
            # Share rotation: Keep same passphrase, split with new K/N
            if new_k is None or new_n is None:
                print("Error: Must specify --new-k and --new-n for share rotation", file=sys.stderr)
                return 1

            # Split passphrase with new threshold
            new_shares = split_secret(current_passphrase, new_k, new_n)
            new_mnemonics = [encode_share(share[1:]) for share in new_shares]

            # Update manifest
            rotation_event = RotationEvent(
                date=datetime.now(timezone.utc).isoformat(),
                event_type="share_rotation",
                k=new_k,
                n=new_n,
            )
            vault.manifest.k = new_k
            vault.manifest.n = new_n
            vault.manifest = append_rotation_event(vault.manifest, rotation_event)

            # Update fingerprints
            vault.manifest.fingerprints = compute_fingerprints(vault)

            # Save vault
            save_vault(vault, vault_path)

            # Print new shares
            print(f"\\n✓ Share rotation complete ({new_k}-of-{new_n})\\n")
            print("New shares:\\n")
            for i, mnemonic in enumerate(new_mnemonics, 1):
                print(f"Share {i}:")
                print(f"  {mnemonic}\\n")

            return 0

        elif mode == "passphrase":
            # Passphrase rotation: Generate new passphrase, re-encrypt private keys
            new_passphrase = generate_passphrase()

            # Re-encrypt private keys with new passphrase
            new_keypair = generate_hybrid_keypair(new_passphrase)

            # Update vault with new encrypted private keys
            vault.keys.rsa_private_encrypted = base64.b64encode(
                new_keypair.rsa_private_encrypted
            ).decode()
            vault.keys.kyber_private_encrypted = base64.b64encode(
                new_keypair.kyber_private_encrypted
            ).decode()
            vault.keys.kdf_salt = base64.b64encode(new_keypair.kdf_salt).decode()

            # Use current K/N or allow changing
            target_k = new_k if new_k is not None else k
            target_n = new_n if new_n is not None else vault.manifest.n

            # Split new passphrase
            new_shares = split_secret(new_passphrase, target_k, target_n)
            new_mnemonics = [encode_share(share[1:]) for share in new_shares]

            # Update manifest
            rotation_event = RotationEvent(
                date=datetime.now(timezone.utc).isoformat(),
                event_type="passphrase_rotation",
                k=target_k,
                n=target_n,
            )
            vault.manifest.k = target_k
            vault.manifest.n = target_n
            vault.manifest = append_rotation_event(vault.manifest, rotation_event)

            # Update fingerprints
            vault.manifest.fingerprints = compute_fingerprints(vault)

            # Save vault
            save_vault(vault, vault_path)

            # Print new shares
            print(f"\\n✓ Passphrase rotation complete ({target_k}-of-{target_n})\\n")
            print("New shares:\\n")
            for i, mnemonic in enumerate(new_mnemonics, 1):
                print(f"Share {i}:")
                print(f"  {mnemonic}\\n")

            return 0

        else:
            print(f"Error: Invalid mode '{mode}' (must be 'shares' or 'passphrase')", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 9
