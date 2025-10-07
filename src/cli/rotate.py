"""Rotate command implementation."""
import base64
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from src.crypto.bip39 import decode_share, encode_share, validate_checksum, format_indexed_share
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
    confirm: bool = None,
) -> int:
    """
    Rotate shares or passphrase.

    Args:
        vault_path: Path to vault file
        mode: "shares" or "passphrase"
        new_k: New threshold (for share rotation)
        new_n: New total shares (for share rotation)
        shares: List of share mnemonics (K shares to reconstruct passphrase)
        confirm: Skip confirmation prompt if True (for testing)

    Returns:
        Exit code (0 = success)
    """
    import os

    # Check vault exists
    if not os.path.exists(vault_path):
        print(f"\nError: Vault not found: {vault_path}", file=sys.stderr)
        print(f"Hint: Check the file path and ensure vault exists", file=sys.stderr)
        return 2

    try:
        # Load vault
        vault = load_vault(vault_path)
        k = vault.manifest.k
        n = vault.manifest.n

        # Interactive mode explanation
        print(f"\n🔄 Vault Key Rotation\n")
        print(f"Current configuration: {k}-of-{n} threshold")
        print(f"Mode: {mode}")
        if mode == "shares":
            print(f"  • Keep same passphrase, change share distribution")
            print(f"  • Useful for: adding/removing key holders, changing threshold")
        elif mode == "passphrase":
            print(f"  • Generate new passphrase, re-encrypt private keys")
            print(f"  • Useful for: suspected compromise, periodic rotation")
        print(f"\nThis operation requires {k} current shares to authorize.\n")
        print("-" * 70)

        # Collect shares if not provided
        if shares is None:
            shares = []
            for i in range(k):
                while True:
                    try:
                        share_str = input(f"\nCurrent share {i+1}/{k}: ").strip()
                        if not share_str:
                            print("  Error: Share cannot be empty.")
                            continue
                        # Validate checksum
                        if not validate_checksum(share_str):
                            print(f"  ✗ Invalid BIP39 checksum.")
                            retry = input(f"  Retry? (yes/no): ").strip().lower()
                            if retry != "yes":
                                print("\nAborted.", file=sys.stderr)
                                return 4
                            continue
                        print(f"  ✓ Share {i+1} validated")
                        shares.append(share_str)
                        break
                    except (EOFError, KeyboardInterrupt):
                        print("\n\nAborted.", file=sys.stderr)
                        return 1

        # Validate shares
        if len(shares) < k:
            print(
                f"Error: Insufficient shares (need {k}, got {len(shares)})",
                file=sys.stderr,
            )
            return 3

        # Parse and validate BIP39 checksums
        from src.crypto.bip39 import parse_indexed_share

        share_bytes = []
        for share_str in shares[:k]:
            # Parse indexed share (e.g., "1: word1 word2..." or just "word1 word2...")
            index, mnemonic = parse_indexed_share(share_str)

            # Validate BIP39 checksum
            if not validate_checksum(mnemonic):
                print(f"Error: Invalid BIP39 checksum in share", file=sys.stderr)
                return 4

            # Decode and prepend index
            decoded = decode_share(mnemonic)
            if index is None:
                # If no index provided, use sequential numbering
                index = len(share_bytes) + 1
            share_bytes.append(bytes([index]) + decoded)

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
                print("\n⚠️  Share rotation requires new K and N values.")
                try:
                    new_k_input = input(f"Enter new threshold K (current: {k}): ").strip()
                    new_k = int(new_k_input)
                    new_n_input = input(f"Enter new total shares N (current: {n}): ").strip()
                    new_n = int(new_n_input)
                except (ValueError, EOFError, KeyboardInterrupt):
                    print("\nError: Invalid input", file=sys.stderr)
                    return 1

            # Validate new K/N
            if new_k < 1 or new_k > new_n or new_n > 255:
                print(f"\nError: Invalid K/N (got K={new_k}, N={new_n})", file=sys.stderr)
                return 1

            # Confirmation
            if confirm is None:
                print(f"\n⚠️  Confirm rotation:")
                print(f"  • Current: {k}-of-{n}")
                print(f"  • New: {new_k}-of-{new_n}")
                print(f"  • Old shares will become INVALID")
                try:
                    confirm_input = input(f"\nProceed with share rotation? (yes/no): ").strip().lower()
                    if confirm_input != "yes":
                        print("Aborted.", file=sys.stderr)
                        return 0
                except (EOFError, KeyboardInterrupt):
                    print("\nAborted.", file=sys.stderr)
                    return 0
            elif not confirm:
                print("Aborted.", file=sys.stderr)
                return 0

            # Progress indicators
            print(f"\n🔄 Rotating shares...")
            print(f"  [1/3] Splitting passphrase into {new_n} new shares...")
            new_shares = split_secret(current_passphrase, new_k, new_n)
            new_mnemonics = [encode_share(share[1:]) for share in new_shares]
            print(f"        ✓ {new_n} shares created")

            # Update manifest
            print(f"  [2/3] Updating vault manifest...")
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
            print(f"        ✓ Manifest updated")

            # Save vault
            print(f"  [3/3] Saving vault...")
            save_vault(vault, vault_path)
            print(f"        ✓ Vault saved")

            # Print new shares with instructions
            print(f"\n{'='*70}")
            print(f"✓ Share rotation complete!")
            print(f"{'='*70}\n")
            print(f"📋 New Shares ({new_k}-of-{new_n} threshold)\n")
            print(f"⚠️  OLD SHARES ARE NOW INVALID. Distribute these new shares:\n")
            print(f"{'-'*70}\n")
            for i, mnemonic in enumerate(new_mnemonics, 1):
                print(f"Share {i}/{new_n}:")
                print(f"  {format_indexed_share(i, mnemonic)}\n")
            print(f"{'-'*70}\n")
            print("📝 Next Steps:")
            print("  1. Securely destroy all old shares")
            print("  2. Distribute new shares to key holders")
            print("  3. Test decryption with new shares immediately")

            return 0

        elif mode == "passphrase":
            # Passphrase rotation: Generate new passphrase, re-encrypt private keys

            # Use current K/N or allow changing
            target_k = new_k if new_k is not None else k
            target_n = new_n if new_n is not None else n

            # Confirmation
            if confirm is None:
                print(f"\n⚠️  Confirm passphrase rotation:")
                print(f"  • Generates NEW 256-bit passphrase")
                print(f"  • Re-encrypts private keys")
                print(f"  • Threshold: {k}-of-{n} → {target_k}-of-{target_n}")
                print(f"  • Old passphrase and shares will become INVALID")
                print(f"  • Messages are NOT re-encrypted (hybrid design)")
                try:
                    confirm_input = input(f"\nProceed with passphrase rotation? (yes/no): ").strip().lower()
                    if confirm_input != "yes":
                        print("Aborted.", file=sys.stderr)
                        return 0
                except (EOFError, KeyboardInterrupt):
                    print("\nAborted.", file=sys.stderr)
                    return 0
            elif not confirm:
                print("Aborted.", file=sys.stderr)
                return 0

            # Progress indicators
            print(f"\n🔄 Rotating passphrase...")
            print(f"  [1/5] Generating new 256-bit passphrase...")
            new_passphrase = generate_passphrase()
            print(f"        ✓ New passphrase generated")

            # Re-encrypt existing private keys with new passphrase
            print(f"  [2/5] Re-encrypting private keys with new passphrase...")

            # Use existing private keys (already decrypted above), re-encrypt with new passphrase
            new_salt = os.urandom(32)

            # Re-encrypt RSA private key
            rsa_private_pem = rsa_private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            encrypted_rsa = encrypt_key_with_passphrase(
                rsa_private_pem, new_passphrase, new_salt, vault.keys.kdf_iterations
            )

            # Re-encrypt Kyber private key
            encrypted_kyber = encrypt_key_with_passphrase(
                kyber_private, new_passphrase, new_salt, vault.keys.kdf_iterations
            )

            print(f"        ✓ Private keys re-encrypted")

            # Update vault with new encrypted private keys
            print(f"  [3/5] Updating vault...")
            vault.keys.rsa_private_encrypted = base64.b64encode(encrypted_rsa).decode()
            vault.keys.kyber_private_encrypted = base64.b64encode(encrypted_kyber).decode()
            vault.keys.kdf_salt = base64.b64encode(new_salt).decode()
            print(f"        ✓ Vault updated")

            # Split new passphrase
            print(f"  [4/5] Splitting new passphrase into {target_n} shares...")
            new_shares = split_secret(new_passphrase, target_k, target_n)
            new_mnemonics = [encode_share(share[1:]) for share in new_shares]
            print(f"        ✓ {target_n} shares created")

            # Update manifest
            print(f"  [5/5] Updating manifest and saving vault...")
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
            print(f"        ✓ Vault saved")

            # Print new shares with instructions
            print(f"\n{'='*70}")
            print(f"✓ Passphrase rotation complete!")
            print(f"{'='*70}\n")
            print(f"📋 New Shares ({target_k}-of-{target_n} threshold)\n")
            print(f"⚠️  OLD PASSPHRASE AND SHARES ARE NOW INVALID. Distribute these new shares:\n")
            print(f"{'-'*70}\n")
            for i, mnemonic in enumerate(new_mnemonics, 1):
                print(f"Share {i}/{target_n}:")
                print(f"  {format_indexed_share(i, mnemonic)}\n")
            print(f"{'-'*70}\n")
            print("📝 Next Steps:")
            print("  1. Securely destroy all old shares")
            print("  2. Distribute new shares to key holders")
            print("  3. Test decryption with new shares immediately")

            return 0

        else:
            print(f"Error: Invalid mode '{mode}' (must be 'shares' or 'passphrase')", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 9
