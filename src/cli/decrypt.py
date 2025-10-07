"""Decrypt command implementation."""
import base64
import sys

from src.crypto.bip39 import decode_share, validate_checksum, parse_indexed_share
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
        print(f"\nError: Vault not found: {vault_path}", file=sys.stderr)
        print(f"Hint: Check the file path and ensure vault exists", file=sys.stderr)
        return 2

    try:
        # Load vault
        vault = load_vault(vault_path)
        k = vault.manifest.k
        n = vault.manifest.n

        # Collect shares with interactive prompts
        if shares is None:
            print(f"\n🔓 Decrypt Vault Messages\n")
            print(f"This vault requires {k} out of {n} shares to decrypt.")
            print(f"Each share is a 24-word BIP39 mnemonic with its original share number.")
            print(f"Format: 'N: word1 word2 ... word24' or just 'word1 word2 ... word24'\n")
            print("-" * 70)
            shares = []
            for i in range(k):
                while True:
                    try:
                        share_str = input(f"\nShare {i+1}/{k}: ").strip()
                        if not share_str:
                            print("  Error: Share cannot be empty. Please try again.")
                            continue

                        # Parse share (with or without index)
                        index, mnemonic = parse_indexed_share(share_str)

                        # Validate format (should be ~24 words in mnemonic part)
                        word_count = len(mnemonic.split())
                        if word_count != 24:
                            print(f"  Warning: Expected 24 words, got {word_count}. Continue anyway? (yes/no): ", end="")
                            confirm = input().strip().lower()
                            if confirm != "yes":
                                continue

                        # Validate BIP39 checksum immediately
                        if not validate_checksum(mnemonic):
                            print(f"  ✗ Invalid BIP39 checksum. Please check for typos.")
                            retry = input(f"  Retry share {i+1}? (yes/no): ").strip().lower()
                            if retry != "yes":
                                print("\nAborted.", file=sys.stderr)
                                return 4
                            continue

                        # If no index was provided, ask for it
                        if index is None:
                            while True:
                                try:
                                    idx_input = input(f"  Enter the original share number (1-{n}): ").strip()
                                    index = int(idx_input)
                                    if index < 1 or index > n:
                                        print(f"    Error: Share number must be 1-{n}")
                                        continue
                                    break
                                except ValueError:
                                    print(f"    Error: Invalid number")
                                    continue

                        print(f"  ✓ Share {index} validated")
                        # Store with index prefix for later parsing
                        shares.append(f"{index}: {mnemonic}")
                        break
                    except (EOFError, KeyboardInterrupt):
                        print("\n\nAborted.", file=sys.stderr)
                        return 1

        # Validate shares count
        if len(shares) < k:
            print(f"\nError: Insufficient shares (need {k}, got {len(shares)})", file=sys.stderr)
            print(f"Recovery: Collect at least {k - len(shares)} more share(s) from key holders", file=sys.stderr)
            return 3

        # Parse and validate shares
        print(f"\n🔍 Validating shares...")
        share_bytes = []
        missing_indices = []

        for share_str in shares[:k]:
            # Parse share with index
            index, mnemonic = parse_indexed_share(share_str)

            # Validate BIP39 checksum
            if not validate_checksum(mnemonic):
                print(f"\nError: Invalid BIP39 checksum in share", file=sys.stderr)
                print(f"Recovery: Check for typos in the mnemonic. The last word contains a checksum.", file=sys.stderr)
                print(f"Hint: Use 'abandon ability able...' format (24 words, space-separated)", file=sys.stderr)
                return 4

            if index is None:
                missing_indices.append(mnemonic)
            else:
                decoded = decode_share(mnemonic)  # Returns 32 bytes
                # Prepend ORIGINAL index to make 33-byte share
                share_bytes.append(bytes([index]) + decoded)

        # Handle missing indices (interactive prompt)
        if missing_indices:
            print(f"\n⚠️  Warning: {len(missing_indices)} share(s) missing index information")
            print(f"Please provide the original share numbers for correct reconstruction.\n")

            for missing_mnemonic in missing_indices:
                while True:
                    try:
                        idx_input = input(f"Enter share number for '{missing_mnemonic[:40]}...': ").strip()
                        index = int(idx_input)
                        if index < 1 or index > 255:
                            print(f"  Error: Share index must be 1-255")
                            continue
                        decoded = decode_share(missing_mnemonic)
                        share_bytes.append(bytes([index]) + decoded)
                        break
                    except ValueError:
                        print(f"  Error: Invalid number")
                        continue

        print(f"  ✓ All {len(share_bytes)} shares validated")

        # Reconstruct passphrase
        print(f"\n🔓 Decrypting vault...")
        print(f"  [1/3] Reconstructing passphrase from {len(share_bytes)} shares...")
        passphrase = reconstruct_secret(share_bytes)
        print(f"        ✓ Passphrase reconstructed")

        # Decrypt private keys
        print(f"  [2/3] Decrypting RSA-4096 + Kyber-1024 private keys...")
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
        print(f"        ✓ Private keys decrypted")

        # Decrypt messages
        print(f"  [3/3] Decrypting {len(vault.messages)} message(s)...")
        decrypted_messages = []
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
            decrypted_messages.append((msg, plaintext))

        print(f"        ✓ All messages decrypted\n")

        # Pretty print decrypted messages
        print("=" * 70)
        print(f"📬 Decrypted Messages ({len(decrypted_messages)})")
        print("=" * 70 + "\n")

        for msg, plaintext in decrypted_messages:
            print(f"╔══ Message {msg.id}: {msg.title}")
            print(f"║")
            print(f"║ Created: {msg.created}")
            print(f"║ Size: {msg.size_bytes:,} bytes")
            print(f"║")
            print(f"╠══ Content:")
            print(f"║")
            # Indent content
            content_lines = plaintext.decode('utf-8').split('\n')
            for line in content_lines:
                print(f"║   {line}")
            print(f"║")
            print("╚" + "═" * 68 + "\n")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 7
