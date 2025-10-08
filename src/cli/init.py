"""Init command implementation."""
import base64
import os
import sys
from datetime import UTC, datetime

from src.cli.share_table import render_share_table
from src.crypto.bip39 import (
    decode_share,
    encode_share,
    format_indexed_share,
    parse_indexed_share,
    validate_checksum,
)
from src.crypto.keypair import generate_hybrid_keypair
from src.crypto.passphrase import generate_passphrase
from src.crypto.shamir import generate_additional_shares, reconstruct_secret, split_secret
from src.docs.crypto_notes import generate_crypto_notes
from src.docs.policy import generate_policy_document
from src.docs.recovery_guide import generate_recovery_guide
from src.storage.manifest import (
    RotationEvent,
    compute_fingerprints,
    create_share_fingerprints,
    match_share_fingerprint,
)
from src.storage.models import Manifest
from src.storage.vault import create_vault, load_vault, save_vault


def init_command(
    k: int | None = None,
    n: int | None = None,
    vault_path: str = "vault.yaml",
    force: bool = False,
    import_shares: list | None = None,
    source_vault: str | None = None,
) -> int:
    """Initialize vault with K-of-N threshold."""
    # Interactive prompts for K and N if not provided
    if k is None:
        try:
            print("\n🔐 Will-Encrypt Vault Initialization\n")
            print("This will create a new encrypted vault using threshold cryptography.")
            print("You'll receive N secret shares, and K shares are needed to decrypt.\n")
            k_input = input("Enter threshold K (minimum shares needed to decrypt): ").strip()
            k = int(k_input)
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nError: Invalid input for K", file=sys.stderr)
            return 1

    if n is None:
        try:
            n_input = input(f"Enter total shares N (K={k}, typically N > K for redundancy): ").strip()
            n = int(n_input)
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nError: Invalid input for N", file=sys.stderr)
            return 1

    # Validate args
    if k < 1:
        print("\nError: K must be >= 1", file=sys.stderr)
        print("Hint: K is the minimum number of shares needed to decrypt", file=sys.stderr)
        return 1
    if k > n:
        print(f"\nError: K must be <= N (got K={k}, N={n})", file=sys.stderr)
        print("Hint: You need at least K shares out of N total shares", file=sys.stderr)
        return 1
    if n > 255:
        print("\nError: N must be <= 255", file=sys.stderr)
        print("Hint: Shamir Secret Sharing supports up to 255 shares", file=sys.stderr)
        return 1

    existing_share_fingerprints = []
    source_vault_fingerprints_found = False
    source_vault_error: str | None = None
    if import_shares:
        candidate_paths = []
        if source_vault:
            candidate_paths.append(source_vault)
        env_source = os.getenv("WILL_ENCRYPT_SOURCE_VAULT")
        if env_source:
            candidate_paths.append(env_source)
        if os.path.exists(vault_path):
            candidate_paths.append(vault_path)

        # Deduplicate paths while preserving priority order (env first, then target vault).
        candidate_paths = list(dict.fromkeys(candidate_paths))

        seen_fingerprint_keys = set()
        for candidate_path in candidate_paths:
            try:
                candidate_vault = load_vault(candidate_path)
            except FileNotFoundError:
                if source_vault and os.path.abspath(candidate_path) == os.path.abspath(source_vault):
                    source_vault_error = f"Source vault not found: {candidate_path}"
                continue
            except Exception as exc:  # pragma: no cover - defensive: log and continue
                if source_vault and os.path.abspath(candidate_path) == os.path.abspath(source_vault):
                    source_vault_error = f"Failed to read source vault: {exc}"
                else:
                    print(
                        f"Warning: Unable to read existing vault at {candidate_path}: {exc}",
                        file=sys.stderr,
                    )
                continue

            if not candidate_vault.manifest:
                continue

            for fingerprint in candidate_vault.manifest.share_fingerprints:
                key = (fingerprint.index, fingerprint.hash)
                if key in seen_fingerprint_keys:
                    continue
                existing_share_fingerprints.append(fingerprint)
                seen_fingerprint_keys.add(key)
                if source_vault and os.path.abspath(candidate_path) == os.path.abspath(source_vault):
                    source_vault_fingerprints_found = True

        if source_vault and not source_vault_fingerprints_found:
            error_message = source_vault_error or (
                f"Source vault manifest missing share fingerprints: {source_vault}"
            )
            print(f"\nError: {error_message}", file=sys.stderr)
            print("Recovery: Verify the --source-vault path and ensure it contains a valid manifest", file=sys.stderr)
            return 6

    # Handle interactive import of shares
    num_shares_to_import = 0
    if import_shares is None and k is not None:
        try:
            print("\n📥 Share Import (Optional)\n")
            print("You can import existing BIP39 shares to reuse the same passphrase.")
            print("This allows multiple vaults to share the same underlying key material.")
            print("")
            print("⚠️  SECURITY WARNING:")
            print("   Reusing shares across vaults means compromising one vault")
            print("   compromises ALL vaults using the same shares.")
            print("")
            import_choice = input("Do you want to use existing shares? (yes/no): ").strip().lower()

            if import_choice == "yes":
                import_shares = []
                print(f"\nYou need to provide at least {k} shares to reconstruct the passphrase.")
                print(f"The remaining {n} - (imported count) shares will be newly generated.")

                try:
                    num_shares_str = input(f"How many shares do you want to import? (min {k}, max {n}): ").strip()
                    num_shares_to_import = int(num_shares_str)

                    if num_shares_to_import < k:
                        print(f"\nError: You must import at least {k} shares to reconstruct the passphrase", file=sys.stderr)
                        return 1

                    if num_shares_to_import > n:
                        print(f"\nError: Cannot import more than {n} shares (total share count)", file=sys.stderr)
                        return 1

                    print("")
                    for i in range(num_shares_to_import):
                        while True:
                            share_str = input(f"Enter share {i+1}: ").strip()
                            if not share_str:
                                print("  Error: Share cannot be empty. Please try again.")
                                continue

                            # Validate format
                            word_count = len(share_str.split())
                            if word_count != 24:
                                print(f"  Warning: Expected 24 words, got {word_count}.")
                                retry = input("  Continue with this share? (yes/no): ").strip().lower()
                                if retry != "yes":
                                    continue

                            # Validate BIP39 checksum
                            if not validate_checksum(share_str):
                                print("  ✗ Invalid BIP39 checksum. Please check for typos.")
                                retry = input(f"  Retry share {i+1}? (yes/no): ").strip().lower()
                                if retry != "yes":
                                    print("\nAborted.", file=sys.stderr)
                                    return 4
                                continue

                            print(f"  ✓ Share {i+1} validated")
                            import_shares.append(share_str)
                            break

                except ValueError:
                    print("\nError: Invalid input", file=sys.stderr)
                    return 1

        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            return 1

    # Check if vault exists
    if os.path.exists(vault_path):
        if not force:
            print(f"\n⚠️  Warning: Vault already exists at {vault_path}", file=sys.stderr)
            try:
                confirm = input("Overwrite existing vault? This will DESTROY all data! (yes/no): ").strip().lower()
                if confirm != "yes":
                    print("Aborted.", file=sys.stderr)
                    return 2
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.", file=sys.stderr)
                return 2
        print(f"\nOverwriting existing vault at {vault_path}...")

    try:
        # Handle passphrase generation or reconstruction from imported shares
        imported_share_indices = set()  # Track which indices came from imported shares
        if import_shares:
            # Validate imported shares
            print(f"\n🔍 Validating {len(import_shares)} imported share(s)...")

            if len(import_shares) < k:
                print(f"\nError: Insufficient shares (need {k}, got {len(import_shares)})", file=sys.stderr)
                print(f"Recovery: Provide at least {k} shares to reconstruct passphrase", file=sys.stderr)
                return 5

            # Validate all checksums
            for i, share_str in enumerate(import_shares, 1):
                if not validate_checksum(share_str):
                    print(f"\nError: Invalid BIP39 checksum in imported share {i}", file=sys.stderr)
                    print("Recovery: Check for typos in the mnemonic", file=sys.stderr)
                    return 4

            print(f"      ✓ All {len(import_shares)} share(s) validated")

            # Decode shares and reconstruct passphrase
            print(f"\n[1/4] Reconstructing passphrase from {len(import_shares)} imported share(s)...")
            share_bytes = []
            used_indices = set()
            unresolved_shares: list[tuple[str, bytes]] = []
            available_fingerprints = existing_share_fingerprints.copy()

            for share_str in import_shares[:k]:  # Use first K shares
                # Parse share with index (if provided)
                index, mnemonic = parse_indexed_share(share_str)
                decoded = decode_share(mnemonic)  # Returns 32 bytes

                if index is None and available_fingerprints:
                    matched = match_share_fingerprint(available_fingerprints, decoded)
                    if matched and matched.index not in used_indices:
                        index = matched.index
                        available_fingerprints.remove(matched)
                        print(
                            f"      ↺ Auto-detected share index {index} via manifest fingerprint"
                        )

                if index is None:
                    unresolved_shares.append((share_str, decoded))
                    continue

                if index < 1 or index > 255:
                    print(
                        f"\nError: Share index must be 1-255 (got {index})",
                        file=sys.stderr,
                    )
                    return 5

                if index in used_indices:
                    print(
                        f"\nError: Duplicate share index detected ({index})",
                        file=sys.stderr,
                    )
                    print("Recovery: Provide each share only once", file=sys.stderr)
                    return 5

                share_bytes.append(bytes([index]) + decoded)
                used_indices.add(index)
                imported_share_indices.add(index)

            # If any shares are missing indices, prompt user
            if unresolved_shares:
                print(f"\n⚠️  Warning: {len(unresolved_shares)} share(s) missing index information")
                print("Attempting manual recovery. Original numbering is required for reconstruction.\n")

                for missing_share, decoded in unresolved_shares:
                    preview = missing_share[:40].strip()
                    while True:
                        try:
                            idx_input = input(
                                f"Enter share number for '{preview}...': "
                            ).strip()
                            index = int(idx_input)
                            if index < 1 or index > 255:
                                print("  Error: Share index must be 1-255")
                                continue
                            if index in used_indices:
                                print("  Error: Share index already used")
                                continue
                            share_bytes.append(bytes([index]) + decoded)
                            used_indices.add(index)
                            imported_share_indices.add(index)
                            break
                        except ValueError:
                            print("  Error: Invalid number")
                            continue

            if len(share_bytes) < k:
                print(f"\nError: Insufficient valid shares (need {k}, got {len(share_bytes)})", file=sys.stderr)
                return 5

            passphrase = reconstruct_secret(share_bytes)
            print("      ✓ Passphrase reconstructed from imported shares")

            # Keep imported shares and generate additional new shares from same polynomial
            print(f"[2/4] Generating {n - len(import_shares)} additional shares (threshold: {k})...")
            num_new_shares = n - len(import_shares)

            if num_new_shares > 0:
                # Find available indices for new shares (avoid imported indices)
                new_indices = []
                next_available_index = 1
                while len(new_indices) < num_new_shares:
                    if next_available_index not in used_indices:
                        new_indices.append(next_available_index)
                    next_available_index += 1

                # Generate additional shares from the same polynomial
                additional_shares = generate_additional_shares(share_bytes, new_indices)

                # Combine imported + newly generated shares
                shares = share_bytes + additional_shares
                print(f"      ✓ {n} total shares: {len(import_shares)} imported + {num_new_shares} newly generated")
            else:
                # All shares are imported (num_shares_to_import == n)
                shares = share_bytes
                print(f"      ✓ Using all {n} imported shares")

            # Mark which shares are imported for display purposes
            imported_share_indices = {share[0] for share in share_bytes}

            # Encode as BIP39 (preserve indices)
            print("[3/4] Encoding shares as BIP39 mnemonics...")
            indexed_mnemonics = []
            for share in shares:
                index = share[0]  # Extract remapped index
                mnemonic = encode_share(share[1:])  # Encode remaining 32 bytes
                indexed_mnemonics.append((index, mnemonic))
            print(f"      ✓ {n} × 24-word mnemonics generated")

        else:
            # Progress: Generate passphrase
            print("\n[1/4] Generating 256-bit passphrase...")
            passphrase = generate_passphrase()
            print("      ✓ Passphrase generated")

            # Progress: Split into shares
            print(f"[2/4] Splitting passphrase into {n} shares (threshold: {k})...")
            shares = split_secret(passphrase, k, n)
            print(f"      ✓ {n} shares created using Shamir Secret Sharing")

            # Encode as BIP39 (preserve original indices)
            print("[3/4] Encoding shares as BIP39 mnemonics...")
            indexed_mnemonics = []
            for share in shares:
                index = share[0]  # Extract original index
                mnemonic = encode_share(share[1:])  # Encode remaining 32 bytes
                indexed_mnemonics.append((index, mnemonic))
            print(f"      ✓ {n} × 24-word mnemonics generated")

        share_fingerprints = create_share_fingerprints(shares)

        # Progress: Generate keypair
        print("[4/4] Generating RSA-4096 + Kyber-1024 keypair...")
        keypair = generate_hybrid_keypair(passphrase)
        print("      ✓ Hybrid keypair generated and encrypted")

        # Create manifest
        manifest = Manifest(
            k=k,
            n=n,
            algorithms={
                "keypair": "RSA-4096 + Kyber-1024 (hybrid)",
                "passphrase_entropy": 256,
                "secret_sharing": "Shamir SSS over GF(256)",
                "message_encryption": "AES-256-GCM",
                "kdf": "PBKDF2-HMAC-SHA512 (600k iterations)",
            },
            fingerprints={},
            rotation_history=[
                RotationEvent(
                    date=datetime.now(UTC).isoformat(),
                    event_type="initial_creation",
                    k=k,
                    n=n,
                )
            ],
            share_fingerprints=share_fingerprints,
        )

        # Generate guides
        guides = {
            "recovery_guide": generate_recovery_guide(k, n),
            "policy_document": generate_policy_document(),
            "crypto_notes": generate_crypto_notes(manifest.to_dict()),
        }

        # Create vault
        keypair_data = {
            "rsa_public": keypair.rsa_public.decode(),
            "rsa_private_encrypted": base64.b64encode(
                keypair.rsa_private_encrypted
            ).decode(),
            "kyber_public": base64.b64encode(keypair.kyber_public).decode(),
            "kyber_private_encrypted": base64.b64encode(
                keypair.kyber_private_encrypted
            ).decode(),
            "kdf_salt": base64.b64encode(keypair.kdf_salt).decode(),
            "kdf_iterations": keypair.kdf_iterations,
        }

        vault = create_vault(keypair_data, manifest, guides)

        # Update fingerprints
        if vault.manifest is None:
            print("\nError: Vault manifest is missing", file=sys.stderr)
            return 2
        vault.manifest.fingerprints = compute_fingerprints(vault)

        # Save vault
        save_vault(vault, vault_path)

        # Print shares with clear instructions
        print(f"\n{'='*70}")
        print(f"✓ Vault initialized successfully: {vault_path}")
        print(f"{'='*70}\n")

        if import_shares:
            print(f"📋 Secret Shares ({k}-of-{n} threshold) - RECONSTRUCTED FROM IMPORTED SHARES\n")
            print("⚠️  SECURITY WARNING:")
            print("    • These shares use the SAME passphrase as the imported shares")
            print("    • Compromising one vault compromises ALL vaults with this passphrase")
            print("    • Only use this feature if you understand the security implications\n")
        else:
            print(f"📋 Secret Shares ({k}-of-{n} threshold)\n")

        print("⚠️  CRITICAL: These shares are displayed ONCE and never stored!")
        print(f"    • Distribute to {n} different key holders")
        print(f"    • {k} shares required to decrypt messages")
        print("    • Each share is 24 words (BIP39 mnemonic)")
        print("    • Share numbers are CRITICAL - they must be preserved with the mnemonics")
        print("    • Store securely: paper backup, password manager, or HSM\n")
        print(f"{'-'*70}\n")

        # Print inline format for easy copy-pasting
        for index, mnemonic in indexed_mnemonics:
            # Mark if this is an imported share
            share_type = " [IMPORTED]" if index in imported_share_indices else " [NEWLY GENERATED]"
            print(f"Share {index}/{n}{share_type if import_shares else ''}:")
            print(f"  {format_indexed_share(index, mnemonic)}\n")

        print(f"{'-'*70}\n")
        print("📊 Numbered Share Tables (for manual transcription)\n")

        # Print table format for manual transcription
        table_output = render_share_table(indexed_mnemonics)
        if table_output:
            print(table_output)
            print()
        print(f"{'-'*70}\n")
        print("📝 Next Steps:")
        print("  1. Copy each share to a secure location (paper, password manager)")
        print("  2. Distribute shares to key holders via secure channels")
        print("  3. Test decryption immediately with K shares")
        print(f"  4. Add messages: will-encrypt encrypt --vault {vault_path} --title '...'")
        print("\n✓ Setup complete. Vault ready for encryption.")

        # Zero sensitive data
        del passphrase, shares, indexed_mnemonics, keypair, share_fingerprints

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
