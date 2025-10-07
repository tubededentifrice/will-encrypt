"""Init command implementation."""
import base64
import sys
from datetime import datetime, timezone

from src.crypto.bip39 import encode_share
from src.crypto.keypair import generate_hybrid_keypair
from src.crypto.passphrase import generate_passphrase
from src.crypto.shamir import split_secret
from src.docs.crypto_notes import generate_crypto_notes
from src.docs.policy import generate_policy_document
from src.docs.recovery_guide import generate_recovery_guide
from src.storage.manifest import RotationEvent, compute_fingerprints
from src.storage.models import Manifest
from src.storage.vault import create_vault, save_vault


def init_command(k: int = None, n: int = None, vault_path: str = "vault.yaml", force: bool = False) -> int:
    """Initialize vault with K-of-N threshold."""
    import os

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
        # Progress: Generate passphrase
        print(f"\n[1/4] Generating 384-bit passphrase...")
        passphrase = generate_passphrase()
        print("      ✓ Passphrase generated")

        # Progress: Split into shares
        print(f"[2/4] Splitting passphrase into {n} shares (threshold: {k})...")
        shares = split_secret(passphrase, k, n)
        print(f"      ✓ {n} shares created using Shamir Secret Sharing")

        # Encode as BIP39 (use 32 bytes of share data, excluding 1-byte index)
        print(f"[3/4] Encoding shares as BIP39 mnemonics...")
        mnemonics = [encode_share(share[1:]) for share in shares]  # Skip index byte, encode remaining 32 bytes
        print(f"      ✓ {n} × 24-word mnemonics generated")

        # Progress: Generate keypair
        print(f"[4/4] Generating RSA-4096 + Kyber-1024 keypair...")
        keypair = generate_hybrid_keypair(passphrase)
        print("      ✓ Hybrid keypair generated and encrypted")

        # Create manifest
        manifest = Manifest(
            k=k,
            n=n,
            algorithms={
                "keypair": "RSA-4096 + Kyber-1024 (hybrid)",
                "passphrase_entropy": 384,
                "secret_sharing": "Shamir SSS over GF(256)",
                "message_encryption": "AES-256-GCM",
                "kdf": "PBKDF2-HMAC-SHA512 (600k iterations)",
            },
            fingerprints={},
            rotation_history=[
                RotationEvent(
                    date=datetime.now(timezone.utc).isoformat(),
                    event_type="initial_creation",
                    k=k,
                    n=n,
                )
            ],
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
        vault.manifest.fingerprints = compute_fingerprints(vault)

        # Save vault
        save_vault(vault, vault_path)

        # Print shares with clear instructions
        print(f"\n{'='*70}")
        print(f"✓ Vault initialized successfully: {vault_path}")
        print(f"{'='*70}\n")

        print(f"📋 Secret Shares ({k}-of-{n} threshold)\n")
        print(f"⚠️  CRITICAL: These shares are displayed ONCE and never stored!")
        print(f"    • Distribute to {n} different key holders")
        print(f"    • {k} shares required to decrypt messages")
        print(f"    • Each share is 24 words (BIP39 mnemonic)")
        print(f"    • Store securely: paper backup, password manager, or HSM\n")
        print(f"{'-'*70}\n")

        for i, mnemonic in enumerate(mnemonics, 1):
            print(f"Share {i}/{n}:")
            print(f"  {mnemonic}\n")

        print(f"{'-'*70}\n")
        print("📝 Next Steps:")
        print("  1. Copy each share to a secure location (paper, password manager)")
        print("  2. Distribute shares to key holders via secure channels")
        print("  3. Test decryption immediately with K shares")
        print(f"  4. Add messages: will-encrypt encrypt --vault {vault_path} --title '...'")
        print(f"\n✓ Setup complete. Vault ready for encryption.")

        # Zero sensitive data
        del passphrase, shares, mnemonics, keypair

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
