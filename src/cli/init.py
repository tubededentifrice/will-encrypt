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


def init_command(k: int, n: int, vault_path: str, force: bool = False) -> int:
    """Initialize vault with K-of-N threshold."""
    import os

    # Validate args
    if k < 1:
        print("Error: K must be >= 1", file=sys.stderr)
        return 1
    if k > n:
        print("Error: K must be <= N", file=sys.stderr)
        return 1
    if n > 255:
        print("Error: N must be <= 255", file=sys.stderr)
        return 1

    # Check if vault exists
    if os.path.exists(vault_path) and not force:
        print(f"Error: Vault already exists at {vault_path}", file=sys.stderr)
        return 2

    try:
        # Generate passphrase
        passphrase = generate_passphrase()

        # Split into shares
        shares = split_secret(passphrase, k, n)

        # Encode as BIP39 (use 32 bytes of share data, excluding 1-byte index)
        mnemonics = [encode_share(share[1:]) for share in shares]  # Skip index byte, encode remaining 32 bytes

        # Generate keypair
        keypair = generate_hybrid_keypair(passphrase)

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

        # Print shares
        print(f"\\n✓ Vault initialized: {vault_path}")
        print(f"\\nShares ({k}-of-{n}):\\n")
        for i, mnemonic in enumerate(mnemonics, 1):
            print(f"Share {i}:")
            print(f"  {mnemonic}\\n")

        print("⚠️  IMPORTANT: Save these shares securely. They are NOT stored in the vault!")

        # Zero sensitive data
        del passphrase, shares, mnemonics, keypair

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
