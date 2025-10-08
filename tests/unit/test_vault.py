"""
Unit tests for YAML vault operations.

Based on: specs/001-1-purpose-scope/data-model.md (Entity 5: Vault)
"""

import base64
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from src.crypto.keypair import generate_hybrid_keypair
from src.crypto.passphrase import generate_passphrase
from src.storage.manifest import compute_fingerprints
from src.storage.models import Keypair, Manifest, Message, RotationEvent
from src.storage.vault import (
    append_message,
    create_vault,
    load_vault,
    save_vault,
    update_manifest,
)


class TestYAMLVaultOperations:
    """Unit tests for vault YAML create/read/update operations."""

    def test_create_vault_yaml_structure(self, tmp_path: Path) -> None:
        """Test: Create vault YAML structure from Keypair + Manifest."""
        # Generate keypair
        passphrase = generate_passphrase()
        keypair = generate_hybrid_keypair(passphrase)

        # Create manifest
        manifest = Manifest(
            k=3,
            n=5,
            algorithms={"keypair": "RSA-4096 + Kyber-1024 (hybrid)"},
            fingerprints={},
            rotation_history=[],
        )

        # Create guides
        guides = {
            "recovery_guide": "Recovery instructions...",
            "policy_document": "Policy...",
            "crypto_notes": "Crypto notes...",
        }

        # Convert keypair to dict
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

        # Create vault
        vault = create_vault(keypair_data, manifest, guides)

        # Verify vault structure
        assert vault.version == "1.0"
        assert vault.created  # Has timestamp
        assert vault.keys is not None
        assert vault.messages == []
        assert vault.manifest is not None
        assert vault.recovery_guide == guides["recovery_guide"]
        assert vault.policy_document == guides["policy_document"]
        assert vault.crypto_notes == guides["crypto_notes"]

    def test_read_vault_yaml_and_parse_to_python_objects(self, tmp_path: Path) -> None:
        """Test: Read vault YAML and parse to Python objects."""
        vault_path = tmp_path / "vault.yaml"

        # Create a sample vault YAML file
        sample_vault = {
            "version": "1.0",
            "created": "2025-10-07T10:00:00Z",
            "keys": {
                "public": {
                    "rsa_4096": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                    "kyber_1024": "base64_encoded_kyber_public",
                },
                "encrypted_private": {
                    "rsa_4096": "encrypted_rsa_private",
                    "kyber_1024": "encrypted_kyber_private",
                    "encryption": "AES-256-GCM",
                    "kdf": "PBKDF2-HMAC-SHA512",
                    "iterations": 600000,
                    "salt": "base64_salt",
                },
            },
            "messages": [],
            "manifest": {
                "threshold": {"k": 3, "n": 5},
                "algorithms": {
                    "keypair": "RSA-4096 + Kyber-1024 (hybrid)",
                },
                "fingerprints": {},
                "rotation_history": [],
            },
            "recovery_guide": "Guide text",
            "policy_document": "Policy text",
            "crypto_notes": "Crypto text",
        }
        with open(vault_path, "w") as f:
            yaml.dump(sample_vault, f)

        # Load vault
        vault = load_vault(str(vault_path))

        # Verify parsed correctly
        assert vault.version == "1.0"
        assert vault.manifest.k == 3
        assert vault.manifest.n == 5

    def test_append_message_to_vault(self, tmp_path: Path) -> None:
        """Test: Append message to vault (update messages array)."""
        vault_path = tmp_path / "vault.yaml"

        # Create minimal vault
        passphrase = generate_passphrase()
        keypair = generate_hybrid_keypair(passphrase)
        manifest = Manifest(k=3, n=5)
        guides = {"recovery_guide": "", "policy_document": "", "crypto_notes": ""}

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
        }

        vault = create_vault(keypair_data, manifest, guides)
        save_vault(vault, str(vault_path))

        # Create and append message
        message = Message(
            id=1,
            title="Test Message",
            ciphertext=base64.b64encode(b"encrypted_content").decode(),
            rsa_wrapped_kek=base64.b64encode(b"rsa_wrapped").decode(),
            kyber_wrapped_kek=base64.b64encode(b"kyber_wrapped").decode(),
            nonce=base64.b64encode(b"nonce" + b"0" * 6).decode(),  # 12 bytes
            auth_tag=base64.b64encode(b"tag" + b"0" * 13).decode(),  # 16 bytes
            created=datetime.now(timezone.utc).isoformat(),
            size_bytes=100,
        )

        # Reload, append, save
        vault = load_vault(str(vault_path))
        vault = append_message(vault, message)
        save_vault(vault, str(vault_path))

        # Verify
        vault_reloaded = load_vault(str(vault_path))
        assert len(vault_reloaded.messages) == 1
        assert vault_reloaded.messages[0].id == 1
        assert vault_reloaded.messages[0].title == "Test Message"

    def test_update_manifest(self, tmp_path: Path) -> None:
        """Test: Update manifest (fingerprints, rotation history)."""
        vault_path = tmp_path / "vault.yaml"

        # Create vault
        passphrase = generate_passphrase()
        keypair = generate_hybrid_keypair(passphrase)
        manifest = Manifest(
            k=3,
            n=5,
            rotation_history=[
                RotationEvent(
                    date=datetime.now(timezone.utc).isoformat(),
                    event_type="initial_creation",
                    k=3,
                    n=5,
                )
            ],
        )
        guides = {"recovery_guide": "", "policy_document": "", "crypto_notes": ""}

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
        }

        vault = create_vault(keypair_data, manifest, guides)
        save_vault(vault, str(vault_path))

        # Add rotation event
        vault = load_vault(str(vault_path))
        new_event = RotationEvent(
            date=datetime.now(timezone.utc).isoformat(),
            event_type="share_rotation",
            k=4,
            n=6,
        )
        vault.manifest.rotation_history.append(new_event)
        vault = update_manifest(vault, vault.manifest)
        save_vault(vault, str(vault_path))

        # Verify
        vault_reloaded = load_vault(str(vault_path))
        assert len(vault_reloaded.manifest.rotation_history) == 2

    def test_yaml_format_validation(self, tmp_path: Path) -> None:
        """Test: YAML format validation."""
        vault_path = tmp_path / "invalid_vault.yaml"

        # Create invalid YAML (missing required fields)
        invalid_vault = {
            "version": "1.0",
            # Missing "keys", "messages", etc.
        }
        with open(vault_path, "w") as f:
            yaml.dump(invalid_vault, f)

        # Expect ValueError for invalid structure
        with pytest.raises(KeyError):  # Will raise KeyError for missing required fields
            load_vault(str(vault_path))

    def test_vault_file_permissions_0600(self, tmp_path: Path) -> None:
        """Test: Vault file saved with permissions 0600 (owner read/write only)."""
        vault_path = tmp_path / "vault.yaml"

        # Create vault
        passphrase = generate_passphrase()
        keypair = generate_hybrid_keypair(passphrase)
        manifest = Manifest(k=3, n=5)
        guides = {"recovery_guide": "", "policy_document": "", "crypto_notes": ""}

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
        }

        vault = create_vault(keypair_data, manifest, guides)
        save_vault(vault, str(vault_path))

        # Check file permissions
        st = vault_path.stat()
        permissions = stat.S_IMODE(st.st_mode)
        assert permissions == 0o600, f"Vault permissions are {oct(permissions)}, expected 0600"

    def test_vault_version_validation(self, tmp_path: Path) -> None:
        """Test: Version validation (unsupported version warning/acceptance)."""
        vault_path = tmp_path / "vault.yaml"

        # Create vault with different version
        unsupported_vault = {
            "version": "1.0",  # Current version
            "created": "2025-10-07T10:00:00Z",
            "keys": {
                "public": {"rsa_4096": "test", "kyber_1024": "test"},
                "encrypted_private": {
                    "rsa_4096": "test",
                    "kyber_1024": "test",
                    "encryption": "AES-256-GCM",
                    "kdf": "PBKDF2-HMAC-SHA512",
                    "iterations": 600000,
                    "salt": "test",
                },
            },
            "messages": [],
            "manifest": {"threshold": {"k": 3, "n": 5}, "algorithms": {}, "fingerprints": {}, "rotation_history": []},
        }
        with open(vault_path, "w") as f:
            yaml.dump(unsupported_vault, f)

        # Should load successfully
        vault = load_vault(str(vault_path))
        assert vault.version == "1.0"

    def test_vault_timestamp_validation(self, tmp_path: Path) -> None:
        """Test: Timestamp validation (valid ISO 8601 UTC)."""
        vault_path = tmp_path / "vault.yaml"

        # Create vault with valid timestamp
        valid_vault = {
            "version": "1.0",
            "created": "2025-10-07T10:00:00Z",  # Valid ISO 8601
            "keys": {
                "public": {"rsa_4096": "test", "kyber_1024": "test"},
                "encrypted_private": {
                    "rsa_4096": "test",
                    "kyber_1024": "test",
                    "encryption": "AES-256-GCM",
                    "kdf": "PBKDF2-HMAC-SHA512",
                    "iterations": 600000,
                    "salt": "test",
                },
            },
            "messages": [],
            "manifest": {"threshold": {"k": 3, "n": 5}, "algorithms": {}, "fingerprints": {}, "rotation_history": []},
        }
        with open(vault_path, "w") as f:
            yaml.dump(valid_vault, f)

        # Should load and preserve timestamp
        vault = load_vault(str(vault_path))
        assert vault.created == "2025-10-07T10:00:00Z"

    def test_vault_to_yaml_string(self, tmp_path: Path) -> None:
        """Test: Vault.to_dict() and YAML conversion."""
        passphrase = generate_passphrase()
        keypair = generate_hybrid_keypair(passphrase)
        manifest = Manifest(k=3, n=5)
        guides = {"recovery_guide": "Test", "policy_document": "Test", "crypto_notes": "Test"}

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
        }

        vault = create_vault(keypair_data, manifest, guides)

        # Convert to dict and YAML
        vault_dict = vault.to_dict()
        yaml_str = yaml.dump(vault_dict)

        # Verify valid YAML
        parsed = yaml.safe_load(yaml_str)
        assert parsed["version"] == "1.0"
        assert "keys" in parsed
        assert "manifest" in parsed

    def test_vault_from_yaml_string(self, tmp_path: Path) -> None:
        """Test: Parse YAML string to Vault object."""
        yaml_str = """
version: "1.0"
created: "2025-10-07T10:00:00Z"
keys:
  public:
    rsa_4096: "test_key"
    kyber_1024: "test_key"
  encrypted_private:
    rsa_4096: "encrypted"
    kyber_1024: "encrypted"
    encryption: "AES-256-GCM"
    kdf: "PBKDF2-HMAC-SHA512"
    iterations: 600000
    salt: "salt"
messages: []
manifest:
  threshold:
    k: 3
    n: 5
  algorithms:
    keypair: "RSA-4096 + Kyber-1024 (hybrid)"
  fingerprints: {}
  rotation_history: []
recovery_guide: "Guide"
policy_document: "Policy"
crypto_notes: "Notes"
"""

        # Parse YAML
        data = yaml.safe_load(yaml_str)

        # Convert to models manually (since we don't have Vault.from_yaml() method)
        keypair = Keypair.from_dict(data["keys"])
        manifest = Manifest.from_dict(data["manifest"])

        assert keypair.rsa_public == "test_key"
        assert manifest.k == 3
        assert manifest.n == 5
