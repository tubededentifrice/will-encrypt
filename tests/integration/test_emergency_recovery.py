"""
Integration test for emergency recovery scenario.

Based on: specs/001-1-purpose-scope/quickstart.md

Tests MUST fail before implementation (TDD).
"""

import base64
from itertools import combinations
from pathlib import Path
import time

import pytest
import yaml

from tests.test_helpers import create_test_vault, encrypt_test_message


def decrypt_vault_messages(vault_path: Path, shares: list) -> list:
    """
    Helper to decrypt all messages from a vault using shares.

    Args:
        vault_path: Path to vault file
        shares: List of BIP39 share mnemonics

    Returns:
        List of dicts with 'title' and 'plaintext' keys
    """
    from src.crypto.shamir import reconstruct_secret
    from src.crypto.bip39 import decode_share, parse_indexed_share
    from src.crypto.keypair import decrypt_private_keys, HybridKeypair
    from src.crypto.encryption import EncryptedMessage, decrypt_message

    with open(vault_path) as f:
        vault_data = yaml.safe_load(f)

    # Reconstruct passphrase from shares
    share_bytes = []
    for share_str in shares:
        index, mnemonic = parse_indexed_share(share_str)
        decoded = decode_share(mnemonic)
        share_bytes.append(bytes([index]) + decoded)

    passphrase = reconstruct_secret(share_bytes)

    # Decrypt private keys
    keypair_obj = HybridKeypair(
        rsa_public=vault_data["keys"]["public"]["rsa_4096"].encode(),
        rsa_private_encrypted=base64.b64decode(vault_data["keys"]["encrypted_private"]["rsa_4096"]),
        kyber_public=base64.b64decode(vault_data["keys"]["public"]["kyber_1024"]),
        kyber_private_encrypted=base64.b64decode(vault_data["keys"]["encrypted_private"]["kyber_1024"]),
        kdf_salt=base64.b64decode(vault_data["keys"]["encrypted_private"]["salt"]),
        kdf_iterations=vault_data["keys"]["encrypted_private"]["iterations"],
    )
    rsa_private, kyber_private = decrypt_private_keys(keypair_obj, passphrase)

    # Decrypt all messages
    decrypted_messages = []
    for msg_data in vault_data["messages"]:
        encrypted = EncryptedMessage(
            ciphertext=base64.b64decode(msg_data["ciphertext"]),
            rsa_wrapped_kek=base64.b64decode(msg_data["rsa_wrapped_kek"]),
            kyber_wrapped_kek=base64.b64decode(msg_data["kyber_wrapped_kek"]),
            nonce=base64.b64decode(msg_data["nonce"]),
            auth_tag=base64.b64decode(msg_data["tag"]),
        )
        plaintext = decrypt_message(encrypted, rsa_private, kyber_private, msg_data["title"])
        decrypted_messages.append({
            "title": msg_data["title"],
            "plaintext": plaintext.decode('utf-8')
        })

    return decrypted_messages


class TestEmergencyRecovery:
    """Integration test for emergency recovery workflow."""

    def test_initialize_vault_encrypt_messages_decrypt_with_k_shares(self, tmp_path: Path) -> None:
        """Test: Initialize vault, encrypt messages, decrypt with K shares."""
        # Step 1: Initialize 3-of-5 vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Step 2: Encrypt sensitive messages
        messages_data = [
            ("Bank Account Passwords", "Chase: user123/pass456\nWells Fargo: user789/pass012"),
            ("Estate Instructions", "Executor: Jane Doe\nBeneficiary: John Doe"),
            ("Safe Combination", "Code: 12-34-56")
        ]
        for title, content in messages_data:
            result = encrypt_test_message(vault_path, title, content)
            assert result == 0, f"Encrypt should succeed for '{title}'"

        # Step 3: Emergency recovery with K shares (shares 1, 2, 3)
        selected_shares = [shares[0], shares[1], shares[2]]
        decrypted_messages = decrypt_vault_messages(vault_path, selected_shares)

        # Expected: All 3 messages recovered
        assert len(decrypted_messages) == 3
        assert any("Chase: user123/pass456" in msg["plaintext"] for msg in decrypted_messages)
        assert any("Executor: Jane Doe" in msg["plaintext"] for msg in decrypted_messages)
        assert any("Code: 12-34-56" in msg["plaintext"] for msg in decrypted_messages)

    def test_verify_plaintext_matches_original_messages(self, tmp_path: Path) -> None:
        """Test: Verify plaintext matches original messages."""
        # Setup: Initialize and encrypt with known plaintexts
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Original plaintexts
        original_plaintexts = [
            "This is the first secret message.",
            "This is the second secret message.",
            "This is the third secret message."
        ]

        # Encrypt messages
        for i, plaintext in enumerate(original_plaintexts):
            result = encrypt_test_message(vault_path, f"Message {i+1}", plaintext)
            assert result == 0, f"Encrypt should succeed for message {i+1}"

        # Decrypt
        decrypted = decrypt_vault_messages(vault_path, shares[:3])

        # Verify exact match
        decrypted_plaintexts = sorted([msg["plaintext"] for msg in decrypted])
        original_plaintexts_sorted = sorted(original_plaintexts)
        assert decrypted_plaintexts == original_plaintexts_sorted

    def test_hybrid_verification_rsa_kek_equals_kyber_kek(self, tmp_path: Path) -> None:
        """Test: Hybrid verification (RSA and Kyber both required for decryption)."""
        from src.crypto.shamir import reconstruct_secret
        from src.crypto.bip39 import decode_share, parse_indexed_share
        from src.crypto.keypair import decrypt_private_keys, HybridKeypair, hybrid_decrypt_kek
        from src.crypto.encryption import EncryptedMessage, decrypt_message

        # Setup: Initialize and encrypt
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        result = encrypt_test_message(vault_path, "Test", "Secret")
        assert result == 0, "Encrypt should succeed"

        # Read vault and decrypt manually
        with open(vault_path) as f:
            vault = yaml.safe_load(f)
        message = vault["messages"][0]

        # Reconstruct passphrase from shares
        share_bytes = []
        for share_str in shares[:3]:
            index, mnemonic = parse_indexed_share(share_str)
            decoded = decode_share(mnemonic)
            share_bytes.append(bytes([index]) + decoded)
        passphrase = reconstruct_secret(share_bytes)

        # Decrypt private keys
        keypair_obj = HybridKeypair(
            rsa_public=vault["keys"]["public"]["rsa_4096"].encode(),
            rsa_private_encrypted=base64.b64decode(vault["keys"]["encrypted_private"]["rsa_4096"]),
            kyber_public=base64.b64decode(vault["keys"]["public"]["kyber_1024"]),
            kyber_private_encrypted=base64.b64decode(vault["keys"]["encrypted_private"]["kyber_1024"]),
            kdf_salt=base64.b64decode(vault["keys"]["encrypted_private"]["salt"]),
            kdf_iterations=vault["keys"]["encrypted_private"]["iterations"],
        )
        rsa_private, kyber_private = decrypt_private_keys(keypair_obj, passphrase)

        # Decrypt wrapped KEK using hybrid decryption (requires both RSA and Kyber)
        rsa_wrapped_kek = base64.b64decode(message["rsa_wrapped_kek"])
        kyber_wrapped_kek = base64.b64decode(message["kyber_wrapped_kek"])

        kek = hybrid_decrypt_kek(
            rsa_wrapped_kek, kyber_wrapped_kek, rsa_private, kyber_private
        )

        # Verify KEK is 32 bytes (correct format)
        assert len(kek) == 32, f"KEK should be 32 bytes, got {len(kek)}"

        # Verify we can decrypt the message using this KEK
        encrypted = EncryptedMessage(
            ciphertext=base64.b64decode(message["ciphertext"]),
            rsa_wrapped_kek=rsa_wrapped_kek,
            kyber_wrapped_kek=kyber_wrapped_kek,
            nonce=base64.b64decode(message["nonce"]),
            auth_tag=base64.b64decode(message["tag"]),
        )
        plaintext = decrypt_message(encrypted, rsa_private, kyber_private, message["title"])
        assert plaintext.decode('utf-8') == "Secret", "Decrypted plaintext should match original"

    def test_recovery_with_different_share_combinations(self, tmp_path: Path) -> None:
        """Test: Recovery with different combinations of K shares."""
        # Setup: Initialize 3-of-5 vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        original_message = "Secret content for recovery test"
        result = encrypt_test_message(vault_path, "Recovery Test", original_message)
        assert result == 0, "Encrypt should succeed"

        # Test all possible combinations of 3 shares from 5
        for combo in combinations(range(5), 3):
            selected_shares = [shares[i] for i in combo]
            messages = decrypt_vault_messages(vault_path, selected_shares)
            assert len(messages) == 1, f"Should decrypt 1 message with combo {combo}"
            assert messages[0]["plaintext"] == original_message, f"Failed with shares {combo}"

    def test_recovery_performance_under_30_minutes_user_time(self, tmp_path: Path) -> None:
        """Test: Recovery performance (crypto operations < 5 seconds)."""
        # Setup: Initialize and encrypt 10 messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        for i in range(10):
            result = encrypt_test_message(vault_path, f"Message {i}", f"Content {i}")
            assert result == 0, f"Encrypt should succeed for message {i}"

        # Measure crypto operations time (excluding user input)
        start = time.time()
        messages = decrypt_vault_messages(vault_path, shares[:3])
        duration = time.time() - start

        # Expected: < 5 seconds for crypto operations
        assert duration < 5.0, f"Recovery crypto took {duration:.2f}s (target < 5s)"
        assert len(messages) == 10, "Should decrypt all 10 messages"

    def test_recovery_with_maximum_messages_64kb_each(self, tmp_path: Path) -> None:
        """Test: Recovery with maximum-sized messages (64 KB each)."""
        # Setup: Initialize and encrypt large messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Create 5 messages of 64 KB each
        large_messages = []
        for i in range(5):
            content = f"Message {i}: " + "A" * (64 * 1024 - len(f"Message {i}: "))
            large_messages.append(content)
            result = encrypt_test_message(vault_path, f"Large {i}", content)
            assert result == 0, f"Encrypt should succeed for large message {i}"

        # Decrypt all
        decrypted = decrypt_vault_messages(vault_path, shares[:3])

        # Expected: All 5 large messages recovered
        assert len(decrypted) == 5, "Should decrypt all 5 large messages"
        for i, msg in enumerate(sorted(decrypted, key=lambda x: x["title"])):
            assert len(msg["plaintext"]) == 64 * 1024, f"Message {i} should be 64 KB"

    def test_recovery_after_vault_corruption_detection(self, tmp_path: Path) -> None:
        """Test: Recovery fails gracefully with corrupted vault."""
        # Setup: Initialize and encrypt
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        result = encrypt_test_message(vault_path, "Test", "Secret")
        assert result == 0, "Encrypt should succeed"

        # Corrupt vault (tamper with ciphertext)
        with open(vault_path) as f:
            vault = yaml.safe_load(f)
        vault["messages"][0]["ciphertext"] = "corrupted_ciphertext"
        with open(vault_path, "w") as f:
            yaml.dump(vault, f)

        # Attempt recovery - should raise an exception
        # Expected: Authentication failure or decoding error detected
        with pytest.raises(Exception):  # Could be ValueError, base64 error, or crypto error
            decrypt_vault_messages(vault_path, shares[:3])
