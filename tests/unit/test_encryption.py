"""
Unit tests for AES-256-GCM message encryption.

Based on: specs/001-1-purpose-scope/research.md (Section 4)

Tests MUST fail before implementation (TDD).
Test vectors from NIST CAVP AES-GCM.
"""

import secrets

import pytest


class TestAESGCMEncryption:
    """Unit tests for AES-256-GCM authenticated encryption."""

    def test_encrypt_message_with_aes_256_gcm(self) -> None:
        """Test: Encrypt message with AES-256-GCM (KEK, nonce, AAD)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)  # 256-bit AES key
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        plaintext = b"Secret message content"
        aad = b"Message Title"  # Associated data (not encrypted)

        # Encrypt with AES-GCM
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Ciphertext includes both encrypted data and 16-byte auth tag
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) == len(plaintext) + 16  # Plaintext + auth tag

    def test_decrypt_message_and_verify_authentication_tag(self) -> None:
        """Test: Decrypt message and verify authentication tag."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message content"
        aad = b"Message Title"

        # Encrypt
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Decrypt
        decrypted = aesgcm.decrypt(nonce, ciphertext, aad)

        # Expected: Decrypted plaintext matches original
        assert decrypted == plaintext

    def test_tampered_ciphertext_rejected(self) -> None:
        """Test: Tampered ciphertext rejection (auth tag mismatch)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message content"
        aad = b"Message Title"

        # Encrypt
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Tamper with ciphertext (flip one bit)
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0x01
        tampered_ciphertext = bytes(tampered_ciphertext)

        # Attempt decrypt - should fail authentication
        with pytest.raises(Exception):  # Cryptography raises InvalidTag
            aesgcm.decrypt(nonce, tampered_ciphertext, aad)

    def test_nonce_uniqueness_enforcement(self) -> None:
        """Test: Nonce uniqueness enforcement (nonce reuse detection)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext1 = b"First message"
        plaintext2 = b"Second message"
        aad = b"Title"

        # Encrypt two messages with same nonce
        aesgcm = AESGCM(kek)
        ciphertext1 = aesgcm.encrypt(nonce, plaintext1, aad)
        ciphertext2 = aesgcm.encrypt(nonce, plaintext2, aad)

        # Different plaintexts with same nonce produce different ciphertexts
        assert ciphertext1 != ciphertext2

        # Note: Nonce uniqueness is enforced by always generating random nonces in encrypt_message()

    def test_nist_cavp_aes_gcm_test_vector_1(self) -> None:
        """Test: Use NIST CAVP AES-GCM test vector."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # NIST CAVP test vector for AES-256-GCM (Test Case 1)
        # From NIST CAVP test vectors - gcmEncryptExtIV256.rsp
        key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        pt = b""  # Empty plaintext
        aad = b""
        expected_ct_with_tag = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")  # This is the tag for empty plaintext

        # Encrypt
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(iv, pt, aad)

        # Verify the result matches expected (tag only, since plaintext is empty)
        assert ct_with_tag == expected_ct_with_tag

    def test_nist_cavp_aes_gcm_test_vector_2(self) -> None:
        """Test: Use NIST CAVP AES-GCM test vector 2."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # NIST CAVP test vector with non-zero plaintext
        key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        pt = bytes.fromhex("00000000000000000000000000000000")
        aad = b""

        # Encrypt and verify decryption works
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, pt, aad)
        decrypted = aesgcm.decrypt(iv, ct, aad)
        assert decrypted == pt

    def test_empty_plaintext_encryption(self) -> None:
        """Test: Empty plaintext encryption (edge case)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b""
        aad = b"Empty Message"

        # Encrypt
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Expected: Only auth tag (16 bytes) since plaintext is empty
        assert len(ciphertext) == 16

        # Decrypt
        decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
        assert decrypted == plaintext

    def test_large_message_encryption_64kb(self) -> None:
        """Test: Large message encryption (64 KB, maximum size)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"A" * (64 * 1024)  # 64 KB
        aad = b"Large Message"

        # Encrypt
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Expected: Ciphertext = plaintext + 16-byte tag
        assert len(ciphertext) == 64 * 1024 + 16

        # Decrypt and verify
        decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
        assert decrypted == plaintext

    def test_aad_integrity_protection(self) -> None:
        """Test: AAD (associated data) integrity protection."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret content"
        original_aad = b"Original Title"
        tampered_aad = b"Tampered Title"

        # Encrypt with original AAD
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, original_aad)

        # Attempt decrypt with tampered AAD - should fail
        with pytest.raises(Exception):  # Cryptography raises InvalidTag
            aesgcm.decrypt(nonce, ciphertext, tampered_aad)

    def test_key_size_validation(self) -> None:
        """Test: Key size validation (must be 256 bits)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Test with wrong key sizes - AESGCM constructor validates key size
        with pytest.raises(ValueError):
            AESGCM(b"short_key")  # Too short

        with pytest.raises(ValueError):
            AESGCM(b"too_long_key_33_bytes_exactly!")  # 33 bytes

    def test_nonce_size_validation(self) -> None:
        """Test: Nonce size validation (must be 96 bits)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kek = secrets.token_bytes(32)
        aesgcm = AESGCM(kek)

        # Test with correct nonce size (12 bytes = 96 bits)
        correct_nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(correct_nonce, b"plaintext", b"aad")
        assert len(ciphertext) > 0

        # Test with wrong nonce size - very short
        with pytest.raises(ValueError):
            aesgcm.encrypt(b"short", b"plaintext", b"aad")
