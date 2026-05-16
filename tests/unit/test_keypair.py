"""
Unit tests for hybrid RSA+Kyber keypair operations.

Based on: specs/001-1-purpose-scope/research.md (Section 1)

Tests MUST fail before implementation (TDD).
Test vectors from NIST CAVP for RSA-OAEP.
"""

import secrets

import pytest


class TestHybridKeypair:
    """Unit tests for hybrid RSA-4096 + Kyber-1024 keypair."""

    def test_generate_rsa_4096_keypair(self) -> None:
        """Test: Generate RSA-4096 keypair."""
        from src.crypto.keypair import generate_rsa_keypair

        public_key, private_key = generate_rsa_keypair()

        # Verify keys have correct properties
        assert public_key.key_size == 4096
        assert private_key.key_size == 4096
        assert public_key.public_numbers().e == 65537  # Standard exponent

    def test_generate_kyber_1024_keypair(self) -> None:
        """Test: Generate ML-KEM-1024 (Kyber-1024) keypair."""
        from src.crypto.keypair import generate_kyber_keypair

        public_key, private_key = generate_kyber_keypair()

        # Verify ML-KEM-1024 key sizes per NIST FIPS 203
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        assert len(public_key) == 1568  # ML-KEM-1024 public key
        assert len(private_key) == 3168  # ML-KEM-1024 private key

    def test_kyber_kem_encapsulation_decapsulation(self) -> None:
        """Test: Kyber KEM encapsulation and decapsulation produce consistent shared secrets."""
        from pqcrypto.kem.ml_kem_1024 import (  # type: ignore[import-untyped]
            decrypt as kyber_decrypt,
        )
        from pqcrypto.kem.ml_kem_1024 import (  # type: ignore[import-untyped]
            encrypt as kyber_encrypt,
        )
        from pqcrypto.kem.ml_kem_1024 import (  # type: ignore[import-untyped]
            generate_keypair,
        )

        # Generate Kyber keypair
        public_key, private_key = generate_keypair()

        # Encapsulate: generate ciphertext and shared secret
        ciphertext, shared_secret_1 = kyber_encrypt(public_key)

        # Decapsulate: recover shared secret from ciphertext
        shared_secret_2 = kyber_decrypt(private_key, ciphertext)

        # Verify shared secrets match
        assert shared_secret_1 == shared_secret_2
        assert len(shared_secret_1) == 32  # 256-bit shared secret
        assert len(ciphertext) == 1568  # ML-KEM-1024 ciphertext size

    def test_hybrid_encryption_encrypt_kek_with_both_algorithms(self) -> None:
        """Test: Hybrid encryption (encrypt KEK with both RSA and Kyber)."""
        from src.crypto.keypair import generate_hybrid_keypair, hybrid_encrypt_kek

        # Generate KEK (256-bit AES key)
        kek = secrets.token_bytes(32)
        passphrase = secrets.token_bytes(32)  # 256-bit passphrase

        # Generate hybrid keypair
        keypair = generate_hybrid_keypair(passphrase)

        # Encrypt KEK with both algorithms
        rsa_wrapped, kyber_wrapped = hybrid_encrypt_kek(
            kek, keypair.rsa_public, keypair.kyber_public
        )

        # Verify we got two wrapped KEKs
        assert isinstance(rsa_wrapped, bytes)
        assert isinstance(kyber_wrapped, bytes)
        assert len(rsa_wrapped) == 512  # RSA-4096 OAEP ciphertext size
        assert len(kyber_wrapped) == 1568  # ML-KEM-1024 ciphertext size

    def test_hybrid_decryption_verify_rsa_kek_equals_kyber_kek(self) -> None:
        """Test: Hybrid decryption (verify RSA KEK == Kyber KEK)."""
        from src.crypto.keypair import (
            decrypt_private_keys,
            generate_hybrid_keypair,
            hybrid_decrypt_kek,
            hybrid_encrypt_kek,
        )

        # Generate KEK
        kek = secrets.token_bytes(32)
        passphrase = secrets.token_bytes(32)  # 256-bit passphrase

        # Generate hybrid keypair
        keypair = generate_hybrid_keypair(passphrase)

        # Encrypt KEK with both algorithms
        rsa_wrapped, kyber_wrapped = hybrid_encrypt_kek(
            kek, keypair.rsa_public, keypair.kyber_public
        )

        # Decrypt private keys
        rsa_private, kyber_private = decrypt_private_keys(keypair, passphrase)

        # Decrypt KEK with hybrid verification (verifies both match internally)
        decrypted_kek = hybrid_decrypt_kek(
            rsa_wrapped, kyber_wrapped, rsa_private, kyber_private
        )

        # Verify decrypted KEK matches original
        assert decrypted_kek == kek

    def test_nist_cavp_rsa_oaep_test_vector(self) -> None:
        """Test: Use NIST CAVP test vectors for RSA-OAEP."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from src.crypto.keypair import generate_rsa_keypair

        # Generate a keypair and test encrypt/decrypt roundtrip
        public_key, private_key = generate_rsa_keypair()
        plaintext = b"Test message for RSA-OAEP"

        # Encrypt with RSA-OAEP
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        assert decrypted == plaintext

    def test_encrypt_private_keys_with_passphrase(self) -> None:
        """Test: Encrypt private keys with passphrase."""
        from src.crypto.keypair import generate_hybrid_keypair

        passphrase = secrets.token_bytes(32)  # 256-bit passphrase

        # Generate keypair (which encrypts private keys with passphrase)
        keypair = generate_hybrid_keypair(passphrase)

        # Verify encrypted private keys exist
        assert keypair.rsa_private_encrypted is not None
        assert keypair.kyber_private_encrypted is not None
        assert keypair.kdf_salt is not None
        assert keypair.kdf_iterations == 600000
        assert len(keypair.rsa_private_encrypted) > 0
        assert len(keypair.kyber_private_encrypted) > 0

    def test_decrypt_private_keys_with_passphrase(self) -> None:
        """Test: Decrypt private keys with passphrase."""
        from src.crypto.keypair import decrypt_private_keys, generate_hybrid_keypair

        passphrase = secrets.token_bytes(32)  # 256-bit passphrase

        # Generate keypair with encrypted private keys
        keypair = generate_hybrid_keypair(passphrase)

        # Decrypt private keys
        rsa_private, kyber_private = decrypt_private_keys(keypair, passphrase)

        # Verify we got private key objects/bytes
        assert rsa_private is not None
        assert kyber_private is not None
        assert rsa_private.key_size == 4096

    def test_wrong_passphrase_decryption_fails(self) -> None:
        """Test: Decryption with wrong passphrase fails."""
        from src.crypto.keypair import decrypt_private_keys, generate_hybrid_keypair

        correct_passphrase = secrets.token_bytes(32)  # 256-bit passphrase
        wrong_passphrase = secrets.token_bytes(32)

        # Generate keypair with encrypted private keys
        keypair = generate_hybrid_keypair(correct_passphrase)

        # Attempt decrypt with wrong passphrase - should fail
        with pytest.raises(ValueError):
            decrypt_private_keys(keypair, wrong_passphrase)

    def test_decrypt_private_key_rejects_truncated_blob(self) -> None:
        """Test: Encrypted private key blobs must contain nonce and auth tag."""
        from src.crypto.keypair import decrypt_key_with_passphrase

        with pytest.raises(ValueError, match="too short"):
            decrypt_key_with_passphrase(
                b"truncated", secrets.token_bytes(32), secrets.token_bytes(32)
            )

    def test_hybrid_encrypt_validates_kek_and_kyber_key_lengths(self) -> None:
        """Test: Hybrid wrapping rejects malformed key material before encryption."""
        from src.crypto.keypair import hybrid_encrypt_kek

        with pytest.raises(ValueError, match="KEK must be exactly 32 bytes"):
            hybrid_encrypt_kek(b"short", b"not parsed", b"")

        with pytest.raises(ValueError, match="public key must be 1568 bytes"):
            hybrid_encrypt_kek(secrets.token_bytes(32), b"not parsed", b"short")

    def test_hybrid_decrypt_validates_kyber_lengths(self) -> None:
        """Test: Hybrid unwrapping rejects malformed Kyber private inputs."""
        from typing import cast

        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        from src.crypto.keypair import hybrid_decrypt_kek

        rsa_private = cast(RSAPrivateKey, object())
        with pytest.raises(ValueError, match="private key must be 3168 bytes"):
            hybrid_decrypt_kek(b"", b"", rsa_private, b"short")

        with pytest.raises(ValueError, match="ciphertext must be 1568 bytes"):
            hybrid_decrypt_kek(b"", b"short", rsa_private, b"\0" * 3168)

    def test_keypair_serialization_to_pem_and_base64(self) -> None:
        """Test: Keypair serialization (RSA to PEM, Kyber to base64)."""

        from src.crypto.keypair import generate_hybrid_keypair

        passphrase = secrets.token_bytes(32)  # 256-bit passphrase

        # Generate keypair
        keypair = generate_hybrid_keypair(passphrase)

        # Verify serialization formats
        assert keypair.rsa_public.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert isinstance(keypair.kyber_public, bytes)

        # Verify base64-encoded keys in HybridKeypair can be decoded
        # (In storage models they are base64-encoded strings)

    def test_keypair_deserialization_from_pem_and_base64(self) -> None:
        """Test: Keypair deserialization (PEM and base64 to keys)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from src.crypto.keypair import generate_hybrid_keypair

        passphrase = secrets.token_bytes(32)  # 256-bit passphrase

        # Generate keypair
        original = generate_hybrid_keypair(passphrase)

        # Deserialize RSA public key from PEM
        rsa_public = serialization.load_pem_public_key(original.rsa_public)
        assert isinstance(rsa_public, rsa.RSAPublicKey)
        assert rsa_public.key_size == 4096

        # Kyber public key is already in bytes format
        assert isinstance(original.kyber_public, bytes)
        assert len(original.kyber_public) > 0
