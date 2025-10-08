"""
Message encryption with AES-256-GCM and hybrid key wrapping.

Based on: specs/001-1-purpose-scope/research.md (Section 4)
"""

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keypair import hybrid_decrypt_kek, hybrid_encrypt_kek


@dataclass
class EncryptedMessage:
    """Encrypted message with hybrid-wrapped KEKs."""

    ciphertext: bytes
    rsa_wrapped_kek: bytes  # RSA-OAEP wrapped hybrid KEK (512 bytes)
    kyber_wrapped_kek: bytes  # ML-KEM-1024 ciphertext (1568 bytes)
    nonce: bytes  # AES-GCM nonce (12 bytes)
    auth_tag: bytes  # AES-GCM authentication tag (16 bytes)


def encrypt_message(
    plaintext: bytes,
    rsa_public_pem: bytes,
    kyber_public: bytes,
    title: str = "",
) -> EncryptedMessage:
    """
    Encrypt message with AES-256-GCM and wrap KEK with hybrid RSA + ML-KEM-1024.

    Args:
        plaintext: Message to encrypt (max 64 KB)
        rsa_public_pem: RSA-4096 public key (PEM format)
        kyber_public: ML-KEM-1024 public key bytes (1568 bytes)
        title: Message title for AAD

    Returns:
        EncryptedMessage with ciphertext and hybrid-wrapped KEKs

    Raises:
        ValueError: If message > 64 KB

    Security:
        Provides hybrid post-quantum security. Attacker must break BOTH
        RSA-4096 (classical) AND ML-KEM-1024 (quantum-resistant) to recover KEK.
    """
    if len(plaintext) > 65536:
        raise ValueError("Message must be <= 64 KB")

    # Generate ephemeral KEK
    kek = secrets.token_bytes(32)

    # Generate nonce
    nonce = secrets.token_bytes(12)

    # Encrypt message with AES-256-GCM
    aesgcm = AESGCM(kek)
    aad = title.encode("utf-8") if title else None
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # Wrap KEK with hybrid keys
    rsa_wrapped, kyber_wrapped = hybrid_encrypt_kek(
        kek, rsa_public_pem, kyber_public
    )

    # Extract auth tag (last 16 bytes of GCM ciphertext)
    auth_tag = ciphertext[-16:]

    return EncryptedMessage(
        ciphertext=ciphertext[:-16],  # Without tag
        rsa_wrapped_kek=rsa_wrapped,
        kyber_wrapped_kek=kyber_wrapped,
        nonce=nonce,
        auth_tag=auth_tag,
    )


def decrypt_message(
    encrypted: EncryptedMessage,
    rsa_private: object,
    kyber_private: bytes,
    title: str = "",
) -> bytes:
    """
    Decrypt message using hybrid RSA + ML-KEM-1024 private keys.

    Args:
        encrypted: EncryptedMessage object
        rsa_private: RSA-4096 private key object
        kyber_private: ML-KEM-1024 private key bytes (3168 bytes)
        title: Message title for AAD verification

    Returns:
        Decrypted plaintext bytes

    Raises:
        ValueError: If decryption fails or auth tag invalid

    Security:
        Both RSA and Kyber legs must successfully decrypt to recover the KEK.
        Provides defense against both classical and quantum attacks.
    """
    # Decrypt KEK with hybrid verification
    kek = hybrid_decrypt_kek(
        encrypted.rsa_wrapped_kek,
        encrypted.kyber_wrapped_kek,
        rsa_private,
        kyber_private,
    )

    # Reconstruct full ciphertext with tag
    full_ciphertext = encrypted.ciphertext + encrypted.auth_tag

    # Decrypt message with AES-256-GCM
    aesgcm = AESGCM(kek)
    aad = title.encode("utf-8") if title else None

    try:
        plaintext = aesgcm.decrypt(encrypted.nonce, full_ciphertext, aad)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")
