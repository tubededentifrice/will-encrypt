"""
Message encryption with AES-256-GCM and hybrid key wrapping.

Based on: specs/001-1-purpose-scope/research.md (Section 4)
"""

import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keypair import hybrid_decrypt_kek, hybrid_encrypt_kek


@dataclass
class EncryptedMessage:
    """Encrypted message with wrapped KEKs."""

    ciphertext: bytes
    rsa_wrapped_kek: bytes
    kyber_wrapped_kek: bytes
    nonce: bytes
    auth_tag: bytes  # Included in ciphertext by GCM


def encrypt_message(
    plaintext: bytes,
    rsa_public_pem: bytes,
    kyber_public: bytes,
    title: str = "",
) -> EncryptedMessage:
    """
    Encrypt message with AES-256-GCM and wrap KEK with hybrid keys.

    Args:
        plaintext: Message to encrypt (max 64 KB)
        rsa_public_pem: RSA public key (PEM)
        kyber_public: Kyber public key bytes
        title: Message title for AAD

    Returns:
        EncryptedMessage with ciphertext and wrapped KEKs

    Raises:
        ValueError: If message > 64 KB
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
    rsa_private,
    kyber_private: bytes,
    title: str = "",
) -> bytes:
    """
    Decrypt message using hybrid private keys.

    Args:
        encrypted: EncryptedMessage object
        rsa_private: RSA private key object
        kyber_private: Kyber private key bytes
        title: Message title for AAD verification

    Returns:
        Decrypted plaintext bytes

    Raises:
        ValueError: If hybrid verification fails or auth tag invalid
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
