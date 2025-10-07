"""
Passphrase generation and key derivation for threshold cryptography.

Based on: specs/001-1-purpose-scope/research.md (Section 2)

Implements 384-bit passphrase generation and PBKDF2-based key derivation
for protecting private keys.
"""

import hashlib
import secrets
from typing import Tuple


def generate_passphrase() -> bytes:
    """
    Generate cryptographically secure 256-bit (32-byte) passphrase.

    Returns:
        32-byte random passphrase

    Uses secrets.token_bytes() for cryptographic randomness.

    Note: Originally designed for 384 bits, but reduced to 256 bits (32 bytes)
    for clean BIP39 integration (24-word mnemonics encode exactly 256 bits).
    256-bit security is still excellent for this use case.
    """
    return secrets.token_bytes(32)


def derive_key(
    passphrase: bytes, salt: bytes, iterations: int = 600000
) -> bytes:
    """
    Derive encryption key from passphrase using PBKDF2-HMAC-SHA512.

    Args:
        passphrase: 32-byte passphrase (256 bits)
        salt: 32-byte random salt
        iterations: Number of PBKDF2 iterations (default 600,000)

    Returns:
        32-byte derived key (for AES-256)

    Raises:
        ValueError: If passphrase or salt have invalid length
        ValueError: If iterations < 600,000 (security requirement)
    """
    if not isinstance(passphrase, bytes):
        raise TypeError("Passphrase must be bytes")

    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")

    if len(passphrase) != 32:
        raise ValueError("Passphrase must be exactly 32 bytes (256 bits)")

    if len(salt) != 32:
        raise ValueError("Salt must be exactly 32 bytes")

    if iterations < 600000:
        raise ValueError("Iterations must be >= 600,000 (OWASP 2023 recommendation)")

    # Derive 32-byte key using PBKDF2-HMAC-SHA512
    derived_key = hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, iterations, dklen=32
    )

    return derived_key


def generate_salt() -> bytes:
    """
    Generate cryptographically secure 32-byte salt for PBKDF2.

    Returns:
        32-byte random salt
    """
    return secrets.token_bytes(32)
