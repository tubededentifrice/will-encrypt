"""
Hybrid RSA+Kyber keypair generation and key encryption.

Based on: specs/001-1-purpose-scope/research.md (Section 1)

IMPLEMENTATION NOTE:
This implementation uses true hybrid post-quantum cryptography:
- RSA-4096 for classical security
- ML-KEM-1024 (CRYSTALS-Kyber) for post-quantum security

Both legs must be broken to compromise the encryption, providing defense
against both classical and quantum adversaries.
"""

import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_1024 import generate_keypair as kyber_generate_keypair
from pqcrypto.kem.ml_kem_1024 import encrypt as kyber_encrypt
from pqcrypto.kem.ml_kem_1024 import decrypt as kyber_decrypt

from .passphrase import derive_key


@dataclass
class HybridKeypair:
    """Hybrid keypair with RSA and ML-KEM-1024 keys."""

    rsa_public: bytes  # PEM-encoded RSA public key
    rsa_private_encrypted: bytes  # Encrypted RSA private key (PEM)
    kyber_public: bytes  # ML-KEM-1024 public key (1568 bytes)
    kyber_private_encrypted: bytes  # Encrypted ML-KEM-1024 private key
    kdf_salt: bytes  # Salt for PBKDF2
    kdf_iterations: int  # PBKDF2 iterations


def generate_rsa_keypair() -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
    """
    Generate RSA-4096 keypair.

    Returns:
        Tuple of (public_key, private_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096
    )
    public_key = private_key.public_key()
    return public_key, private_key


def generate_kyber_keypair() -> Tuple[bytes, bytes]:
    """
    Generate ML-KEM-1024 (CRYSTALS-Kyber) keypair.

    Returns:
        Tuple of (public_key_bytes, private_key_bytes)
        - Public key: 1568 bytes
        - Private key: 3168 bytes
    """
    public_key, private_key = kyber_generate_keypair()
    return public_key, private_key


def encrypt_key_with_passphrase(
    key_bytes: bytes, passphrase: bytes, salt: bytes, iterations: int = 600000
) -> bytes:
    """
    Encrypt a key with passphrase using AES-256-GCM.

    Args:
        key_bytes: Key to encrypt (PEM or DER encoded)
        passphrase: 32-byte passphrase (256 bits)
        salt: 32-byte salt
        iterations: PBKDF2 iterations

    Returns:
        Encrypted key bytes (nonce + ciphertext + tag)
    """
    # Derive encryption key from passphrase
    encryption_key = derive_key(passphrase, salt, iterations)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(encryption_key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, key_bytes, None)

    # Return: nonce || ciphertext (ciphertext includes auth tag)
    return nonce + ciphertext


def decrypt_key_with_passphrase(
    encrypted_bytes: bytes, passphrase: bytes, salt: bytes, iterations: int = 600000
) -> bytes:
    """
    Decrypt a key with passphrase using AES-256-GCM.

    Args:
        encrypted_bytes: Encrypted key (nonce + ciphertext + tag)
        passphrase: 32-byte passphrase (256 bits)
        salt: 32-byte salt
        iterations: PBKDF2 iterations

    Returns:
        Decrypted key bytes

    Raises:
        ValueError: If decryption fails (wrong passphrase or tampered data)
    """
    # Derive decryption key from passphrase
    decryption_key = derive_key(passphrase, salt, iterations)

    # Extract nonce and ciphertext
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    # Decrypt with AES-256-GCM
    try:
        aesgcm = AESGCM(decryption_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed (wrong passphrase or corrupted data): {e}")


def generate_hybrid_keypair(passphrase: bytes) -> HybridKeypair:
    """
    Generate hybrid RSA+Kyber keypair and encrypt private keys with passphrase.

    Args:
        passphrase: 32-byte passphrase for encrypting private keys (256 bits)

    Returns:
        HybridKeypair with public keys (plaintext) and encrypted private keys
    """
    # Generate salt for KDF
    kdf_salt = secrets.token_bytes(32)
    kdf_iterations = 600000

    # Generate RSA keypair
    rsa_public, rsa_private = generate_rsa_keypair()

    # Generate ML-KEM-1024 keypair
    kyber_public, kyber_private = generate_kyber_keypair()

    # Serialize RSA keys to PEM format
    rsa_public_pem = rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    rsa_private_pem = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Encrypt private keys with passphrase
    rsa_private_encrypted = encrypt_key_with_passphrase(
        rsa_private_pem, passphrase, kdf_salt, kdf_iterations
    )

    kyber_private_encrypted = encrypt_key_with_passphrase(
        kyber_private, passphrase, kdf_salt, kdf_iterations
    )

    return HybridKeypair(
        rsa_public=rsa_public_pem,
        rsa_private_encrypted=rsa_private_encrypted,
        kyber_public=kyber_public,
        kyber_private_encrypted=kyber_private_encrypted,
        kdf_salt=kdf_salt,
        kdf_iterations=kdf_iterations,
    )


def decrypt_private_keys(
    keypair: HybridKeypair, passphrase: bytes
) -> Tuple[rsa.RSAPrivateKey, bytes]:
    """
    Decrypt private keys from HybridKeypair using passphrase.

    Args:
        keypair: HybridKeypair with encrypted private keys
        passphrase: 32-byte passphrase (256 bits)

    Returns:
        Tuple of (rsa_private_key, kyber_private_key_bytes)

    Raises:
        ValueError: If decryption fails
    """
    # Decrypt RSA private key
    rsa_private_pem = decrypt_key_with_passphrase(
        keypair.rsa_private_encrypted,
        passphrase,
        keypair.kdf_salt,
        keypair.kdf_iterations,
    )

    # Load RSA private key from PEM
    rsa_private = serialization.load_pem_private_key(
        rsa_private_pem, password=None
    )

    # Decrypt Kyber private key
    kyber_private = decrypt_key_with_passphrase(
        keypair.kyber_private_encrypted,
        passphrase,
        keypair.kdf_salt,
        keypair.kdf_iterations,
    )

    return rsa_private, kyber_private


def hybrid_encrypt_kek(
    kek: bytes, rsa_public_pem: bytes, kyber_public: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypt KEK with both RSA and ML-KEM-1024 public keys.

    Args:
        kek: 32-byte key encryption key
        rsa_public_pem: PEM-encoded RSA public key
        kyber_public: ML-KEM-1024 public key bytes (1568 bytes)

    Returns:
        Tuple of (rsa_wrapped_kek, kyber_ciphertext)

    Note:
        Kyber KEM generates its own shared secret; we XOR it with our KEK
        for hybrid protection. Both RSA and Kyber must be broken to recover KEK.
    """
    # Load RSA public key
    rsa_public = serialization.load_pem_public_key(rsa_public_pem)

    # Kyber KEM: encapsulate to get ciphertext and shared secret
    kyber_ciphertext, kyber_shared_secret = kyber_encrypt(kyber_public)

    # XOR KEK with Kyber shared secret for hybrid protection
    # Attacker needs both: RSA private key AND Kyber private key to recover KEK
    hybrid_kek = bytes(a ^ b for a, b in zip(kek, kyber_shared_secret))

    # Encrypt the hybrid KEK with RSA-OAEP
    rsa_wrapped = rsa_public.encrypt(
        hybrid_kek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return rsa_wrapped, kyber_ciphertext


def hybrid_decrypt_kek(
    rsa_wrapped: bytes,
    kyber_ciphertext: bytes,
    rsa_private: rsa.RSAPrivateKey,
    kyber_private: bytes,
) -> bytes:
    """
    Decrypt KEK with both RSA and ML-KEM-1024 private keys.

    Args:
        rsa_wrapped: RSA-wrapped hybrid KEK
        kyber_ciphertext: Kyber KEM ciphertext (1568 bytes)
        rsa_private: RSA private key object
        kyber_private: ML-KEM-1024 private key bytes (3168 bytes)

    Returns:
        Decrypted KEK (32 bytes)

    Raises:
        ValueError: If decryption fails on either leg
    """
    # Decrypt hybrid KEK with RSA
    hybrid_kek = rsa_private.decrypt(
        rsa_wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Kyber KEM: decapsulate to recover shared secret
    kyber_shared_secret = kyber_decrypt(kyber_private, kyber_ciphertext)

    # XOR back to recover original KEK
    kek = bytes(a ^ b for a, b in zip(hybrid_kek, kyber_shared_secret))

    return kek
