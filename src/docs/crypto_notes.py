"""Cryptographic implementation notes."""
from typing import Dict


def generate_crypto_notes(manifest_dict: Dict) -> str:
    """Generate crypto notes text."""
    return f"""# Cryptographic Implementation Notes

## Algorithm Choices

- **RSA-4096**: FIPS 186-4, OAEP padding with SHA-256
- **ML-KEM-1024**: NIST FIPS 203 (CRYSTALS-Kyber), post-quantum KEM
- **Shamir SSS**: Lagrange interpolation over GF(256)
- **AES-256-GCM**: AEAD with 96-bit nonce, 128-bit auth tag
- **BIP39**: Bitcoin Improvement Proposal 39 (2013 standard)
- **PBKDF2**: HMAC-SHA512, 600,000 iterations (OWASP 2023)

## Hybrid Post-Quantum Encryption

This vault uses **true hybrid cryptography** to protect against both classical and quantum attacks:

1. **Key Encapsulation**: ML-KEM-1024 generates a quantum-resistant shared secret
2. **Hybrid KEK**: The KEK is XORed with the Kyber shared secret
3. **Classical Layer**: The hybrid KEK is then wrapped with RSA-4096-OAEP

**Security Property**: Both RSA AND Kyber must be broken to compromise the KEK.
- If quantum computers break RSA → Kyber still protects the data
- If Kyber has a flaw → RSA still protects the data

## Security Parameters

- Passphrase entropy: 256 bits
- Threshold: {manifest_dict.get('threshold', {}).get('k', 'N/A')}-of-{manifest_dict.get('threshold', {}).get('n', 'N/A')}
- RSA key size: 4096 bits
- ML-KEM public key: 1568 bytes
- ML-KEM private key: 3168 bytes
- ML-KEM ciphertext: 1568 bytes
- AES key size: 256 bits

## Test Vectors

- BIP39: Specification test vectors (entropy 0x00...00 and 0x7f...7f)
- RSA-OAEP: NIST CAVP test vectors
- AES-GCM: NIST CAVP test vectors
- ML-KEM-1024: NIST FIPS 203 known-answer tests

## Interoperability Notes

### Decryption Without will-encrypt

1. Parse vault.yaml with any YAML library
2. Reconstruct passphrase from K shares using Shamir SSS over GF(256)
3. Derive AES key with PBKDF2 (SHA-512, 600k iterations, stored salt)
4. Decrypt private keys (RSA and Kyber) with AES-256-GCM
5. Decrypt Kyber ciphertext to get shared secret (32 bytes)
6. Decrypt RSA-wrapped hybrid KEK with RSA-4096-OAEP (SHA-256)
7. XOR hybrid KEK with Kyber shared secret to recover original KEK
8. Decrypt messages with AES-256-GCM (KEK, nonce, AAD=title)

### Migration Path

If RSA, Kyber, or AES are broken:
1. Decrypt all messages with current vault
2. Generate new vault with updated algorithms
3. Re-encrypt messages with new keys
4. Generate new shares

The hybrid design provides graceful migration: if only one algorithm is broken,
data remains secure while you migrate to a new vault.

## Implementation Status

- **Production Ready**: All algorithms (RSA, ML-KEM-1024, AES, BIP39, Shamir, PBKDF2)
- **Library**: pqcrypto>=0.3.4 for ML-KEM-1024 implementation

## References

- BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- Shamir SSS: Shamir, Adi (1979). "How to share a secret"
- NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- pqcrypto: https://github.com/PQClean/PQClean-Python
"""
