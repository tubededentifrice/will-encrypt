"""Cryptographic implementation notes."""
from typing import Dict


def generate_crypto_notes(manifest_dict: Dict) -> str:
    """Generate crypto notes text."""
    return f"""# Cryptographic Implementation Notes

## Algorithm Choices

- **RSA-4096**: FIPS 186-4, OAEP padding with SHA-256
- **Kyber-1024**: NIST PQC Round 3 standard (simulated with RSA pending stable bindings)
- **Shamir SSS**: Lagrange interpolation over GF(256)
- **AES-256-GCM**: AEAD with 96-bit nonce, 128-bit auth tag
- **BIP39**: Bitcoin Improvement Proposal 39 (2013 standard)
- **PBKDF2**: HMAC-SHA512, 600,000 iterations (OWASP 2023)

## Security Parameters

- Passphrase entropy: 384 bits
- Threshold: {manifest_dict.get('threshold', {}).get('k', 'N/A')}-of-{manifest_dict.get('threshold', {}).get('n', 'N/A')}
- RSA key size: 4096 bits
- AES key size: 256 bits

## Test Vectors

- BIP39: Specification test vectors (entropy 0x00...00 and 0x7f...7f)
- RSA-OAEP: NIST CAVP test vectors
- AES-GCM: NIST CAVP test vectors

## Interoperability Notes

### Decryption Without will-encrypt

1. Parse vault.yaml with any YAML library
2. Reconstruct passphrase from K shares using Shamir SSS
3. Derive AES key with PBKDF2 (SHA-512, 600k iterations, stored salt)
4. Decrypt private keys with AES-256-GCM
5. Decrypt message KEKs with RSA-4096-OAEP (SHA-256)
6. Decrypt messages with AES-256-GCM (KEK, nonce, AAD=title)

### Migration Path

If RSA or AES are broken:
1. Decrypt all messages with current vault
2. Generate new vault with updated algorithms
3. Re-encrypt messages with new keys
4. Generate new shares

## Implementation Status

- **Production Ready**: RSA, AES, BIP39, Shamir, PBKDF2
- **Simulated**: Kyber (using RSA until python-pqcrypto stable)

## References

- BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- Shamir SSS: Shamir, Adi (1979). "How to share a secret"
- NIST PQC: https://csrc.nist.gov/Projects/post-quantum-cryptography
"""
