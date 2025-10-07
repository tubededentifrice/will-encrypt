# Research: Threshold Cryptography Implementation

**Date**: 2025-10-07
**Feature**: Threshold Cryptography System for Emergency Access

## 1. Hybrid RSA-4096 + Kyber Implementation

### Decision
Use layered hybrid encryption: RSA-4096 for backwards compatibility and established trust + Kyber-1024 for quantum resistance. Encrypt message with ephemeral symmetric key, then encrypt that key with both RSA and Kyber public keys. Decryption requires both private keys.

### Rationale
- **Kyber-1024** (NIST PQC standard, CRYSTALS-Kyber) provides 256-bit quantum security
- **RSA-4096** provides 152-bit classical security, well-established and trusted
- **Hybrid approach** ensures security if either algorithm is broken
- **Transition safety**: If Kyber is found weak, RSA still protects; if quantum computers break RSA, Kyber protects
- **40-year durability**: Conservative choice given uncertainty in PQC cryptanalysis timeline

### Implementation Approach
```
Message Encryption:
1. Generate ephemeral AES-256-GCM key (KEK)
2. Encrypt message with KEK → ciphertext
3. Encrypt KEK with RSA-4096 public key → RSA_wrapped_KEK
4. Encrypt KEK with Kyber-1024 public key → Kyber_wrapped_KEK
5. Store: {ciphertext, RSA_wrapped_KEK, Kyber_wrapped_KEK, nonce, tag}

Message Decryption:
1. Decrypt RSA_wrapped_KEK with RSA private key → KEK_1
2. Decrypt Kyber_wrapped_KEK with Kyber private key → KEK_2
3. Verify KEK_1 == KEK_2 (both must match)
4. Decrypt ciphertext with KEK
```

### Alternatives Considered
- **RSA-4096 only**: Rejected - not quantum-resistant
- **Kyber only**: Rejected - too new, lacks long-term trust, no fallback if broken
- **SPHINCS+ signatures**: Rejected - stateless hash-based, but large signatures (49 KB), not suitable for encryption
- **Classic McEliece**: Rejected - extremely large keys (1 MB+), impractical for storage

### Dependencies
- **Python `cryptography` library**: Provides RSA-4096 support via `hazmat` primitives
- **`pqcrypto` or `liboqs-python`**: Provides Kyber implementation (NIST PQC standards)
- **Fallback**: If PQC library unavailable, document manual integration with `liboqs` C library

### Test Vectors
- RSA-4096: NIST CAVP test vectors for RSA-OAEP
- Kyber-1024: NIST PQC Round 3 submission test vectors

---

## 2. Shamir's Secret Sharing

### Decision
Use **`secretsharing` Python library** (v0.2.7+) or implement Shamir SSS manually using Lagrange interpolation over GF(256).

### Rationale
- **Shamir's Secret Sharing** is the industry standard for K-of-N threshold schemes
- **Information-theoretic security**: Fewer than K shares reveal zero information about the secret
- **Flexible thresholds**: Supports any K ≤ N configuration
- **Well-understood**: Published 1979, extensively analyzed, no known attacks
- **Compatible with BIP39**: Can split the 384-bit passphrase into shares, then encode each share as BIP39 mnemonic

### Implementation Approach
```
Share Generation:
1. Generate 384-bit passphrase (48 bytes)
2. Split into K-of-N shares using Shamir SSS
   - Prime field: Use GF(2^8) or large prime > 2^384
   - Polynomial: Degree K-1, random coefficients
3. Encode each share as BIP39 mnemonic (24 words for ~256 bits + checksum)

Share Reconstruction:
1. Decode K shares from BIP39 mnemonics
2. Use Lagrange interpolation to reconstruct passphrase
3. Verify passphrase decrypts private key (implicit validation)
```

### Alternatives Considered
- **Threshold ECDSA**: Rejected - more complex, requires interactive protocols, overkill for our use case
- **Blakley's Secret Sharing**: Rejected - less efficient, information leakage with fewer shares
- **SSSS (Shamir's Secret Sharing Software)**: Rejected - C implementation, harder to integrate with Python

### Dependencies
- **Option 1**: `secretsharing` library (pure Python, MIT license)
- **Option 2**: Custom implementation using `sympy` for polynomial arithmetic (if avoiding external deps)
- **Standard library**: `secrets` for random coefficient generation

### Test Vectors
- Academic papers on Shamir SSS with known input/output pairs
- Custom test: Generate shares with K=3, N=5, verify reconstruction with any 3 shares
- Negative test: Verify reconstruction fails with K-1 shares

---

## 3. BIP39 Mnemonic Generation and Validation

### Decision
Use **BIP39 standard** (Bitcoin Improvement Proposal 39) for encoding shares as human-readable mnemonics with checksums.

### Rationale
- **Human-friendly**: 24-word mnemonics easier to transcribe than hex strings
- **Checksums**: Built-in error detection (last word encodes checksum)
- **Widely supported**: Standard wordlist (2048 words), multiple implementations available
- **Durability**: BIP39 is stable standard (2013), unlikely to be deprecated
- **Printable**: Mnemonics can be handwritten on paper for physical backup

### Implementation Approach
```
Encoding (Share → BIP39):
1. Take 32-byte share from Shamir SSS
2. Compute SHA-256 checksum, take first 8 bits
3. Append checksum to share: 256 + 8 = 264 bits
4. Split into 24 groups of 11 bits (264 / 11 = 24)
5. Map each 11-bit value to BIP39 wordlist index
6. Result: 24-word mnemonic

Decoding (BIP39 → Share):
1. Map 24 words to 11-bit indices
2. Concatenate to 264 bits
3. Split: first 256 bits = share, last 8 bits = checksum
4. Verify: SHA-256(share)[0:8] == checksum
5. Return 32-byte share if valid, error if checksum fails
```

### Alternatives Considered
- **Raw hex**: Rejected - no checksums, high transcription error rate
- **Base58 (Bitcoin-style)**: Rejected - not standardized for this use case, no mnemonic benefits
- **PGP word list**: Rejected - less standard than BIP39, fewer implementations

### Dependencies
- **`mnemonic` library** (python-mnemonic, MIT license): Official BIP39 implementation
- **Wordlist**: Embedded in library, no external files needed

### Test Vectors
- BIP39 specification test vectors (entropy → mnemonic)
- Invalid checksum tests to verify detection

---

## 4. AEAD Encryption for Messages

### Decision
Use **AES-256-GCM** (Galois/Counter Mode) for authenticated encryption of messages.

### Rationale
- **AEAD**: Authenticated Encryption with Associated Data - provides confidentiality + integrity + authentication
- **AES-256**: Industry standard, hardware-accelerated on modern CPUs, 256-bit security
- **GCM mode**: Efficient, parallelizable, provides authentication tag (128 bits)
- **NIST approved**: FIPS 197 (AES) + SP 800-38D (GCM)
- **40-year durability**: AES-256 expected to remain secure; if broken, documented migration path

### Implementation Approach
```
Message Encryption:
1. Generate random 96-bit nonce (unique per message)
2. Use AES-256-GCM with:
   - Key: Ephemeral KEK (from hybrid encryption)
   - Nonce: Random 96-bit value
   - Plaintext: Message (up to 64 KB)
   - Associated Data: Message title (unencrypted metadata)
3. Output: {ciphertext, nonce, authentication_tag (128 bits)}

Message Decryption:
1. Reconstruct KEK from hybrid decryption
2. Verify authentication tag (GCM validation)
3. Decrypt ciphertext with AES-256-GCM
4. Return plaintext if tag valid, error if tampered
```

### Alternatives Considered
- **ChaCha20-Poly1305**: Rejected - slightly less standardized than AES-GCM for long-term storage
- **AES-256-CBC + HMAC**: Rejected - GCM is more efficient and provides built-in authentication
- **XSalsa20-Poly1305 (NaCl)**: Rejected - less established for 40-year use case

### Dependencies
- **Python `cryptography` library**: Provides AES-256-GCM implementation
- **Standard library**: `secrets` for nonce generation

### Test Vectors
- NIST CAVP AES-GCM test vectors

---

## 5. YAML Vault File Format

### Decision
Single YAML file with top-level sections for keys, messages, manifest, and documentation. Human-readable structure with PEM-encoded keys and base64-encoded ciphertexts.

### Rationale
- **Human-readable**: YAML is text-based, can be inspected without special tools
- **Single file**: Simplifies backup (copy one file), SSH-friendly (cat vault.yaml)
- **Structured**: Native support for nested data (messages array, manifest dict)
- **Stable format**: YAML 1.2 standard, unlikely to be deprecated
- **Tool-agnostic**: Any YAML parser can read vault (Python, Go, Rust, manual inspection)

### Vault Structure
```yaml
version: "1.0"
created: "2025-10-07T10:30:00Z"

keys:
  public:
    rsa_4096: |
      -----BEGIN PUBLIC KEY-----
      [PEM-encoded RSA-4096 public key]
      -----END PUBLIC KEY-----
    kyber_1024: |
      [Base64-encoded Kyber-1024 public key]
  encrypted_private:
    rsa_4096: |
      -----BEGIN ENCRYPTED PRIVATE KEY-----
      [PEM-encoded RSA private key encrypted with passphrase]
      -----END ENCRYPTED PRIVATE KEY-----
    kyber_1024: |
      [Base64-encoded Kyber-1024 private key encrypted with passphrase]
    encryption: "AES-256-GCM"
    kdf: "PBKDF2-HMAC-SHA512"
    iterations: 600000
    salt: "[Base64-encoded salt]"

messages:
  - id: 1
    title: "Bank Account Passwords"
    created: "2025-10-07T11:00:00Z"
    ciphertext: "[Base64-encoded encrypted message]"
    rsa_wrapped_kek: "[Base64-encoded RSA-wrapped key]"
    kyber_wrapped_kek: "[Base64-encoded Kyber-wrapped key]"
    nonce: "[Base64-encoded GCM nonce]"
    tag: "[Base64-encoded GCM auth tag]"
    size_bytes: 1024
  - id: 2
    title: "Estate Instructions"
    created: "2025-10-08T14:30:00Z"
    # ... (same structure)

manifest:
  threshold:
    k: 3
    n: 5
  algorithms:
    keypair: "RSA-4096 + Kyber-1024 (hybrid)"
    passphrase_entropy: 384
    secret_sharing: "Shamir SSS over GF(2^8)"
    message_encryption: "AES-256-GCM"
    kdf: "PBKDF2-HMAC-SHA512 (600k iterations)"
  fingerprints:
    rsa_public_key_sha256: "[Hex fingerprint]"
    kyber_public_key_sha256: "[Hex fingerprint]"
    vault_sha256: "[Hex fingerprint of entire vault]"
  rotation_history:
    - date: "2025-10-07T10:30:00Z"
      event: "Initial creation"
      k: 3
      n: 5

recovery_guide: |
  # Emergency Recovery Guide

  ## When to Use This Guide
  [Non-technical instructions for beneficiaries]

  ## Prerequisites
  - At least 3 secret shares (BIP39 mnemonics) from key holders
  - Access to this vault file (vault.yaml)
  - Will-encrypt tool installed on Linux or macOS

  ## Step-by-Step Recovery
  1. Collect shares from key holders...
  2. Run: will-encrypt decrypt --vault vault.yaml...
  [Detailed steps]

policy_document: |
  # Access Policy

  ## Recovery Eligibility
  [When recovery is legitimate]

  ## Key Holder Coordination
  [How to contact holders, proof requirements]

crypto_notes: |
  # Cryptographic Implementation Notes

  ## Algorithm Choices
  - RSA-4096: FIPS 186-4, OAEP padding with SHA-256
  - Kyber-1024: NIST PQC Round 3 standard
  - Shamir SSS: Lagrange interpolation over GF(2^8)
  - BIP39: Bitcoin Improvement Proposal 39 (2013)

  ## Test Vectors
  [References to NIST test vectors used]

  ## Interoperability Notes
  [How to decrypt with alternative tools]
```

### Alternatives Considered
- **Separate files per section**: Rejected - harder to manage, more complex backup
- **Binary format (Protocol Buffers)**: Rejected - not human-readable, violates simplicity principle
- **JSON**: Rejected - less readable than YAML for large documents (no comments, strict syntax)
- **SQLite database**: Rejected - overkill for append-only message storage, less portable

### Dependencies
- **`pyyaml` library**: Standard YAML parser for Python

---

## 6. Python Cryptography Library Capabilities

### Decision
Use **`cryptography` library** (v41.0+) as primary cryptographic provider for RSA, AES, PBKDF2, and key management.

### Rationale
- **Widely established**: Industry standard Python cryptography library
- **Well-maintained**: PyCA (Python Cryptographic Authority), active development
- **Comprehensive**: RSA, AES-GCM, PBKDF2, X.509, PKCS standards
- **Hardware acceleration**: Uses OpenSSL backend, benefits from CPU crypto instructions
- **Type-safe**: Provides high-level APIs with explicit error handling
- **FIPS compliance available**: Can use FIPS-validated OpenSSL backend

### Capabilities Used
- **RSA-4096**: `cryptography.hazmat.primitives.asymmetric.rsa`
  - Key generation: `rsa.generate_private_key(65537, 4096)`
  - Encryption: RSA-OAEP with SHA-256
  - Serialization: PEM format (PKCS#8 for private, SubjectPublicKeyInfo for public)
- **AES-256-GCM**: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
  - One-shot encryption/decryption
  - Automatic tag verification
- **PBKDF2**: `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`
  - Derive key from passphrase for private key encryption
  - SHA-512 hash, 600,000 iterations (OWASP 2023 recommendation)
- **Key Encryption**: `cryptography.hazmat.primitives.serialization`
  - Encrypt private key with passphrase using BestAvailableEncryption

### Limitations
- **No Kyber support**: Must use external PQC library (`pqcrypto`, `liboqs-python`)
- **Workaround**: Implement Kyber integration as separate module

### Test Strategy
- Use `cryptography` test vectors from upstream project
- NIST CAVP vectors for RSA-OAEP and AES-GCM
- Cross-validation with OpenSSL command-line tools

---

## 7. GPG Integration Strategy

### Decision
**Do NOT use GPG** for core encryption operations. Use Python `cryptography` library directly for full control and auditability. Reserve GPG as optional verification tool.

### Rationale
- **Complexity**: GPG adds significant complexity (keyring management, agent, configuration)
- **Auditability**: Python implementation is more transparent and testable
- **Minimal dependency principle**: Avoid external process calls when library suffices
- **Version compatibility**: GPG versions vary across platforms (2.2 vs 2.4)
- **Hybrid PQC**: GPG does not support Kyber (as of GPG 2.4)

### Limited GPG Use
- **Optional**: Owners can manually GPG-sign the vault file for additional authenticity
- **Verification**: Document how to verify vault signatures with GPG (not required for decryption)
- **Interoperability note**: Document that RSA keys can be exported to GPG format if needed

### Alternative Considered
- **Full GPG integration**: Rejected - conflicts with minimal dependency principle, adds complexity
- **Current approach**: Pure Python implementation for core operations, GPG as optional tool

---

## 8. Threat Model

### Decision
Document explicit threat model in vault manifest and README covering assumptions, mitigated threats, and residual risks.

### Threat Model Summary

#### Assumptions
1. **Physical share custody**: Key holders protect their BIP39 mnemonics (paper, password manager, HSM)
2. **Non-collusion**: Fewer than K holders do not collude to reconstruct passphrase
3. **Vault availability**: At least one copy of vault YAML accessible in emergency
4. **Computational hardness**: RSA-4096, Kyber-1024, AES-256, Shamir SSS remain secure for 40 years
5. **Beneficiary legitimacy**: Social/legal controls verify recovery requests (e.g., death certificate)

#### Threats Mitigated
1. **Vault breach**: ✅ Encrypted private key + ciphertext useless without K shares
2. **Single holder coercion**: ✅ One share reveals zero information (Shamir SSS property)
3. **Data rot**: ✅ Open standards (YAML, PEM, Base64) decryptable decades later
4. **Quantum attacks**: ✅ Hybrid RSA+Kyber protects against future quantum computers
5. **Tampering**: ✅ AES-GCM authentication tags detect ciphertext modifications
6. **Transcription errors**: ✅ BIP39 checksums catch invalid mnemonics
7. **Algorithm weakness**: ✅ Hybrid approach: If either RSA or Kyber breaks, other protects
8. **Passphrase compromise**: ✅ Rotation procedure: Re-encrypt private key without touching messages

#### Threats NOT Mitigated (Out of Scope)
1. **K-holder collusion**: Must be prevented by social/legal controls (will, executor, logging)
2. **All shares lost**: Unrecoverable - consider (N-1)-of-N or escrow share to reduce risk
3. **Implementation bugs**: Mitigated by TDD, test vectors, code review (but not eliminated)
4. **Side-channel attacks**: Physical access to decryption environment (not protected against)
5. **Social engineering**: Fraudulent emergency claims (policy document provides governance)

#### Residual Risks
1. **Share loss** (especially N-of-N): Mitigate by choosing (N-1)-of-N or secure escrow
2. **Holder coordination failure**: Mitigate with clear policy document and executor role
3. **Technology obsolescence**: Mitigate with open standards and documented migration paths
4. **Regulatory changes**: Jurisdiction-agnostic design, but laws may affect storage/transport

---

## Summary of Research Findings

All technical unknowns resolved. No NEEDS CLARIFICATION remaining. Key decisions:

1. **Hybrid RSA-4096 + Kyber-1024** for quantum resistance
2. **Shamir SSS** with BIP39 encoding for shares
3. **AES-256-GCM** for message encryption (AEAD)
4. **Single YAML file** for vault storage
5. **Python `cryptography` library** for core operations
6. **384-bit passphrase** entropy with PBKDF2 key derivation
7. **No GPG dependency** for core functions (optional for signing)
8. **Explicit threat model** documented

**Phase 0 Complete** ✅ Ready for Phase 1 (Design & Contracts).
