# Data Model: Threshold Cryptography System

**Date**: 2025-10-07
**Feature**: Threshold Cryptography System for Emergency Access

## Overview

The data model consists of cryptographic artifacts, vault storage, and operational metadata. All data persists in a single YAML file with human-readable structure and base64/PEM encodings for binary data.

---

## Entities

### 1. Keypair

**Purpose**: Asymmetric hybrid cryptographic keypair for message encryption/decryption.

**Attributes**:
- `rsa_public_key` (string, PEM-encoded): RSA-4096 public key for classical encryption
- `rsa_private_key` (string, PEM-encrypted): RSA-4096 private key, encrypted with passphrase
- `kyber_public_key` (bytes, base64-encoded): Kyber-1024 public key for quantum-resistant encryption
- `kyber_private_key` (bytes, base64-encoded): Kyber-1024 private key, encrypted with passphrase
- `encryption_algorithm` (string): "AES-256-GCM" (algorithm used to encrypt private keys)
- `kdf_algorithm` (string): "PBKDF2-HMAC-SHA512" (key derivation function)
- `kdf_iterations` (int): 600,000 (OWASP 2023 recommendation)
- `kdf_salt` (bytes, base64-encoded): Random 32-byte salt for PBKDF2

**Validation Rules**:
- RSA key size MUST be exactly 4096 bits
- Kyber key MUST be Kyber-1024 variant (256-bit quantum security)
- Private keys MUST be encrypted before storage
- KDF iterations MUST be ≥ 600,000
- Salt MUST be exactly 32 bytes, cryptographically random

**State Transitions**:
- `uninitialized` → `generated`: Key generation during initialization
- `generated` → `rotated`: Passphrase rotation (re-encrypt private keys)

**Relationships**:
- One Keypair per Vault (1:1)
- Keypair used by multiple Messages (1:N)

---

### 2. Passphrase

**Purpose**: High-entropy secret that protects the private keys. Split into N shares using Shamir's Secret Sharing.

**Attributes**:
- `entropy_bits` (int): 384 (fixed)
- `raw_bytes` (bytes, 48 bytes): Never stored on disk, exists only in memory during generation/reconstruction
- `shares` (list of bytes): N shares from Shamir SSS, never stored in vault
- `bip39_mnemonics` (list of strings): N 24-word mnemonics, displayed to terminal only

**Validation Rules**:
- Entropy MUST be exactly 384 bits (48 bytes)
- Passphrase MUST be generated using `secrets.token_bytes(48)`
- Shares MUST be generated using Shamir SSS with threshold K ≤ N
- BIP39 mnemonics MUST include valid checksums
- Passphrase MUST NOT be stored in vault or on disk

**State Transitions**:
- `nonexistent` → `generated`: During initialization
- `generated` → `split`: Split into N shares
- `reconstructed` → `verified`: K shares recombined and verified against private key decryption

**Relationships**:
- One Passphrase per Vault (1:1)
- Passphrase split into N Shares (1:N)

---

### 3. Share

**Purpose**: One of N fragments of the passphrase. K shares required to reconstruct passphrase.

**Attributes**:
- `share_index` (int): 1 to N (identifies which share)
- `share_data` (bytes, 48 bytes): Shamir SSS share data
- `bip39_mnemonic` (string): 24-word BIP39-encoded representation
- `bip39_checksum_valid` (bool): Validation flag for checksum

**Validation Rules**:
- Share index MUST be in range [1, N]
- Share data MUST be exactly 48 bytes
- BIP39 mnemonic MUST contain exactly 24 words from standard wordlist
- Checksum MUST be valid (last word encodes checksum of first 23 words)
- Shares MUST NOT be stored in vault

**State Transitions**:
- `generated` → `printed`: Displayed to terminal during initialization
- `collected` → `validated`: BIP39 checksum verified during recovery
- `validated` → `reconstructed`: K shares combined to recover passphrase

**Relationships**:
- N Shares per Passphrase (N:1)
- K or more Shares required for recovery (constraint)

---

### 4. Message

**Purpose**: Encrypted user content (passwords, instructions, documents).

**Attributes**:
- `id` (int): Sequential message ID (1, 2, 3, ...)
- `title` (string, unencrypted): Human-readable message title, max 256 characters
- `plaintext` (bytes): Original message content, max 64 KB, never stored on disk
- `ciphertext` (bytes, base64-encoded): AES-256-GCM encrypted message content
- `rsa_wrapped_kek` (bytes, base64-encoded): RSA-4096 encrypted key-encryption-key
- `kyber_wrapped_kek` (bytes, base64-encoded): Kyber-1024 encrypted key-encryption-key
- `nonce` (bytes, base64-encoded): AES-GCM 96-bit nonce (unique per message)
- `auth_tag` (bytes, base64-encoded): AES-GCM 128-bit authentication tag
- `created_timestamp` (string, ISO 8601): Creation timestamp (UTC)
- `size_bytes` (int): Plaintext size in bytes (for validation)

**Validation Rules**:
- Title MUST NOT be empty, max 256 UTF-8 characters
- Plaintext size MUST be ≤ 65,536 bytes (64 KB)
- Nonce MUST be 96 bits (12 bytes), cryptographically random, unique per message
- Auth tag MUST be 128 bits (16 bytes)
- RSA_wrapped_KEK size determined by RSA-4096-OAEP (~512 bytes)
- Kyber_wrapped_KEK size determined by Kyber-1024 (~1568 bytes)
- Ciphertext size = plaintext size (GCM is stream cipher, no padding)

**State Transitions**:
- `plaintext` → `encrypted`: Encryption process during message addition
- `ciphertext` → `decrypted`: Decryption during recovery
- `metadata_update`: Title can be changed without re-encryption

**Relationships**:
- Multiple Messages per Vault (N:1)
- Each Message encrypted with Keypair (N:1)

---

### 5. Vault

**Purpose**: Container for all cryptographic artifacts, messages, and metadata. Single YAML file.

**Attributes**:
- `version` (string): Vault format version (e.g., "1.0")
- `created_timestamp` (string, ISO 8601): Vault creation timestamp
- `keys` (Keypair): Embedded keypair object
- `messages` (list of Message): Array of encrypted messages
- `manifest` (Manifest): Configuration and metadata
- `recovery_guide` (string): Multi-line text recovery instructions
- `policy_document` (string): Multi-line text policy document
- `crypto_notes` (string): Multi-line text cryptographic implementation notes

**Validation Rules**:
- Version MUST match supported format (currently "1.0")
- Created timestamp MUST be valid ISO 8601 UTC
- Keys section MUST contain valid Keypair
- Messages array MAY be empty (no messages yet)
- Manifest MUST be present and valid
- Recovery guide, policy, crypto notes MUST be non-empty strings

**State Transitions**:
- `nonexistent` → `created`: Initialization command
- `created` → `updated`: Message added, title edited, rotation performed
- `validated`: Integrity check passed

**Relationships**:
- One Vault per instance (singleton file)
- Vault contains one Keypair (1:1)
- Vault contains N Messages (1:N)
- Vault contains one Manifest (1:1)

**File Format**: YAML, UTF-8 encoding, LF line endings

---

### 6. Manifest

**Purpose**: Machine-readable metadata documenting vault configuration, algorithms, fingerprints, and rotation history.

**Attributes**:
- `threshold.k` (int): Number of shares required (K)
- `threshold.n` (int): Total number of shares (N)
- `algorithms.keypair` (string): "RSA-4096 + Kyber-1024 (hybrid)"
- `algorithms.passphrase_entropy` (int): 384
- `algorithms.secret_sharing` (string): "Shamir SSS over GF(2^8)"
- `algorithms.message_encryption` (string): "AES-256-GCM"
- `algorithms.kdf` (string): "PBKDF2-HMAC-SHA512 (600k iterations)"
- `fingerprints.rsa_public_key_sha256` (string, hex): SHA-256 of RSA public key
- `fingerprints.kyber_public_key_sha256` (string, hex): SHA-256 of Kyber public key
- `fingerprints.vault_sha256` (string, hex): SHA-256 of entire vault content
- `rotation_history` (list of RotationEvent): Chronological rotation log

**Validation Rules**:
- K MUST be in range [1, N]
- N MUST be in range [K, 255]
- Algorithm strings MUST match documented choices
- Fingerprints MUST be 64-character hex strings (SHA-256)
- Rotation history MUST be chronologically ordered

**State Transitions**:
- `initialized`: Created during vault initialization
- `updated`: Updated during rotation or message operations

**Relationships**:
- One Manifest per Vault (1:1)

---

### 7. RotationEvent

**Purpose**: Log entry documenting a key/share rotation operation.

**Attributes**:
- `date` (string, ISO 8601): Event timestamp
- `event_type` (string): "initial_creation", "share_rotation", "passphrase_rotation", "k_n_change"
- `k` (int): K value after event
- `n` (int): N value after event
- `operator` (string, optional): Who performed rotation (for audit)
- `notes` (string, optional): Additional context

**Validation Rules**:
- Date MUST be valid ISO 8601 UTC
- Event type MUST be from enumerated list
- K and N MUST satisfy 1 ≤ K ≤ N ≤ 255

**State Transitions**:
- `logged`: Appended to rotation_history during operations

**Relationships**:
- Multiple RotationEvents per Manifest (N:1)

---

## Entity Relationship Diagram (ERD)

```
┌─────────────────┐
│      Vault      │
│  (YAML file)    │
└────────┬────────┘
         │ 1:1
         ├─────────────────┐
         │                 │
         ├── Keypair ──────┤── Passphrase (not stored)
         │   (RSA+Kyber)   │   └── N x Share (not stored, BIP39 printed)
         │                 │
         ├── Manifest ─────┤
         │   ├── threshold │
         │   ├── algorithms│
         │   ├── fingerprints
         │   └── rotation_history (N x RotationEvent)
         │
         └── N x Message
             ├── id
             ├── title (unencrypted)
             ├── ciphertext
             ├── rsa_wrapped_kek
             ├── kyber_wrapped_kek
             ├── nonce
             ├── auth_tag
             └── metadata
```

---

## Data Flow: Initialization

```
1. User provides K, N
2. Generate 384-bit Passphrase
3. Split Passphrase → N Shares (Shamir SSS)
4. Encode Shares → N BIP39 Mnemonics (24 words each)
5. Print BIP39 Mnemonics to terminal (NEVER store)
6. Generate RSA-4096 Keypair
7. Generate Kyber-1024 Keypair
8. Derive encryption key from Passphrase (PBKDF2)
9. Encrypt RSA private key with encryption key
10. Encrypt Kyber private key with encryption key
11. Create Vault YAML:
    - Store public keys (plaintext)
    - Store encrypted private keys
    - Store KDF parameters (algorithm, iterations, salt)
    - Create Manifest (K, N, algorithms, fingerprints)
    - Generate Recovery Guide, Policy, Crypto Notes
12. Write Vault to disk (vault.yaml)
13. Zero Passphrase from memory
```

---

## Data Flow: Message Encryption

```
1. User provides title and plaintext message (≤ 64 KB)
2. Validate message size
3. Generate random 256-bit KEK (AES key)
4. Generate random 96-bit nonce
5. Encrypt message with AES-256-GCM:
   - Key: KEK
   - Nonce: nonce
   - AAD: title
   - Plaintext: message
   → Output: ciphertext, auth_tag
6. Encrypt KEK with RSA-4096 public key (OAEP):
   → rsa_wrapped_kek
7. Encrypt KEK with Kyber-1024 public key:
   → kyber_wrapped_kek
8. Create Message object:
   - id: next sequential ID
   - title: unencrypted
   - ciphertext, nonce, auth_tag
   - rsa_wrapped_kek, kyber_wrapped_kek
   - created_timestamp
9. Append Message to Vault.messages array
10. Update Vault.manifest.fingerprints.vault_sha256
11. Write updated Vault to disk
12. Zero KEK and plaintext from memory
```

---

## Data Flow: Message Decryption (Recovery)

```
1. User provides K BIP39 Mnemonics
2. Validate each mnemonic (BIP39 checksum)
3. Decode mnemonics → K Shares
4. Reconstruct Passphrase from K Shares (Shamir SSS)
5. Derive decryption key from Passphrase (PBKDF2 with stored salt)
6. Decrypt RSA private key with decryption key
7. Decrypt Kyber private key with decryption key
8. For each Message in Vault:
   a. Decrypt RSA_wrapped_KEK with RSA private key → KEK_1
   b. Decrypt Kyber_wrapped_KEK with Kyber private key → KEK_2
   c. Verify KEK_1 == KEK_2 (hybrid verification)
   d. Decrypt ciphertext with AES-256-GCM:
      - Key: KEK_1
      - Nonce: stored nonce
      - AAD: message title
      - Auth tag: stored auth_tag
   e. Verify auth tag (tamper detection)
   f. Return plaintext message
9. Display all decrypted messages with titles
10. Zero Passphrase, KEKs, private keys from memory
```

---

## Data Flow: Share Rotation

```
1. User provides old K BIP39 Mnemonics
2. User provides new K', N' values
3. Reconstruct Passphrase from old K Shares
4. Verify Passphrase (decrypt private keys to validate)
5. Generate N' new Shares from same Passphrase
6. Encode new Shares → N' BIP39 Mnemonics
7. Print new BIP39 Mnemonics to terminal (NEVER store)
8. Update Vault.manifest.threshold (K', N')
9. Append RotationEvent to manifest.rotation_history
10. Update vault_sha256 fingerprint
11. Write updated Vault to disk
12. Zero Passphrase and all shares from memory
```

---

## Data Flow: Passphrase Rotation

```
1. User provides old K BIP39 Mnemonics
2. Reconstruct old Passphrase from K Shares
3. Decrypt RSA and Kyber private keys with old Passphrase
4. Generate new 384-bit Passphrase
5. Split new Passphrase → N Shares (same K, N or new values)
6. Encode new Shares → N BIP39 Mnemonics
7. Print new BIP39 Mnemonics to terminal
8. Derive new encryption key from new Passphrase (PBKDF2 with new salt)
9. Re-encrypt RSA private key with new encryption key
10. Re-encrypt Kyber private key with new encryption key
11. Update Vault.keys.encrypted_private with new ciphertexts
12. Update KDF salt in Vault.keys
13. Append RotationEvent to manifest.rotation_history
14. Update vault_sha256 fingerprint
15. Write updated Vault to disk
16. Zero both Passphrases, encryption keys, private keys from memory
```

---

## Storage Constraints

- **Vault file size**: Approximately 5 KB base + (messages × 3 KB average)
- **Maximum practical size**: ~3 MB (1000 messages × 3 KB)
- **Filesystem**: Must support UTF-8 filenames and POSIX permissions (chmod 600)
- **Backup copies**: User responsible for manual copies to ≥3 locations

---

## Security Properties

- **Passphrase never stored**: Only exists in memory during generation/recovery
- **Shares never stored**: Displayed once, never written to disk
- **Private keys encrypted at rest**: PBKDF2 + AES-256-GCM protection
- **Message integrity**: AES-GCM authentication tags prevent tampering
- **Hybrid security**: Both RSA and Kyber must be broken to decrypt
- **Threshold security**: Fewer than K shares reveal zero information (Shamir SSS)
- **Forward secrecy**: Each message uses unique ephemeral KEK and nonce

---

## Phase 1 Data Model Complete ✅
