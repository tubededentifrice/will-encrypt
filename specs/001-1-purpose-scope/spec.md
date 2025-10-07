# Feature Specification: Threshold Cryptography System for Emergency Access

**Feature Branch**: `001-1-purpose-scope`
**Created**: 2025-10-07
**Status**: Draft
**Input**: User description: Comprehensive threshold cryptography system for secure, durable, multi-party access control to sensitive estate information

## Clarifications

### Session 2025-10-07

- Q: Which quantum-resistant algorithm family should be used for the asymmetric keypair to ensure 40-year durability? → A: Hybrid classical+PQC (RSA-4096 + Kyber for transition safety and long-term quantum resistance)
- Q: What minimum entropy (in bits) should the generated passphrase have to ensure cryptographic strength for 40 years? → A: 384 bits (very high security, future-proof against advanced attacks)
- Q: What is the maximum size limit for a single encrypted message to ensure practical storage and performance? → A: 64 KB (small text notes, passwords, short instructions)
- Q: How should the vault directory structure be organized to ensure clarity and SSH-friendly access? → A: Single YAML file containing all vault data (keys, messages, manifest, metadata); BIP39 shares never materialized on disk, only printed during setup
- Q: What backup and redundancy strategy should be documented for the vault YAML file to ensure long-term availability? → A: Manual copies only (user responsible for copying vault file to multiple locations such as cloud, USB, paper)

## User Scenarios & Testing

### Primary User Story

**Owner Initialization and Message Management**: An individual (the Owner) wants to store sensitive information (passwords, account details, final instructions) that should only be accessible in a genuine emergency with cooperation from multiple trusted parties. The Owner initializes the system by choosing K-of-N threshold parameters, generates cryptographic keys, distributes secret shares to N key holders, and then routinely adds encrypted messages over time—all without needing to contact key holders for routine operations.

**Emergency Recovery**: When a legitimate emergency occurs (e.g., death, incapacitation), a Beneficiary (family member, executor) follows a clear recovery guide to collect K shares from key holders, combine them to reconstruct the decryption passphrase, decrypt the private key, and access all stored messages. The process must be completable by a non-technical person within 30 minutes.

### Acceptance Scenarios

1. **Given** the system is uninitialized, **When** the Owner runs initialization with K=3 and N=5, **Then** the system generates a keypair, creates 5 BIP39 mnemonic shares (24 words each) displayed to terminal only (never stored), produces a vault YAML file with manifest and recovery guide.

2. **Given** the system is initialized, **When** the Owner adds a new encrypted message with title "Bank Account Passwords", **Then** the system encrypts the message using the public key, appends it to the YAML messages file with an unencrypted title field, and requires no interaction with key holders.

3. **Given** 3 valid shares are collected, **When** the Beneficiary runs the recovery process, **Then** the system reconstructs the passphrase, decrypts the private key, decrypts all messages, and presents them in a readable format—all within 30 minutes for a competent user.

4. **Given** only 2 of 5 shares are available, **When** a decryption attempt is made, **Then** the system fails to decrypt and produces an error indicating insufficient shares.

5. **Given** a share is compromised, **When** the Owner performs share rotation, **Then** new shares are generated and distributed without re-encrypting any existing messages.

6. **Given** encrypted artifacts stored in the vault, **When** an auditor verifies fingerprints and formats, **Then** all artifacts are confirmed present, unmodified, and in documented open standard formats—without exposing any secrets.

8. **Given** the vault YAML file is created, **When** the Owner follows backup procedures, **Then** the file is manually copied to at least 3 independent locations (e.g., cloud storage, encrypted USB drive, secure facility) as documented in the Recovery Guide.

7. **Given** the system has been idle for 10 years, **When** a Beneficiary attempts recovery using the documented procedures and K valid shares, **Then** decryption succeeds using only open-standard tools and the provided documentation.

### Edge Cases

- What happens when fewer than K shares are provided? System must refuse decryption and clearly indicate the shortfall.
- How does the system handle corrupted ciphertext or tampered artifacts? Integrity checks must detect and report corruption without exposing partial plaintext.
- What if a share is transcribed incorrectly? BIP39 checksums detect invalid mnemonics before attempting reconstruction.
- How does share rotation work when K or N changes? System must support changing threshold parameters while preserving access to old messages.
- What if the passphrase protecting the private key is compromised? Owner can rotate the passphrase and re-share without re-encrypting messages.
- How does the system ensure quantum resistance for 40 years? Algorithm selection and documentation must support future migration paths.
- What happens if message titles are edited after encryption? Only the unencrypted title metadata is updated; ciphertext remains unchanged.
- How are messages entered securely without disk persistence? Use in-memory terminal editor that encrypts before any disk write.
- What happens if a message exceeds 64 KB? System must reject the message with a clear error before encryption.

## Requirements

### Functional Requirements

#### Initialization & Key Management

- **FR-001**: System MUST support initialization with user-specified K and N values where 1 ≤ K ≤ N ≤ 255
- **FR-002**: System MUST generate a hybrid quantum-resistant asymmetric keypair (RSA-4096 + Kyber) suitable for 40+ year durability
- **FR-003**: System MUST generate a 384-bit entropy passphrase and split it into N BIP39 mnemonic shares using Shamir's Secret Sharing
- **FR-004**: System MUST generate shares as 24-word BIP39 mnemonics with checksums
- **FR-005**: System MUST encrypt the private key using the passphrase and store it in a publicly-accessible vault location
- **FR-006**: System MUST create a machine-readable manifest documenting K/N, algorithm choices, key fingerprints, format versions, and crypto provenance

#### Message Encryption & Storage

- **FR-007**: System MUST accept text input up to 64 KB via in-memory terminal editor without materializing plaintext to disk
- **FR-008**: System MUST encrypt messages using the public key with authenticated encryption (AEAD)
- **FR-009**: System MUST append encrypted messages to a YAML file with structure: unencrypted title, encrypted content, timestamp, integrity tag
- **FR-010**: System MUST store all vault artifacts (public key, encrypted private key, messages, manifest, recovery guide, policy document, crypto notes) in a single human-readable YAML file; BIP39 shares MUST NOT be stored in vault or on disk
- **FR-011**: System MUST support listing messages by their unencrypted titles without requiring decryption
- **FR-012**: System MUST support editing message titles without requiring decryption or re-encryption

#### Threshold Decryption & Recovery

- **FR-013**: System MUST accept K or more BIP39 shares and reconstruct the passphrase using Shamir's Secret Sharing
- **FR-014**: System MUST fail securely when fewer than K shares are provided, revealing no information about the passphrase or shares
- **FR-015**: System MUST decrypt the private key using the reconstructed passphrase
- **FR-016**: System MUST decrypt all messages and present them with titles in a readable format
- **FR-017**: System MUST complete the recovery process in under 30 minutes for a competent non-technical user following the recovery guide

#### Key Lifecycle & Rotation

- **FR-018**: System MUST support share rotation: generate new shares for the same passphrase without re-encrypting messages
- **FR-019**: System MUST support passphrase rotation: re-encrypt the private key with a new passphrase, then generate new shares—without re-encrypting messages
- **FR-020**: System MUST support changing K and N values during rotation operations
- **FR-021**: System MUST update the manifest to reflect rotation events with timestamps and version increments

#### Integrity & Validation

- **FR-022**: System MUST verify BIP39 checksums before attempting share reconstruction
- **FR-023**: System MUST verify integrity tags on all encrypted artifacts before decryption
- **FR-024**: System MUST detect corruption or tampering and report it without exposing partial plaintext
- **FR-025**: System MUST provide a validation command that verifies artifact presence, format correctness, and fingerprint matches—without exposing secrets

#### Portability & Documentation

- **FR-026**: System MUST generate a non-technical Recovery Guide with step-by-step emergency instructions for beneficiaries
- **FR-027**: System MUST generate a Policy Document template stating recovery eligibility criteria and holder coordination procedures
- **FR-028**: System MUST generate Crypto Notes documenting algorithm choices, versions, test vectors, and interoperability expectations
- **FR-037**: System MUST document backup procedures instructing users to manually copy the vault YAML file to multiple locations (cloud storage, USB drives, paper printouts)
- **FR-029**: System MUST store all vault artifacts in a single YAML file using open standard encodings (PEM-encoded keys, UTF-8 text, RFC-compliant YAML structure)
- **FR-030**: System MUST operate entirely via command-line scripts suitable for remote SSH execution without GUI
- **FR-031**: System MUST be implementable from documentation alone without requiring access to original tools

#### Security & Threat Mitigation

- **FR-032**: System MUST enforce that no single share reveals any information about the passphrase (information-theoretic security)
- **FR-033**: System MUST use only algorithms with public specifications and peer-reviewed security proofs
- **FR-034**: System MUST document the threat model explicitly in the manifest and README
- **FR-035**: System MUST log all cryptographic operations (key generation, encryption, decryption, rotation) without leaking sensitive data
- **FR-036**: System MUST use hybrid classical+PQC encryption (RSA-4096 + Kyber) with documented migration path to pure PQC when cryptanalysis matures

### Key Entities

- **Keypair**: Asymmetric public/private key pair; public key used for encryption, private key protected by passphrase and used for decryption
- **Passphrase**: 384-bit entropy secret that encrypts the private key; reconstructed from K shares during recovery
- **Share**: One of N BIP39 mnemonic secrets generated via Shamir's Secret Sharing; K shares reconstruct the passphrase
- **Message**: Plaintext content with unencrypted title, encrypted body, timestamp, and integrity tag
- **Vault**: Single YAML file containing all public artifacts (public key, encrypted private key, messages, manifest, recovery guide, policy document, crypto notes); BIP39 shares excluded and never stored on disk
- **Manifest**: Machine-readable YAML documenting system configuration (K/N, algorithms, fingerprints, versions, rotation history)
- **Recovery Guide**: Human-readable step-by-step instructions for emergency decryption
- **Policy Document**: Human-readable governance rules for recovery eligibility and holder coordination

## Review & Acceptance Checklist

### Content Quality
- [x] No implementation details (languages, frameworks, APIs) - focuses on capabilities and requirements
- [x] Focused on user value and business needs - emergency access with multi-party trust
- [x] Written for non-technical stakeholders - recovery guide must be usable by beneficiaries
- [x] All mandatory sections completed

### Requirement Completeness
- [x] No [NEEDS CLARIFICATION] markers remain - all requirements are explicit
- [x] Requirements are testable and unambiguous - each FR can be verified
- [x] Success criteria are measurable - 30 minute recovery time, zero single-party decryption
- [x] Scope is clearly bounded - vault storage is external; no automated emergency detection
- [x] Dependencies and assumptions identified - threat model explicitly documented

## Execution Status

- [x] User description parsed
- [x] Key concepts extracted (threshold cryptography, K-of-N, BIP39 shares, quantum resistance, append-only)
- [x] Ambiguities marked (none remaining - specification is complete)
- [x] User scenarios defined (initialization, message addition, recovery, rotation, validation)
- [x] Requirements generated (36 functional requirements covering all capabilities)
- [x] Entities identified (keypair, passphrase, shares, messages, vault, manifest, guides, policy)
- [x] Review checklist passed
