
# Implementation Plan: Threshold Cryptography System for Emergency Access

**Branch**: `001-1-purpose-scope` | **Date**: 2025-10-07 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/Users/vincent/will-encrypt/specs/001-1-purpose-scope/spec.md`

## Summary

A command-line threshold cryptography system enabling secure emergency access to sensitive information (passwords, estate instructions) through K-of-N secret sharing. The Owner encrypts messages using a hybrid quantum-resistant keypair (RSA-4096 + Kyber), with the private key protected by a 384-bit passphrase split into N BIP39 mnemonic shares. Recovery requires K shares to reconstruct the passphrase and decrypt messages. All vault artifacts stored in a single human-readable YAML file. Implementation uses Python 3 and standard CLI utilities (GPG) with minimal external dependencies, targeting Linux (Debian) and macOS compatibility.

## Technical Context

**Language/Version**: Python 3.11+ (standard library preferred)
**Primary Dependencies**:
- `pyyaml` (quasi-standard for YAML parsing)
- `cryptography` (for cryptographic primitives, widely established)
- GPG/OpenSSL (system utilities for hybrid RSA+PQC operations)
- Standard library: `secrets`, `hashlib`, `hmac`, `base64`

**Storage**: Single YAML file on local filesystem (vault.yaml); no database required
**Testing**: pytest (industry standard, stable), test vectors from NIST/IETF standards
**Target Platform**: Linux (Debian 11+), macOS 12+ (command-line only, SSH-friendly)
**Project Type**: Single project (CLI utility with library components)
**Performance Goals**:
- Initialization: < 5 seconds for key generation and share creation
- Message encryption: < 1 second for 64 KB message
- Recovery: < 30 minutes for non-technical user (including share collection)
- Validation: < 2 seconds for artifact integrity checks

**Constraints**:
- Offline-capable after initial installation (no network dependencies)
- No proprietary dependencies (open standards only)
- BIP39 shares never stored on disk (displayed to terminal only)
- Messages limited to 64 KB each
- 384-bit passphrase entropy minimum
- Hybrid RSA-4096 + Kyber encryption for 40-year durability

**Scale/Scope**:
- Single user per vault instance
- Up to 255 key holders (N ≤ 255)
- Estimated 100-1000 messages per vault over lifetime
- Total vault size: < 10 MB typical, < 100 MB maximum

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Verify compliance with `.specify/memory/constitution.md`:

- [x] **Three Invariants**: ✅ Design preserves (1) no single-actor decryption (K-of-N threshold), (2) future-generation decryptability (open standards, documented procedures), (3) provable strength (RSA-4096 + Kyber, 384-bit passphrase)
- [x] **Minimal Dependency**: ✅ All dependencies are open standards (Python stdlib, GPG, YAML, BIP39, Shamir's Secret Sharing). No proprietary services. Cryptographic primitives from established libraries (cryptography, GPG).
- [x] **Simplicity Over Convenience**: ✅ Design uses standard CLI patterns, single YAML file, human-readable formats. Implementable from documentation alone using open standards.
- [x] **Test-First**: ✅ Tests planned before implementation with NIST test vectors for crypto operations, independent BIP39 test vectors, Shamir SSS validation.
- [x] **Code Quality**: ✅ Python type hints for type safety, explicit error handling (no silent crypto failures), modular design (crypto, storage, CLI separated).
- [x] **Security Requirements**: ✅ Cryptographic standards documented (RSA-4096, Kyber, Shamir SSS, BIP39), key ceremonies defined, audit logging planned, threat model to be documented in research phase.
- [x] **Documentation Standards**: ✅ README.md, CLAUDE.md, threat model, key ceremony procedures, disaster recovery guide all planned in spec FR-026 through FR-037.

**Initial Constitution Check: PASS** ✅

*No violations identified. Design fully aligns with constitutional principles.*

## Project Structure

### Documentation (this feature)
```
specs/001-1-purpose-scope/
├── spec.md              # Feature specification
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
│   ├── init.schema.yaml
│   ├── encrypt.schema.yaml
│   ├── decrypt.schema.yaml
│   ├── rotate.schema.yaml
│   └── validate.schema.yaml
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
will-encrypt/
├── src/
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── keypair.py       # RSA+Kyber hybrid key generation
│   │   ├── passphrase.py    # 384-bit passphrase generation
│   │   ├── shamir.py        # Shamir Secret Sharing implementation
│   │   ├── bip39.py         # BIP39 mnemonic encoding/decoding
│   │   └── encryption.py    # Message encryption/decryption (AEAD)
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── vault.py         # YAML vault read/write/update operations
│   │   └── manifest.py      # Manifest generation and validation
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── init.py          # Initialization command
│   │   ├── encrypt.py       # Message encryption command
│   │   ├── decrypt.py       # Recovery/decryption command
│   │   ├── rotate.py        # Share/passphrase rotation command
│   │   ├── validate.py      # Artifact validation command
│   │   └── list.py          # Message listing command
│   ├── docs/
│   │   ├── __init__.py
│   │   ├── recovery_guide.py  # Recovery guide generation
│   │   ├── policy.py          # Policy document template generation
│   │   └── crypto_notes.py    # Cryptographic documentation generation
│   └── main.py              # CLI entry point
├── tests/
│   ├── contract/
│   │   ├── test_init_contract.py
│   │   ├── test_encrypt_contract.py
│   │   ├── test_decrypt_contract.py
│   │   ├── test_rotate_contract.py
│   │   └── test_validate_contract.py
│   ├── integration/
│   │   ├── test_full_lifecycle.py
│   │   ├── test_emergency_recovery.py
│   │   ├── test_share_rotation.py
│   │   └── test_validation_audit.py
│   └── unit/
│       ├── test_shamir.py
│       ├── test_bip39.py
│       ├── test_keypair.py
│       ├── test_encryption.py
│       └── test_vault.py
├── README.md                # User-facing documentation
├── CLAUDE.md                # AI assistant context
├── requirements.txt         # Python dependencies
├── setup.py                 # Package installation
└── pyproject.toml           # Modern Python project metadata
```

**Structure Decision**: Single project structure selected. This is a standalone CLI utility with no web/mobile components. The structure follows Python best practices with clear separation of concerns: `crypto/` for cryptographic primitives, `storage/` for vault operations, `cli/` for command handlers, `docs/` for documentation generation. Tests mirror the source structure with contract, integration, and unit test categories as required by TDD principles.

## Phase 0: Outline & Research

**Research Areas Identified**:
1. Hybrid RSA-4096 + Kyber implementation approaches
2. Shamir's Secret Sharing libraries and best practices
3. BIP39 mnemonic generation and validation
4. AEAD encryption schemes suitable for 40-year durability
5. YAML structure for vault file format
6. GPG integration for RSA operations
7. Python cryptography library capabilities
8. Test vectors for cryptographic validation

**Output**: `research.md` - All research areas resolved, no NEEDS CLARIFICATION remaining.

**Key Decisions**:
- Hybrid RSA-4096 + Kyber-1024 (layered encryption)
- Python `cryptography` library + external PQC library for Kyber
- `secretsharing` or custom Shamir SSS implementation
- BIP39 via `mnemonic` library
- AES-256-GCM for message encryption
- Single YAML file for vault storage
- Explicit threat model documented

**Phase 0 Complete** ✅

---

## Phase 1: Design & Contracts

**Prerequisites**: research.md complete ✅

### 1.1 Data Model

**Output**: `data-model.md`

**Entities Defined**:
- Keypair (RSA-4096 + Kyber-1024 hybrid)
- Passphrase (384-bit, never stored)
- Share (N BIP39 mnemonics, never stored)
- Message (encrypted content with unencrypted title)
- Vault (single YAML file container)
- Manifest (configuration and metadata)
- RotationEvent (audit log entry)

**Key Relationships**:
- 1 Vault : 1 Keypair : 1 Passphrase : N Shares
- 1 Vault : N Messages
- 1 Vault : 1 Manifest : N RotationEvents

**Data Flows Documented**:
- Initialization (keygen, share split, vault creation)
- Message encryption (hybrid RSA+Kyber + AES-GCM)
- Message decryption (share reconstruction, hybrid verification)
- Share rotation (same passphrase, new shares)
- Passphrase rotation (new passphrase, re-encrypt private keys)

### 1.2 API Contracts

**Output**: `contracts/` directory with 6 command schemas

**Contracts Defined**:
1. **init.schema.yaml**: Initialize K-of-N threshold vault
   - Arguments: --k, --n, --vault, --force
   - Outputs: BIP39 shares (terminal only), vault.yaml file
   - Performance: < 5 seconds

2. **encrypt.schema.yaml**: Encrypt and append message
   - Arguments: --vault, --title, --editor/--message/--stdin
   - Outputs: Updated vault with new message
   - Performance: < 1 second per 64 KB message

3. **decrypt.schema.yaml**: Emergency recovery with K shares
   - Arguments: --vault, --shares/--interactive, --output, --message-id
   - Inputs: K BIP39 shares
   - Outputs: Decrypted messages
   - Performance: < 30 minutes (user time), < 5 seconds (crypto time)

4. **rotate.schema.yaml**: Rotate shares or passphrase
   - Arguments: --vault, --mode (shares|passphrase), --k, --n
   - Modes: Share rotation (same passphrase) vs passphrase rotation (new passphrase)
   - Outputs: New BIP39 shares (terminal only), updated vault

5. **validate.schema.yaml**: Vault integrity audit
   - Arguments: --vault, --verbose, --check-format, --check-fingerprints
   - Outputs: Validation report (no secrets exposed)
   - Performance: < 2 seconds

6. **list.schema.yaml**: List messages by title
   - Arguments: --vault, --format (table|json|csv), --sort
   - Outputs: Message metadata (no decryption)
   - Performance: < 0.5 seconds

**All contracts specify**: Arguments, validation rules, exit codes, outputs, performance targets, security requirements, example usage.

### 1.3 Quickstart Guide

**Output**: `quickstart.md`

**Scenario**: Complete lifecycle test (10 steps)
1. Initialize 3-of-5 vault
2. Encrypt 3 messages
3. List messages (no decryption)
4. Validate vault
5. Emergency recovery (3 shares decrypt all)
6. Test insufficient shares (negative test)
7. Share rotation (3-of-5 → 4-of-6)
8. Verify rotated shares work
9. Test old shares invalidated (negative test)
10. Final validation

**Duration**: ~10 minutes manual execution
**Success Criteria**: All steps pass with expected exit codes and outputs
**Integration Test Scenarios**: 6 automated test scenarios described

### 1.4 Agent Context

**Output**: `CLAUDE.md` (repository root)

**Contents**:
- Language: Python 3.11+
- Database: Single YAML file (vault.yaml)
- Project type: Single project CLI utility
- Recent changes: Feature 001 (threshold cryptography system)
- Tech stack: Python cryptography library, pytest, pyyaml

**Phase 1 Complete** ✅

---

## Phase 2: Task Planning Approach
*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:
- Load `.specify/templates/tasks-template.md` as base
- Generate tasks from Phase 1 design docs (contracts, data model, quickstart)

**Contract-Driven Tasks**:
- Each command contract → contract test task [P]
- Each command → CLI implementation task
- 6 commands × (1 test + 1 implementation) = 12 core tasks

**Data Model-Driven Tasks**:
- Each entity → model class creation task [P]
- Keypair, Passphrase, Share, Message, Vault, Manifest = 6 model tasks

**Quickstart-Driven Tasks**:
- Each quickstart step → integration test task
- 10 steps = 10 integration test tasks

**Cryptographic Tasks**:
- Shamir SSS implementation with test vectors
- BIP39 encoding/decoding with test vectors
- Hybrid RSA+Kyber encryption with test vectors
- AES-256-GCM with NIST test vectors
- PBKDF2 key derivation

**Documentation Tasks**:
- Recovery guide generation
- Policy document template
- Crypto notes generation
- README.md (user guide)
- CLAUDE.md (already created, may need updates)

**Ordering Strategy**:
- **Setup phase**: Project structure, dependencies, linting
- **Tests first (TDD)**: Contract tests, unit tests with test vectors
- **Core cryptography**: Shamir SSS, BIP39, hybrid encryption, AES-GCM
- **Data models**: Entity classes with validation
- **Storage layer**: YAML vault operations
- **CLI commands**: Command handlers using crypto + storage layers
- **Integration tests**: Full lifecycle scenarios from quickstart
- **Documentation**: Generated guides and README

**Parallelization**:
- Mark [P] for tasks operating on different files or independent modules
- Cryptographic primitives can be developed in parallel
- Contract tests can be written in parallel
- CLI command implementations sequential (depend on crypto/storage layers)

**Estimated Output**: 40-50 numbered, dependency-ordered tasks in tasks.md

**TDD Enforcement**:
- Every implementation task MUST be preceded by its test task
- Test task must be marked complete (failing tests written) before implementation begins
- Red-Green-Refactor cycle strictly enforced per constitution

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

---

## Phase 3+: Future Implementation
*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)
**Phase 4**: Implementation (execute tasks.md following constitutional principles)
**Phase 5**: Validation (run tests, execute quickstart.md, performance validation)

---

## Complexity Tracking

**No constitutional violations identified**. Design fully complies with all principles:
- Three Invariants: ✅ No single-actor decryption, future-generation decryptability, provable strength
- Minimal Dependency: ✅ Open standards only (Python stdlib, cryptography, YAML, BIP39, Shamir SSS)
- Simplicity Over Convenience: ✅ Single YAML file, CLI patterns, standard formats
- Test-First: ✅ Contract tests, unit tests with vectors, integration tests planned before implementation
- Code Quality: ✅ Python type hints, explicit errors, modular design
- Security Requirements: ✅ Hybrid crypto, 384-bit passphrase, test vectors, audit logging
- Documentation Standards: ✅ README, CLAUDE.md, recovery guide, policy, crypto notes all planned

**No complexity deviations to justify.**

---

## Progress Tracking

**Phase Status**:
- [x] Phase 0: Research complete (/plan command) ✅
- [x] Phase 1: Design complete (/plan command) ✅
- [x] Phase 2: Task planning approach described (/plan command) ✅
- [ ] Phase 3: Tasks generated (/tasks command - NEXT STEP)
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: PASS ✅
- [x] Post-Design Constitution Check: PASS ✅
- [x] All NEEDS CLARIFICATION resolved ✅
- [x] Complexity deviations documented (NONE) ✅

**Artifacts Generated**:
- ✅ research.md (Phase 0)
- ✅ data-model.md (Phase 1)
- ✅ contracts/init.schema.yaml (Phase 1)
- ✅ contracts/encrypt.schema.yaml (Phase 1)
- ✅ contracts/decrypt.schema.yaml (Phase 1)
- ✅ contracts/rotate.schema.yaml (Phase 1)
- ✅ contracts/validate.schema.yaml (Phase 1)
- ✅ contracts/list.schema.yaml (Phase 1)
- ✅ quickstart.md (Phase 1)
- ✅ CLAUDE.md (Phase 1)

---

## Post-Design Constitution Check

**Re-evaluate constitutional compliance after design phase:**

- [x] **Three Invariants**: ✅ Design preserves all three invariants. Hybrid encryption ensures provable strength, K-of-N ensures no single-actor decryption, open standards and documentation ensure future-generation decryptability.

- [x] **Minimal Dependency**: ✅ All dependencies remain open standards. Python `cryptography` library is widely established. PQC library (pqcrypto/liboqs-python) implements NIST standards. BIP39, Shamir SSS, AES-GCM all have open specifications.

- [x] **Simplicity Over Convenience**: ✅ Design uses single YAML file (simpler than multiple files or database). CLI commands follow standard Unix patterns. Data model is straightforward with clear entity relationships.

- [x] **Test-First**: ✅ Contract tests defined before implementation. Test vectors identified for all cryptographic operations (NIST, BIP39, Shamir SSS). Quickstart provides integration test scenarios. TDD order enforced in Phase 2 planning.

- [x] **Code Quality**: ✅ Design supports type safety (Python type hints), explicit error handling (exit codes documented per contract), minimal coupling (crypto/storage/CLI layers separated), readability (clear module structure).

- [x] **Security Requirements**: ✅ Algorithms documented (RSA-4096, Kyber-1024, AES-256-GCM, Shamir SSS, BIP39). Key management procedures defined (passphrase never stored, shares never stored, private keys encrypted at rest). Audit logging planned (rotation history in manifest). Threat model documented in research.md.

- [x] **Documentation Standards**: ✅ README.md planned, CLAUDE.md created, threat model documented, key ceremonies defined (initialization, rotation procedures in contracts), disaster recovery guide planned (recovery_guide in vault).

**Post-Design Constitution Check: PASS** ✅

**No design refactoring required. Proceed to Phase 3 (/tasks command).**

---
*Based on Constitution v1.0.0 - See `.specify/memory/constitution.md`*
