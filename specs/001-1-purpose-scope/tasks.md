# Tasks: Threshold Cryptography System for Emergency Access

**Input**: Design documents from `/Users/vincent/will-encrypt/specs/001-1-purpose-scope/`
**Prerequisites**: plan.md, research.md, data-model.md, contracts/, quickstart.md

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Include exact file paths in descriptions

## Path Conventions
- **Single project**: `src/`, `tests/` at repository root
- All paths relative to `/Users/vincent/will-encrypt/`

---

## Phase 3.1: Setup

- [X] T001 Create Python project structure (src/, tests/, setup.py, pyproject.toml, requirements.txt)
- [X] T002 Initialize Python package with dependencies (pyyaml, cryptography, pytest, mnemonic, secretsharing)
- [X] T003 [P] Configure linting and type checking (ruff, mypy, pre-commit hooks)
- [X] T004 [P] Create .gitignore for Python project (exclude __pycache__, *.pyc, venv/, vault*.yaml test files)

---

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3

**CRITICAL: These tests MUST be written and MUST FAIL before ANY implementation**

### Contract Tests (Based on contracts/*.schema.yaml)

- [X] T005 [P] Contract test for init command in tests/contract/test_init_contract.py
  - Test: Initialize 3-of-5 vault, verify vault.yaml created with correct structure
  - Test: K > N rejection, K < 1 rejection, vault exists without --force rejection
  - Test: 5 BIP39 mnemonics displayed (24 words each, valid checksums)
  - Test: Performance < 5 seconds
  - ✅ ALL TESTS FAIL (verified: 8 tests failing)

- [X] T006 [P] Contract test for encrypt command in tests/contract/test_encrypt_contract.py
  - Test: Encrypt message via --message argument, verify vault updated
  - Test: Encrypt message via stdin, verify vault updated
  - Test: Message size > 64 KB rejection
  - Test: Performance < 1 second for 64 KB message
  - ✅ ALL TESTS FAIL (verified: 7 tests failing)

- [X] T007 [P] Contract test for decrypt command in tests/contract/test_decrypt_contract.py
  - Test: Decrypt with K valid shares, verify all messages recovered
  - Test: Decrypt with K-1 shares rejection (insufficient shares)
  - Test: Invalid BIP39 checksum rejection
  - Test: Performance < 5 seconds crypto operations
  - ✅ ALL TESTS FAIL (verified: 7 tests failing)

- [X] T008 [P] Contract test for rotate command in tests/contract/test_rotate_contract.py
  - Test: Share rotation (same passphrase, new K/N), verify new shares work
  - Test: Passphrase rotation (new passphrase), verify private keys re-encrypted
  - Test: Old shares invalid after rotation
  - ✅ ALL TESTS FAIL (verified: 6 tests failing)

- [X] T009 [P] Contract test for validate command in tests/contract/test_validate_contract.py
  - Test: Validation passes for valid vault
  - Test: Fingerprint mismatch detection (tampered vault)
  - Test: Missing required fields detection
  - Test: Performance < 2 seconds
  - ✅ ALL TESTS FAIL (verified: 7 tests failing)

- [X] T010 [P] Contract test for list command in tests/contract/test_list_contract.py
  - Test: List messages in table format
  - Test: List messages in JSON format
  - Test: Sort by various fields (id, title, created, size)
  - ✅ ALL TESTS FAIL (verified: 7 tests failing)

### Unit Tests with Test Vectors (Based on research.md)

- [X] T011 [P] Unit tests for Shamir Secret Sharing in tests/unit/test_shamir.py
  - Test: Split 384-bit secret into K-of-N shares using Shamir SSS
  - Test: Reconstruct secret from any K shares
  - Test: Reconstruction fails with K-1 shares
  - Test: Information-theoretic security (K-1 shares reveal nothing)
  - Use test vectors from academic papers or generate known input/output pairs
  - ✅ ALL TESTS FAIL (verified: 9 tests failing)

- [X] T012 [P] Unit tests for BIP39 encoding in tests/unit/test_bip39.py
  - Test: Encode 32-byte share → 24-word BIP39 mnemonic
  - Test: Decode 24-word mnemonic → 32-byte share
  - Test: Checksum validation (detect invalid checksums)
  - Test: Invalid word rejection (not in BIP39 wordlist)
  - Use BIP39 specification test vectors
  - ✅ ALL TESTS FAIL (verified: 10 tests failing)

- [X] T013 [P] Unit tests for hybrid RSA+Kyber encryption in tests/unit/test_keypair.py
  - Test: Generate RSA-4096 keypair
  - Test: Generate Kyber-1024 keypair
  - Test: Hybrid encryption (encrypt KEK with both RSA and Kyber)
  - Test: Hybrid decryption (verify RSA KEK == Kyber KEK)
  - Use NIST CAVP test vectors for RSA-OAEP
  - ✅ ALL TESTS FAIL (verified: 10 tests failing)

- [X] T014 [P] Unit tests for AES-256-GCM encryption in tests/unit/test_encryption.py
  - Test: Encrypt message with AES-256-GCM (KEK, nonce, AAD)
  - Test: Decrypt message and verify authentication tag
  - Test: Tampered ciphertext rejection (auth tag mismatch)
  - Test: Nonce uniqueness enforcement
  - Use NIST CAVP AES-GCM test vectors
  - ✅ ALL TESTS FAIL (verified: 12 tests failing)

- [X] T015 [P] Unit tests for YAML vault operations in tests/unit/test_vault.py
  - Test: Create vault YAML structure from Keypair + Manifest
  - Test: Read vault YAML and parse to Python objects
  - Test: Append message to vault (update messages array)
  - Test: Update manifest (fingerprints, rotation history)
  - Test: YAML format validation
  - ✅ ALL TESTS FAIL (verified: 10 tests failing)

### Integration Tests (Based on quickstart.md scenarios)

- [X] T016 [P] Integration test for full lifecycle in tests/integration/test_full_lifecycle.py
  - Test: Steps 1-10 from quickstart.md (init → encrypt → decrypt → rotate → validate)
  - Test: End-to-end workflow with temporary vault file
  - ✅ ALL TESTS FAIL (verified: 11 tests failing)

- [X] T017 [P] Integration test for emergency recovery in tests/integration/test_emergency_recovery.py
  - Test: Initialize vault, encrypt messages, decrypt with K shares
  - Test: Verify plaintext matches original messages
  - Test: Hybrid verification (RSA KEK == Kyber KEK)
  - ✅ ALL TESTS FAIL (verified: 7 tests failing)

- [X] T018 [P] Integration test for share rotation in tests/integration/test_share_rotation.py
  - Test: Initialize vault, rotate shares (change K/N)
  - Test: Verify new shares work, old shares fail
  - Test: Messages not re-encrypted (efficiency)
  - ✅ ALL TESTS FAIL (verified: 7 tests failing)

- [X] T019 [P] Integration test for validation and audit in tests/integration/test_validation_audit.py
  - Test: Validate valid vault (all checks pass)
  - Test: Detect tampered vault (fingerprint mismatch)
  - Test: Detect corrupted message (auth tag failure)
  - ✅ ALL TESTS FAIL (verified: 10 tests failing)

---

## Phase 3.3: Core Implementation (ONLY after tests are failing)

### Cryptographic Primitives

- [ ] T020 [P] Implement Shamir Secret Sharing in src/crypto/shamir.py
  - Function: split_secret(secret: bytes, k: int, n: int) → List[bytes]
  - Function: reconstruct_secret(shares: List[bytes]) → bytes
  - Use Lagrange interpolation over GF(2^8)
  - Validate: 1 ≤ k ≤ n ≤ 255
  - Make T011 tests pass

- [ ] T021 [P] Implement BIP39 encoding/decoding in src/crypto/bip39.py
  - Function: encode_share(share: bytes) → str (24-word mnemonic)
  - Function: decode_share(mnemonic: str) → bytes
  - Function: validate_checksum(mnemonic: str) → bool
  - Use python-mnemonic library or implement BIP39 spec
  - Make T012 tests pass

- [ ] T022 [P] Implement 384-bit passphrase generation in src/crypto/passphrase.py
  - Function: generate_passphrase() → bytes (48 bytes)
  - Use secrets.token_bytes(48) for cryptographic randomness
  - Function: derive_key(passphrase: bytes, salt: bytes, iterations: int) → bytes
  - Use PBKDF2-HMAC-SHA512 with 600,000 iterations
  - Type hints for all functions

- [ ] T023 Implement hybrid RSA+Kyber keypair generation in src/crypto/keypair.py
  - Class: HybridKeypair with rsa_public, rsa_private, kyber_public, kyber_private
  - Method: generate(passphrase: bytes, salt: bytes) → HybridKeypair
  - RSA-4096 key generation using cryptography.hazmat.primitives.asymmetric.rsa
  - Kyber-1024 key generation using pqcrypto or liboqs-python
  - Method: encrypt_private_keys(passphrase: bytes, salt: bytes) → EncryptedKeypair
  - Method: decrypt_private_keys(encrypted: EncryptedKeypair, passphrase: bytes) → HybridKeypair
  - Make T013 tests pass
  - Depends on: T022 (passphrase derivation)

- [ ] T024 Implement hybrid message encryption in src/crypto/encryption.py
  - Function: encrypt_message(plaintext: bytes, public_keys: HybridKeypair, title: str) → EncryptedMessage
  - Steps: Generate KEK → Encrypt plaintext with AES-256-GCM → Wrap KEK with RSA → Wrap KEK with Kyber
  - Function: decrypt_message(encrypted: EncryptedMessage, private_keys: HybridKeypair) → bytes
  - Steps: Unwrap KEK with RSA → Unwrap KEK with Kyber → Verify KEKs match → Decrypt with AES-256-GCM
  - Validate message size ≤ 64 KB
  - Make T014 tests pass
  - Depends on: T023 (keypair)

### Data Models (Based on data-model.md entities)

- [ ] T025 [P] Implement Keypair model in src/storage/models.py
  - Dataclass: Keypair with attributes from data-model.md
  - Validation: RSA 4096 bits, Kyber 1024, KDF iterations ≥ 600k, salt 32 bytes
  - Methods: to_dict(), from_dict() for YAML serialization

- [ ] T026 [P] Implement Message model in src/storage/models.py
  - Dataclass: Message with id, title, ciphertext, wrapped_keks, nonce, tag, created, size
  - Validation: title ≤ 256 chars, size ≤ 64 KB, nonce 96 bits, tag 128 bits
  - Methods: to_dict(), from_dict()

- [ ] T027 [P] Implement Manifest model in src/storage/models.py
  - Dataclass: Manifest with threshold (k, n), algorithms, fingerprints, rotation_history
  - Validation: 1 ≤ k ≤ n ≤ 255, fingerprints are 64-char hex
  - Methods: to_dict(), from_dict()

- [ ] T028 [P] Implement Vault model in src/storage/models.py
  - Dataclass: Vault with version, created, keys (Keypair), messages (List[Message]), manifest (Manifest)
  - Methods: to_yaml() → str, from_yaml(yaml_str: str) → Vault
  - Validation: version supported, timestamps valid ISO 8601

### Storage Layer

- [ ] T029 Implement vault YAML operations in src/storage/vault.py
  - Function: create_vault(keypair: Keypair, manifest: Manifest, guides: Dict[str, str]) → Vault
  - Function: save_vault(vault: Vault, path: str) → None (write YAML with permissions 0600)
  - Function: load_vault(path: str) → Vault
  - Function: append_message(vault: Vault, message: Message) → Vault
  - Function: update_manifest(vault: Vault, manifest: Manifest) → Vault
  - Make T015 tests pass
  - Depends on: T025, T026, T027, T028 (models)

- [ ] T030 Implement manifest operations in src/storage/manifest.py
  - Function: compute_fingerprints(vault: Vault) → Dict[str, str] (SHA-256 hashes)
  - Function: validate_fingerprints(vault: Vault) → bool
  - Function: append_rotation_event(manifest: Manifest, event: RotationEvent) → Manifest
  - Depends on: T027 (Manifest model)

### Documentation Generation

- [ ] T031 [P] Implement recovery guide generation in src/docs/recovery_guide.py
  - Function: generate_recovery_guide(k: int, n: int) → str
  - Template: Multi-line text with step-by-step emergency instructions
  - Include: When to use, prerequisites, step-by-step recovery with K shares, expected duration

- [ ] T032 [P] Implement policy document generation in src/docs/policy.py
  - Function: generate_policy_document() → str
  - Template: Recovery eligibility criteria, key holder coordination procedures
  - Placeholder text for user customization

- [ ] T033 [P] Implement crypto notes generation in src/docs/crypto_notes.py
  - Function: generate_crypto_notes(manifest: Manifest) → str
  - Document: Algorithm choices, versions, test vectors, interoperability notes
  - Include threat model summary

### CLI Commands (Based on contracts/*.schema.yaml)

- [ ] T034 Implement init command in src/cli/init.py
  - Arguments: --k, --n, --vault, --force (use argparse)
  - Steps: Generate passphrase → Split into shares → Encode as BIP39 → Generate keypairs → Encrypt private keys → Create vault → Print shares to terminal
  - Exit codes: 0 (success), 1 (invalid args), 2 (vault exists), 3 (crypto error), 4 (filesystem error)
  - Make T005 tests pass
  - Depends on: T020 (Shamir), T021 (BIP39), T022 (passphrase), T023 (keypair), T029 (vault), T031, T032, T033 (docs)

- [ ] T035 Implement encrypt command in src/cli/encrypt.py
  - Arguments: --vault, --title, --editor / --message / --stdin (use argparse)
  - Steps: Load vault → Read message (editor/arg/stdin) → Validate size ≤ 64 KB → Encrypt with hybrid → Append to vault → Save vault
  - Exit codes: 0 (success), 1 (invalid args), 2 (vault not found), 4 (size exceeded), 5 (encryption error), 6 (vault write error)
  - Make T006 tests pass
  - Depends on: T024 (encryption), T029 (vault)

- [ ] T036 Implement decrypt command in src/cli/decrypt.py
  - Arguments: --vault, --shares / --interactive, --output, --message-id (use argparse)
  - Steps: Load vault → Collect K shares (interactive/args) → Validate BIP39 → Reconstruct passphrase → Decrypt private keys → Decrypt messages → Display/write output
  - Exit codes: 0 (success), 1 (invalid args), 2 (vault not found), 3 (insufficient shares), 4 (invalid share), 6 (wrong passphrase), 7 (decryption failed), 8 (hybrid verification failed)
  - Make T007 tests pass
  - Depends on: T020 (Shamir), T021 (BIP39), T023 (keypair), T024 (encryption), T029 (vault)

- [ ] T037 Implement rotate command in src/cli/rotate.py
  - Arguments: --vault, --mode (shares|passphrase), --k, --n, --old-shares / --interactive (use argparse)
  - Share rotation: Reconstruct passphrase → Generate new shares → Update manifest
  - Passphrase rotation: Reconstruct passphrase → Decrypt private keys → Generate new passphrase → Re-encrypt private keys → Generate new shares → Update manifest
  - Exit codes: 0 (success), 1-9 per contract spec
  - Make T008 tests pass
  - Depends on: T020 (Shamir), T021 (BIP39), T022 (passphrase), T023 (keypair), T029 (vault), T030 (manifest)

- [ ] T038 Implement validate command in src/cli/validate.py
  - Arguments: --vault, --verbose, --check-format, --check-fingerprints, --check-algorithms (use argparse)
  - Steps: Load vault → Validate YAML structure → Validate required fields → Recompute fingerprints → Compare to manifest → Validate algorithms → Display report
  - Exit codes: 0 (pass), 1-8 per contract spec
  - Make T009 tests pass
  - Depends on: T029 (vault), T030 (manifest)

- [ ] T039 Implement list command in src/cli/list.py
  - Arguments: --vault, --format (table|json|csv), --sort (use argparse)
  - Steps: Load vault → Extract message metadata (id, title, created, size) → Format output → Display
  - Exit codes: 0 (success), 1-4 per contract spec
  - Make T010 tests pass
  - Depends on: T029 (vault)

- [ ] T040 Implement main CLI entry point in src/main.py
  - Subcommands: init, encrypt, decrypt, rotate, validate, list (use argparse)
  - Import command handlers from src/cli/*
  - Error handling and exit codes
  - Help text and usage examples

---

## Phase 3.4: Integration & Polish

- [ ] T041 Run integration test suite (make T016, T017, T018, T019 pass)
  - Execute tests/integration/test_full_lifecycle.py
  - Execute tests/integration/test_emergency_recovery.py
  - Execute tests/integration/test_share_rotation.py
  - Execute tests/integration/test_validation_audit.py
  - Fix any failures, verify all 10 quickstart steps work

- [ ] T042 Performance validation
  - Measure: Initialization (target < 5 sec)
  - Measure: Message encryption (target < 1 sec for 64 KB)
  - Measure: Recovery crypto operations (target < 5 sec)
  - Measure: Validation (target < 2 sec)
  - Optimize if targets not met

- [ ] T043 [P] Create README.md with user guide
  - Sections: Introduction, Installation, Quick Start, Commands Reference, Security Model, Threat Model, Backup Procedures, Troubleshooting
  - Include: All commands from contracts with examples
  - Include: Recovery guide summary
  - Target audience: Non-technical users (beneficiaries) and technical users (owners)

- [ ] T044 [P] Update CLAUDE.md with implementation details
  - Add: Cryptographic library choices (cryptography, pqcrypto/liboqs-python, python-mnemonic)
  - Add: Module structure and responsibilities
  - Add: Common debugging scenarios
  - Add: Test execution commands

- [ ] T045 Create requirements.txt and setup.py
  - List dependencies: pyyaml, cryptography, mnemonic, secretsharing (or custom), pytest, ruff, mypy
  - Specify minimum versions
  - Setup.py: Package metadata, entry point for will-encrypt command

- [ ] T046 Run full test suite and verify coverage
  - Execute: pytest tests/ --cov=src --cov-report=html
  - Target: > 90% code coverage for src/crypto/, src/storage/, src/cli/
  - Fix any uncovered critical paths

- [ ] T047 Manual quickstart execution (10 steps)
  - Execute all 10 steps from quickstart.md manually
  - Verify exit codes, outputs, performance targets
  - Document any deviations or issues

---

## Dependencies

**Setup → Tests → Implementation → Integration → Polish**

- T001-T004 (Setup) → Everything else
- T005-T019 (Tests) → T020-T040 (Implementation)
- T020-T022 (Crypto primitives) → T023-T024 (Higher-level crypto)
- T023-T024 (Crypto) → T025-T028 (Models), T034-T039 (CLI)
- T025-T028 (Models) → T029-T030 (Storage)
- T029-T030 (Storage) → T034-T039 (CLI)
- T031-T033 (Docs generation) → T034 (init command)
- T034-T040 (CLI) → T041-T047 (Integration & polish)

**Blocking relationships**:
- T023 blocks T024 (encryption needs keypair)
- T029 blocks T034-T039 (all CLI commands need vault operations)
- T034 blocks T035, T036 (must init before encrypt/decrypt)
- T020, T021, T022, T023, T024 block T036 (decrypt needs all crypto primitives)

---

## Parallel Execution Examples

### Parallel Group 1: Setup
```bash
# Launch T003 and T004 together (different files, no dependencies after T001-T002)
Task: "Configure linting and type checking (ruff, mypy, pre-commit hooks)"
Task: "Create .gitignore for Python project"
```

### Parallel Group 2: Contract Tests
```bash
# Launch T005-T010 together (all contract tests in different files)
Task: "Contract test for init command in tests/contract/test_init_contract.py"
Task: "Contract test for encrypt command in tests/contract/test_encrypt_contract.py"
Task: "Contract test for decrypt command in tests/contract/test_decrypt_contract.py"
Task: "Contract test for rotate command in tests/contract/test_rotate_contract.py"
Task: "Contract test for validate command in tests/contract/test_validate_contract.py"
Task: "Contract test for list command in tests/contract/test_list_contract.py"
```

### Parallel Group 3: Unit Tests
```bash
# Launch T011-T015 together (all unit tests in different files)
Task: "Unit tests for Shamir Secret Sharing in tests/unit/test_shamir.py"
Task: "Unit tests for BIP39 encoding in tests/unit/test_bip39.py"
Task: "Unit tests for hybrid RSA+Kyber encryption in tests/unit/test_keypair.py"
Task: "Unit tests for AES-256-GCM encryption in tests/unit/test_encryption.py"
Task: "Unit tests for YAML vault operations in tests/unit/test_vault.py"
```

### Parallel Group 4: Integration Tests
```bash
# Launch T016-T019 together (all integration tests in different files)
Task: "Integration test for full lifecycle in tests/integration/test_full_lifecycle.py"
Task: "Integration test for emergency recovery in tests/integration/test_emergency_recovery.py"
Task: "Integration test for share rotation in tests/integration/test_share_rotation.py"
Task: "Integration test for validation and audit in tests/integration/test_validation_audit.py"
```

### Parallel Group 5: Cryptographic Primitives
```bash
# Launch T020-T022 together (different files, no dependencies between them)
Task: "Implement Shamir Secret Sharing in src/crypto/shamir.py"
Task: "Implement BIP39 encoding/decoding in src/crypto/bip39.py"
Task: "Implement 384-bit passphrase generation in src/crypto/passphrase.py"
```

### Parallel Group 6: Data Models
```bash
# Launch T025-T028 together (all in same file but independent dataclasses)
Task: "Implement Keypair model in src/storage/models.py"
Task: "Implement Message model in src/storage/models.py"
Task: "Implement Manifest model in src/storage/models.py"
Task: "Implement Vault model in src/storage/models.py"
```

### Parallel Group 7: Documentation Generation
```bash
# Launch T031-T033 together (different files, no dependencies)
Task: "Implement recovery guide generation in src/docs/recovery_guide.py"
Task: "Implement policy document generation in src/docs/policy.py"
Task: "Implement crypto notes generation in src/docs/crypto_notes.py"
```

### Parallel Group 8: Polish
```bash
# Launch T043-T044 together (different files)
Task: "Create README.md with user guide"
Task: "Update CLAUDE.md with implementation details"
```

---

## Notes

- **[P] tasks**: Different files, no dependencies between them
- **TDD enforcement**: Verify all tests in T005-T019 fail before starting T020
- **Test vectors**: Use NIST CAVP, BIP39 spec, academic papers for validation
- **Commit strategy**: Commit after each task completion
- **Performance**: Measure during T042, optimize if targets not met
- **Security**: Never store passphrases or shares on disk, zero memory after use
- **Type hints**: Use throughout for mypy validation
- **Error handling**: Explicit exit codes per contract specifications

---

## Task Execution Order Summary

1. **Setup** (T001-T004): Can run T003-T004 in parallel after T001-T002
2. **Contract Tests** (T005-T010): All parallel [P]
3. **Unit Tests** (T011-T015): All parallel [P]
4. **Integration Tests** (T016-T019): All parallel [P]
5. **Crypto Primitives** (T020-T022): All parallel [P]
6. **Advanced Crypto** (T023-T024): Sequential (T023 → T024)
7. **Data Models** (T025-T028): All parallel [P] (same file but independent)
8. **Storage** (T029-T030): Sequential (depends on models)
9. **Docs Generation** (T031-T033): All parallel [P]
10. **CLI Commands** (T034-T040): Sequential (each depends on crypto + storage)
11. **Integration & Polish** (T041-T047): Mostly sequential, T043-T044 parallel

**Total Tasks**: 47
**Estimated Parallel Opportunities**: ~25 tasks can run in parallel across 8 groups
**Critical Path**: Setup → Tests → Crypto → Storage → CLI → Integration

---

*Based on plan.md, data-model.md, contracts/, research.md, quickstart.md*
*Constitution v1.0.0 compliance enforced throughout*
