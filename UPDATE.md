# Maintenance Update Prompt for will-encrypt

This document contains instructions for an AI agent to maintain the will-encrypt repository over time, ensuring dependencies stay current, deprecated features are replaced, and **all existing vaults remain fully compatible**.

---

## Mission Statement

Maintain the will-encrypt codebase by:
1. Updating dependencies to their latest stable versions
2. Replacing deprecated APIs and patterns with modern alternatives
3. Ensuring **100% backward compatibility** with existing vaults
4. Maintaining all tests in passing state with ≥69% coverage
5. Preserving cryptographic guarantees and security properties

**CRITICAL: Zero tolerance for vault compatibility breaks. Users must be able to decrypt old vaults with the updated codebase.**

---

## Maintenance Checklist

### 1. Dependency Updates

Check and update all dependencies in `requirements.txt` and `requirements-dev.txt`:

```bash
# Check for outdated packages
pip list --outdated

# Review each dependency:
# - pyyaml>=6.0
# - cryptography>=41.0
# - mnemonic>=0.20
# - secretsharing>=0.2.6
# - pytest, pytest-cov, ruff, mypy (dev dependencies)
```

**For each dependency:**
- Review CHANGELOG for breaking changes
- Update version constraints to latest stable
- Run full test suite after each update
- Pay special attention to `cryptography` library changes affecting:
  - AES-256-GCM implementation
  - RSA-4096 key generation/serialization
  - PBKDF2-HMAC-SHA512 parameters
  - PEM encoding/decoding

**Red flags:**
- Any changes to `cryptography.hazmat` APIs
- Deprecation of `serialization.load_pem_private_key` or `load_pem_public_key`
- Changes to `Cipher`, `modes.GCM`, or `AESGCM` interfaces
- Modifications to `hashes.SHA512` or `PBKDF2HMAC`

### 2. Python Version Support

Check if newer Python versions are available:

```bash
# Current requirement: Python 3.11+
# Test compatibility with Python 3.12, 3.13, etc.
```

**Steps:**
1. Review Python release notes for breaking changes
2. Update `pyproject.toml` and documentation if new versions supported
3. Test on multiple Python versions if possible
4. Update `python_requires` in `pyproject.toml`

**Do NOT drop support for Python 3.11 without explicit approval.**

### 3. Cryptographic Compatibility Verification

**CRITICAL: These must remain unchanged to maintain vault compatibility:**

#### Vault Format Constants (src/storage/vault.py)
```python
# These values MUST NOT change:
VAULT_VERSION = 1
PBKDF2_ITERATIONS = 600_000
PBKDF2_HASH_ALGORITHM = "sha512"
AES_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
```

#### Cryptographic Parameters
- **Passphrase:** 256-bit entropy, 24-word BIP39 mnemonic
- **Shamir Sharing:** GF(256) arithmetic (src/crypto/shamir.py)
- **Key Derivation:** PBKDF2-HMAC-SHA512, 600K iterations, 32-byte salt
- **Symmetric Encryption:** AES-256-GCM, 12-byte nonce, 16-byte tag
- **Asymmetric Encryption:** RSA-4096 with OAEP-SHA256, ML-KEM-1024 (post-quantum)
- **BIP39:** Wordlist and checksum calculation (src/crypto/bip39.py)

#### Backward Compatibility Test
Create a test vault with the **old codebase**, then decrypt with the **new codebase**:

```bash
# Before updates (commit current state)
git stash
git checkout <previous-stable-tag>
./will-encrypt init --k 3 --n 5 --vault test_old_vault.yaml
echo "Test message from old version" | ./will-encrypt encrypt --vault test_old_vault.yaml --title "Old Test"
# Save the shares printed during init

# After updates (return to updated code)
git checkout main
git stash pop

# MUST successfully decrypt with saved shares
./will-encrypt decrypt --vault test_old_vault.yaml --shares "share1" "share2" "share3"

# Verify output matches "Test message from old version"
```

**If decryption fails or produces wrong output, the update MUST be rolled back.**

### 4. Deprecated API Replacement

Scan for deprecation warnings:

```bash
# Run tests with deprecation warnings enabled
pytest -W default::DeprecationWarning

# Common areas to check:
# - cryptography library API changes
# - Python standard library deprecations
# - yaml.safe_load changes (already using safe_load)
```

**When replacing deprecated APIs:**
1. Identify the deprecated function/class
2. Find the recommended replacement in the library's migration guide
3. Update code to use new API
4. Verify backward compatibility with existing vaults
5. Run full test suite
6. Document the change in commit message

### 5. Test Suite Maintenance

Ensure all tests pass and coverage is maintained:

```bash
# Run full test suite (must be 146/146 passing)
pytest -v

# Check coverage (must be ≥69%)
pytest --cov=src --cov-report=term-missing

# Run specific test categories
pytest tests/unit/ -v           # 57 tests
pytest tests/contract/ -v       # 43 tests
pytest tests/integration/ -v    # 46 tests
```

**If tests fail:**
1. Investigate the root cause (dependency change, API deprecation, etc.)
2. Fix the code while maintaining backward compatibility
3. Update tests ONLY if they're testing implementation details, not behavior
4. Never modify tests that verify cryptographic correctness

### 6. Security Audit Checklist

After updates, verify these security properties:

- [ ] Shares are never written to disk (grep for file writes in share handling)
- [ ] Private keys are encrypted at rest (check vault.yaml format)
- [ ] Vault files have 0600 permissions (check file creation code)
- [ ] Secrets are cleared from memory when possible (check for explicit zeroing)
- [ ] No hardcoded credentials or test secrets in production code
- [ ] Random number generation uses `secrets` module (not `random`)
- [ ] All cryptographic operations use constant-time comparisons where applicable

```bash
# Automated checks
grep -r "open.*'w'" src/  # Should not write shares
grep -r "random\." src/   # Should use secrets module instead
grep -r "TODO\|FIXME\|XXX" src/  # Review any security TODOs
```

### 7. Documentation Updates

Update documentation to reflect any changes:

- [ ] README.md: Update dependency versions if user-facing
- [ ] CLAUDE.md: Update any changed commands or workflows
- [ ] AGENTS.md: Update if agent workflows affected
- [ ] Inline docstrings: Update for API changes
- [ ] IMPLEMENTATION_SUMMARY.md: Note any architectural changes

### 8. Linting and Type Checking

Ensure code quality standards are maintained:

```bash
# Ruff linting (must pass with no errors)
ruff check src tests

# MyPy type checking (must pass with no errors)
mypy src tests
```

**If linting errors appear:**
- New linting rules from ruff: Evaluate if they improve code quality
- Type errors from mypy: Fix type annotations to match new library types
- Do not disable linting rules without documenting the reason

### 9. Final Verification

Before committing updates:

1. **All tests pass:** `pytest -v`
2. **Coverage maintained or improved:** `pytest --cov=src` (≥69%)
3. **Linting passes:** `ruff check src tests`
4. **Type checking passes:** `mypy src tests`
5. **Backward compatibility verified:** Old vaults decrypt correctly
6. **Documentation updated:** All changed behavior documented
7. **Git status clean:** No unintended file changes

```bash
# Run all checks
pytest -v && \
pytest --cov=src && \
ruff check src tests && \
mypy src tests && \
echo "✓ All checks passed"
```

### 10. Commit and Document

Create a clear commit message:

```
Update dependencies and replace deprecated APIs

- Bump cryptography to 43.0.0 (from 41.0.0)
- Replace deprecated `rsa.generate_private_key` with new API
- Update pytest to 8.0.0 with new fixture syntax
- Python 3.11-3.13 now supported

Backward compatibility verified:
- Old vaults (version 1) decrypt correctly
- All 146 tests passing
- 69% code coverage maintained

Security audit completed: No issues found
```

---

## Emergency Rollback Procedure

If updates break vault compatibility:

```bash
# Revert the breaking commit
git revert <commit-hash>

# Or reset to last known good state
git reset --hard <good-commit>

# Re-run verification
pytest -v
./will-encrypt decrypt --vault test_old_vault.yaml --shares "share1" "share2" "share3"
```

---

## Contact and Escalation

If uncertain about:
- Cryptographic changes (AES, RSA, Shamir, BIP39)
- Vault format modifications
- Breaking changes in dependencies

**DO NOT PROCEED.** Document the concern and escalate to a human reviewer.

---

## Success Criteria

An update is successful when:
1. ✅ All tests pass
3. ✅ Linting and type checking pass
4. ✅ Old vaults decrypt with new code
5. ✅ No security regressions
6. ✅ Documentation reflects all changes
7. ✅ Dependencies are current and stable

**Backward compatibility is non-negotiable. When in doubt, preserve the old behavior.**
