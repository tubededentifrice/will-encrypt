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

## Quick Reference

**Essential commands for maintenance:**
```bash
# 1. Security audit (ALWAYS RUN FIRST)
pip install pip-audit && pip-audit

# 2. Check outdated packages
pip list --outdated

# 3. Run all tests
pytest -v  # Must be 171/171 passing

# 4. Check coverage
pytest --cov=src  # Must be ≥75%

# 5. Lint and type check
ruff check src tests
mypy src tests

# 6. Full verification pipeline
pip-audit && pytest -v && pytest --cov=src && ruff check src tests && mypy src tests
```

---

## Maintenance Checklist

### 1. Security Audit and CVE Checks

**ALWAYS START HERE.** Before any dependency updates, check for security vulnerabilities:

```bash
# Install pip-audit if not already installed
pip install pip-audit

# Check for CVEs in current dependencies
pip-audit

# Alternative: Check PyPI advisory database
pip-audit --desc
```

**For each CVE found:**
1. Assess severity (Critical, High, Medium, Low)
2. Check if the vulnerability affects will-encrypt's usage patterns
3. Review the CVE details and recommended fix version
4. Prioritize critical and high-severity CVEs
5. Update affected package to patched version
6. Re-run `pip-audit` to verify fix
7. Run full test suite to ensure compatibility

**If a CVE cannot be fixed without breaking changes:**
- Document the security risk assessment
- Consider if the vulnerability is exploitable in will-encrypt's context
- Escalate to human reviewer for critical/high-severity issues

---

### 2. Dependency Updates

Check and update all dependencies in `requirements.txt` and `requirements-dev.txt`:

```bash
# Check for outdated packages
pip list --outdated

# Current dependencies:
# - pyyaml>=6.0
# - cryptography>=41.0
# - mnemonic>=0.20
# - pqcrypto>=0.3.4
#
# Dev dependencies:
# - pytest>=7.4, pytest-cov>=4.1, pytest-xdist>=3.6
# - ruff>=0.1, mypy>=1.7
```

**For each dependency:**
1. Review CHANGELOG for breaking changes
2. Check for security advisories (CVEs)
3. Update version constraints to latest stable
4. Run full test suite after each update
5. Pay special attention to `cryptography` library changes affecting:
   - AES-256-GCM implementation
   - RSA-4096 key generation/serialization
   - PBKDF2-HMAC-SHA512 parameters
   - PEM encoding/decoding

**Red flags:**
- Any changes to `cryptography.hazmat` APIs
- Deprecation of `serialization.load_pem_private_key` or `load_pem_public_key`
- Changes to `Cipher`, `modes.GCM`, or `AESGCM` interfaces
- Modifications to `hashes.SHA512` or `PBKDF2HMAC`
- Breaking changes in `pqcrypto` ML-KEM-1024 implementation

### 3. Python Version Support

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

### 4. Cryptographic Compatibility Verification

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

### 5. Deprecated API Replacement

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

### 6. Test Suite Maintenance

Ensure all tests pass and coverage is maintained:

```bash
# Run full test suite (must be 171/171 passing)
pytest -v

# Check coverage (must be ≥75%)
pytest --cov=src --cov-report=term-missing

# Run specific test categories
pytest tests/unit/ -v           # 88 tests
pytest tests/contract/ -v       # 45 tests
pytest tests/integration/ -v    # 38 tests
```

**If tests fail:**
1. Investigate the root cause (dependency change, API deprecation, etc.)
2. Fix the code while maintaining backward compatibility
3. Update tests ONLY if they're testing implementation details, not behavior
4. Never modify tests that verify cryptographic correctness

### 7. Security Audit Checklist

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

### 8. Documentation Updates

Update documentation to reflect any changes:

- [ ] README.md: Update dependency versions if user-facing
- [ ] CLAUDE.md: Update any changed commands or workflows
- [ ] AGENTS.md: Update if agent workflows affected
- [ ] Inline docstrings: Update for API changes
- [ ] IMPLEMENTATION_SUMMARY.md: Note any architectural changes

### 9. Linting and Type Checking

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

### 10. Final Verification

Before committing updates:

1. **CVE check passes:** `pip-audit` reports no vulnerabilities
2. **All tests pass:** `pytest -v` (171/171)
3. **Coverage maintained or improved:** `pytest --cov=src` (≥75%)
4. **Linting passes:** `ruff check src tests`
5. **Type checking passes:** `mypy src tests`
6. **Backward compatibility verified:** Old vaults decrypt correctly
7. **Documentation updated:** All changed behavior documented
8. **Git status clean:** No unintended file changes

```bash
# Run all checks
pip-audit && \
pytest -v && \
pytest --cov=src && \
ruff check src tests && \
mypy src tests && \
echo "✓ All checks passed"
```

### 11. Commit and Document

Create a clear commit message:

```
Update dependencies and replace deprecated APIs

Security:
- pip-audit: No CVEs found
- Fixed CVE-XXXX-XXXXX in cryptography (bumped to 43.0.0)

Dependency updates:
- cryptography: 41.0.0 → 43.0.0
- pytest: 7.4.0 → 8.0.0
- ruff: 0.1.0 → 0.2.0
- Python 3.11-3.13 now supported

API changes:
- Replace deprecated `rsa.generate_private_key` with new API
- Update pytest fixture syntax for pytest 8.0

Backward compatibility verified:
- Old vaults (version 1) decrypt correctly
- All 171 tests passing (88 unit, 45 contract, 38 integration)
- 75% code coverage maintained

Security audit: ✅ All checks passed
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
1. ✅ CVE audit passes (pip-audit shows no vulnerabilities)
2. ✅ All tests pass (171/171)
3. ✅ Code coverage maintained (≥75%)
4. ✅ Linting and type checking pass
5. ✅ Old vaults decrypt with new code
6. ✅ No security regressions
7. ✅ Documentation reflects all changes
8. ✅ Dependencies are current and CVE-free

**Security first. Backward compatibility is non-negotiable. When in doubt, preserve the old behavior.**
