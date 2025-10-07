# Quickstart Guide: Threshold Cryptography System

**Date**: 2025-10-07
**Feature**: Threshold Cryptography System for Emergency Access

## Purpose

This quickstart validates the complete lifecycle of the threshold cryptography system:
1. Vault initialization
2. Message encryption
3. Emergency recovery (decryption with K shares)
4. Share rotation
5. Validation and audit

Expected duration: **10 minutes** for manual execution.

---

## Prerequisites

- **Platform**: Linux (Debian 11+) or macOS 12+
- **Python**: 3.11+ installed
- **Dependencies installed**: `pip install -r requirements.txt`
- **Tool installed**: `will-encrypt` command available in PATH
- **Working directory**: Clean directory for test vault

---

## Scenario: Complete Lifecycle Test

### Step 1: Initialize 3-of-5 Threshold Vault

**Command**:
```bash
will-encrypt init --k 3 --n 5 --vault test_vault.yaml
```

**Expected Output**:
```
====================================
THRESHOLD VAULT INITIALIZED
====================================

Configuration:
- Threshold: 3 of 5 shares required
- Vault: test_vault.yaml

SECRET SHARES (BIP39 MNEMONICS)
⚠️  NEVER SHARE THIS SCREEN ⚠️

Share 1 of 5:
abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across act action actor actress actual

Share 2 of 5:
[24 words]

Share 3 of 5:
[24 words]

Share 4 of 5:
[24 words]

Share 5 of 5:
[24 words]

Vault created successfully at: test_vault.yaml
```

**Validation**:
- [ ] Exit code: 0
- [ ] File `test_vault.yaml` created with permissions 0600
- [ ] 5 BIP39 mnemonics displayed (24 words each, valid checksums)
- [ ] Duration: < 5 seconds

**Manual Test**:
```bash
# Verify vault file exists and has correct permissions
ls -l test_vault.yaml
# Expected: -rw------- (owner read/write only)

# Verify vault structure
head -20 test_vault.yaml
# Expected: YAML with version, created, keys, messages (empty array), manifest
```

**Save Shares**: Copy the 5 displayed mnemonics to separate text files for later steps:
```bash
echo "abandon ability able..." > share1.txt
echo "[share 2 mnemonic]" > share2.txt
echo "[share 3 mnemonic]" > share3.txt
echo "[share 4 mnemonic]" > share4.txt
echo "[share 5 mnemonic]" > share5.txt
```

---

### Step 2: Encrypt Messages

**Command 1** (Bank passwords):
```bash
will-encrypt encrypt --vault test_vault.yaml --title "Bank Account Passwords" \
  --message "Chase: user=john.doe, pass=SecurePass123
Citibank: user=jdoe, pass=AnotherPass456"
```

**Expected Output**:
```
Message encrypted successfully.
Message ID: 1
Ciphertext size: 156 bytes
```

**Command 2** (Estate instructions):
```bash
will-encrypt encrypt --vault test_vault.yaml --title "Estate Instructions" \
  --message "Executor: Jane Doe, phone: 555-1234
Will location: Safety deposit box #789 at Chase Bank
Life insurance policy: #ABC-123456, beneficiary: Jane Doe"
```

**Expected Output**:
```
Message encrypted successfully.
Message ID: 2
Ciphertext size: 220 bytes
```

**Command 3** (WiFi password):
```bash
echo "HomeWiFi: SSID=MyNetwork, Password=SuperSecret789" | \
  will-encrypt encrypt --vault test_vault.yaml --title "WiFi Credentials" --stdin
```

**Expected Output**:
```
Message encrypted successfully.
Message ID: 3
Ciphertext size: 89 bytes
```

**Validation**:
- [ ] Exit code: 0 for all 3 commands
- [ ] Message IDs: 1, 2, 3 (sequential)
- [ ] Duration: < 1 second per message
- [ ] Vault file updated (size increased)

**Manual Test**:
```bash
# Verify messages array populated
grep -A 5 "^messages:" test_vault.yaml
# Expected: 3 message entries with ids 1, 2, 3
```

---

### Step 3: List Messages (No Decryption)

**Command**:
```bash
will-encrypt list --vault test_vault.yaml
```

**Expected Output**:
```
ID  Title                     Created              Size
──  ────────────────────────  ───────────────────  ──────
1   Bank Account Passwords    2025-10-07 10:00:00  156 B
2   Estate Instructions       2025-10-07 10:01:00  220 B
3   WiFi Credentials          2025-10-07 10:02:00  89 B

Total: 3 messages, 465 B encrypted
```

**Validation**:
- [ ] Exit code: 0
- [ ] 3 messages listed with correct titles
- [ ] No decrypted content displayed (titles only)
- [ ] Duration: < 0.5 seconds

---

### Step 4: Validate Vault (Audit)

**Command**:
```bash
will-encrypt validate --vault test_vault.yaml --verbose
```

**Expected Output** (abbreviated):
```
====================================
VAULT VALIDATION
====================================

FORMAT CHECKS:
✓ YAML structure valid
✓ All required sections present
✓ Messages array valid (3 messages)

FINGERPRINT CHECKS:
✓ RSA public key SHA-256: [hex] (matches manifest)
✓ Kyber public key SHA-256: [hex] (matches manifest)
✓ Vault SHA-256: [hex] (matches manifest)

ALGORITHM CHECKS:
✓ Keypair: RSA-4096 + Kyber-1024 ✓ Constitutional compliance
✓ Passphrase entropy: 384 bits ✓ Constitutional compliance
✓ Message encryption: AES-256-GCM ✓ Constitutional compliance

====================================
VALIDATION RESULT: ✓ PASS
====================================
```

**Validation**:
- [ ] Exit code: 0
- [ ] All checks passed
- [ ] No fingerprint mismatches
- [ ] Duration: < 2 seconds

---

### Step 5: Emergency Recovery (Decrypt with 3 Shares)

**Command** (interactive):
```bash
will-encrypt decrypt --vault test_vault.yaml
```

**Interactive Flow**:
```
====================================
EMERGENCY RECOVERY
====================================

Vault: test_vault.yaml
Threshold: 3 of 5 shares required

Enter share 1 of 3:
> [Paste content of share1.txt]
✓ Share 1 valid

Enter share 2 of 3:
> [Paste content of share2.txt]
✓ Share 2 valid

Enter share 3 of 3:
> [Paste content of share3.txt]
✓ Share 3 valid

Reconstructing passphrase...
Decrypting private keys...
Decrypting messages...

====================================
MESSAGE RECOVERY
====================================

Message ID: 1
Title: Bank Account Passwords
Created: 2025-10-07T10:00:00Z
Size: 156 bytes
────────────────────────────────────
Chase: user=john.doe, pass=SecurePass123
Citibank: user=jdoe, pass=AnotherPass456
════════════════════════════════════

Message ID: 2
Title: Estate Instructions
Created: 2025-10-07T10:01:00Z
Size: 220 bytes
────────────────────────────────────
Executor: Jane Doe, phone: 555-1234
Will location: Safety deposit box #789 at Chase Bank
Life insurance policy: #ABC-123456, beneficiary: Jane Doe
════════════════════════════════════

Message ID: 3
Title: WiFi Credentials
Created: 2025-10-07T10:02:00Z
Size: 89 bytes
────────────────────────────────────
HomeWiFi: SSID=MyNetwork, Password=SuperSecret789
════════════════════════════════════

Total messages decrypted: 3
```

**Validation**:
- [ ] Exit code: 0
- [ ] All 3 messages decrypted successfully
- [ ] Plaintext matches original messages from Step 2
- [ ] Hybrid verification passed (RSA KEK == Kyber KEK)
- [ ] Duration: < 5 seconds for crypto operations

---

### Step 6: Test Insufficient Shares (Negative Test)

**Command**:
```bash
# Attempt recovery with only 2 shares (K=3 required)
will-encrypt decrypt --vault test_vault.yaml --shares \
  "$(cat share1.txt)" \
  "$(cat share2.txt)"
```

**Expected Output**:
```
Error: Insufficient shares
Required: 3 shares
Provided: 2 shares

Recovery failed.
```

**Validation**:
- [ ] Exit code: 3 (insufficient shares error code)
- [ ] No decryption occurred
- [ ] Clear error message

---

### Step 7: Share Rotation (Change to 4-of-6)

**Command**:
```bash
will-encrypt rotate --vault test_vault.yaml --mode shares --k 4 --n 6
```

**Interactive Flow**:
```
====================================
SHARE ROTATION
====================================

Old configuration: 3 of 5 shares
New configuration: 4 of 6 shares

Collecting old shares for authentication...

Enter old share 1 of 3:
> [Paste share1.txt]
✓ Valid

Enter old share 2 of 3:
> [Paste share2.txt]
✓ Valid

Enter old share 3 of 3:
> [Paste share3.txt]
✓ Valid

Authenticating...
Generating 6 new shares...

NEW SECRET SHARES (BIP39 MNEMONICS)
⚠️  NEVER SHARE THIS SCREEN ⚠️

Share 1 of 6:
[24 new words]

Share 2 of 6:
[24 new words]

[... shares 3-6 ...]

Rotation complete. Vault updated at: test_vault.yaml
```

**Validation**:
- [ ] Exit code: 0
- [ ] 6 new BIP39 mnemonics displayed
- [ ] Vault manifest updated: k=4, n=6
- [ ] Rotation history appended
- [ ] Messages NOT re-encrypted (efficiency check)

**Save New Shares**:
```bash
# Save the 6 new mnemonics displayed
echo "[new share 1]" > new_share1.txt
echo "[new share 2]" > new_share2.txt
# ... etc for shares 3-6
```

---

### Step 8: Verify Rotated Shares Work

**Command**:
```bash
# Decrypt using 4 of the 6 new shares
will-encrypt decrypt --vault test_vault.yaml
```

**Interactive Input**: Provide any 4 of the 6 new shares (e.g., new_share1.txt through new_share4.txt)

**Expected Output**: Same 3 decrypted messages as Step 5

**Validation**:
- [ ] Exit code: 0
- [ ] Decryption successful with 4 new shares
- [ ] All 3 messages recovered correctly
- [ ] Old shares (from Step 1) NO LONGER WORK (test this separately)

---

### Step 9: Test Old Shares Invalidated (Negative Test)

**Command**:
```bash
# Attempt recovery with old shares after rotation
will-encrypt decrypt --vault test_vault.yaml --shares \
  "$(cat share1.txt)" \
  "$(cat share2.txt)" \
  "$(cat share3.txt)"
```

**Expected Output**:
```
Error: Private key decryption failed
The provided shares may be outdated or incorrect.

Recovery failed.
```

**Validation**:
- [ ] Exit code: 6 (private key decryption failure)
- [ ] Old shares rejected (passphrase reconstructs but doesn't decrypt private keys)

---

### Step 10: Final Validation

**Command**:
```bash
will-encrypt validate --vault test_vault.yaml --verbose
```

**Expected Output**: Similar to Step 4, with updated values:
- Threshold: 4 of 6
- Rotation history: 2 events (initial creation + share rotation)

**Validation**:
- [ ] Exit code: 0
- [ ] All checks passed
- [ ] Rotation event logged in manifest

---

## Success Criteria

All steps must pass with expected exit codes and outputs. Key validations:

1. **Initialization**: 3-of-5 vault created, 5 BIP39 shares displayed
2. **Encryption**: 3 messages encrypted, no shares required
3. **Listing**: Messages listed by title without decryption
4. **Validation**: Vault integrity confirmed, no tampering
5. **Recovery**: 3 shares successfully decrypt all messages
6. **Insufficient shares**: Recovery fails with 2 shares (< K)
7. **Share rotation**: 3-of-5 → 4-of-6, new shares generated
8. **Rotated recovery**: 4 new shares decrypt messages
9. **Old shares invalid**: Old shares rejected after rotation
10. **Final validation**: Vault integrity maintained after rotation

---

## Cleanup

```bash
# Remove test vault and shares
rm test_vault.yaml share*.txt new_share*.txt
```

---

## Performance Benchmarks

| Operation | Target | Actual |
|-----------|--------|--------|
| Initialization | < 5 sec | _____ |
| Message encryption | < 1 sec | _____ |
| Message listing | < 0.5 sec | _____ |
| Validation | < 2 sec | _____ |
| Recovery (3 shares) | < 5 sec | _____ |
| Share rotation | < 2 sec | _____ |

---

## Integration Test Scenarios

### Scenario A: Full Lifecycle (Automated)
Run all 10 steps sequentially in automated test harness. Assert exit codes and output patterns.

### Scenario B: Concurrent Operations (Not Supported)
Attempt simultaneous `encrypt` operations on same vault. Expect file locking or serialization errors.

### Scenario C: Large Message (Boundary Test)
Encrypt message at 64 KB limit. Verify encryption succeeds. Attempt 64 KB + 1 byte, verify rejection.

### Scenario D: Invalid BIP39 (Error Handling)
Provide share with modified word (invalid checksum). Verify BIP39 validation catches error before Shamir reconstruction.

### Scenario E: Corrupted Vault (Integrity)
Manually modify ciphertext in vault YAML. Run validation. Verify fingerprint mismatch detected. Attempt decryption. Verify authentication tag failure.

### Scenario F: Passphrase Rotation
After Step 7, run passphrase rotation instead of share rotation. Verify private keys re-encrypted, new shares generated, messages still decrypt.

---

## Phase 1 Quickstart Complete ✅

This quickstart provides:
- Step-by-step validation of core functionality
- Manual execution checklist
- Automated test scenario descriptions
- Performance benchmarks
- Negative test cases (insufficient shares, old shares, corrupted vault)

Ready for test implementation in Phase 3 (tasks.md).
