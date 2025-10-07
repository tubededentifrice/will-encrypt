# Import Shares Feature - Usage Examples

This document demonstrates the new `--import-share` feature for reusing BIP39 shares across multiple vaults.

## Feature Overview

The `--import-share` argument allows you to:
1. **Reuse shares across multiple vaults** - Create different vaults with the same passphrase
2. **Change K/N threshold** - Use the same passphrase with different share distribution
3. **Vault migration** - Recreate a vault with new parameters without generating a new passphrase

## Security Warning

⚠️ **IMPORTANT**: Reusing shares across vaults means compromising one vault compromises ALL vaults using the same shares. Only use this feature if you understand the security implications.

## Example 1: Multiple Vaults with Same Shares

### Scenario
You want to create separate vaults for personal and business data, but use the same set of key holders.

```bash
# Create first vault (personal)
will-encrypt init --k 3 --n 5 --vault personal.yaml

# Output (save these 5 shares):
Share 1/5:
  cupboard patrol sand close flush cushion old problem...
Share 2/5:
  grape scrap isolate lunch want used dolphin inside...
Share 3/5:
  belt math vault into room dad install found atom...
Share 4/5:
  ...
Share 5/5:
  ...

# Create second vault (business) using the same shares
will-encrypt init --k 3 --n 5 --vault business.yaml \
  --import-share "cupboard patrol sand close flush cushion old problem..." \
  --import-share "grape scrap isolate lunch want used dolphin inside..." \
  --import-share "belt math vault into room dad install found atom..."

# Result: business.yaml uses same passphrase, outputs SAME 5 shares
```

**Use Case**: Family estate planning with separate vaults for different asset types (financial, legal, digital).

## Example 2: Different K/N with Same Passphrase

### Scenario
You want to change the threshold policy but keep the same underlying passphrase.

```bash
# Original vault (3-of-5)
will-encrypt init --k 3 --n 5 --vault original.yaml
# Outputs 5 shares (save shares 1, 2, 3)

# Create new vault with 2-of-3 threshold (more convenient, less redundancy)
will-encrypt init --k 2 --n 3 --vault convenient.yaml \
  --import-share "SHARE_1" \
  --import-share "SHARE_2" \
  --import-share "SHARE_3"

# Result: convenient.yaml uses same passphrase, outputs NEW 3 shares (2-of-3 split)
```

**Use Case**: Migration from high-redundancy (3-of-5) to lower-redundancy (2-of-3) for convenience.

## Example 3: Interactive Import Mode

### Scenario
You prefer to enter shares interactively rather than on the command line.

```bash
will-encrypt init --k 3 --n 5 --vault new_vault.yaml
```

**Interactive Prompts**:
```
🔐 Will-Encrypt Vault Initialization

This will create a new encrypted vault using threshold cryptography.
You'll receive N secret shares, and K shares are needed to decrypt.

Enter threshold K (minimum shares needed to decrypt): 3
Enter total shares N (K=3, typically N > K for redundancy): 5

📥 Share Import (Optional)

You can import existing BIP39 shares to reuse the same passphrase.
This allows multiple vaults to share the same underlying key material.

⚠️  SECURITY WARNING:
   Reusing shares across vaults means compromising one vault
   compromises ALL vaults using the same shares.

Import existing shares? (yes/no): yes

You need to provide at least 3 shares to reconstruct the passphrase.
How many shares do you want to import? (min 3): 3

Enter share 1:
> cupboard patrol sand close flush cushion old problem...
  ✓ Share 1 validated

Enter share 2:
> grape scrap isolate lunch want used dolphin inside...
  ✓ Share 2 validated

Enter share 3:
> belt math vault into room dad install found atom...
  ✓ Share 3 validated

🔍 Validating 3 imported share(s)...
      ✓ All 3 share(s) validated

[1/4] Reconstructing passphrase from 3 imported share(s)...
      ✓ Passphrase reconstructed from imported shares

[2/4] Splitting passphrase into 5 shares (threshold: 3)...
      ✓ 5 shares created using Shamir Secret Sharing

[3/4] Encoding shares as BIP39 mnemonics...
      ✓ 5 × 24-word mnemonics generated

[4/4] Generating RSA-4096 + Kyber-1024 keypair...
      ✓ Hybrid keypair generated and encrypted

======================================================================
✓ Vault initialized successfully: new_vault.yaml
======================================================================

📋 Secret Shares (3-of-5 threshold) - RECONSTRUCTED FROM IMPORTED SHARES

⚠️  SECURITY WARNING:
    • These shares use the SAME passphrase as the imported shares
    • Compromising one vault compromises ALL vaults with this passphrase
    • Only use this feature if you understand the security implications

⚠️  CRITICAL: These shares are displayed ONCE and never stored!
    • Distribute to 5 different key holders
    • 3 shares required to decrypt messages
    • Each share is 24 words (BIP39 mnemonic)
    • Store securely: paper backup, password manager, or HSM

----------------------------------------------------------------------

Share 1/5:
  cupboard patrol sand close flush cushion old problem...

Share 2/5:
  grape scrap isolate lunch want used dolphin inside...

...
```

## Example 4: Validation and Testing

### Verify Shares Work Across Vaults

```bash
# Create first vault
will-encrypt init --k 3 --n 5 --vault vault1.yaml > shares.txt

# Extract shares (in practice, save these securely)
SHARE1=$(grep -A 1 "Share 1/5:" shares.txt | tail -1)
SHARE2=$(grep -A 1 "Share 2/5:" shares.txt | tail -1)
SHARE3=$(grep -A 1 "Share 3/5:" shares.txt | tail -1)

# Create second vault with imported shares
will-encrypt init --k 3 --n 5 --vault vault2.yaml \
  --import-share "$SHARE1" \
  --import-share "$SHARE2" \
  --import-share "$SHARE3"

# Encrypt messages in both vaults
will-encrypt encrypt --vault vault1.yaml --title "Test1" --message "Message in vault1"
will-encrypt encrypt --vault vault2.yaml --title "Test2" --message "Message in vault2"

# Decrypt both vaults with the same shares
will-encrypt decrypt --vault vault1.yaml --shares "$SHARE1" "$SHARE2" "$SHARE3"
will-encrypt decrypt --vault vault2.yaml --shares "$SHARE1" "$SHARE2" "$SHARE3"

# Validate both vaults
will-encrypt validate --vault vault1.yaml
will-encrypt validate --vault vault2.yaml
```

## Example 5: Error Handling

### Insufficient Shares

```bash
# Try to import only 2 shares (need 3)
will-encrypt init --k 3 --n 5 --vault vault.yaml \
  --import-share "SHARE_1" \
  --import-share "SHARE_2"

# Output:
# Error: Insufficient shares (need 3, got 2)
# Recovery: Provide at least 3 shares to reconstruct passphrase
```

### Invalid BIP39 Checksum

```bash
# Try to import share with typo
will-encrypt init --k 1 --n 1 --vault vault.yaml \
  --import-share "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Output:
# Error: Invalid BIP39 checksum in imported share 1
# Recovery: Check for typos in the mnemonic
```

## Security Considerations

### When to Use Import Shares

✅ **Good Use Cases**:
- Multiple vaults for different purposes (personal, business, family)
- Changing threshold policy (e.g., from 3-of-5 to 2-of-3)
- Vault migration after software upgrade
- Testing and development

❌ **Bad Use Cases**:
- Sharing same shares across unrelated parties
- Creating "backup" vaults without understanding security implications
- Using imported shares from untrusted sources

### Security Properties

1. **Same Passphrase = Same Security**:
   - All vaults with imported shares share the same 384-bit passphrase
   - Compromising one vault's passphrase compromises all vaults

2. **Independent Encryption**:
   - Each vault has independent RSA/Kyber keypairs
   - Messages are encrypted independently
   - Only the *passphrase* is shared, not the encryption keys

3. **Threshold Properties Preserved**:
   - Each vault maintains its own K/N threshold
   - Can have vault1 with 3-of-5 and vault2 with 2-of-3 using same passphrase

### Best Practices

1. **Document Share Relationships**:
   - Keep a record of which vaults share the same passphrase
   - Note the security implications in your documentation

2. **Use Different Passphrases for Different Security Domains**:
   - Personal vs. Business: Different passphrases
   - Family vs. Corporate: Different passphrases
   - Production vs. Staging: Can share passphrase

3. **Test Import Before Production Use**:
   - Create test vaults with imported shares
   - Verify decryption works across all vaults
   - Validate all vaults before distributing shares

4. **Secure Share Storage**:
   - Store imported shares with same security as generated shares
   - Use password managers, HSMs, or paper backups
   - Never store shares in plaintext on disk

## Technical Details

### How Import Works

1. **Share Validation**:
   - Each imported share validated for BIP39 checksum
   - Minimum K shares required
   - Extra shares ignored (uses first K)

2. **Passphrase Reconstruction**:
   - Uses Shamir Secret Sharing (Lagrange interpolation)
   - Reconstructs 32-byte (256-bit) passphrase
   - Passphrase used to derive encryption keys

3. **Re-splitting**:
   - Reconstructed passphrase split into new K/N shares
   - New shares can have same or different K/N
   - New shares are cryptographically independent (different polynomial)

### Cryptographic Properties

- **Passphrase Entropy**: 384 bits (48 bytes) - same across all vaults
- **BIP39 Encoding**: 24 words per share (256-bit entropy + checksum)
- **Shamir SSS**: Information-theoretic security (Lagrange interpolation over GF(256))
- **Key Derivation**: PBKDF2-HMAC-SHA512 (600,000 iterations)

### Share Format

Each share is:
- **24 words** (BIP39 mnemonic)
- **256-bit entropy** + 8-bit checksum
- **Space-separated** lowercase English words

Example:
```
cupboard patrol sand close flush cushion old problem...
```

## Troubleshooting

### Issue: "Insufficient shares"

**Cause**: Provided fewer than K shares.

**Fix**: Provide at least K shares using `--import-share` argument.

### Issue: "Invalid BIP39 checksum"

**Cause**: Typo in share or corrupted mnemonic.

**Fix**:
- Re-enter share carefully
- Verify last word (contains checksum)
- Use BIP39 validator: https://iancoleman.io/bip39/

### Issue: Decryption fails across vaults

**Cause**: Shares from different vaults (different passphrases).

**Fix**:
- Verify shares are from the same original vault
- Check that vaults were created with `--import-share`
- Validate vault integrity with `will-encrypt validate`

## Conclusion

The `--import-share` feature provides powerful flexibility for managing multiple vaults with threshold cryptography. Use it carefully with full understanding of the security implications.

For questions or issues, see:
- README.md - Full documentation
- GitHub Issues - Report bugs
- Security documentation - src/docs/crypto_notes.py
