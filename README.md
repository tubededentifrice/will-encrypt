# will-encrypt

**Threshold cryptography system for emergency access to sensitive information**

./will-encrypt is a command-line tool that encrypts messages with a hybrid RSA-4096 + post-quantum (Kyber-1024) cryptosystem, protected by Shamir Secret Sharing. Access requires K out of N key holders to combine their shares, making it ideal for emergency access scenarios like digital wills, estate planning, and business continuity.

## Features

- **Threshold Cryptography**: K-of-N secret sharing using Shamir's Secret Sharing Scheme
- **Post-Quantum Ready**: Hybrid RSA-4096 + Kyber-1024 encryption
- **BIP39 Shares**: Human-friendly 24-word mnemonics for key distribution
- **Multiple Messages**: Store multiple encrypted messages in a single vault
- **Tamper Detection**: SHA-256 fingerprints protect vault integrity
- **Key Rotation**: Rotate shares or passphrase without re-encrypting messages
- **Zero Trust**: Shares never stored on disk, only distributed to key holders

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Command Reference](#command-reference)
4. [Security Model](#security-model)
5. [Deployment Guide](#deployment-guide)
6. [Recovery Procedures](#recovery-procedures)
7. [Key Rotation](#key-rotation)
8. [Troubleshooting](#troubleshooting)
9. [Architecture](#architecture)
10. [Development](#development)

---

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/yourusername/will-encrypt.git
cd will-encrypt

# Install dependencies
pip install -r requirements.txt

# Install tool
pip install -e .
```

> ℹ️ **Launcher script:** All CLI examples assume you are running `./will-encrypt` from the repository root. If you install the package (e.g., `pip install -e .`), the command is available as `will-encrypt` on your PATH, and you can omit the `./` prefix.

### 2. Initialize Vault (3-of-5 threshold)

```bash
./will-encrypt init --k 3 --n 5 --vault my-vault.yaml
```

This generates:
- A vault file (`my-vault.yaml`) with encrypted keypair
- 5 BIP39 shares (24 words each) - distribute to key holders
- Recovery guide and policy documents

**IMPORTANT**: Save the 5 shares securely. They are NOT stored in the vault!

### 3. Encrypt a Message

```bash
./will-encrypt encrypt --vault my-vault.yaml \
    --title "Bank Account Access" \
    --message "Account: 123456, PIN: 9876, Contact: John Doe"
```

### 4. Decrypt Messages (requires 3 shares)

```bash
./will-encrypt decrypt --vault my-vault.yaml
```

Enter 3 of the 5 shares when prompted. All messages will be decrypted and displayed.

---

## Installation

### Requirements

- **Python**: 3.11 or higher
- **Operating System**: Linux, macOS, Windows
- **Dependencies**: PyYAML, cryptography, mnemonic, secretsharing

### Installation Methods

#### Option 1: From Source (Development)

```bash
git clone https://github.com/yourusername/will-encrypt.git
cd will-encrypt
pip install -e .
```

#### Option 2: Using pip (Production)

```bash
pip install will-encrypt
```

#### Option 3: Virtual Environment (Recommended)

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

### Verify Installation

```bash
./will-encrypt --help
python -m pytest tests/  # Run test suite
```

---

## Command Reference

### `init` - Initialize Vault

Create a new vault with K-of-N threshold.

```bash
./will-encrypt init --k K --n N [--vault FILE] [--force] [--import-share "SHARE"]
```

**Arguments:**
- `--k`: Threshold (minimum shares needed to decrypt)
- `--n`: Total number of shares to generate
- `--vault`: Vault file path (default: `vault.yaml`)
- `--force`: Overwrite existing vault
- `--import-share`: Import existing BIP39 share (24 words). Can be used multiple times. Requires K shares to reconstruct passphrase.

**Examples:**

```bash
# 3-of-5 threshold (typical family scenario)
./will-encrypt init --k 3 --n 5 --vault family-vault.yaml

# 2-of-3 threshold (small team)
./will-encrypt init --k 2 --n 3

# Single key holder (1-of-1, emergency backup only)
./will-encrypt init --k 1 --n 1
```

**Output:**
- Vault file created at specified path
- N BIP39 shares printed to stdout
- Recovery guide, policy document, and crypto notes embedded in vault

**Security Notes:**
- Shares are printed ONCE and never stored
- Write shares to paper or password manager immediately
- Each share is 24 words (BIP39 standard)
- Shares can be distributed via secure channels (encrypted email, in-person)

---

#### Importing Existing Shares

You can reuse existing BIP39 shares from another vault to create a new vault with the same passphrase. This allows multiple vaults to share the same underlying key material.

**Use Cases:**
1. **Multiple vaults with same shares**: Create different vaults for different purposes (personal, business, family) but use the same set of key holders
2. **Different K/N with same passphrase**: Change the threshold policy while keeping the same passphrase
3. **Vault migration**: Recreate a vault with new K/N values without generating a new passphrase

**Security Warning:**
⚠️ **Reusing shares across vaults means compromising one vault compromises ALL vaults using the same shares.** Only use this feature if you understand the security implications and have a valid use case.

**Examples:**

```bash
# Create first vault (3-of-5)
./will-encrypt init --k 3 --n 5 --vault vault1.yaml
# Outputs 5 shares (save these)

# Create second vault with SAME shares (same 3-of-5, same passphrase)
./will-encrypt init --k 3 --n 5 --vault vault2.yaml \
  --import-share "abandon ability able..." \
  --import-share "abandon about above..." \
  --import-share "abandon absent absorb..."
# Reconstructs passphrase from 3 shares
# Outputs SAME 5 shares (if using same K/N)

# Create third vault with DIFFERENT K/N but same passphrase
./will-encrypt init --k 2 --n 3 --vault vault3.yaml \
  --import-share "abandon ability able..." \
  --import-share "abandon about above..." \
  --import-share "abandon absent absorb..."
# Reconstructs same passphrase from 3 shares
# Outputs NEW 3 shares (different split, 2-of-3)
```

**Interactive Mode:**

If you don't provide shares on the command line, the CLI will prompt you:

```
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
> abandon ability able...
  ✓ Share 1 validated

Enter share 2:
> abandon about above...
  ✓ Share 2 validated

Enter share 3:
> abandon absent absorb...
  ✓ Share 3 validated

Passphrase reconstructed from 3 imported shares.
```

**Validation:**
- Each imported share must be a valid BIP39 mnemonic (24 words)
- BIP39 checksum is validated for each share
- At least K shares must be provided
- If fewer than K shares provided, initialization fails with clear error message
- If more than K shares provided, first K shares are used

**How Import Works:**

1. **Share Validation**: Each imported share validated for BIP39 checksum; minimum K shares required
2. **Passphrase Reconstruction**: Uses Shamir Secret Sharing (Lagrange interpolation) to reconstruct 32-byte passphrase
3. **Re-splitting**: Reconstructed passphrase split into new K/N shares (can have same or different K/N)

**Security Considerations:**

When to use:
- ✅ Multiple vaults for different purposes (personal, business, family)
- ✅ Changing threshold policy (e.g., from 3-of-5 to 2-of-3)
- ✅ Vault migration after software upgrade
- ✅ Testing and development

When NOT to use:
- ❌ Sharing same shares across unrelated parties
- ❌ Creating "backup" vaults without understanding security implications

**Best Practices:**
1. Document which vaults share the same passphrase
2. Use different passphrases for different security domains (personal vs. business)
3. Test import before production use
4. Store imported shares with same security as generated shares

---

### `encrypt` - Encrypt Message

Add an encrypted message to the vault.

```bash
./will-encrypt encrypt --vault FILE --title TITLE [--message TEXT | --stdin]
```

**Arguments:**
- `--vault`: Vault file path (default: `vault.yaml`)
- `--title`: Message title (max 256 characters)
- `--message`: Message content (max 64 KB)
- `--stdin`: Read message from stdin

**Examples:**

```bash
# Encrypt a short message
./will-encrypt encrypt --vault vault.yaml \
    --title "WiFi Password" \
    --message "SSID: HomeNet, Password: SecurePass123!"

# Encrypt from stdin
echo "Secret data" | will-encrypt encrypt --vault vault.yaml \
    --title "API Key" --stdin

# Encrypt a file
cat credentials.json | will-encrypt encrypt --vault vault.yaml \
    --title "AWS Credentials" --stdin
```

**Limits:**
- Title: 256 characters max
- Message: 64 KB max
- No limit on number of messages per vault

**Security:**
- Each message encrypted with unique AES-256-GCM key
- Message encryption key wrapped with RSA-4096-OAEP + Kyber-1024
- Authenticated encryption with title as additional data (AAD)

---

### `decrypt` - Decrypt Messages

Decrypt all messages in the vault using K shares.

```bash
./will-encrypt decrypt --vault FILE [--shares SHARE1 SHARE2 ...]
```

**Arguments:**
- `--vault`: Vault file path (default: `vault.yaml`)
- `--shares`: K shares (24-word BIP39 mnemonics) - if omitted, prompts interactively

**Examples:**

```bash
# Interactive mode (recommended)
./will-encrypt decrypt --vault vault.yaml

# Non-interactive mode (for automation)
./will-encrypt decrypt --vault vault.yaml \
    --shares "abandon abandon abandon ... about" \
    "ability ability ability ... about" \
    "able able able ... about"
```

**Process:**
1. Collect K shares from key holders
2. Reconstruct passphrase using Shamir Secret Sharing
3. Decrypt private keys (RSA + Kyber)
4. Decrypt all messages in vault
5. Display decrypted messages with metadata

**Output Format:**
```
Message 1: Bank Account Access
Created: 2025-01-15T10:30:00Z
Content:
Account: 123456, PIN: 9876, Contact: John Doe
------------------------------------------------------------

Message 2: WiFi Password
Created: 2025-01-16T14:20:00Z
Content:
SSID: HomeNet, Password: SecurePass123!
------------------------------------------------------------
```

---

### `list` - List Messages

List all messages in the vault (metadata only, no decryption).

```bash
./will-encrypt list --vault FILE [--format FORMAT] [--sort FIELD]
```

**Arguments:**
- `--vault`: Vault file path (default: `vault.yaml`)
- `--format`: Output format (`table` or `json`, default: `table`)
- `--sort`: Sort by field (`id`, `title`, `created`, `size`, default: `id`)

**Examples:**

```bash
# Table format (default)
./will-encrypt list --vault vault.yaml

# JSON format (for scripting)
./will-encrypt list --vault vault.yaml --format json

# Sort by creation date
./will-encrypt list --vault vault.yaml --sort created

# Sort by size
./will-encrypt list --vault vault.yaml --sort size
```

**Output (Table Format):**
```
ID   Title                              Created                    Size
-------------------------------------------------------------------------------------
1    Bank Account Access                2025-01-15T10:30:00Z       42
2    WiFi Password                      2025-01-16T14:20:00Z       35
```

**Output (JSON Format):**
```json
[
  {
    "id": 1,
    "title": "Bank Account Access",
    "created": "2025-01-15T10:30:00Z",
    "size_bytes": 42
  }
]
```

---

### `validate` - Validate Vault

Verify vault integrity and structure.

```bash
./will-encrypt validate --vault FILE [--verbose]
```

**Arguments:**
- `--vault`: Vault file path (default: `vault.yaml`)
- `--verbose`: Show detailed information

**Examples:**

```bash
# Basic validation
./will-encrypt validate --vault vault.yaml

# Verbose output
./will-encrypt validate --vault vault.yaml --verbose
```

**Checks Performed:**
- Vault version compatibility
- Manifest structure and threshold validity
- SHA-256 fingerprint verification (tamper detection)
- Encrypted keypair structure
- Message structure and metadata

**Output:**
```
✓ Vault validation passed
  Version: 1.0
  Threshold: 3-of-5
  Messages: 2
  Rotation events: 1
```

**Exit Codes:**
- `0`: Validation passed
- `2`: Vault not found or parsing error
- `3`: Fingerprint mismatch (vault tampered)
- `4`: Invalid threshold values
- `6`: Missing manifest
- `8`: Unsupported version

---

### `rotate` - Rotate Keys/Shares

Rotate shares or passphrase for enhanced security.

```bash
./will-encrypt rotate --vault FILE --mode MODE [--new-k K] [--new-n N] [--shares ...]
```

**Arguments:**
- `--vault`: Vault file path (default: `vault.yaml`)
- `--mode`: Rotation mode (`shares` or `passphrase`)
- `--new-k`: New threshold (optional, defaults to current)
- `--new-n`: New total shares (optional, defaults to current)
- `--shares`: K current shares to authorize rotation

**Rotation Modes:**

#### Share Rotation (Change K/N, Keep Passphrase)

Use when:
- Adding/removing key holders
- Changing threshold policy
- Key holder loses their share

```bash
# Change from 3-of-5 to 2-of-4
./will-encrypt rotate --vault vault.yaml \
    --mode shares --new-k 2 --new-n 4
```

**Process:**
1. Collect K current shares
2. Reconstruct passphrase
3. Split passphrase with new K/N
4. Print new shares
5. Old shares become invalid

> ⚠️ **Share numbers matter:** The CLI prints labels such as `Share 3/6` followed by the 24-word mnemonic. When recording a share, keep the numeric prefix (for example, store it as `3: word1 ... word24`) so later commands can reconstruct the original indices correctly.

#### Passphrase Rotation (New Passphrase + Optional K/N Change)

Use when:
- Suspected passphrase compromise
- Periodic security rotation
- Major key holder changes

```bash
# Rotate passphrase, keep 3-of-5 threshold
./will-encrypt rotate --vault vault.yaml --mode passphrase

# Rotate passphrase and change to 2-of-3
./will-encrypt rotate --vault vault.yaml \
    --mode passphrase --new-k 2 --new-n 3
```

**Process:**
1. Collect K current shares
2. Reconstruct current passphrase
3. Generate new passphrase (256-bit entropy)
4. Re-encrypt private keys with new passphrase
5. Split new passphrase with K/N (new or current)
6. Print new shares
7. Old shares and passphrase become invalid

> ⚠️ **Known issue:** `rotate --mode passphrase` currently generates fresh key material without rewrapping previously stored ciphertexts, which leaves the vault undecryptable. Avoid this mode until the implementation is updated to rewrap existing messages and align public/private keys.

**Security Notes:**
- Messages are NOT re-encrypted (hybrid encryption design)
- Rotation is logged in vault manifest
- Always validate vault after rotation
- Distribute new shares immediately

---

## Security Model

### Cryptographic Algorithms

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Asymmetric Encryption | RSA-4096-OAEP | SHA-256 hash, MGF1 |
| Post-Quantum Encryption | Kyber-1024 | NIST PQC Round 3 (simulated) |
| Symmetric Encryption | AES-256-GCM | 96-bit nonce, 128-bit auth tag |
| Secret Sharing | Shamir SSS | Lagrange interpolation, GF(256) |
| Key Derivation | PBKDF2-HMAC-SHA512 | 600,000 iterations (OWASP 2023) |
| Mnemonic Encoding | BIP39 | 24-word phrases (256-bit entropy) |
| Tamper Detection | SHA-256 | Fingerprints for all vault components |

### Threat Model

**Protections:**
- **Ciphertext-Only Attack**: AES-256-GCM with unique keys per message
- **Key Compromise**: Threshold scheme requires K shares (collusion resistant)
- **Tamper Detection**: SHA-256 fingerprints detect modification
- **Quantum Attacks**: Hybrid RSA + Kyber (future-proof)
- **Brute Force**: 256-bit passphrase entropy, PBKDF2 key stretching

**Out of Scope:**
- **Physical Access**: Assumes vault file is public/untrusted
- **Side-Channel Attacks**: Standard Python `cryptography` library protections
- **Social Engineering**: Key holder verification is out of scope
- **Malware**: Assumes decryption occurs on trusted device

**Assumptions:**
- K key holders do not collude maliciously
- Passphrase has 256 bits of entropy (32 random bytes)
- PBKDF2 with 600,000 iterations is sufficient (2025 standards)
- AES-256 and RSA-4096 remain secure until 2030+

### Key Distribution Best Practices

**For Key Holders:**
1. **Storage Options** (choose one):
   - Paper backup (laminated, fireproof safe)
   - Password manager (1Password, Bitwarden)
   - Hardware Security Module (YubiKey, Ledger)
   - Encrypted USB drive (VeraCrypt)

2. **Never**:
   - Share via unencrypted email or SMS
   - Store in plaintext on disk
   - Share with other key holders
   - Write partial share (all 24 words or nothing)

3. **Verification**:
   - Test share immediately after receipt
   - Validate BIP39 checksum (last word)
   - Confirm vault can be decrypted

**For Vault Owner:**
1. Distribute shares via secure channels:
   - In-person handoff (recommended)
   - Encrypted email (PGP, S/MIME)
   - Secure messaging (Signal, WhatsApp)
   - Physical mail (certified, signature required)

2. Document key holders:
   - Name, contact info, share number
   - Distribution date and method
   - Verification status

3. Test recovery process:
   - Dry-run with 3 key holders
   - Verify decryption works
   - Update documentation

---

## Deployment Guide

### Production Setup

#### 1. Environment Preparation

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash will-encrypt
sudo su - will-encrypt

# Set up virtual environment
python3.11 -m venv ~/.venv/will-encrypt
source ~/.venv/will-encrypt/bin/activate

# Install will-encrypt
pip install will-encrypt

# Verify installation
./will-encrypt --help
```

#### 2. Vault Initialization

```bash
# Create vault directory
mkdir -p ~/vaults
cd ~/vaults

# Initialize vault (adjust K/N for your needs)
./will-encrypt init --k 3 --n 5 --vault estate-vault.yaml
```

**Save shares immediately:**
- Print to paper and store in safe
- OR encrypt and email to key holders
- OR use password manager for distribution

#### 3. Share Distribution

**Method 1: Physical Distribution (Most Secure)**
```bash
# Print shares to PDF
./will-encrypt init --k 3 --n 5 --vault vault.yaml > shares.txt
# Manually copy each share to separate paper
# Shred shares.txt immediately
```

**Method 2: Encrypted Email**
```bash
# Encrypt share for each key holder
for i in {1..5}; do
  echo "Share $i: [SHARE_TEXT]" | gpg --encrypt --armor -r keyholder$i@example.com > share$i.asc
done

# Email each share separately
```

**Method 3: Secure Messaging**
- Send via Signal, WhatsApp (disappearing messages)
- Confirm receipt out-of-band (phone call)

#### 4. Backup Strategy

**Vault Backup (Public Data, OK to Share)**
```bash
# Backup to multiple locations
cp estate-vault.yaml ~/Dropbox/estate-vault.yaml
cp estate-vault.yaml /mnt/usb/estate-vault.yaml

# Optional: Version control
git init ~/vaults
git add estate-vault.yaml
git commit -m "Initial vault"
```

**Share Backup (Never Store with Vault)**
- Key holders responsible for their own share backup
- Vault owner should NOT keep a copy of shares
- Consider giving executor a sealed envelope (2-of-3 recovery)

#### 5. Access Control

```bash
# Vault file permissions (world-readable OK, it's encrypted)
chmod 644 ~/vaults/estate-vault.yaml

# But restrict directory access if desired
chmod 700 ~/vaults
```

#### 6. Monitoring and Maintenance

**Regular Tasks:**
- Quarterly: Test decryption with key holders (dry-run)
- Annually: Rotate shares (update K/N if needed)
- Ad-hoc: Rotate passphrase if suspected compromise

**Monitoring:**
```bash
# Validate vault integrity
./will-encrypt validate --vault estate-vault.yaml --verbose

# Check message count
./will-encrypt list --vault estate-vault.yaml

# Review rotation history
grep 'rotation_history' estate-vault.yaml
```

---

## Recovery Procedures

### Emergency Recovery (Normal Case)

**Scenario**: Account owner deceased, executor needs access to encrypted messages.

**Prerequisites:**
- K key holders available
- Vault file accessible
- will-encrypt tool installed

**Steps:**

1. **Contact Key Holders**
   ```bash
   # Executor contacts K key holders
   # Provides proof (death certificate, legal authorization)
   ```

2. **Collect Shares**
   - Key holders independently verify legitimacy
   - Each provides their 24-word share
   - No need to combine shares manually (tool does this)

3. **Decrypt Messages**
   ```bash
   ./will-encrypt decrypt --vault estate-vault.yaml
   # Enter K shares when prompted
   # All messages displayed
   ```

4. **Document Access**
   - Log which key holders participated
   - Record date/time of decryption
   - Note which messages were accessed

**Expected Duration**: 1-7 days (depends on key holder availability)

---

### Disaster Recovery (Share Loss)

#### Scenario 1: Lost Share (K-1 Shares Still Available)

**Solution**: Share rotation with K-1 remaining shares

```bash
# Requires K current shares (including lost share holder must be replaced)
# If you only have K-1, you CANNOT rotate
# Prevention: Always have K+1 shares minimum (e.g., 3-of-5, not 3-of-3)
```

**If possible:**
1. Collect K shares from remaining holders
2. Rotate shares with new N
3. Distribute new shares

#### Scenario 2: Lost Multiple Shares (< K Remaining)

**Solution**: NO RECOVERY POSSIBLE

This is by design (threshold cryptography). Messages are permanently inaccessible.

**Prevention:**
- Use K < N with margin (e.g., 3-of-5 allows 2 share losses)
- Regular share verification (annual check-ins)
- Backup shares securely (password manager, sealed envelope)

#### Scenario 3: Vault File Corrupted

**Solution**: Restore from backup

```bash
# Vault file is public data, OK to backup freely
cp ~/Dropbox/estate-vault.yaml.backup estate-vault.yaml
./will-encrypt validate --vault estate-vault.yaml
```

#### Scenario 4: Passphrase Compromise Suspected

**Solution**: Immediate passphrase rotation

```bash
# Collect K shares
./will-encrypt rotate --vault vault.yaml --mode passphrase

# Distribute new shares immediately
# Old passphrase and shares become invalid
```

---

### Recovery Testing (Recommended)

**Quarterly Dry-Run:**

1. Contact 3 key holders (for 3-of-5 threshold)
2. Collect their shares
3. Decrypt vault (verify access works)
4. Document test results
5. Thank key holders

**Benefits:**
- Verifies key holders still have shares
- Tests decryption process
- Updates recovery documentation
- Builds confidence in system

---

## Key Rotation

### When to Rotate

**Share Rotation (Change K/N):**
- Adding/removing key holders
- Key holder loses share
- Adjusting threshold policy
- Annual security refresh

**Passphrase Rotation (New Passphrase):**
- Suspected compromise
- Major key holder changes (e.g., divorce, death)
- Regulatory compliance (annual rotation)
- After emergency recovery event

### Rotation Process

#### Share Rotation Example

```bash
# Current: 3-of-5, Want: 2-of-4 (remove 1 key holder)
./will-encrypt rotate --vault vault.yaml \
    --mode shares --new-k 2 --new-n 4

# Enter 3 current shares when prompted
# New 4 shares printed to stdout
# Distribute to 4 key holders
```

**What Changes:**
- K and N values in manifest
- Share distribution (new shares printed)

**What Stays Same:**
- Passphrase (same 256-bit value)
- Private keys (same encryption)
- Messages (no re-encryption needed)

#### Passphrase Rotation Example

```bash
# Rotate passphrase, keep 3-of-5 threshold
./will-encrypt rotate --vault vault.yaml --mode passphrase

# Enter 3 current shares when prompted
# New passphrase generated
# New 5 shares printed to stdout
# Distribute to 5 key holders
```

**What Changes:**
- Passphrase (new 256-bit value)
- Private key encryption (re-encrypted with new passphrase)
- KDF salt (new random value)
- Share distribution (new shares printed)

**What Stays Same:**
- Public keys (RSA, Kyber)
- Messages (no re-encryption needed)
- K and N values (unless specified)

### Post-Rotation Checklist

1. **Validate vault**
   ```bash
   ./will-encrypt validate --vault vault.yaml --verbose
   ```

2. **Verify decryption with new shares**
   ```bash
   ./will-encrypt decrypt --vault vault.yaml
   # Use K new shares
   ```

3. **Securely destroy old shares**
   - Shred paper copies
   - Delete password manager entries
   - Overwrite digital copies (use `shred` or `srm`)

4. **Document rotation**
   - Date and reason for rotation
   - New K/N values
   - New key holder list

5. **Notify key holders**
   - Old shares are now invalid
   - New shares must be stored securely
   - Test new shares immediately

---

## Troubleshooting

### Initialization Issues

#### Error: `K must be <= N`
```
Error: K must be <= N
```

**Cause**: Threshold K exceeds total shares N.

**Fix**: Ensure K ≤ N (e.g., `--k 3 --n 5`, not `--k 5 --n 3`).

#### Error: `Vault already exists`
```
Error: Vault already exists at vault.yaml
```

**Cause**: Vault file exists, `--force` not used.

**Fix**:
```bash
# Option 1: Use different filename
./will-encrypt init --k 3 --n 5 --vault new-vault.yaml

# Option 2: Overwrite (DESTROYS EXISTING VAULT)
./will-encrypt init --k 3 --n 5 --vault vault.yaml --force
```

---

### Encryption Issues

#### Error: `Vault not found`
```
Error: Vault not found: vault.yaml
```

**Cause**: Vault file doesn't exist or incorrect path.

**Fix**:
```bash
# Check file exists
ls -l vault.yaml

# Use absolute path
./will-encrypt encrypt --vault /full/path/to/vault.yaml --title "..." --message "..."
```

#### Error: `Message exceeds 64 KB limit`
```
Error: Message exceeds 64 KB limit
```

**Cause**: Message too large (65,536 bytes max).

**Fix**:
- Split message into multiple smaller messages
- Store large files separately (encrypt file path/credentials instead)

#### Error: `Title exceeds 256 characters`
```
Error: Title exceeds 256 characters
```

**Fix**: Use shorter title (256 char limit).

---

### Decryption Issues

#### Error: `Insufficient shares`
```
Error: Insufficient shares (need 3, got 2)
```

**Cause**: Provided fewer than K shares.

**Fix**: Collect at least K shares from key holders.

#### Error: `Invalid BIP39 checksum in share 2`
```
Error: Invalid BIP39 checksum in share 2
```

**Cause**: Share has typo or incorrect checksum word.

**Fix**:
- Re-enter share carefully (24 words, space-separated)
- Verify last word (contains checksum)
- Use BIP39 validator: https://iancoleman.io/bip39/

**Example valid share format:**
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
```

#### Error: `Insufficient shares for import`
```
Error: Insufficient shares (need 3, got 2)
```

**Cause**: Provided fewer than K shares when using `--import-share`.

**Fix**: Provide at least K shares to reconstruct passphrase:
```bash
./will-encrypt init --k 3 --n 5 --vault vault.yaml \
  --import-share "SHARE_1" \
  --import-share "SHARE_2" \
  --import-share "SHARE_3"
```

#### Error: `Decryption failed`
```
Error: Decryption failed: MAC check failed
```

**Cause**: Wrong shares, tampered vault, or corrupted data.

**Fix**:
1. **Validate vault integrity**:
   ```bash
   ./will-encrypt validate --vault vault.yaml
   ```

2. **Try different shares**: May have entered wrong shares.

3. **Restore from backup**: If vault corrupted, restore backup.

4. **Check rotation history**: May have provided old shares after rotation.

---

### Validation Issues

#### Error: `Fingerprint mismatch`
```
✗ Fingerprint mismatch (vault may be tampered)
```

**Cause**: Vault file modified (tampered or corrupted).

**Fix**:
1. **Restore from backup**:
   ```bash
   cp vault.yaml.backup vault.yaml
   ```

2. **Check file integrity**:
   ```bash
   sha256sum vault.yaml
   ```

3. **If intentional edit**: Re-encrypt or regenerate vault.

---

### Rotation Issues

#### Error: `Must specify --new-k and --new-n for share rotation`
```
Error: Must specify --new-k and --new-n for share rotation
```

**Cause**: Share rotation requires explicit K/N values.

**Fix**:
```bash
./will-encrypt rotate --vault vault.yaml \
    --mode shares --new-k 3 --new-n 5
```

#### Error: `Invalid mode 'key'`
```
Error: Invalid mode 'key' (must be 'shares' or 'passphrase')
```

**Fix**: Use `--mode shares` or `--mode passphrase`.

---

### General Issues

#### Error: `ModuleNotFoundError: No module named 'src'`

**Cause**: will-encrypt not installed or not in PYTHONPATH.

**Fix**:
```bash
# Install in editable mode
pip install -e .

# Or run from project root
cd /path/to/will-encrypt
python -m src.main init --k 3 --n 5
```

#### Error: `yaml.scanner.ScannerError`

**Cause**: Vault YAML is malformed.

**Fix**: Restore from backup or regenerate vault.

---

## Architecture

### System Design

```
┌─────────────────────────────────────────────────────────────────┐
│                         will-encrypt CLI                        │
├─────────────────────────────────────────────────────────────────┤
│  init   encrypt   decrypt   list   validate   rotate            │
└───┬─────────┬──────────┬─────────┬─────────┬───────────┬────────┘
    │         │          │         │         │           │
    v         v          v         v         v           v
┌─────────────────────────────────────────────────────────────────┐
│                        Core Modules                             │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│   Crypto     │   Storage    │   Docs       │   CLI             │
├──────────────┼──────────────┼──────────────┼───────────────────┤
│ • keypair.py │ • vault.py   │ • recovery_  │ • init.py         │
│ • shamir.py  │ • models.py  │   guide.py   │ • encrypt.py      │
│ • bip39.py   │ • manifest.py│ • policy.py  │ • decrypt.py      │
│ • encryption │              │ • crypto_    │ • rotate.py       │
│   .py        │              │   notes.py   │ • validate.py     │
│ • passphrase │              │              │ • list.py         │
│   .py        │              │              │                   │
└──────────────┴──────────────┴──────────────┴───────────────────┘
```

### Data Flow

#### Initialization (init)
```
1. Generate 256-bit passphrase (32 random bytes)
2. Split passphrase → K-of-N shares (Shamir SSS)
3. Encode shares → BIP39 mnemonics (24 words each)
4. Generate RSA-4096 + Kyber-1024 keypair
5. Encrypt private keys with passphrase (PBKDF2 + AES-256-GCM)
6. Create vault structure (YAML)
7. Compute SHA-256 fingerprints
8. Save vault, print shares to stdout
```

#### Encryption (encrypt)
```
1. Generate random 256-bit KEK (Key Encryption Key)
2. Encrypt message with KEK (AES-256-GCM, AAD=title)
3. Wrap KEK with RSA-4096-OAEP (public key)
4. Wrap KEK with Kyber-1024 (public key)
5. Store: ciphertext, wrapped KEKs, nonce, auth tag
6. Update vault manifest
7. Recompute fingerprints, save vault
```

#### Decryption (decrypt)
```
1. Collect K shares from key holders
2. Decode BIP39 mnemonics → raw shares
3. Reconstruct passphrase (Shamir SSS)
4. Derive AES key from passphrase (PBKDF2)
5. Decrypt private keys (AES-256-GCM)
6. For each message:
   a. Unwrap KEK with RSA-4096-OAEP (private key)
   b. Verify Kyber-wrapped KEK matches (hybrid check)
   c. Decrypt message with KEK (AES-256-GCM, verify AAD)
7. Display plaintext messages
```

### File Structure

```
./will-encrypt/
├── src/
│   ├── main.py              # CLI entry point
│   ├── cli/                 # Command implementations
│   │   ├── init.py
│   │   ├── encrypt.py
│   │   ├── decrypt.py
│   │   ├── rotate.py
│   │   ├── validate.py
│   │   └── list.py
│   ├── crypto/              # Cryptographic primitives
│   │   ├── keypair.py       # RSA/Kyber key generation
│   │   ├── encryption.py    # AES-GCM message encryption
│   │   ├── shamir.py        # Shamir Secret Sharing
│   │   ├── bip39.py         # BIP39 mnemonic encoding
│   │   └── passphrase.py    # Passphrase generation
│   ├── storage/             # Vault persistence
│   │   ├── vault.py         # YAML serialization
│   │   ├── models.py        # Data structures
│   │   └── manifest.py      # Fingerprinting
│   └── docs/                # Documentation generation
│       ├── recovery_guide.py
│       ├── policy.py
│       └── crypto_notes.py
├── tests/                   # Test suite (127 tests)
│   ├── unit/
│   └── contract/
├── pyproject.toml           # Project metadata
├── setup.py                 # Installation script
└── README.md                # This file
```

### Vault File Format

```yaml
version: "1.0"

keys:
  rsa_public: "-----BEGIN PUBLIC KEY-----\n..."
  rsa_private_encrypted: "base64..."  # AES-256-GCM encrypted
  kyber_public: "base64..."
  kyber_private_encrypted: "base64..."  # AES-256-GCM encrypted
  kdf_salt: "base64..."  # PBKDF2 salt
  kdf_iterations: 600000

manifest:
  k: 3
  n: 5
  algorithms:
    keypair: "RSA-4096 + Kyber-1024 (hybrid)"
    passphrase_entropy: 256
    secret_sharing: "Shamir SSS over GF(256)"
    message_encryption: "AES-256-GCM"
    kdf: "PBKDF2-HMAC-SHA512 (600k iterations)"
  fingerprints:
    keys: "sha256..."
    messages: "sha256..."
    guides: "sha256..."
  rotation_history:
    - date: "2025-01-15T10:30:00Z"
      event_type: "initial_creation"
      k: 3
      n: 5

messages:
  - id: 1
    title: "Bank Account Access"
    ciphertext: "base64..."
    rsa_wrapped_kek: "base64..."
    kyber_wrapped_kek: "base64..."
    nonce: "base64..."
    auth_tag: "base64..."
    created: "2025-01-15T10:30:00Z"
    size_bytes: 42

guides:
  recovery_guide: "# Emergency Recovery Guide\n..."
  policy_document: "# Access Policy\n..."
  crypto_notes: "# Cryptographic Implementation\n..."
```

---

## Development

### Running Tests

```bash
# Full test suite (127 tests)
pytest tests/

# With coverage
pytest tests/ --cov=src --cov-report=html

# Specific test file
pytest tests/contract/test_decrypt_contract.py

# Verbose output
pytest tests/ -v
```

### Code Quality

```bash
# Lint with ruff
ruff check .

# Type checking with mypy
mypy src/

# Format code
ruff format .
```

### Project Structure

- **`src/`**: Source code
  - **`cli/`**: Command implementations
  - **`crypto/`**: Cryptographic primitives
  - **`storage/`**: Vault persistence
  - **`docs/`**: Documentation generation
- **`tests/`**: Test suite
  - **`unit/`**: Unit tests (individual functions)
  - **`contract/`**: Contract tests (end-to-end CLI)

### Adding New Commands

1. Create `src/cli/newcommand.py`:
   ```python
   def newcommand_command(arg1: str, arg2: int) -> int:
       """Command implementation."""
       # ... implementation ...
       return 0  # Success
   ```

2. Add to `src/main.py`:
   ```python
   from src.cli.newcommand import newcommand_command

   # In main():
   newcommand_parser = subparsers.add_parser("newcommand", help="...")
   newcommand_parser.add_argument("--arg1", required=True)
   # ...

   if args.command == "newcommand":
       return newcommand_command(args.arg1, args.arg2)
   ```

3. Add tests in `tests/contract/test_newcommand_contract.py`

4. Update this README

---

## FAQ

### Why BIP39 for shares?

BIP39 mnemonics are:
- Human-readable (24 common English words)
- Error-correcting (checksum in last word)
- Widely supported (hardware wallets, password managers)
- Easy to transcribe (paper backup)

### Can I change K/N after initialization?

Yes! Use `rotate --mode shares --new-k X --new-n Y`. Messages are NOT re-encrypted.

### What happens if I lose K shares?

**Data is permanently inaccessible**. This is by design (threshold cryptography). Use K < N with margin (e.g., 3-of-5 allows 2 losses).

### Can I use this for non-emergency scenarios?

Yes! Use cases:
- Password managers (family shared account)
- Business continuity (critical credentials)
- Open-source projects (shared secrets)
- Legal documents (attorney access)

### Is the vault file secret?

**No, vault file is public data**. It contains:
- Encrypted private keys (requires passphrase to decrypt)
- Encrypted messages (requires private keys to decrypt)
- Metadata (threshold, algorithms, fingerprints)

Safe to:
- Backup to cloud storage (Dropbox, Google Drive)
- Commit to version control (git)
- Email to backup locations

**Shares are secret** - never store with vault.

### How is this different from Shamir's Secret Sharing alone?

Shamir SSS splits the passphrase, but:
- Messages are encrypted with RSA/Kyber (public-key crypto)
- Allows adding messages without distributing new shares
- Supports key rotation without re-encrypting messages
- Provides tamper detection (fingerprints)

### What if quantum computers break RSA?

Hybrid design: Both RSA and Kyber must be broken. If RSA is broken:
1. Decrypt all messages with current vault (RSA still works today)
2. Generate new vault with quantum-resistant algorithm only
3. Re-encrypt messages
4. Distribute new shares

### Can I audit the cryptography?

Yes! All cryptographic code is in `src/crypto/`. Uses standard libraries:
- `cryptography` (Python Cryptographic Authority)
- `mnemonic` (BIP39 implementation)
- `secretsharing` (Shamir SSS)

Review `src/docs/crypto_notes.py` for algorithm details and test vectors.

---

## License

MIT License - see LICENSE file for details.

---

## Support

- **Issues**: https://github.com/yourusername/will-encrypt/issues
- **Discussions**: https://github.com/yourusername/will-encrypt/discussions
- **Email**: support@will-encrypt.example.com

---

## Changelog

### v1.0.0 (2025-01-15)

- Initial release
- RSA-4096 + Kyber-1024 hybrid encryption
- Shamir K-of-N threshold (1-255 shares)
- BIP39 mnemonic encoding
- Message encryption (64 KB limit)
- Share rotation
- Passphrase rotation
- Vault validation (fingerprints)
- 127 tests, 100% coverage

---

## Acknowledgments

- **Shamir, Adi**: "How to share a secret" (1979)
- **BIP39**: Bitcoin Improvement Proposal 39 (2013)
- **NIST**: Post-Quantum Cryptography Standardization
- **Python Cryptographic Authority**: `cryptography` library
- **Contributors**: See CONTRIBUTORS.md

---

**Made with ❤️ for digital estate planning and emergency access scenarios.**
