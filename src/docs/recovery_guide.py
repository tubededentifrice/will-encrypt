"""Recovery guide generation."""


def generate_recovery_guide(k: int, n: int) -> str:
    """Generate recovery guide text."""
    return f"""# Emergency Recovery Guide

## What Is This Document?
This guide explains how to access encrypted messages stored in your Will-Encrypt vault.
It is designed for executors, family members, or trusted individuals who may not have
technical experience.

## When to Use This Guide

Emergency recovery is authorized when:
- The vault owner is deceased (death certificate required)
- The vault owner is incapacitated (medical certification required)
- Legal authorization is provided (court order, power of attorney)
- The vault owner has given explicit permission

⚠️  **IMPORTANT**: Before starting recovery, ensure you have proper legal authorization
to access this vault. Key holders are responsible for verifying legitimacy before
releasing their shares.

## What You Need

To decrypt messages in this vault, you need:
1. **At least {k} secret shares** (out of {n} total shares)
   - Each share is a sequence of exactly 24 words (called a "BIP39 mnemonic")
   - These shares are held by different trusted key holders
2. **The vault file** (typically named "vault.yaml")
   - This file can be safely stored anywhere (it contains no secrets by itself)
3. **A computer** with internet access (any Windows, macOS, or Linux computer)

## Key Holder Coordination

### Step 1: Initial Contact
As the person coordinating recovery (executor, family member, etc.):
1. Contact all key holders who have secret shares
2. Explain the situation and reason for recovery
3. Provide proof of authorization (death certificate, court order, etc.)

### Step 2: Collecting Shares
Each key holder should:
1. Independently verify the legitimacy of your recovery request
2. Review the proof of authorization you provided
3. If satisfied, provide their secret share (24 words)
4. Keep a record of when and why they released their share

⚠️  **SECURITY NOTE**: You only need {k} shares, but {n} shares exist for redundancy.
If some key holders are unreachable, you can still proceed with {k} shares.

## Installation Steps (First Time Only)

### Step 1: Install Python (if not already installed)

Python is the programming language needed to run Will-Encrypt.

- **Windows**:
  1. Visit https://www.python.org/downloads/
  2. Download the latest Python 3.11 or higher
  3. Run the installer
  4. ✓ CHECK the box "Add Python to PATH" during installation
  5. Complete the installation

- **macOS**:
  - Python 3 is pre-installed on recent versions
  - Or install via Homebrew: Open Terminal and type `brew install python3`

- **Linux**:
  - Use your package manager: Open Terminal and type `sudo apt install python3 python3-pip`

### Step 2: Verify Python Installation

Open a terminal/command prompt:
- **Windows**: Press Windows+R, type `cmd`, press Enter
- **macOS**: Press Command+Space, type "Terminal", press Enter
- **Linux**: Press Ctrl+Alt+T

Type this command and press Enter:
```bash
python3 --version
```

You should see "Python 3.11" or higher. If not, repeat Step 1.

### Step 3: Download Will-Encrypt

**Option A: Using Git (recommended if available)**

In the terminal, type:
```bash
git clone https://github.com/tubededentifrice/will-encrypt.git
cd will-encrypt
```

If git is not installed:
- **Windows**: Download from https://git-scm.com/download/win
- **macOS**: Type `xcode-select --install` in Terminal
- **Linux**: Type `sudo apt install git` in Terminal

**Option B: Download ZIP File (easier for non-technical users)**

1. Visit https://github.com/tubededentifrice/will-encrypt
2. Click the green "Code" button
3. Select "Download ZIP"
4. Extract the ZIP file to your Desktop or Documents folder
5. Open a terminal in that folder

### Step 4: Install Dependencies

In the terminal, make sure you're in the will-encrypt folder, then type:
```bash
pip install -r requirements.txt
pip install -e .
```

This installs the necessary software components. It may take a few minutes.

## Step-by-Step Recovery Process

### Step 1: Collect at Least {k} Shares
Contact key holders and ask them to provide their 24-word shares. Write them down
carefully or have them sent securely (encrypted email, secure messaging).

Each share looks like this:
```
word1 word2 word3 word4 ... word24
```

### Step 2: Locate the Vault File
Find the vault file (typically "vault.yaml"). This might be:
- On a backup drive
- In cloud storage
- Attached to a document
- Provided by the vault owner

Place the vault file in the will-encrypt folder you extracted earlier.

### Step 3: Run Decryption Command
In the terminal, navigate to the will-encrypt folder and type:
```bash
./will-encrypt decrypt --vault vault.yaml
```

If the vault file is in a different location, use its full path:
```bash
./will-encrypt decrypt --vault /path/to/vault.yaml
```

### Step 4: Enter Shares
The tool will prompt you to enter shares one at a time.

When prompted:
1. Type or paste the first share (all 24 words, separated by spaces)
2. Press Enter
3. Repeat for each additional share (you need {k} total)

⚠️  **IMPORTANT**:
- Enter exactly 24 words per share
- Check for typos - even one wrong letter will cause failure
- If a share is rejected, verify it and try again

### Step 5: View and Save Messages
Once you've entered {k} valid shares, all encrypted messages will be decrypted
and displayed on screen.

**To save the messages**:
1. Copy the text from the terminal window
2. Paste into a text editor (Notepad, TextEdit, etc.)
3. Save to a secure location
4. Or take screenshots for documentation

## Expected Time Required
- **First-time installation**: 10-30 minutes (depending on internet speed)
- **Share collection**: Variable (depends on key holder availability)
- **Decryption process**: Less than 1 minute once you have the shares

## Troubleshooting Common Issues

### "Invalid BIP39 checksum" or Share Rejected
**Problem**: One or more shares contain typos or are incorrect.
**Solution**:
1. Double-check each word in the share
2. Verify there are exactly 24 words
3. Contact the key holder to re-verify the share
4. Try entering the shares again

### "Insufficient shares"
**Problem**: You need {k} shares but provided fewer.
**Solution**:
1. Contact additional key holders
2. Collect more shares until you have at least {k}

### "Vault not found" or "File not found"
**Problem**: The vault file path is incorrect.
**Solution**:
1. Verify the vault file exists
2. Check the file name (usually "vault.yaml")
3. Use the full path to the file (e.g., `/Users/john/Documents/vault.yaml`)

### "Python not found" or "Command not found"
**Problem**: Python is not installed or not in your system PATH.
**Solution**:
1. Reinstall Python and ensure "Add to PATH" is checked
2. Restart your terminal/command prompt after installation
3. Try `python` instead of `python3` (Windows may use this)

### Permission Denied
**Problem**: You don't have permission to access the vault file.
**Solution**:
1. Make sure you're the owner of the file or have read permissions
2. On macOS/Linux: Try `chmod 600 vault.yaml` to set proper permissions

### Other Issues
- Visit the project's issue tracker: https://github.com/tubededentifrice/will-encrypt/issues
- Search for similar problems or create a new issue with details
- Contact a technically savvy friend or IT professional for help

## Security and Privacy

### What's Safe to Share?
- **Vault file**: YES - Safe to backup, email, or store in cloud storage
- **Secret shares**: NO - Must be kept confidential by key holders
- **Decrypted messages**: NO - Handle with same care as the original secrets

### After Recovery
1. **Document everything**: Record which shares were used, when, and by whom
2. **Secure the messages**: Store decrypted content in a safe location
3. **Notify key holders**: Let them know recovery was completed successfully
4. **Consider destroying shares**: If appropriate, key holders may choose to
   securely destroy their shares after successful recovery

### Audit Trail
It's good practice to maintain a record of:
- Date and time of recovery attempt
- Who coordinated the recovery (your name and contact)
- Which key holders provided shares
- What proof of authorization was provided
- Date and time of successful decryption
- How the decrypted messages were handled

## Technical Notes (for Advanced Users)

This vault uses:
- **Threshold cryptography**: {k}-of-{n} Shamir Secret Sharing over GF(256)
- **BIP39 encoding**: 24-word mnemonics with checksums for error detection
- **Hybrid post-quantum encryption**: RSA-4096 + Kyber-1024
- **Message encryption**: AES-256-GCM authenticated encryption
- **Key derivation**: PBKDF2-HMAC-SHA512 with 600K iterations

The vault file itself contains only public keys and encrypted data. Private keys
are encrypted with a passphrase derived from the secret shares, so the vault
is useless without at least {k} shares.

## Questions or Help Needed?

If you're stuck or need assistance:
1. Read the troubleshooting section above
2. Check the project documentation: https://github.com/tubededentifrice/will-encrypt
3. Ask a technically experienced friend or IT professional to help
4. Contact the key holders - they may have additional guidance

Remember: The vault owner chose this system to protect important information.
Take your time, follow the steps carefully, and don't hesitate to ask for help.
"""
