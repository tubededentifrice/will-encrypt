"""Recovery guide generation."""


def generate_recovery_guide(k: int, n: int) -> str:
    """Generate recovery guide text."""
    return f"""# Emergency Recovery Guide

## When to Use This Guide
Use this guide when you need to access encrypted messages in the vault.
You will need {k} out of {n} secret shares (BIP39 mnemonics) from key holders.

## Prerequisites
- At least {k} secret shares (24-word BIP39 mnemonics)
- Access to the vault file (vault.yaml)
- Python 3.11 or higher installed on your computer
- Will-encrypt tool (instructions below)

## Installation Steps (First Time Only)

### Step 1: Install Python (if not already installed)
- **Windows**: Download from https://www.python.org/downloads/
  - During installation, check "Add Python to PATH"
- **macOS**: Python 3 is pre-installed, or use Homebrew: `brew install python3`
- **Linux**: Use your package manager: `sudo apt install python3 python3-pip`

### Step 2: Verify Python Installation
Open a terminal (Command Prompt on Windows, Terminal on macOS/Linux) and type:
```bash
python3 --version
```
You should see "Python 3.11" or higher. If not, install Python first.

### Step 3: Download Will-Encrypt
In the terminal, navigate to a folder where you want to install will-encrypt, then:
```bash
git clone https://github.com/tubededentifrice/will-encrypt.git
cd will-encrypt
```

If you don't have git installed:
- **Windows**: Download Git from https://git-scm.com/download/win
- **macOS**: Install Xcode Command Line Tools: `xcode-select --install`
- **Linux**: `sudo apt install git`

Alternatively, download the ZIP file from GitHub:
1. Visit https://github.com/tubededentifrice/will-encrypt
2. Click the green "Code" button
3. Select "Download ZIP"
4. Extract the ZIP file and open a terminal in that folder

### Step 4: Install Dependencies
In the will-encrypt folder, run:
```bash
pip install -r requirements.txt
pip install -e .
```

## Step-by-Step Recovery

### Step 1: Collect Shares
Contact key holders and collect at least {k} shares. Each share is a sequence of exactly 24 words.

### Step 2: Locate the Vault File
Find the vault file (typically named "vault.yaml" or similar). Place it in the will-encrypt folder or note its full path.

### Step 3: Run Decryption
In the terminal, navigate to the will-encrypt folder and execute:
```bash
./will-encrypt decrypt --vault vault.yaml
```

(If the vault file is elsewhere, use the full path: `./will-encrypt decrypt --vault /path/to/vault.yaml`)

### Step 4: Enter Shares
When prompted, carefully enter each of the {k} shares (24 words each). Double-check for typos.

### Step 5: View Messages
All encrypted messages will be decrypted and displayed on screen.

## Expected Duration
- Installation (first time): 10-30 minutes
- Share collection: Variable (depends on key holder availability)
- Decryption process: < 1 minute

## Troubleshooting
- **If shares are rejected**: Verify you entered all 24 words correctly with no typos
- **If decryption fails**: Ensure you have exactly {k} valid shares
- **If vault not found**: Check the file path and ensure the vault file exists
- **If Python not found**: Make sure Python 3.11+ is installed and in your PATH
- **If git not found**: Install git or download the ZIP file from GitHub instead
- **For other issues**: Visit https://github.com/tubededentifrice/will-encrypt/issues

## Security Notes
- The vault file can be safely backed up (it contains no secrets)
- Shares must be kept secret - never share them publicly
- Once decrypted, save the messages securely or write them down
"""
