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
- Will-encrypt tool installed

## Step-by-Step Recovery

1. **Collect Shares**: Contact key holders and collect at least {k} shares
2. **Verify Shares**: Each share should be exactly 24 words
3. **Run Decryption**: Execute `will-encrypt decrypt --vault vault.yaml`
4. **Enter Shares**: When prompted, enter each of the {k} shares
5. **View Messages**: All encrypted messages will be decrypted and displayed

## Expected Duration

- Share collection: Variable (depends on key holder availability)
- Decryption process: < 1 minute

## Troubleshooting

- If shares are rejected: Verify BIP39 checksum validity
- If decryption fails: Ensure you have exactly {k} valid shares
- If vault not found: Check file path and permissions
"""
