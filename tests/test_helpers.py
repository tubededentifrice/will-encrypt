"""Test helper utilities for will-encrypt tests."""

import re
from pathlib import Path


def extract_shares_from_output(output: str) -> list[str]:
    """
    Extract BIP39 shares from init command output.

    Args:
        output: Captured stdout from init command

    Returns:
        List of share mnemonics WITH index prefix (e.g., "1: word1 word2 ...")
    """
    # New format: Parse table-based share output
    # Format:
    # Share 1/5:
    #
    # +---------------+---------------+---------------+---------------+
    # | 1. word      | 2. word      | 3. word      | 4. word      |
    # +---------------+---------------+---------------+---------------+
    # ...

    shares = []

    # Split by "Share N/M:" to find individual share sections
    share_pattern = r'Share (\d+)/(\d+):'
    share_matches = list(re.finditer(share_pattern, output))

    for i, match in enumerate(share_matches):
        share_index = int(match.group(1))

        # Extract the section for this share (from current match to next match or end)
        start_pos = match.end()
        end_pos = share_matches[i + 1].start() if i + 1 < len(share_matches) else len(output)
        share_section = output[start_pos:end_pos]

        # Extract words from table cells: "| 1. word |" or "|10. word |"
        # Pattern matches numbered words in table cells
        # Note: Don't require closing | since cells can be adjacent like "|word|word|"
        word_pattern = r'\|\s*\d+\.\s+(\w+)\s*'
        words = re.findall(word_pattern, share_section)

        if len(words) == 24:
            # Reconstruct the mnemonic
            mnemonic = ' '.join(words)
            # Format with index prefix like "1: word1 word2 ..."
            shares.append(f"{share_index}: {mnemonic}")

    return shares


def create_test_vault(tmp_path: Path, k: int = 3, n: int = 5) -> tuple[Path, list[str]]:
    """
    Create a test vault and return the path and shares.

    Args:
        tmp_path: pytest tmp_path fixture
        k: Threshold (minimum shares needed)
        n: Total number of shares

    Returns:
        Tuple of (vault_path, shares)
    """
    import io
    import sys

    from src.cli.init import init_command

    vault_path = tmp_path / "test_vault.yaml"

    # Capture output to extract shares
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()

    try:
        result = init_command(k=k, n=n, vault_path=str(vault_path), import_shares=[])
        assert result == 0, "Init command should succeed"

        output = captured_output.getvalue()
        shares = extract_shares_from_output(output)
        assert len(shares) == n, f"Expected {n} shares, got {len(shares)}"

        return vault_path, shares
    finally:
        sys.stdout = old_stdout


def encrypt_test_message(vault_path: Path, title: str, message: str) -> int:
    """
    Encrypt a message in the test vault.

    Args:
        vault_path: Path to vault file
        title: Message title
        message: Message plaintext

    Returns:
        Exit code from encrypt command
    """
    from src.cli.encrypt import encrypt_command

    return encrypt_command(
        vault_path=str(vault_path),
        title=title,
        message_text=message
    )


def decrypt_test_vault(vault_path: Path, shares: list[str]) -> int:
    """
    Decrypt messages from vault using shares.

    Args:
        vault_path: Path to vault file
        shares: List of BIP39 share mnemonics

    Returns:
        Exit code from decrypt command
    """
    from src.cli.decrypt import decrypt_command

    return decrypt_command(
        vault_path=str(vault_path),
        shares=shares
    )


def get_vault_manifest(vault_path: Path) -> dict:
    """
    Load and return the manifest from a vault file.

    Args:
        vault_path: Path to vault file

    Returns:
        Manifest dictionary
    """
    import yaml

    with open(vault_path) as f:
        vault = yaml.safe_load(f)

    return vault.get("manifest", {})


def get_vault_messages(vault_path: Path) -> list[dict]:
    """
    Load and return messages from a vault file.

    Args:
        vault_path: Path to vault file

    Returns:
        List of message dictionaries
    """
    import yaml

    with open(vault_path) as f:
        vault = yaml.safe_load(f)

    return vault.get("messages", [])


def validate_bip39_share(share: str) -> bool:
    """
    Validate a BIP39 share mnemonic.

    Args:
        share: BIP39 mnemonic string

    Returns:
        True if valid, False otherwise
    """
    from src.crypto.bip39 import validate_checksum

    return validate_checksum(share)
