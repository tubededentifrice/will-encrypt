"""
BIP39 mnemonic encoding/decoding for Shamir shares.

Based on: specs/001-1-purpose-scope/research.md (Section 3)

Implements BIP39 (Bitcoin Improvement Proposal 39) for encoding
32-byte shares as 24-word human-readable mnemonics with checksums.
"""

from typing import Optional
from mnemonic import Mnemonic


# Initialize BIP39 handler for English wordlist
_mnemonic = Mnemonic("english")


def encode_share(share: bytes) -> str:
    """
    Encode share to 24-word BIP39 mnemonic.

    Args:
        share: Share bytes to encode (will use first 32 bytes if longer)

    Returns:
        24-word space-separated mnemonic string

    Raises:
        ValueError: If share is less than 32 bytes
    """
    if not isinstance(share, bytes):
        raise TypeError("Share must be bytes")

    if len(share) < 32:
        raise ValueError("Share must be at least 32 bytes")

    # Take first 32 bytes for BIP39 encoding
    share_data = share[:32] if len(share) > 32 else share

    # Convert bytes to mnemonic (includes checksum generation)
    mnemonic_words = _mnemonic.to_mnemonic(share_data)

    return mnemonic_words


def decode_share(mnemonic_str: str) -> bytes:
    """
    Decode 24-word BIP39 mnemonic to 32-byte share.

    Supports 4-character word prefixes (e.g., "aban" → "abandon").

    Args:
        mnemonic_str: 24-word space-separated mnemonic (full words or 4-char prefixes)

    Returns:
        32-byte decoded share

    Raises:
        ValueError: If mnemonic is invalid or checksum fails
    """
    if not isinstance(mnemonic_str, str):
        raise TypeError("Mnemonic must be a string")

    # Normalize whitespace and case
    normalized = " ".join(mnemonic_str.lower().split())

    # Expand 4-character prefixes to full words
    expanded = _mnemonic.expand(normalized)

    # Check if mnemonic is valid (includes checksum verification)
    if not _mnemonic.check(expanded):
        raise ValueError("Invalid mnemonic or checksum failed")

    # Convert mnemonic to bytes
    try:
        share = _mnemonic.to_entropy(expanded)
    except Exception as e:
        raise ValueError(f"Failed to decode mnemonic: {e}")

    if len(share) != 32:
        raise ValueError(f"Decoded share must be 32 bytes, got {len(share)}")

    # Ensure return type is bytes (not bytearray)
    return bytes(share)


def validate_checksum(mnemonic_str: str) -> bool:
    """
    Validate BIP39 mnemonic checksum.

    Supports 4-character word prefixes (e.g., "aban" → "abandon").

    Args:
        mnemonic_str: 24-word space-separated mnemonic (full words or 4-char prefixes)

    Returns:
        True if checksum is valid, False otherwise
    """
    if not isinstance(mnemonic_str, str):
        return False

    # Normalize whitespace and case
    normalized = " ".join(mnemonic_str.lower().split())

    # Expand 4-character prefixes to full words
    expanded = _mnemonic.expand(normalized)

    # Use library's checksum validation
    return _mnemonic.check(expanded)


def format_indexed_share(index: int, mnemonic: str) -> str:
    """
    Format share with index prefix for display/storage.

    Args:
        index: 1-based share index (1-255)
        mnemonic: 24-word BIP39 mnemonic

    Returns:
        Formatted string like "1: abandon ability able..."
    """
    if index < 1 or index > 255:
        raise ValueError(f"Share index must be 1-255, got {index}")
    return f"{index}: {mnemonic}"


def parse_indexed_share(indexed_str: str) -> tuple[Optional[int], str]:
    """
    Parse share with optional index prefix.

    Supports formats:
    - "1: abandon ability able..." (explicit index)
    - "Share 1: abandon ability able..." (with label)
    - "abandon ability able..." (no index, returns None)

    Args:
        indexed_str: Share string with optional index prefix

    Returns:
        Tuple of (index or None, mnemonic_str)
    """
    stripped = indexed_str.strip()

    # Try "Share N:" format
    if stripped.lower().startswith("share "):
        parts = stripped.split(":", 1)
        if len(parts) == 2:
            try:
                # Extract number from "Share N"
                share_part = parts[0].strip()
                index_str = share_part.split()[1]  # Get the number after "Share"
                index = int(index_str)
                mnemonic = parts[1].strip()
                return (index, mnemonic)
            except (IndexError, ValueError):
                pass  # Fall through to next format

    # Try "N:" format
    if ":" in stripped:
        parts = stripped.split(":", 1)
        try:
            index = int(parts[0].strip())
            mnemonic = parts[1].strip()
            return (index, mnemonic)
        except ValueError:
            pass  # Not a valid index, treat whole string as mnemonic

    # No index prefix found
    return (None, stripped)
