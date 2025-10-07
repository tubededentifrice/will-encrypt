"""
BIP39 mnemonic encoding/decoding for Shamir shares.

Based on: specs/001-1-purpose-scope/research.md (Section 3)

Implements BIP39 (Bitcoin Improvement Proposal 39) for encoding
32-byte shares as 24-word human-readable mnemonics with checksums.
"""

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
