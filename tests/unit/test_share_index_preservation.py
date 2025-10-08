"""
Unit tests for share index preservation through BIP39 encoding.

Security requirement: Share indices must be preserved to prevent
reconstruction failures when shares are provided out of order.
"""

import secrets
import pytest


class TestShareIndexPreservation:
    """Tests that verify share indices are correctly preserved."""

    def test_shares_out_of_order_reconstruction(self) -> None:
        """Test: Shares can be reconstructed in any order with correct indices."""
        from src.crypto.shamir import split_secret, reconstruct_secret
        from src.crypto.bip39 import encode_share, decode_share

        # Generate random secret
        secret = secrets.token_bytes(32)
        k, n = 3, 5

        # Split into shares
        shares = split_secret(secret, k, n)

        # Encode shares as BIP39 (preserving indices separately)
        indexed_mnemonics = []
        for share in shares:
            index = share[0]  # Extract index
            mnemonic = encode_share(share[1:])  # Encode 32-byte payload
            indexed_mnemonics.append((index, mnemonic))

        # Test reconstruction with shares in REVERSE order (5, 4, 3)
        reversed_shares = []
        for i in [4, 3, 2]:  # Use shares 5, 4, 3 (indices in shares list)
            index, mnemonic = indexed_mnemonics[i]
            decoded = decode_share(mnemonic)
            # Use ORIGINAL index, not sequential
            reversed_shares.append(bytes([index]) + decoded)

        # Reconstruct with reversed shares
        reconstructed_reverse = reconstruct_secret(reversed_shares)
        assert reconstructed_reverse == secret, "Failed to reconstruct with reverse order shares"

        # Test reconstruction with shares 1, 3, 5 (non-sequential)
        sparse_shares = []
        for i in [0, 2, 4]:  # Use shares 1, 3, 5
            index, mnemonic = indexed_mnemonics[i]
            decoded = decode_share(mnemonic)
            sparse_shares.append(bytes([index]) + decoded)

        reconstructed_sparse = reconstruct_secret(sparse_shares)
        assert reconstructed_sparse == secret, "Failed to reconstruct with sparse shares"

    def test_wrong_index_causes_reconstruction_failure(self) -> None:
        """Test: Using wrong indices causes reconstruction to fail (negative test)."""
        from src.crypto.shamir import split_secret, reconstruct_secret
        from src.crypto.bip39 import encode_share, decode_share

        # Generate random secret
        secret = secrets.token_bytes(32)
        k, n = 3, 5

        # Split into shares
        shares = split_secret(secret, k, n)

        # Encode shares as BIP39
        indexed_mnemonics = []
        for share in shares:
            index = share[0]
            mnemonic = encode_share(share[1:])
            indexed_mnemonics.append((index, mnemonic))

        # Reconstruct with WRONG indices (sequential 1, 2, 3 instead of original)
        wrong_index_shares = []
        for i, (original_index, mnemonic) in enumerate(indexed_mnemonics[:k], 1):
            decoded = decode_share(mnemonic)
            # Use SEQUENTIAL index instead of original - this is the BUG we fixed!
            wrong_index_shares.append(bytes([i]) + decoded)

        # If we used shares 1, 2, 3 in order, this might work by accident
        # Let's use shares 2, 3, 5 with wrong indices 1, 2, 3
        wrong_index_shares = []
        for i, original_idx in enumerate([1, 2, 4], 1):  # Use shares 2, 3, 5
            _, mnemonic = indexed_mnemonics[original_idx]
            decoded = decode_share(mnemonic)
            # Assign sequential indices 1, 2, 3 instead of original 2, 3, 5
            wrong_index_shares.append(bytes([i]) + decoded)

        reconstructed_wrong = reconstruct_secret(wrong_index_shares)
        # This should produce WRONG result (unless by extreme chance)
        assert reconstructed_wrong != secret, "Wrong indices should produce wrong secret"

    def test_bip39_indexed_share_format_parsing(self) -> None:
        """Test: Indexed share format (N: mnemonic) is parsed correctly."""
        from src.crypto.bip39 import format_indexed_share, parse_indexed_share

        test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # Format share 3
        formatted = format_indexed_share(3, test_mnemonic)
        assert formatted == f"3: {test_mnemonic}"

        # Parse it back
        index, mnemonic = parse_indexed_share(formatted)
        assert index == 3
        assert mnemonic == test_mnemonic

    def test_share_indices_preserved_through_full_workflow(self) -> None:
        """Test: Share indices preserved through split -> encode -> decode -> reconstruct."""
        from src.crypto.shamir import split_secret, reconstruct_secret
        from src.crypto.bip39 import encode_share, decode_share, format_indexed_share, parse_indexed_share

        # Generate secret
        secret = secrets.token_bytes(32)
        k, n = 3, 5

        # Split into shares
        shares = split_secret(secret, k, n)

        # Verify indices are 1-based and correct
        for i in range(n):
            assert shares[i][0] == i + 1, f"Share {i} has wrong index: {shares[i][0]}"

        # Encode as indexed mnemonics (simulating init command)
        formatted_shares = []
        for share in shares:
            index = share[0]
            mnemonic = encode_share(share[1:])
            formatted = format_indexed_share(index, mnemonic)
            formatted_shares.append(formatted)

        # User provides shares out of order: 5, 2, 1
        user_input = [formatted_shares[4], formatted_shares[1], formatted_shares[0]]

        # Parse and reconstruct (simulating decrypt command)
        share_bytes = []
        for user_share in user_input:
            index, mnemonic = parse_indexed_share(user_share)
            decoded = decode_share(mnemonic)
            share_bytes.append(bytes([index]) + decoded)

        # Reconstruct should work with out-of-order shares
        reconstructed = reconstruct_secret(share_bytes)
        assert reconstructed == secret, "Failed to reconstruct with out-of-order shares"
