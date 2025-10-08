"""
Unit tests for BIP39 mnemonic encoding/decoding.

Based on: specs/001-1-purpose-scope/research.md (Section 3)

Tests MUST fail before implementation (TDD).
Test vectors from BIP39 specification.
"""

import secrets

import pytest


class TestBIP39Encoding:
    """Unit tests for BIP39 mnemonic operations."""

    def test_encode_32_byte_share_to_24_word_mnemonic(self) -> None:
        """Test: Encode 32-byte share → 24-word BIP39 mnemonic."""
        from src.crypto.bip39 import encode_share

        # Generate 32-byte share (256 bits)
        share = secrets.token_bytes(32)

        mnemonic = encode_share(share)

        # Expected: 24-word mnemonic (space-separated)
        assert isinstance(mnemonic, str)
        assert len(mnemonic.split()) == 24

    def test_encode_share_type_validation(self) -> None:
        """Test: encode_share rejects non-bytes input."""
        from src.crypto.bip39 import encode_share

        with pytest.raises(TypeError, match="Share must be bytes"):
            encode_share("not-bytes")  # type: ignore[arg-type]

    def test_encode_share_length_validation(self) -> None:
        """Test: encode_share enforces 32-byte minimum."""
        from src.crypto.bip39 import encode_share

        with pytest.raises(ValueError, match="Share must be at least 32 bytes"):
            encode_share(b"short")


    def test_decode_24_word_mnemonic_to_32_byte_share(self) -> None:
        """Test: Decode 24-word mnemonic → 32-byte share."""
        from src.crypto.bip39 import decode_share

        # Known BIP39 mnemonic (24 words with valid checksum)
        known_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        share = decode_share(known_mnemonic)

        # Expected: 32-byte share
        assert isinstance(share, bytes)
        assert len(share) == 32

    def test_decode_share_type_validation(self) -> None:
        """Test: decode_share rejects non-string input."""
        from src.crypto.bip39 import decode_share

        with pytest.raises(TypeError, match="Mnemonic must be a string"):
            decode_share(12345)  # type: ignore[arg-type]

    def test_decode_share_valid_but_wrong_length(self) -> None:
        """Test: decode_share raises when entropy length is not 32 bytes."""
        from src.crypto.bip39 import decode_share

        twelve_word_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"

        with pytest.raises(ValueError, match="Decoded share must be 32 bytes"):
            decode_share(twelve_word_mnemonic)


    def test_checksum_validation_valid_mnemonic(self) -> None:
        """Test: Checksum validation (valid checksum)."""
        from src.crypto.bip39 import validate_checksum

        # Valid BIP39 mnemonic with correct checksum
        valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        is_valid = validate_checksum(valid_mnemonic)

        # Expected: True
        assert is_valid is True


    def test_checksum_validation_invalid_mnemonic(self) -> None:
        """Test: Checksum validation (invalid checksum detected)."""
        from src.crypto.bip39 import validate_checksum

        # Invalid BIP39 mnemonic (last word modified to break checksum)
        invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"  # 'zoo' breaks checksum

        is_valid = validate_checksum(invalid_mnemonic)

        # Expected: False
        assert is_valid is False

    def test_validate_checksum_non_string_returns_false(self) -> None:
        """Test: validate_checksum returns False for non-string input."""
        from src.crypto.bip39 import validate_checksum

        assert validate_checksum(None) is False


    def test_invalid_word_rejection(self) -> None:
        """Test: Invalid word rejection (not in BIP39 wordlist)."""
        from src.crypto.bip39 import decode_share

        # Mnemonic with word not in BIP39 wordlist
        invalid_mnemonic = "abandon abandon abandon notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # Expected: ValueError for invalid word
        with pytest.raises(ValueError, match="Invalid mnemonic"):
            decode_share(invalid_mnemonic)


    def test_bip39_spec_test_vector_1(self) -> None:
        """Test: BIP39 specification test vector 1."""
        from src.crypto.bip39 import encode_share, decode_share

        # Test vector from BIP39 spec
        entropy = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        mnemonic = encode_share(entropy)
        assert mnemonic == expected_mnemonic

        decoded = decode_share(expected_mnemonic)
        assert decoded == entropy


    def test_bip39_spec_test_vector_2(self) -> None:
        """Test: BIP39 specification test vector 2."""
        from src.crypto.bip39 import encode_share, decode_share

        # Test vector from BIP39 spec
        entropy = bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        expected_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"

        mnemonic = encode_share(entropy)
        assert mnemonic == expected_mnemonic

        decoded = decode_share(expected_mnemonic)
        assert decoded == entropy


    def test_encode_decode_roundtrip(self) -> None:
        """Test: Encode-decode roundtrip (original share recovered)."""
        from src.crypto.bip39 import encode_share, decode_share

        # Generate random 32-byte share
        original_share = secrets.token_bytes(32)

        # Encode to mnemonic
        mnemonic = encode_share(original_share)

        # Decode back to share
        decoded_share = decode_share(mnemonic)

        # Expected: decoded_share == original_share
        assert decoded_share == original_share


    def test_mnemonic_case_insensitive(self) -> None:
        """Test: Mnemonic decoding is case-insensitive."""
        from src.crypto.bip39 import decode_share

        # Valid BIP39 mnemonic in lowercase
        lowercase_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # Same mnemonic in uppercase
        uppercase_mnemonic = lowercase_mnemonic.upper()

        decode_lower = decode_share(lowercase_mnemonic)
        decode_upper = decode_share(uppercase_mnemonic)

        # Expected: Both decode to same share
        assert decode_lower == decode_upper


    def test_extra_whitespace_handling(self) -> None:
        """Test: Extra whitespace in mnemonic is handled correctly."""
        from src.crypto.bip39 import decode_share

        # Valid BIP39 mnemonic with extra spaces
        mnemonic_with_spaces = "  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  art  "

        share = decode_share(mnemonic_with_spaces)

        # Expected: Decodes correctly (whitespace normalized)
        assert isinstance(share, bytes)
        assert len(share) == 32


    def test_four_character_prefix_expansion_decode(self) -> None:
        """Test: 4-character word prefixes expand to full words (decode)."""
        from src.crypto.bip39 import decode_share

        # Full BIP39 mnemonic
        full_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # Same mnemonic with 4-char prefixes
        prefix_mnemonic = "aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban art"

        share_full = decode_share(full_mnemonic)
        share_prefix = decode_share(prefix_mnemonic)

        # Expected: Both decode to same share
        assert share_full == share_prefix
        assert len(share_prefix) == 32


    def test_four_character_prefix_expansion_validate(self) -> None:
        """Test: 4-character word prefixes expand to full words (validate)."""
        from src.crypto.bip39 import validate_checksum

        # Valid BIP39 mnemonic with 4-char prefixes
        prefix_mnemonic = "aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban art"

        is_valid = validate_checksum(prefix_mnemonic)

        # Expected: True (prefixes expand correctly)
        assert is_valid is True


    def test_four_character_prefix_invalid_checksum(self) -> None:
        """Test: 4-character prefixes with invalid checksum detected."""
        from src.crypto.bip39 import validate_checksum

        # Invalid BIP39 mnemonic with 4-char prefixes (wrong last word)
        invalid_prefix_mnemonic = "aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban zoo"

        is_valid = validate_checksum(invalid_prefix_mnemonic)

        # Expected: False (checksum fails even with prefixes)
        assert is_valid is False


    def test_mixed_prefix_and_full_words(self) -> None:
        """Test: Mix of 4-char prefixes and full words works correctly."""
        from src.crypto.bip39 import decode_share

        # Full BIP39 mnemonic
        full_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # Mixed prefixes and full words
        mixed_mnemonic = "aban abandon aban abandon aban aban abandon aban aban abandon aban aban abandon aban aban abandon aban aban abandon aban aban abandon aban art"

        share_full = decode_share(full_mnemonic)
        share_mixed = decode_share(mixed_mnemonic)

        # Expected: Both decode to same share
        assert share_full == share_mixed


class TestIndexedShares:
    """Unit tests for indexed share formatting and parsing."""

    def test_format_indexed_share(self) -> None:
        """Test: Format share with index prefix."""
        from src.crypto.bip39 import format_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        formatted = format_indexed_share(1, mnemonic)

        assert formatted == f"1: {mnemonic}"

    def test_format_indexed_share_validates_index_range(self) -> None:
        """Test: format_indexed_share rejects invalid indices."""
        from src.crypto.bip39 import format_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # Index too low
        with pytest.raises(ValueError, match="Share index must be 1-255"):
            format_indexed_share(0, mnemonic)

        # Index too high
        with pytest.raises(ValueError, match="Share index must be 1-255"):
            format_indexed_share(256, mnemonic)

    def test_parse_indexed_share_with_number_prefix(self) -> None:
        """Test: Parse share with 'N:' format."""
        from src.crypto.bip39 import parse_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        indexed_str = f"1: {mnemonic}"

        index, parsed_mnemonic = parse_indexed_share(indexed_str)

        assert index == 1
        assert parsed_mnemonic == mnemonic

    def test_parse_indexed_share_with_share_label(self) -> None:
        """Test: Parse share with 'Share N:' format."""
        from src.crypto.bip39 import parse_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        indexed_str = f"Share 5: {mnemonic}"

        index, parsed_mnemonic = parse_indexed_share(indexed_str)

        assert index == 5
        assert parsed_mnemonic == mnemonic

    def test_parse_indexed_share_without_index(self) -> None:
        """Test: Parse share without index prefix returns None."""
        from src.crypto.bip39 import parse_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        index, parsed_mnemonic = parse_indexed_share(mnemonic)

        assert index is None
        assert parsed_mnemonic == mnemonic

    def test_parse_indexed_share_handles_whitespace(self) -> None:
        """Test: Parse share handles extra whitespace."""
        from src.crypto.bip39 import parse_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        indexed_str = f"  3:   {mnemonic}  "

        index, parsed_mnemonic = parse_indexed_share(indexed_str)

        assert index == 3
        assert parsed_mnemonic == mnemonic

    def test_parse_indexed_share_large_index(self) -> None:
        """Test: Parse share with large valid index (255)."""
        from src.crypto.bip39 import parse_indexed_share

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        indexed_str = f"255: {mnemonic}"

        index, parsed_mnemonic = parse_indexed_share(indexed_str)

        assert index == 255
        assert parsed_mnemonic == mnemonic
