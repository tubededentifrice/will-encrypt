"""Unit tests for passphrase generation and derivation."""

import os

import pytest

from src.crypto.passphrase import derive_key, generate_passphrase, generate_salt


class TestPassphraseUtilities:
    """Verify entropy helpers enforce security constraints."""

    def test_generate_passphrase_returns_32_random_bytes(self) -> None:
        first = generate_passphrase()
        second = generate_passphrase()
        assert isinstance(first, bytes) and len(first) == 32
        assert isinstance(second, bytes) and len(second) == 32
        # Extremely low probability of equality; guard against deterministic bug.
        assert first != second

    def test_generate_salt_returns_32_bytes(self) -> None:
        salt = generate_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 32

    def test_derive_key_success(self) -> None:
        passphrase = b"\x01" * 32
        salt = b"\x02" * 32
        key = derive_key(passphrase, salt)
        assert isinstance(key, bytes)
        assert len(key) == 32
        # Deterministic for identical inputs.
        assert key == derive_key(passphrase, salt)

    def test_derive_key_requires_byte_inputs(self) -> None:
        salt = os.urandom(32)
        with pytest.raises(TypeError, match="Passphrase must be bytes"):
            derive_key("not-bytes", salt)
        with pytest.raises(TypeError, match="Salt must be bytes"):
            derive_key(os.urandom(32), "not-bytes")

    def test_derive_key_validates_lengths(self) -> None:
        salt = os.urandom(32)
        with pytest.raises(ValueError, match="Passphrase must be exactly 32 bytes"):
            derive_key(b"short", salt)
        with pytest.raises(ValueError, match="Salt must be exactly 32 bytes"):
            derive_key(os.urandom(32), b"short")

    def test_derive_key_enforces_iteration_floor(self) -> None:
        passphrase = os.urandom(32)
        salt = os.urandom(32)
        with pytest.raises(ValueError, match="Iterations must be >= 600,000"):
            derive_key(passphrase, salt, iterations=1000)
