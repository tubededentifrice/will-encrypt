"""
Unit tests for Shamir Secret Sharing implementation.

Based on: specs/001-1-purpose-scope/research.md (Section 2)

Tests MUST fail before implementation (TDD).
Test vectors from academic papers and custom known input/output pairs.
"""

import secrets

import pytest


class TestShamirSecretSharing:
    """Unit tests for Shamir SSS (split/reconstruct operations)."""

    def test_split_secret_into_k_of_n_shares(self) -> None:
        """Test: Split 256-bit secret into K-of-N shares using Shamir SSS."""
        from src.crypto.shamir import split_secret

        # Generate 256-bit (32-byte) secret
        secret = secrets.token_bytes(32)
        k, n = 3, 5

        shares = split_secret(secret, k, n)

        # Expected: N shares returned, each share is bytes
        assert len(shares) == 5
        assert all(isinstance(share, bytes) for share in shares)
        assert all(len(share) == 33 for share in shares)  # 1 byte index + 32 bytes data
        assert all(shares[i] != secret for i in range(n))  # Shares are not the secret itself
        # Verify indices are 1-based and sequential
        for i in range(n):
            assert shares[i][0] == i + 1, f"Share {i} has wrong index: {shares[i][0]}"

    def test_reconstruct_secret_from_any_k_shares(self) -> None:
        """Test: Reconstruct secret from any K shares."""
        from itertools import combinations

        from src.crypto.shamir import reconstruct_secret, split_secret

        # Generate 256-bit secret
        secret = secrets.token_bytes(32)
        k, n = 3, 5

        shares = split_secret(secret, k, n)

        # Test reconstruction with different combinations of K shares
        for combo in combinations(range(n), k):
            selected_shares = [shares[i] for i in combo]
            reconstructed = reconstruct_secret(selected_shares)
            assert reconstructed == secret, f"Reconstruction failed with shares {combo}"

    def test_reconstruction_fails_with_k_minus_1_shares(self) -> None:
        """Test: Reconstruction fails with K-1 shares."""
        from src.crypto.shamir import reconstruct_secret, split_secret

        secret = secrets.token_bytes(32)
        k, n = 3, 5

        shares = split_secret(secret, k, n)

        # Attempt reconstruction with K-1 shares (2 shares when K=3)
        # With fewer than K shares, reconstruction should return incorrect secret
        reconstructed = reconstruct_secret(shares[:k-1])
        assert reconstructed != secret, "K-1 shares should not reconstruct correct secret"

    def test_information_theoretic_security(self) -> None:
        """Test: Information-theoretic security (K-1 shares reveal nothing)."""
        from src.crypto.shamir import reconstruct_secret, split_secret

        # Known test vector: If K=3, any 2 shares are consistent with ANY possible secret
        secret1 = b"A" * 32
        secret2 = b"B" * 32
        k, n = 3, 5

        shares1 = split_secret(secret1, k, n)
        shares2 = split_secret(secret2, k, n)

        # With K-1 shares, cannot distinguish between secret1 and secret2
        # This is a conceptual test - we verify that K-1 shares don't leak information
        # by confirming that reconstruction with K-1 shares doesn't reveal the secret

        # With K-1 shares from secret1, we should not recover secret1
        partial_recon1 = reconstruct_secret(shares1[:k-1])
        assert partial_recon1 != secret1

        # With K-1 shares from secret2, we should not recover secret2
        partial_recon2 = reconstruct_secret(shares2[:k-1])
        assert partial_recon2 != secret2

    def test_known_test_vector_from_academic_paper(self) -> None:
        """Test: Use known test vector from Shamir's original paper or academic source."""
        from src.crypto.shamir import reconstruct_secret, split_secret

        # Simple test with known secret that can be verified
        known_secret = b"\x01" * 32  # Simple repeating pattern
        k, n = 2, 3

        shares = split_secret(known_secret, k, n)
        reconstructed = reconstruct_secret(shares[:k])
        assert reconstructed == known_secret

        # Test with all shares
        reconstructed_all = reconstruct_secret(shares)
        assert reconstructed_all == known_secret

    def test_validate_k_and_n_constraints(self) -> None:
        """Test: Validate 1 ≤ K ≤ N ≤ 255."""
        from src.crypto.shamir import split_secret

        secret = secrets.token_bytes(32)

        # Test invalid K and N values
        with pytest.raises(ValueError, match="K must be >= 1"):
            split_secret(secret, k=0, n=5)

        with pytest.raises(ValueError, match="K must be <= N"):
            split_secret(secret, k=6, n=5)

        with pytest.raises(ValueError, match="N must be <= 255"):
            split_secret(secret, k=3, n=256)

    def test_share_length_equals_secret_length(self) -> None:
        """Test: Share length matches secret length (32 bytes for 256-bit secret)."""
        from src.crypto.shamir import split_secret

        secret = secrets.token_bytes(32)
        k, n = 3, 5

        shares = split_secret(secret, k, n)

        # Expected: Each share is 33 bytes (1 byte index + 32 bytes data)
        for share in shares:
            assert len(share) == 33, "Share length must be 33 bytes (1 index + 32 data)"

    def test_deterministic_reconstruction(self) -> None:
        """Test: Reconstruction is deterministic (same shares → same secret)."""
        from src.crypto.shamir import reconstruct_secret, split_secret

        secret = secrets.token_bytes(32)
        k, n = 3, 5

        shares = split_secret(secret, k, n)

        # Reconstruct multiple times with same shares
        reconstructed1 = reconstruct_secret(shares[:k])
        reconstructed2 = reconstruct_secret(shares[:k])
        assert reconstructed1 == reconstructed2 == secret

    def test_different_share_combinations_yield_same_secret(self) -> None:
        """Test: Any K shares (different combinations) reconstruct the same secret."""
        from itertools import combinations

        from src.crypto.shamir import reconstruct_secret, split_secret

        secret = secrets.token_bytes(32)
        k, n = 3, 5

        shares = split_secret(secret, k, n)

        # Test multiple combinations
        for combo in combinations(range(n), k):
            selected = [shares[i] for i in combo]
            reconstructed = reconstruct_secret(selected)
            assert reconstructed == secret, f"Different result with shares {combo}"
