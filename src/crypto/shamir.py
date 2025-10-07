"""
Shamir Secret Sharing implementation for threshold cryptography.

Based on: specs/001-1-purpose-scope/research.md (Section 2)

Implementation uses Lagrange interpolation over GF(256) for splitting
a 256-bit passphrase into K-of-N shares with information-theoretic security.
"""

import secrets
from typing import List


def _gf256_add(a: int, b: int) -> int:
    """Addition in GF(256) is XOR."""
    return a ^ b


def _gf256_sub(a: int, b: int) -> int:
    """Subtraction in GF(256) is also XOR."""
    return a ^ b


def _gf256_mul(a: int, b: int) -> int:
    """Multiplication in GF(256) using log/antilog tables."""
    if a == 0 or b == 0:
        return 0

    # GF(256) with primitive polynomial x^8 + x^4 + x^3 + x + 1
    LOG_TABLE = _get_log_table()
    EXP_TABLE = _get_exp_table()

    log_result = (LOG_TABLE[a] + LOG_TABLE[b]) % 255
    return EXP_TABLE[log_result]


def _gf256_div(a: int, b: int) -> int:
    """Division in GF(256)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0

    LOG_TABLE = _get_log_table()
    EXP_TABLE = _get_exp_table()

    log_result = (LOG_TABLE[a] - LOG_TABLE[b]) % 255
    return EXP_TABLE[log_result]


def _get_log_table() -> List[int]:
    """Generate logarithm table for GF(256)."""
    # Cache the table
    if not hasattr(_get_log_table, 'cache'):
        log = [0] * 256
        exp = [0] * 256
        x = 1
        for i in range(255):
            exp[i] = x
            log[x] = i
            # Multiply by generator (0x03) with primitive polynomial
            x ^= (x << 1)
            if x & 0x100:
                x ^= 0x11B  # x^8 + x^4 + x^3 + x + 1
        exp[255] = exp[0]
        _get_log_table.cache = log
        _get_exp_table.cache = exp
    return _get_log_table.cache


def _get_exp_table() -> List[int]:
    """Generate exponentiation table for GF(256)."""
    if not hasattr(_get_exp_table, 'cache'):
        _get_log_table()  # Initialize both tables
    return _get_exp_table.cache


def _eval_polynomial(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at x using Horner's method in GF(256)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gf256_add(_gf256_mul(result, x), coeff)
    return result


def _lagrange_interpolate(shares: List[tuple], x: int = 0) -> int:
    """
    Lagrange interpolation in GF(256) to recover polynomial value at x.

    Args:
        shares: List of (x_i, y_i) tuples
        x: Point to evaluate at (default 0 for secret recovery)

    Returns:
        Interpolated value at x
    """
    if not shares:
        raise ValueError("No shares provided")

    result = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1

        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = _gf256_mul(numerator, _gf256_sub(x, xj))
                denominator = _gf256_mul(denominator, _gf256_sub(xi, xj))

        if denominator == 0:
            raise ValueError("Duplicate share indices detected")

        lagrange_term = _gf256_mul(yi, _gf256_div(numerator, denominator))
        result = _gf256_add(result, lagrange_term)

    return result


def split_secret(secret: bytes, k: int, n: int) -> List[bytes]:
    """
    Split secret into K-of-N shares using Shamir Secret Sharing.

    Args:
        secret: 32-byte (256-bit) secret to split
        k: Threshold (minimum shares needed to reconstruct)
        n: Total number of shares to generate

    Returns:
        List of n shares, each 33 bytes (1-byte index + 32-byte data)

    Raises:
        ValueError: If k, n constraints violated or secret wrong size
    """
    # Validate constraints
    if not isinstance(secret, bytes):
        raise TypeError("Secret must be bytes")

    if len(secret) != 32:
        raise ValueError("Secret must be exactly 32 bytes (256 bits)")

    if k < 1:
        raise ValueError("K must be >= 1")

    if k > n:
        raise ValueError("K must be <= N")

    if n > 255:
        raise ValueError("N must be <= 255")

    # Generate shares byte by byte
    shares = [bytearray() for _ in range(n)]

    # Process each byte of the secret independently
    for byte_idx in range(32):
        secret_byte = secret[byte_idx]

        # Generate random polynomial coefficients: a_0 = secret_byte, a_1..a_{k-1} random
        coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(k - 1)]

        # Evaluate polynomial at x = 1, 2, ..., n
        for share_idx in range(n):
            x = share_idx + 1  # x must be non-zero (1-based indexing)
            y = _eval_polynomial(coeffs, x)
            shares[share_idx].append(y)

    # Prepend share index to each share (1-based)
    result = []
    for share_idx in range(n):
        indexed_share = bytes([share_idx + 1]) + bytes(shares[share_idx])
        result.append(indexed_share)

    return result


def reconstruct_secret(shares: List[bytes]) -> bytes:
    """
    Reconstruct secret from K or more shares using Lagrange interpolation.

    Args:
        shares: List of shares (each 33 bytes: 1-byte index + 32-byte data)

    Returns:
        32-byte reconstructed secret

    Raises:
        ValueError: If insufficient shares or invalid format
    """
    if not shares:
        raise ValueError("No shares provided")

    # Validate share format
    for share in shares:
        if not isinstance(share, bytes):
            raise TypeError("All shares must be bytes")
        if len(share) != 33:
            raise ValueError(f"Each share must be 33 bytes, got {len(share)}")

    # Extract indices and data
    indexed_shares = []
    for share in shares:
        index = share[0]
        if index < 1 or index > 255:
            raise ValueError(f"Share index must be 1-255, got {index}")
        data = share[1:]
        indexed_shares.append((index, data))

    # Check for duplicate indices
    indices = [idx for idx, _ in indexed_shares]
    if len(indices) != len(set(indices)):
        raise ValueError("Duplicate share indices detected")

    # Reconstruct secret byte by byte
    secret = bytearray()

    for byte_idx in range(32):
        # Collect (x, y) pairs for this byte position
        points = []
        for index, data in indexed_shares:
            x = index
            y = data[byte_idx]
            points.append((x, y))

        # Use Lagrange interpolation to find polynomial value at x=0 (the secret)
        secret_byte = _lagrange_interpolate(points, x=0)
        secret.append(secret_byte)

    return bytes(secret)
