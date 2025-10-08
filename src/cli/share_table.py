"""Utility helpers for presenting shares in tabular form."""

from __future__ import annotations

from typing import Sequence

from src.crypto.bip39 import format_indexed_share


def render_share_table(indexed_shares: Sequence[tuple[int, str]]) -> str:
    """Render indexed shares as an ASCII table for easy copying.

    Args:
        indexed_shares: Sequence of tuples containing the share index and mnemonic.

    Returns:
        A string representation of the numbered share table. Returns an empty string
        when no shares are provided.
    """

    if not indexed_shares:
        return ""

    rendered_shares = [format_indexed_share(index, mnemonic) for index, mnemonic in indexed_shares]

    row_numbers = [str(row_number) for row_number in range(1, len(rendered_shares) + 1)]

    number_header = "#"
    share_header = "Indexed Share"

    number_width = max(len(number_header), max(len(number) for number in row_numbers))
    share_width = max(len(share_header), max(len(share) for share in rendered_shares))

    horizontal = "+" + "-" * (number_width + 2) + "+" + "-" * (share_width + 2) + "+"
    header = f"| {number_header.ljust(number_width)} | {share_header.ljust(share_width)} |"

    data_rows = [
        f"| {row_numbers[i].ljust(number_width)} | {rendered_shares[i].ljust(share_width)} |"
        for i in range(len(rendered_shares))
    ]

    table_lines = [horizontal, header, horizontal, *data_rows, horizontal]

    return "\n".join(table_lines)

