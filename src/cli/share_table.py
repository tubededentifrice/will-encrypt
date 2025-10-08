"""Utility helpers for presenting shares in tabular form."""

from __future__ import annotations

from typing import Sequence


def render_share_table(indexed_shares: Sequence[tuple[int, str]]) -> str:
    """Render indexed shares as individual numbered tables for easy copying.

    Args:
        indexed_shares: Sequence of tuples containing the share index and mnemonic.

    Returns:
        A string representation of individual share tables, each showing the 24 words
        numbered in cells. Returns an empty string when no shares are provided.
    """

    if not indexed_shares:
        return ""

    tables = []
    total_shares = len(indexed_shares)

    for share_idx, (share_number, mnemonic) in enumerate(indexed_shares, 1):
        # Split mnemonic into 24 words
        words = mnemonic.split()
        if len(words) != 24:
            # Fallback for invalid mnemonics
            continue

        # Create table header
        table_lines = []
        table_lines.append(f"Share {share_number}/{total_shares}:")
        table_lines.append("")

        # Create a 6x4 grid (6 rows, 4 columns) for the 24 words
        # Column widths: word number (2 chars) + word (longest word + padding)
        max_word_len = max(len(word) for word in words)
        col_width = max(max_word_len + 5, 15)  # At least 15 chars per column

        # Cell content width (with padding on both sides)
        cell_width = col_width + 2  # +2 for spaces around content

        # Build header with proper alignment
        horizontal = "+" + "+".join(["-" * cell_width] * 4) + "+"
        table_lines.append(horizontal)

        # Build rows (6 rows of 4 words each)
        for row in range(6):
            row_cells = []
            for col in range(4):
                word_idx = row * 4 + col
                if word_idx < len(words):
                    cell_content = f"{word_idx + 1:2d}. {words[word_idx]}"
                    # Pad with spaces: " content "
                    row_cells.append(" " + cell_content.ljust(col_width) + " ")
                else:
                    row_cells.append(" " * cell_width)

            table_lines.append("|" + "|".join(row_cells) + "|")
            table_lines.append(horizontal)

        tables.append("\n".join(table_lines))

    return "\n\n".join(tables)

