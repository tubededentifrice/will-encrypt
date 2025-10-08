"""
Integration tests for share index recovery during import.

Based on: specs/001-1-purpose-scope/contracts/init.schema.yaml (share recovery)
"""

import io
import os
import sys
from pathlib import Path

import pytest
import yaml

from tests.test_helpers import extract_shares_from_output


class TestShareImportMatching:
    """Validate that init auto-detects share indices using manifest fingerprints."""

    def test_init_import_missing_index_auto_matches(self, tmp_path: Path) -> None:
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"

        # First initialization to capture shares and establish manifest data.
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result_initial = init_command(
                k=3,
                n=5,
                vault_path=str(vault_path),
                import_shares=[],
            )
            initial_output = sys.stdout.getvalue()
        finally:
            sys.stdout = original_stdout

        assert result_initial == 0, "Initial init should succeed"

        shares = extract_shares_from_output(initial_output)
        assert len(shares) >= 3, "Need at least three shares for threshold recovery"

        mnemonics = [entry.split(":", 1)[1].strip() for entry in shares]

        # Lose the numeric prefix for the first share to simulate unlabeled input.
        import_shares = [mnemonics[0], mnemonics[1], mnemonics[2]]

        # Second init overwrites existing vault using the unlabeled share.
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result_second = init_command(
                k=3,
                n=5,
                vault_path=str(vault_path),
                force=True,
                import_shares=import_shares,
            )
            second_output = sys.stdout.getvalue()
        finally:
            sys.stdout = original_stdout

        assert result_second == 0, "Init with import should succeed via auto-matching"
        assert "Auto-detected share index" in second_output
        assert "Enter share number" not in second_output

        # Manifest of the new vault should still contain share fingerprints.
        with open(vault_path) as f:
            vault = yaml.safe_load(f)

        fingerprints = vault["manifest"].get("share_fingerprints", [])
        assert len(fingerprints) == 5, "Share fingerprints persist across reinitialization"

    def test_init_source_vault_flag_overrides_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.cli.init import init_command

        primary_vault = tmp_path / "primary.yaml"
        alternate_vault = tmp_path / "alternate.yaml"

        # Create a reference vault whose manifest we will reuse later.
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result_initial = init_command(
                k=3,
                n=5,
                vault_path=str(primary_vault),
                import_shares=[],
            )
            initial_output = sys.stdout.getvalue()
        finally:
            sys.stdout = original_stdout

        assert result_initial == 0, "Initial init should succeed"

        shares = extract_shares_from_output(initial_output)
        mnemonics = [entry.split(":", 1)[1].strip() for entry in shares]

        # Prepare mixed inputs: first share loses its prefix.
        import_shares = [mnemonics[0], mnemonics[1], mnemonics[2]]

        # Environment variable mistakenly points somewhere else; flag must win.
        monkeypatch.setenv("WILL_ENCRYPT_SOURCE_VAULT", str(alternate_vault))

        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result_second = init_command(
                k=3,
                n=5,
                vault_path=str(alternate_vault),
                force=True,
                import_shares=import_shares,
                source_vault=str(primary_vault),
            )
            second_output = sys.stdout.getvalue()
        finally:
            sys.stdout = original_stdout

        assert result_second == 0, "Init should succeed when source vault provided explicitly"
        assert "Auto-detected share index" in second_output

        # Without the override, the env path would have caused failure. Ensure env was untouched.
        assert os.environ.get("WILL_ENCRYPT_SOURCE_VAULT") == str(alternate_vault)
