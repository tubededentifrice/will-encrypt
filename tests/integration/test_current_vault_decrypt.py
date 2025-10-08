"""Integration test for decrypting current-version vault artifacts."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from src.main import main


def test_decrypt_current_vault_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure decrypt command handles vault produced by current release."""
    artifacts_dir = Path(__file__).resolve().parent.parent / "artifacts" / "current_vault"
    vault_source = artifacts_dir / "current_vault.yaml"
    shares_path = artifacts_dir / "shares.json"

    assert vault_source.exists(), "Vault artifact must exist"
    assert shares_path.exists(), "Share metadata missing"

    vault_copy = tmp_path / "current_vault.yaml"
    shutil.copy(vault_source, vault_copy)

    with shares_path.open(encoding="utf-8") as fp:
        share_data = json.load(fp)

    shares = share_data["shares"][: share_data["k"]]

    argv = [
        "will-encrypt",
        "decrypt",
        "--vault",
        str(vault_copy),
        "--shares",
        *shares,
    ]

    monkeypatch.setattr(sys, "argv", argv)

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0, f"Decrypt command failed: {captured.err}"
    assert "E2E Test Message" in captured.out
    assert "This is an end-to-end test message." in captured.out
