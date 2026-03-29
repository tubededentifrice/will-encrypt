"""Backward compatibility tests for versioned vault artifacts.

Parametrized over all v* directories under tests/artifacts/.
Each test copies the artifact to tmp_path before any mutation.
"""
from __future__ import annotations

import itertools
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"


def _discover_versioned_artifacts() -> list[Path]:
    """Find all v* artifact directories containing vault.yaml + metadata.json."""
    if not ARTIFACTS_DIR.is_dir():
        return []
    return sorted(
        d
        for d in ARTIFACTS_DIR.iterdir()
        if d.is_dir()
        and d.name.startswith("v")
        and (d / "vault.yaml").exists()
        and (d / "metadata.json").exists()
    )


@dataclass
class ArtifactFixture:
    """Parsed artifact ready for testing."""

    vault_path: Path
    shares: list[str]
    k: int
    n: int
    metadata: dict[str, Any]
    messages: list[dict[str, Any]] = field(default_factory=list)


def _load_artifact(artifact_dir: Path, tmp_path: Path) -> ArtifactFixture:
    """Copy artifact into tmp_path and parse metadata."""
    dest = tmp_path / artifact_dir.name
    shutil.copytree(artifact_dir, dest)

    with (dest / "shares.json").open(encoding="utf-8") as f:
        share_data = json.load(f)

    with (dest / "metadata.json").open(encoding="utf-8") as f:
        metadata = json.load(f)

    return ArtifactFixture(
        vault_path=dest / "vault.yaml",
        shares=share_data["shares"],
        k=share_data["k"],
        n=share_data["n"],
        metadata=metadata,
        messages=metadata.get("messages", []),
    )


# ---------------------------------------------------------------------------
# Parametrized fixture
# ---------------------------------------------------------------------------

_VERSIONED = _discover_versioned_artifacts()


@pytest.fixture(params=_VERSIONED, ids=[d.name for d in _VERSIONED])
def artifact(request: pytest.FixtureRequest, tmp_path: Path) -> ArtifactFixture:
    """Yield a copy of each versioned artifact for isolated testing."""
    return _load_artifact(request.param, tmp_path)


# ---------------------------------------------------------------------------
# Sentinel: at least one artifact must exist
# ---------------------------------------------------------------------------


def test_versioned_artifacts_exist() -> None:
    """Guard against accidental deletion of all versioned artifacts."""
    assert len(_VERSIONED) >= 1, (
        f"No versioned artifacts found under {ARTIFACTS_DIR}. "
        "Run generate_artifact.py to create them."
    )


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------


class TestBackwardCompatDecrypt:
    """Verify old vaults can be decrypted with the current code."""

    def test_decrypt_all_messages(
        self,
        artifact: ArtifactFixture,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Decrypt with K shares and verify every message plaintext."""
        from src.main import main

        shares = artifact.shares[: artifact.k]
        argv = [
            "will-encrypt", "decrypt",
            "--vault", str(artifact.vault_path),
            "--shares", *shares,
        ]
        monkeypatch.setattr(sys, "argv", argv)

        rc = main()
        captured = capsys.readouterr()

        assert rc == 0, f"Decrypt failed (rc={rc}): {captured.err}"
        for msg in artifact.messages:
            assert msg["title"] in captured.out, f"Missing title: {msg['title']}"
            assert msg["plaintext"] in captured.out, f"Missing plaintext for msg {msg['id']}"

    def test_decrypt_with_different_share_combos(
        self,
        artifact: ArtifactFixture,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Any K-sized subset of shares should decrypt successfully."""
        from src.main import main

        # Test up to 3 distinct combinations to keep runtime bounded
        combos = list(itertools.combinations(artifact.shares, artifact.k))
        for combo in combos[:3]:
            argv = [
                "will-encrypt", "decrypt",
                "--vault", str(artifact.vault_path),
                "--shares", *list(combo),
            ]
            monkeypatch.setattr(sys, "argv", argv)

            rc = main()
            captured = capsys.readouterr()
            assert rc == 0, f"Decrypt failed with combo {combo}: {captured.err}"


# ---------------------------------------------------------------------------
# Encrypt into old vault
# ---------------------------------------------------------------------------


class TestBackwardCompatEncrypt:
    """Verify new messages can be encrypted into old vaults."""

    def test_encrypt_new_message(
        self,
        artifact: ArtifactFixture,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Encrypt a new message, then decrypt ALL messages (old + new)."""
        from src.cli.encrypt import encrypt_command
        from src.main import main

        new_title = "New Compat Test Message"
        new_plaintext = "Freshly encrypted into an old vault."

        rc = encrypt_command(
            vault_path=str(artifact.vault_path),
            title=new_title,
            message_text=new_plaintext,
        )
        assert rc == 0, "Encrypt into old vault failed"

        # Decrypt all messages including the new one
        shares = artifact.shares[: artifact.k]
        argv = [
            "will-encrypt", "decrypt",
            "--vault", str(artifact.vault_path),
            "--shares", *shares,
        ]
        monkeypatch.setattr(sys, "argv", argv)

        rc = main()
        captured = capsys.readouterr()

        assert rc == 0, f"Decrypt after encrypt failed: {captured.err}"
        # Old messages still present
        for msg in artifact.messages:
            assert msg["plaintext"] in captured.out
        # New message present
        assert new_title in captured.out
        assert new_plaintext in captured.out

    def test_validate_after_encrypt(
        self,
        artifact: ArtifactFixture,
    ) -> None:
        """Vault integrity holds after encrypting a new message."""
        from src.cli.encrypt import encrypt_command
        from src.cli.validate import validate_command

        rc = encrypt_command(
            vault_path=str(artifact.vault_path),
            title="Integrity Check Message",
            message_text="Testing post-encrypt validation.",
        )
        assert rc == 0

        rc = validate_command(str(artifact.vault_path))
        assert rc == 0, "Validate failed after encrypting into old vault"


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class TestBackwardCompatList:
    """Verify list command works with old vaults."""

    def test_list_messages(
        self,
        artifact: ArtifactFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """List output contains all expected message titles."""
        from src.cli.list import list_command

        rc = list_command(vault_path=str(artifact.vault_path))
        captured = capsys.readouterr()

        assert rc == 0, f"List failed: {captured.err}"
        for msg in artifact.messages:
            assert msg["title"] in captured.out, f"Missing title in list: {msg['title']}"

    def test_list_json_format(
        self,
        artifact: ArtifactFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """JSON list output has correct message count."""
        from src.cli.list import list_command

        rc = list_command(vault_path=str(artifact.vault_path), output_format="json")
        captured = capsys.readouterr()

        assert rc == 0
        data = json.loads(captured.out)
        assert len(data) == len(artifact.messages)


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


class TestBackwardCompatValidate:
    """Verify validate command works with old vaults."""

    def test_validate_vault(self, artifact: ArtifactFixture) -> None:
        """Unmodified artifact passes validation."""
        from src.cli.validate import validate_command

        rc = validate_command(str(artifact.vault_path))
        assert rc == 0, "Validate failed on unmodified artifact"


# ---------------------------------------------------------------------------
# Edit
# ---------------------------------------------------------------------------


class TestBackwardCompatEdit:
    """Verify edit command works with old vaults."""

    def test_edit_message_title(
        self,
        artifact: ArtifactFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Edit first message title, verify via list.

        Note: decrypt of the edited message will fail because the title is used
        as AAD in AES-256-GCM — this is correct security behavior.
        """
        from src.cli.edit import edit_command
        from src.cli.list import list_command

        first_msg = artifact.messages[0]
        new_title = "Edited Compat Title"

        rc = edit_command(
            vault_path=str(artifact.vault_path),
            message_id=first_msg["id"],
            new_title=new_title,
        )
        assert rc == 0, "Edit failed on old vault"

        rc = list_command(vault_path=str(artifact.vault_path))
        captured = capsys.readouterr()
        assert rc == 0
        assert new_title in captured.out

    def test_validate_after_edit(self, artifact: ArtifactFixture) -> None:
        """Vault integrity holds after editing a message title."""
        from src.cli.edit import edit_command
        from src.cli.validate import validate_command

        first_msg = artifact.messages[0]
        edit_command(
            vault_path=str(artifact.vault_path),
            message_id=first_msg["id"],
            new_title="Post-Edit Validation",
        )

        rc = validate_command(str(artifact.vault_path))
        assert rc == 0, "Validate failed after edit on old vault"


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


class TestBackwardCompatDelete:
    """Verify delete command works with old vaults."""

    def test_delete_message(
        self,
        artifact: ArtifactFixture,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Delete one message, verify count decreases, decrypt remaining."""
        if len(artifact.messages) < 2:
            pytest.skip("Need >= 2 messages to test delete without emptying vault")

        from src.cli.delete import delete_command
        from src.main import main

        # Delete the last message
        last_msg = artifact.messages[-1]
        remaining = artifact.messages[:-1]

        rc = delete_command(
            vault_path=str(artifact.vault_path),
            message_id=last_msg["id"],
        )
        assert rc == 0, "Delete failed on old vault"

        # Decrypt remaining messages
        shares = artifact.shares[: artifact.k]
        argv = [
            "will-encrypt", "decrypt",
            "--vault", str(artifact.vault_path),
            "--shares", *shares,
        ]
        monkeypatch.setattr(sys, "argv", argv)

        rc = main()
        captured = capsys.readouterr()

        assert rc == 0, f"Decrypt after delete failed: {captured.err}"
        for msg in remaining:
            assert msg["plaintext"] in captured.out
        # Deleted message should not appear
        assert last_msg["plaintext"] not in captured.out

    def test_validate_after_delete(
        self,
        artifact: ArtifactFixture,
    ) -> None:
        """Vault integrity holds after deleting a message."""
        if len(artifact.messages) < 2:
            pytest.skip("Need >= 2 messages to test delete")

        from src.cli.delete import delete_command
        from src.cli.validate import validate_command

        last_msg = artifact.messages[-1]
        delete_command(
            vault_path=str(artifact.vault_path),
            message_id=last_msg["id"],
        )

        rc = validate_command(str(artifact.vault_path))
        assert rc == 0, "Validate failed after delete on old vault"
