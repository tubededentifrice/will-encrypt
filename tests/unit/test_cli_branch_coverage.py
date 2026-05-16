"""Focused branch coverage tests for CLI commands."""

import base64
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


def input_sequence(values: list[str | BaseException]) -> Callable[[str], str]:
    """Return an input replacement that can also raise queued exceptions."""
    answers = iter(values)

    def fake_input(_prompt: str = "") -> str:
        value = next(answers)
        if isinstance(value, BaseException):
            raise value
        return value

    return fake_input


def fake_vault(manifest: Any) -> Any:
    """Build a minimal vault object for command branch tests."""
    encoded = base64.b64encode(b"value").decode()
    return SimpleNamespace(
        manifest=manifest,
        keys=SimpleNamespace(
            rsa_public="public",
            rsa_private_encrypted=encoded,
            kyber_public=encoded,
            kyber_private_encrypted=encoded,
            kdf_salt=encoded,
            kdf_iterations=1,
        ),
        messages=[],
    )


class TestEncryptCommandBranches:
    """Branch tests for encrypt_command."""

    def test_interactive_title_rejects_empty_input(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Interactive title prompt rejects blank titles."""
        from src.cli.encrypt import encrypt_command

        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr("builtins.input", input_sequence([""]))

        assert encrypt_command(str(vault_path)) == 1

    def test_interactive_title_handles_keyboard_interrupt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Interactive title prompt handles cancellation."""
        from src.cli.encrypt import encrypt_command

        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr("builtins.input", input_sequence([KeyboardInterrupt()]))

        assert encrypt_command(str(vault_path)) == 1

    def test_editor_cancel_and_empty_message_are_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Interactive editor cancellation and blank content are rejected."""
        from src.cli import encrypt

        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")

        monkeypatch.setattr(encrypt, "get_message_text", lambda _title: None)
        assert encrypt.encrypt_command(str(vault_path), title="Title") == 1

        monkeypatch.setattr(encrypt, "get_message_text", lambda _title: "   ")
        assert encrypt.encrypt_command(str(vault_path), title="Title") == 1

    def test_basic_input_fallback_encrypts_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Secure-editor failure falls back to multi-line basic input."""
        from src.cli import encrypt
        from tests.test_helpers import create_test_vault, get_vault_messages

        vault_path, _shares = create_test_vault(tmp_path, k=3, n=5)
        monkeypatch.setattr(
            encrypt, "get_message_text", lambda _title: (_ for _ in ()).throw(RuntimeError())
        )
        monkeypatch.setattr("builtins.input", input_sequence(["line one", "line two", EOFError()]))

        result = encrypt.encrypt_command(str(vault_path), title="Fallback")

        assert result == 0
        messages = get_vault_messages(vault_path)
        assert messages[0]["title"] == "Fallback"
        assert messages[0]["size_bytes"] == len("line one\nline two")


class TestDecryptCommandBranches:
    """Branch tests for decrypt_command."""

    def test_missing_manifest_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Decrypt rejects vaults without a manifest."""
        from src.cli import decrypt

        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(decrypt, "load_vault", lambda _path: fake_vault(None))

        assert decrypt.decrypt_command(str(vault_path), shares=[]) == 2

    def test_interactive_share_collection_decrypts_empty_vault(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Interactive share collection accepts a valid indexed share."""
        from src.cli import decrypt

        manifest = SimpleNamespace(k=1, n=1, share_fingerprints=[])
        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(decrypt, "load_vault", lambda _path: fake_vault(manifest))
        monkeypatch.setattr(decrypt, "validate_checksum", lambda _mnemonic: True)
        monkeypatch.setattr(decrypt, "decode_share", lambda _mnemonic: b"\x01" * 32)
        monkeypatch.setattr(decrypt, "reconstruct_secret", lambda _shares: b"p" * 32)
        monkeypatch.setattr(
            decrypt, "decrypt_private_keys", lambda _keypair, _pass: (object(), b"k")
        )
        monkeypatch.setattr("builtins.input", input_sequence(["1: " + "word " * 24]))

        assert decrypt.decrypt_command(str(vault_path), shares=None) == 0

    def test_noninteractive_missing_indices_return_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-interactive decrypt rejects shares whose index cannot be detected."""
        from src.cli import decrypt

        manifest = SimpleNamespace(k=1, n=1, share_fingerprints=[])
        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(decrypt, "load_vault", lambda _path: fake_vault(manifest))
        monkeypatch.setattr(decrypt, "validate_checksum", lambda _mnemonic: True)
        monkeypatch.setattr(decrypt, "decode_share", lambda _mnemonic: b"\x01" * 32)
        monkeypatch.setattr(decrypt, "match_share_fingerprint", lambda _fps, _decoded: None)

        assert decrypt.decrypt_command(str(vault_path), shares=["word " * 24]) == 5


class TestRotateCommandBranches:
    """Branch tests for rotate_command."""

    def test_missing_manifest_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rotate rejects vaults without a manifest."""
        from src.cli import rotate

        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(rotate, "load_vault", lambda _path: fake_vault(None))

        assert rotate.rotate_command(str(vault_path), mode="shares", shares=[]) == 2

    def test_invalid_mode_after_authorization_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rotate validates mode after shares authorize the operation."""
        from src.cli import rotate

        manifest = SimpleNamespace(k=1, n=1, share_fingerprints=[])
        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(rotate, "load_vault", lambda _path: fake_vault(manifest))
        monkeypatch.setattr(rotate, "validate_checksum", lambda _mnemonic: True)
        monkeypatch.setattr(rotate, "decode_share", lambda _mnemonic: b"\x01" * 32)
        monkeypatch.setattr(rotate, "reconstruct_secret", lambda _shares: b"p" * 32)
        monkeypatch.setattr(
            rotate, "decrypt_private_keys", lambda _keypair, _pass: (object(), b"k")
        )

        result = rotate.rotate_command(
            str(vault_path), mode="unknown", shares=["1: " + "word " * 24]
        )

        assert result == 1

    def test_share_rotation_confirmation_can_abort(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Share rotation returns success-without-change when user declines confirmation."""
        from src.cli import rotate

        manifest = SimpleNamespace(k=1, n=1, share_fingerprints=[])
        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(rotate, "load_vault", lambda _path: fake_vault(manifest))
        monkeypatch.setattr(rotate, "validate_checksum", lambda _mnemonic: True)
        monkeypatch.setattr(rotate, "decode_share", lambda _mnemonic: b"\x01" * 32)
        monkeypatch.setattr(rotate, "reconstruct_secret", lambda _shares: b"p" * 32)
        monkeypatch.setattr(
            rotate, "decrypt_private_keys", lambda _keypair, _pass: (object(), b"k")
        )
        monkeypatch.setattr("builtins.input", input_sequence(["no"]))

        result = rotate.rotate_command(
            str(vault_path),
            mode="shares",
            new_k=1,
            new_n=2,
            shares=["1: " + "word " * 24],
            confirm=None,
        )

        assert result == 0

    def test_invalid_new_threshold_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Share rotation rejects invalid new K/N values."""
        from src.cli import rotate

        manifest = SimpleNamespace(k=1, n=1, share_fingerprints=[])
        vault_path = tmp_path / "vault.yaml"
        vault_path.write_text("exists")
        monkeypatch.setattr(rotate, "load_vault", lambda _path: fake_vault(manifest))
        monkeypatch.setattr(rotate, "validate_checksum", lambda _mnemonic: True)
        monkeypatch.setattr(rotate, "decode_share", lambda _mnemonic: b"\x01" * 32)
        monkeypatch.setattr(rotate, "reconstruct_secret", lambda _shares: b"p" * 32)
        monkeypatch.setattr(
            rotate, "decrypt_private_keys", lambda _keypair, _pass: (object(), b"k")
        )

        result = rotate.rotate_command(
            str(vault_path),
            mode="shares",
            new_k=3,
            new_n=2,
            shares=["1: " + "word " * 24],
            confirm=True,
        )

        assert result == 1


class TestInitCommandBranches:
    """Branch tests for init_command."""

    def test_interactive_k_and_n_input_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Interactive K/N prompts reject invalid numeric input."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        monkeypatch.setattr("builtins.input", input_sequence(["bad"]))
        assert init_command(k=None, n=3, vault_path=str(vault_path), import_shares=[]) == 1

        monkeypatch.setattr("builtins.input", input_sequence(["bad"]))
        assert init_command(k=2, n=None, vault_path=str(vault_path), import_shares=[]) == 1

    def test_rejects_n_above_shamir_limit(self, tmp_path: Path) -> None:
        """Init rejects N values above GF(256)'s share count limit."""
        from src.cli.init import init_command

        result = init_command(
            k=1,
            n=256,
            vault_path=str(tmp_path / "vault.yaml"),
            import_shares=[],
        )

        assert result == 1

    def test_source_vault_without_fingerprints_returns_error(self, tmp_path: Path) -> None:
        """Explicit source vault must exist and contain share fingerprints."""
        from src.cli.init import init_command

        result = init_command(
            k=1,
            n=1,
            vault_path=str(tmp_path / "target.yaml"),
            import_shares=["not validated yet"],
            source_vault=str(tmp_path / "missing.yaml"),
        )

        assert result == 6
