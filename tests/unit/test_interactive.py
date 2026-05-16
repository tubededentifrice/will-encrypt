"""Tests for interactive mode helpers and handlers."""

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from src.cli import interactive


@pytest.fixture(autouse=True)
def reset_interactive_state() -> Iterator[None]:
    """Reset module session state between tests."""
    interactive._last_vault_path = None
    yield
    interactive._last_vault_path = None


def input_sequence(values: list[str]) -> Callable[[str], str]:
    """Return an input replacement that consumes values in order."""
    answers = iter(values)

    def fake_input(_prompt: str = "") -> str:
        return next(answers)

    return fake_input


def test_print_header_and_menu(capsys: pytest.CaptureFixture[str]) -> None:
    """Header and menu show the expected options."""
    interactive.print_header()
    interactive.print_menu()

    output = capsys.readouterr().out
    assert "Will-Encrypt" in output
    assert "1. Create a new vault" in output
    assert "9. Learn more about will-encrypt" in output
    assert "0. Exit" in output


def test_get_choice_reprompts_until_valid(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Invalid choices are rejected before returning a valid one."""
    monkeypatch.setattr("builtins.input", input_sequence(["bad", "2"]))

    choice = interactive.get_choice("Choice: ", ["1", "2"])

    assert choice == "2"
    assert "Invalid choice" in capsys.readouterr().out


def test_get_vault_path_for_creation_reprompts_when_overwrite_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Creation prompts again when the default vault exists and overwrite is declined."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vault.yaml").write_text("existing")
    monkeypatch.setattr("builtins.input", input_sequence(["", "no", "new.yaml"]))

    path = interactive.get_vault_path(for_creation=True)

    assert path == "new.yaml"
    assert interactive._last_vault_path == "new.yaml"
    assert "Please choose a different path" in capsys.readouterr().out


def test_get_vault_path_for_creation_allows_confirmed_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Creation returns the existing default path when overwrite is confirmed."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vault.yaml").write_text("existing")
    monkeypatch.setattr("builtins.input", input_sequence(["", "yes"]))

    path = interactive.get_vault_path(for_creation=True)

    assert path == "vault.yaml"


def test_get_vault_path_existing_supports_quick_select(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Existing vault prompt accepts a numbered selection."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.yaml").write_text("a")
    (tmp_path / "b.yml").write_text("b")
    monkeypatch.setattr("builtins.input", input_sequence(["2"]))

    path = interactive.get_vault_path()

    assert path == "b.yml"
    assert "Available vault files" in capsys.readouterr().out


def test_get_vault_path_existing_reprompts_invalid_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Out-of-range quick-select values are rejected."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "only.yaml").write_text("vault")
    monkeypatch.setattr("builtins.input", input_sequence(["4", "custom.yaml"]))

    path = interactive.get_vault_path()

    assert path == "custom.yaml"
    assert "Number must be 1-1" in capsys.readouterr().out


@pytest.mark.parametrize(
    "handler",
    [
        interactive.handle_encrypt,
        interactive.handle_decrypt,
        interactive.handle_list,
        interactive.handle_validate,
        interactive.handle_edit,
        interactive.handle_delete,
        interactive.handle_rotate,
    ],
)
def test_handlers_return_error_for_missing_vault(
    handler: Callable[[], int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Handlers that require an existing vault fail before invoking commands."""
    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: "missing.yaml")
    monkeypatch.setattr(interactive.os.path, "exists", lambda _path: False)

    assert handler() == 1


def test_handle_init_passes_creation_path_and_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Init handler delegates to init_command with overwrite state."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("existing")
    calls: list[tuple[int | None, int | None, str, bool, list[str] | None, str | None]] = []

    def fake_init(
        k: int | None,
        n: int | None,
        path: str,
        force: bool,
        import_shares: list[str] | None,
        source_vault: str | None,
    ) -> int:
        calls.append((k, n, path, force, import_shares, source_vault))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "init_command", fake_init)

    assert interactive.handle_init() == 0
    assert calls == [(None, None, str(vault_path), True, None, None)]


def test_handle_encrypt_delegates_to_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Encrypt handler delegates with interactive title/message arguments."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    calls: list[tuple[str, str | None, str | None, bool]] = []

    def fake_encrypt(path: str, title: str | None, message: str | None, stdin: bool) -> int:
        calls.append((path, title, message, stdin))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "encrypt_command", fake_encrypt)

    assert interactive.handle_encrypt() == 0
    assert calls == [(str(vault_path), None, None, False)]


def test_handle_list_collects_format_and_sort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """List handler maps menu choices to command arguments."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    calls: list[tuple[str, str, str]] = []

    def fake_list(path: str, output_format: str, sort: str) -> int:
        calls.append((path, output_format, sort))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "list_command", fake_list)
    monkeypatch.setattr("builtins.input", input_sequence(["2", "4"]))

    assert interactive.handle_list() == 0
    assert calls == [(str(vault_path), "json", "size")]


def test_handle_validate_collects_verbose_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate handler maps yes/no prompt to verbose flag."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    calls: list[tuple[str, bool]] = []

    def fake_validate(path: str, verbose: bool) -> int:
        calls.append((path, verbose))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "validate_command", fake_validate)
    monkeypatch.setattr("builtins.input", input_sequence(["yes"]))

    assert interactive.handle_validate() == 0
    assert calls == [(str(vault_path), True)]


def test_handle_edit_validates_id_and_title(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Edit handler rejects blank IDs and blank titles before delegating."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "list_command", lambda *_args: 0)

    monkeypatch.setattr("builtins.input", input_sequence([""]))
    assert interactive.handle_edit() == 1

    monkeypatch.setattr("builtins.input", input_sequence(["1", ""]))
    assert interactive.handle_edit() == 1


def test_handle_edit_delegates_to_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Edit handler passes message ID and title to edit_command."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    calls: list[tuple[str, str, str]] = []

    def fake_edit(path: str, message_id: str, title: str) -> int:
        calls.append((path, message_id, title))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "list_command", lambda *_args: 0)
    monkeypatch.setattr(interactive, "edit_command", fake_edit)
    monkeypatch.setattr("builtins.input", input_sequence(["7", "Updated"]))

    assert interactive.handle_edit() == 0
    assert calls == [(str(vault_path), "7", "Updated")]


def test_handle_delete_cancel_and_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delete handler supports cancellation and confirmed deletion."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    calls: list[tuple[str, str]] = []

    def fake_delete(path: str, message_id: str) -> int:
        calls.append((path, message_id))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "list_command", lambda *_args: 0)
    monkeypatch.setattr(interactive, "delete_command", fake_delete)

    monkeypatch.setattr("builtins.input", input_sequence(["1", "no"]))
    assert interactive.handle_delete() == 0
    assert calls == []

    monkeypatch.setattr("builtins.input", input_sequence(["2", "yes"]))
    assert interactive.handle_delete() == 0
    assert calls == [(str(vault_path), "2")]


def test_handle_rotate_maps_mode_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rotate handler maps menu choice to rotation mode."""
    vault_path = tmp_path / "vault.yaml"
    vault_path.write_text("vault")
    calls: list[tuple[str, str, int | None, int | None, list[str] | None]] = []

    def fake_rotate(
        path: str,
        mode: str,
        new_k: int | None,
        new_n: int | None,
        shares: list[str] | None,
    ) -> int:
        calls.append((path, mode, new_k, new_n, shares))
        return 0

    monkeypatch.setattr(interactive, "get_vault_path", lambda for_creation=False: str(vault_path))
    monkeypatch.setattr(interactive, "rotate_command", fake_rotate)
    monkeypatch.setattr("builtins.input", input_sequence(["2"]))

    assert interactive.handle_rotate() == 0
    assert calls == [(str(vault_path), "passphrase", None, None, None)]


def test_explain_system_waits_for_enter(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Help text is printed and waits before returning."""
    monkeypatch.setattr("builtins.input", input_sequence([""]))

    interactive.explain_system()

    output = capsys.readouterr().out
    assert "How Will-Encrypt Works" in output
    assert "CREATE A VAULT" in output


def test_interactive_mode_dispatches_handler_and_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Main loop dispatches selected handlers and exits cleanly."""
    called: list[str] = []

    def fake_encrypt() -> int:
        called.append("encrypt")
        return 0

    monkeypatch.setattr(interactive, "handle_encrypt", fake_encrypt)
    monkeypatch.setattr("builtins.input", input_sequence(["2", "0"]))

    assert interactive.interactive_mode() == 0
    assert called == ["encrypt"]
    assert "Goodbye" in capsys.readouterr().out


def test_interactive_mode_waits_after_handler_error(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Main loop pauses after a handler returns an error."""
    called: list[str] = []

    def fake_decrypt() -> int:
        called.append("decrypt")
        return 1

    monkeypatch.setattr(interactive, "handle_decrypt", fake_decrypt)
    monkeypatch.setattr("builtins.input", input_sequence(["3", "", "0"]))

    assert interactive.interactive_mode() == 0
    assert called == ["decrypt"]
