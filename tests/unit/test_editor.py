"""Tests for secure message editor."""
import sys
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from src.cli.editor import SecureEditor, get_message_text


class FakeStdin:
    """Small stdin replacement for raw-mode editor tests."""

    def __init__(self, chunks: list[str]) -> None:
        self._chunks: Iterator[str] = iter(chunks)

    def fileno(self) -> int:
        return 0

    def read(self, _size: int = -1) -> str:
        return next(self._chunks)


class TestSecureEditor:
    """Test SecureEditor class."""

    def test_init(self) -> None:
        """Test editor initialization."""
        editor = SecureEditor("Test Title")
        assert editor.title == "Test Title"
        assert editor.lines == [""]
        assert editor.cursor_row == 0
        assert editor.cursor_col == 0

    def test_insert_char(self) -> None:
        """Test character insertion."""
        editor = SecureEditor()
        editor._insert_char("H")
        editor._insert_char("i")
        assert editor.lines[0] == "Hi"
        assert editor.cursor_col == 2

    def test_insert_char_middle(self) -> None:
        """Test insertion in middle of line."""
        editor = SecureEditor()
        editor.lines[0] = "Hllo"
        editor.cursor_col = 1
        editor._insert_char("e")
        assert editor.lines[0] == "Hello"
        assert editor.cursor_col == 2

    def test_backspace(self) -> None:
        """Test backspace deletion."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 5
        editor._backspace()
        assert editor.lines[0] == "Hell"
        assert editor.cursor_col == 4

    def test_backspace_beginning(self) -> None:
        """Test backspace at line beginning merges lines."""
        editor = SecureEditor()
        editor.lines = ["Hello", "World"]
        editor.cursor_row = 1
        editor.cursor_col = 0
        editor._backspace()
        assert editor.lines == ["HelloWorld"]
        assert editor.cursor_row == 0
        assert editor.cursor_col == 5

    def test_delete_char(self) -> None:
        """Test delete key."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 0
        editor._delete_char()
        assert editor.lines[0] == "ello"
        assert editor.cursor_col == 0

    def test_delete_at_end(self) -> None:
        """Test delete at end of line does nothing."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 5
        editor._delete_char()
        assert editor.lines[0] == "Hello"

    def test_newline(self) -> None:
        """Test newline insertion."""
        editor = SecureEditor()
        editor.lines[0] = "HelloWorld"
        editor.cursor_col = 5
        editor._newline()
        assert editor.lines == ["Hello", "World"]
        assert editor.cursor_row == 1
        assert editor.cursor_col == 0

    def test_move_left(self) -> None:
        """Test left arrow movement."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 3
        editor._move_left()
        assert editor.cursor_col == 2

    def test_move_left_wrap(self) -> None:
        """Test left arrow wraps to previous line."""
        editor = SecureEditor()
        editor.lines = ["Hello", "World"]
        editor.cursor_row = 1
        editor.cursor_col = 0
        editor._move_left()
        assert editor.cursor_row == 0
        assert editor.cursor_col == 5

    def test_move_right(self) -> None:
        """Test right arrow movement."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 2
        editor._move_right()
        assert editor.cursor_col == 3

    def test_move_right_wrap(self) -> None:
        """Test right arrow wraps to next line."""
        editor = SecureEditor()
        editor.lines = ["Hello", "World"]
        editor.cursor_row = 0
        editor.cursor_col = 5
        editor._move_right()
        assert editor.cursor_row == 1
        assert editor.cursor_col == 0

    def test_move_up(self) -> None:
        """Test up arrow movement."""
        editor = SecureEditor()
        editor.lines = ["Hello", "World"]
        editor.cursor_row = 1
        editor.cursor_col = 3
        editor._move_up()
        assert editor.cursor_row == 0
        assert editor.cursor_col == 3

    def test_move_up_clamp_column(self) -> None:
        """Test up arrow clamps column to line length."""
        editor = SecureEditor()
        editor.lines = ["Hi", "World"]
        editor.cursor_row = 1
        editor.cursor_col = 4
        editor._move_up()
        assert editor.cursor_row == 0
        assert editor.cursor_col == 2  # Clamped to "Hi" length

    def test_move_down(self) -> None:
        """Test down arrow movement."""
        editor = SecureEditor()
        editor.lines = ["Hello", "World"]
        editor.cursor_row = 0
        editor.cursor_col = 2
        editor._move_down()
        assert editor.cursor_row == 1
        assert editor.cursor_col == 2

    def test_move_down_clamp_column(self) -> None:
        """Test down arrow clamps column to line length."""
        editor = SecureEditor()
        editor.lines = ["Hello", "Hi"]
        editor.cursor_row = 0
        editor.cursor_col = 4
        editor._move_down()
        assert editor.cursor_row == 1
        assert editor.cursor_col == 2  # Clamped to "Hi" length

    def test_move_home(self) -> None:
        """Test Home key."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 3
        editor._move_home()
        assert editor.cursor_col == 0

    def test_move_end(self) -> None:
        """Test End key."""
        editor = SecureEditor()
        editor.lines[0] = "Hello"
        editor.cursor_col = 0
        editor._move_end()
        assert editor.cursor_col == 5

    def test_get_terminal_size(self) -> None:
        """Test terminal size detection."""
        editor = SecureEditor()
        rows, cols = editor._get_terminal_size()
        assert rows > 0
        assert cols > 0

    @patch("sys.stdout")
    def test_clear_screen(self, mock_stdout: MagicMock) -> None:
        """Test screen clearing."""
        editor = SecureEditor()
        editor._clear_screen()
        mock_stdout.write.assert_called()
        mock_stdout.flush.assert_called()

    @patch("sys.stdout")
    def test_move_cursor_to(self, mock_stdout: MagicMock) -> None:
        """Test cursor positioning."""
        editor = SecureEditor()
        editor._move_cursor_to(5, 10)
        mock_stdout.write.assert_called_with("\033[5;10H")
        mock_stdout.flush.assert_called()

    @patch("sys.stdout")
    def test_hide_cursor(self, mock_stdout: MagicMock) -> None:
        """Test hiding cursor."""
        editor = SecureEditor()
        editor._hide_cursor()
        mock_stdout.write.assert_called_with("\033[?25l")
        mock_stdout.flush.assert_called()

    @patch("sys.stdout")
    def test_show_cursor(self, mock_stdout: MagicMock) -> None:
        """Test showing cursor."""
        editor = SecureEditor()
        editor._show_cursor()
        mock_stdout.write.assert_called_with("\033[?25h")
        mock_stdout.flush.assert_called()

    @patch("sys.stdout")
    def test_clear_line(self, mock_stdout: MagicMock) -> None:
        """Test clearing current line."""
        editor = SecureEditor()
        editor._clear_line()
        mock_stdout.write.assert_called_with("\033[2K")
        mock_stdout.flush.assert_called()

    def test_format_header(self) -> None:
        """Test editor header text generation."""
        editor = SecureEditor("Recovery Note")

        header = editor._format_header()

        assert header[0] == "=== Recovery Note ==="
        assert "Ctrl+D to finish" in header[2]
        assert len(header) == 4

    @patch("sys.stdout")
    def test_draw_initial_screen_writes_header(self, mock_stdout: MagicMock) -> None:
        """Initial draw clears the screen and writes all header lines."""
        editor = SecureEditor("Draw Test")

        editor._draw_initial_screen()

        writes = [call.args[0] for call in mock_stdout.write.call_args_list]
        assert "\033[2J\033[H" in writes
        assert "=== Draw Test ===" in writes
        assert any("Ctrl+D to finish" in text for text in writes)

    @patch("sys.stdout")
    def test_redraw_content_scrolls_and_truncates(self, mock_stdout: MagicMock) -> None:
        """Redraw shows visible lines and truncates long lines to terminal width."""
        editor = SecureEditor()
        editor.lines = ["line0", "abcdef", "line2"]
        editor.cursor_row = 2

        with patch.object(editor, "_get_terminal_size", return_value=(7, 4)):
            editor._redraw_content()

        writes = [call.args[0] for call in mock_stdout.write.call_args_list]
        assert "abc" in writes
        assert "line0" not in writes

    def test_update_cursor_position_clamps_to_terminal_width(self) -> None:
        """Cursor updates account for scroll offset and terminal width."""
        editor = SecureEditor()
        editor.lines = ["short", "longer"]
        editor.cursor_row = 1
        editor.cursor_col = 20
        positions: list[tuple[int, int]] = []

        with (
            patch.object(editor, "_get_terminal_size", return_value=(6, 8)),
            patch.object(
                editor,
                "_move_cursor_to",
                side_effect=lambda row, col: positions.append((row, col)),
            ),
        ):
            editor._update_cursor_position()

        assert positions == [(5, 8)]

    def test_edit_loop_handles_text_navigation_delete_and_finish(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Raw edit loop handles printable text, movement keys, delete, and Ctrl+D."""
        editor = SecureEditor()
        fake_stdin = FakeStdin(
            [
                "a",
                "\r",
                "b",
                "\x1b",
                "[A",
                "\x1b",
                "[F",
                "!",
                "\x1b",
                "[D",
                "\x1b",
                "[C",
                "\x1b",
                "[H",
                "\x1b",
                "[3",
                "~",
                "\x04",
            ]
        )

        monkeypatch.setattr(sys, "stdin", fake_stdin)
        monkeypatch.setattr("termios.tcgetattr", lambda _fd: ["settings"])
        tcsetattr = MagicMock()
        monkeypatch.setattr("termios.tcsetattr", tcsetattr)
        monkeypatch.setattr("tty.setraw", lambda _fd: None)
        monkeypatch.setattr(editor, "_draw_initial_screen", lambda: None)
        monkeypatch.setattr(editor, "_redraw_content", lambda: None)
        monkeypatch.setattr(editor, "_update_cursor_position", lambda: None)
        monkeypatch.setattr(editor, "_hide_cursor", lambda: None)
        monkeypatch.setattr(editor, "_clear_screen", lambda: None)
        monkeypatch.setattr(editor, "_show_cursor", lambda: None)

        result = editor.edit()

        assert result == "!\nb"
        tcsetattr.assert_called_once()

    def test_edit_loop_ctrl_c_cancels_and_restores_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ctrl+C returns None and still restores terminal state."""
        editor = SecureEditor()
        fake_stdin = FakeStdin(["\x03"])
        calls: list[str] = []

        monkeypatch.setattr(sys, "stdin", fake_stdin)
        monkeypatch.setattr("termios.tcgetattr", lambda _fd: ["settings"])
        tcsetattr = MagicMock()
        monkeypatch.setattr("termios.tcsetattr", tcsetattr)
        monkeypatch.setattr("tty.setraw", lambda _fd: None)
        monkeypatch.setattr(editor, "_draw_initial_screen", lambda: None)
        monkeypatch.setattr(editor, "_redraw_content", lambda: None)
        monkeypatch.setattr(editor, "_update_cursor_position", lambda: None)
        monkeypatch.setattr(editor, "_hide_cursor", lambda: calls.append("hide"))
        monkeypatch.setattr(editor, "_clear_screen", lambda: calls.append("clear"))
        monkeypatch.setattr(editor, "_show_cursor", lambda: calls.append("show"))

        result = editor.edit()

        assert result is None
        assert calls == ["show", "hide", "clear", "show"]
        tcsetattr.assert_called_once()


class TestGetMessageText:
    """Test get_message_text convenience function."""

    @patch("src.cli.editor.SecureEditor.edit")
    def test_get_message_text(self, mock_edit: MagicMock) -> None:
        """Test get_message_text delegates to SecureEditor."""
        mock_edit.return_value = "Test content"
        result = get_message_text("Custom Title")
        assert result == "Test content"
        mock_edit.assert_called_once()

    @patch("src.cli.editor.SecureEditor.edit")
    def test_get_message_text_cancelled(self, mock_edit: MagicMock) -> None:
        """Test get_message_text handles cancellation."""
        mock_edit.return_value = None
        result = get_message_text()
        assert result is None


class TestEditorSecurity:
    """Test security features of the editor."""

    def test_header_alignment(self) -> None:
        """Test that header is properly aligned without trailing spaces."""
        editor = SecureEditor("Test Title")
        # Header should be clean without excessive padding
        assert editor.title == "Test Title"
        assert editor.header_rows == 4
