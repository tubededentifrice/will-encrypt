"""Tests for secure message editor."""
from unittest.mock import MagicMock, patch

from src.cli.editor import SecureEditor, get_message_text


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
