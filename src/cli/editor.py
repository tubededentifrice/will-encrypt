"""Secure message editor with keyboard navigation.

Provides a multi-line text editor with:
- Arrow key navigation (up, down, left, right)
- Standard editing keys (Home, End, Delete, Backspace)
- Multi-line support
- Screen clearing after input for security
- No disk writes (operates entirely in memory)
"""
import sys
import termios
import tty


class SecureEditor:
    """In-memory text editor with keyboard navigation and automatic screen clearing."""

    def __init__(self, title: str = "Message Editor") -> None:
        """Initialize editor.

        Args:
            title: Title to display at top of editor
        """
        self.title = title
        self.lines: list[str] = [""]
        self.cursor_row = 0
        self.cursor_col = 0
        self.header_rows = 4  # Title + separator + instructions + separator

    def _get_terminal_size(self) -> tuple[int, int]:
        """Get terminal dimensions (rows, cols)."""
        import shutil

        size = shutil.get_terminal_size(fallback=(80, 24))
        return size.lines, size.columns

    def _clear_screen(self) -> None:
        """Clear terminal screen."""
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    def _hide_cursor(self) -> None:
        """Hide cursor."""
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    def _show_cursor(self) -> None:
        """Show cursor."""
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    def _move_cursor_to(self, row: int, col: int) -> None:
        """Move cursor to absolute position (1-indexed)."""
        sys.stdout.write(f"\033[{row};{col}H")
        sys.stdout.flush()

    def _clear_line(self) -> None:
        """Clear current line."""
        sys.stdout.write("\033[2K")
        sys.stdout.flush()

    def _format_header(self) -> list[str]:
        """Format header lines for editor display."""
        header = f"=== {self.title} ==="
        instructions = "Ctrl+D to finish | Ctrl+C to cancel | Arrow keys to navigate"
        sep_length = max(len(header), len(instructions))
        separator = "─" * len(header)
        separator2 = "─" * sep_length
        return [header, separator, instructions, separator2]

    def _draw_initial_screen(self) -> None:
        """Draw initial editor screen with header."""
        rows, cols = self._get_terminal_size()
        self._clear_screen()

        header_lines = self._format_header()
        for i, line in enumerate(header_lines, start=1):
            self._move_cursor_to(i, 1)
            sys.stdout.write(line)
            sys.stdout.flush()

    def _redraw_content(self) -> None:
        """Redraw all content lines without clearing screen."""
        rows, cols = self._get_terminal_size()
        max_lines = rows - self.header_rows - 1

        # Calculate scroll offset
        scroll_offset = 0
        if self.cursor_row >= max_lines:
            scroll_offset = self.cursor_row - max_lines + 1

        # Draw each visible line
        for i in range(max_lines):
            line_idx = i + scroll_offset
            screen_row = self.header_rows + 1 + i

            self._move_cursor_to(screen_row, 1)
            self._clear_line()

            if line_idx < len(self.lines):
                line = self.lines[line_idx]
                # Truncate if too long
                display_line = line[: cols - 1] if len(line) >= cols else line
                sys.stdout.write(display_line)

        sys.stdout.flush()

    def _update_cursor_position(self) -> None:
        """Update cursor position on screen."""
        rows, cols = self._get_terminal_size()
        max_lines = rows - self.header_rows - 1

        # Calculate scroll offset
        scroll_offset = 0
        if self.cursor_row >= max_lines:
            scroll_offset = self.cursor_row - max_lines + 1

        # Calculate screen position
        screen_row = self.header_rows + 1 + (self.cursor_row - scroll_offset)
        screen_col = self.cursor_col + 1

        # Clamp to terminal bounds
        screen_col = min(screen_col, cols)

        self._move_cursor_to(screen_row, screen_col)

    def _insert_char(self, char: str) -> None:
        """Insert character at cursor position."""
        line = self.lines[self.cursor_row]
        self.lines[self.cursor_row] = line[: self.cursor_col] + char + line[self.cursor_col :]
        self.cursor_col += 1

    def _delete_char(self) -> None:
        """Delete character at cursor (Delete key)."""
        line = self.lines[self.cursor_row]
        if self.cursor_col < len(line):
            self.lines[self.cursor_row] = line[: self.cursor_col] + line[self.cursor_col + 1 :]

    def _backspace(self) -> None:
        """Delete character before cursor (Backspace)."""
        if self.cursor_col > 0:
            line = self.lines[self.cursor_row]
            self.lines[self.cursor_row] = line[: self.cursor_col - 1] + line[self.cursor_col :]
            self.cursor_col -= 1
        elif self.cursor_row > 0:
            # Join with previous line
            prev_line = self.lines[self.cursor_row - 1]
            curr_line = self.lines[self.cursor_row]
            self.lines[self.cursor_row - 1] = prev_line + curr_line
            del self.lines[self.cursor_row]
            self.cursor_row -= 1
            self.cursor_col = len(prev_line)

    def _newline(self) -> None:
        """Insert newline at cursor position."""
        line = self.lines[self.cursor_row]
        self.lines[self.cursor_row] = line[: self.cursor_col]
        self.lines.insert(self.cursor_row + 1, line[self.cursor_col :])
        self.cursor_row += 1
        self.cursor_col = 0

    def _move_left(self) -> None:
        """Move cursor left."""
        if self.cursor_col > 0:
            self.cursor_col -= 1
        elif self.cursor_row > 0:
            # Move to end of previous line
            self.cursor_row -= 1
            self.cursor_col = len(self.lines[self.cursor_row])

    def _move_right(self) -> None:
        """Move cursor right."""
        if self.cursor_col < len(self.lines[self.cursor_row]):
            self.cursor_col += 1
        elif self.cursor_row < len(self.lines) - 1:
            # Move to start of next line
            self.cursor_row += 1
            self.cursor_col = 0

    def _move_up(self) -> None:
        """Move cursor up."""
        if self.cursor_row > 0:
            self.cursor_row -= 1
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))

    def _move_down(self) -> None:
        """Move cursor down."""
        if self.cursor_row < len(self.lines) - 1:
            self.cursor_row += 1
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_row]))

    def _move_home(self) -> None:
        """Move cursor to start of line."""
        self.cursor_col = 0

    def _move_end(self) -> None:
        """Move cursor to end of line."""
        self.cursor_col = len(self.lines[self.cursor_row])

    def edit(self) -> str | None:
        """Run editor and return text content.

        Returns:
            Entered text, or None if cancelled
        """
        # Save terminal settings
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            # Enter raw mode
            tty.setraw(fd)

            # Draw initial screen
            self._draw_initial_screen()
            self._redraw_content()
            self._update_cursor_position()
            self._show_cursor()

            while True:
                # Read one character
                char = sys.stdin.read(1)

                # Handle control characters
                if char == "\x04":  # Ctrl+D (finish)
                    break
                elif char == "\x03":  # Ctrl+C (cancel)
                    # Clear screen on cancel for security
                    self._hide_cursor()
                    self._clear_screen()
                    return None
                elif char == "\r" or char == "\n":  # Enter
                    self._newline()
                    self._redraw_content()
                elif char == "\x7f":  # Backspace
                    self._backspace()
                    self._redraw_content()
                elif char == "\x1b":  # Escape sequence (arrow keys, etc.)
                    seq = sys.stdin.read(2)
                    if seq == "[A":  # Up arrow
                        self._move_up()
                    elif seq == "[B":  # Down arrow
                        self._move_down()
                    elif seq == "[C":  # Right arrow
                        self._move_right()
                    elif seq == "[D":  # Left arrow
                        self._move_left()
                    elif seq == "[H":  # Home
                        self._move_home()
                    elif seq == "[F":  # End
                        self._move_end()
                    elif seq == "[3":  # Delete (followed by ~)
                        sys.stdin.read(1)  # Read the ~
                        self._delete_char()
                        self._redraw_content()
                elif ord(char) >= 32:  # Printable character
                    self._insert_char(char)
                    self._redraw_content()

                # Update cursor position after any action
                self._update_cursor_position()

            # Hide cursor, clear screen for security after editing
            self._hide_cursor()
            self._clear_screen()

            # Return joined content
            return "\n".join(self.lines)

        finally:
            # Restore terminal settings and show cursor
            self._show_cursor()
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def get_message_text(title: str = "Enter Message") -> str | None:
    """Get multi-line message text with secure editor.

    Args:
        title: Title to display in editor

    Returns:
        Message text or None if cancelled
    """
    editor = SecureEditor(title)
    return editor.edit()
