#!/usr/bin/env python3
"""Quick test script to verify editor alignment."""
from src.cli.editor import get_message_text

print("Testing editor alignment...")
print("The header should be aligned at the left edge without extra spacing.")
print("Press Ctrl+C to cancel and check screen clearing.\n")

result = get_message_text("Test Message")

if result is None:
    print("\n✓ Editor cancelled - screen should have been cleared")
else:
    print(f"\n✓ Editor completed successfully")
    print(f"Message entered: {result}")
