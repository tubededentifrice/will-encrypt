"""Interactive mode for will-encrypt - guides users through all operations."""
import os
from enum import Enum
from typing import Optional

from src.cli.decrypt import decrypt_command
from src.cli.delete import delete_command
from src.cli.edit import edit_command
from src.cli.encrypt import encrypt_command
from src.cli.init import init_command
from src.cli.list import list_command
from src.cli.rotate import rotate_command
from src.cli.validate import validate_command


class MenuOption(Enum):
    """Menu option choices for interactive mode."""

    INIT = "1"
    ENCRYPT = "2"
    DECRYPT = "3"
    LIST = "4"
    EDIT = "5"
    DELETE = "6"
    VALIDATE = "7"
    ROTATE = "8"
    HELP = "9"
    EXIT = "0"


# Menu option descriptions
MENU_DESCRIPTIONS = {
    MenuOption.INIT: "Create a new vault",
    MenuOption.ENCRYPT: "Add an encrypted message",
    MenuOption.DECRYPT: "Decrypt messages (requires recovery shares)",
    MenuOption.LIST: "View all messages",
    MenuOption.EDIT: "Edit a message title",
    MenuOption.DELETE: "Delete a message",
    MenuOption.VALIDATE: "Validate vault integrity",
    MenuOption.ROTATE: "Rotate shares or passphrase",
    MenuOption.HELP: "Learn more about will-encrypt",
    MenuOption.EXIT: "Exit",
}


def print_header() -> None:
    """Print welcome header."""
    print("\n" + "=" * 70)
    print("  Will-Encrypt: Secure Emergency Access System")
    print("  Protect your important messages with threshold cryptography")
    print("=" * 70 + "\n")


def print_menu() -> None:
    """Print main menu options."""
    print("What would you like to do?\n")
    # Print in enum definition order
    for option in MenuOption:
        print(f"  {option.value}. {MENU_DESCRIPTIONS[option]}")
    print()


def get_choice(prompt: str, valid_options: list[str]) -> str:
    """Get validated user choice."""
    while True:
        choice = input(prompt).strip()
        if choice in valid_options:
            return choice
        print(f"❌ Invalid choice. Please enter one of: {', '.join(valid_options)}\n")


_last_vault_path: Optional[str] = None  # Session memory for vault path


def get_vault_path(for_creation: bool = False) -> str:
    """Get vault path from user, with numbered quick-select and session memory.

    Args:
        for_creation: If True, prompts for a new vault path and validates it doesn't exist.
                     If False, shows existing vaults with numbered quick-select.
    """
    global _last_vault_path
    import glob

    default = _last_vault_path if _last_vault_path else "vault.yaml"

    if for_creation:
        # For new vaults, just ask for a path without listing existing ones
        while True:
            user_input = input(f"New vault file path (default: {default}): ").strip()
            result = user_input if user_input else default

            # Check if file already exists
            if os.path.exists(result):
                print(f"  ⚠️  File already exists: {result}")
                overwrite = input("  Overwrite? (yes/no): ").strip().lower()
                if overwrite == "yes":
                    break
                else:
                    print("  Please choose a different path.")
                    continue
            else:
                break
    else:
        # For existing vaults, show numbered quick-select
        yaml_files = sorted(glob.glob("*.yaml") + glob.glob("*.yml"))

        # Display available vault files if any exist
        if yaml_files:
            print("\nAvailable vault files:")
            for i, path in enumerate(yaml_files, 1):
                print(f"  {i}. {path}")
            print()

        # Single prompt for number or path
        while True:
            user_input = input(f"Vault file (number, path, or Enter for '{default}'): ").strip()

            if not user_input:
                result = default
                break

            # Check if input is a number (quick-select)
            if user_input.isdigit():
                index = int(user_input)
                if 1 <= index <= len(yaml_files):
                    result = yaml_files[index - 1]
                    break
                else:
                    print(f"  Error: Number must be 1-{len(yaml_files)}")
                    continue

            # Otherwise treat as a path
            result = user_input
            break

    _last_vault_path = result  # Remember for next time
    return result


def explain_system() -> None:
    """Explain how will-encrypt works."""
    print("\n" + "=" * 70)
    print("  How Will-Encrypt Works")
    print("=" * 70 + "\n")

    print("Will-encrypt uses threshold cryptography to protect your messages:")
    print("")
    print("1. CREATE A VAULT")
    print("   - You choose K (threshold) and N (total shares)")
    print("   - The system generates N recovery shares")
    print("   - Any K shares can decrypt your messages")
    print("   - Shares are 24-word phrases (BIP39 format)")
    print("")
    print("2. DISTRIBUTE SHARES")
    print("   - Give each share to a different trusted person")
    print("   - Example: K=3, N=5 means 3 out of 5 people must cooperate")
    print("   - No single person can access your messages alone")
    print("")
    print("3. ENCRYPT MESSAGES")
    print("   - Store important information (passwords, instructions, etc.)")
    print("   - Messages are encrypted with military-grade cryptography")
    print("   - Only retrievable when K shares are combined")
    print("")
    print("4. EMERGENCY ACCESS")
    print("   - In an emergency, K share holders meet")
    print("   - They provide their shares to decrypt all messages")
    print("   - Perfect for wills, estate planning, emergency access")
    print("")
    print("5. SECURITY")
    print("   - Uses RSA-4096 + Kyber-1024 hybrid encryption")
    print("   - AES-256-GCM for message encryption")
    print("   - Shamir Secret Sharing for threshold cryptography")
    print("   - BIP39 checksums prevent typing errors")
    print("")

    input("Press Enter to return to menu...")


def handle_init() -> int:
    """Handle vault initialization."""
    print("\n" + "=" * 70)
    print("  Create a New Vault")
    print("=" * 70 + "\n")

    print("A vault stores your encrypted messages and requires K out of N shares")
    print("to decrypt them.\n")

    # Get path for new vault (with overwrite check built-in)
    vault_path = get_vault_path(for_creation=True)

    # Check if overwrite was confirmed (file exists)
    force = os.path.exists(vault_path)

    # Let init_command handle all prompts (K, N, share import, etc.)
    return init_command(None, None, vault_path, force, None, None)


def handle_encrypt() -> int:
    """Handle message encryption."""
    print("\n" + "=" * 70)
    print("  Encrypt a Message")
    print("=" * 70 + "\n")

    print("Add an encrypted message to your vault. You'll be prompted for:")
    print("  - Message title (for identification)")
    print("  - Message content (the secret information)")
    print("")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        print("Please create a vault first (option 1).")
        return 1

    # Let encrypt_command handle the prompts
    return encrypt_command(vault_path, None, None, False)


def handle_decrypt() -> int:
    """Handle message decryption."""
    print("\n" + "=" * 70)
    print("  Decrypt Messages")
    print("=" * 70 + "\n")

    print("To decrypt messages, you need K recovery shares (24 words each).")
    print("Share holders should gather together to provide their shares.\n")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        return 1

    # Let decrypt_command handle share collection
    return decrypt_command(vault_path, None)


def handle_list() -> int:
    """Handle message listing."""
    print("\n" + "=" * 70)
    print("  View All Messages")
    print("=" * 70 + "\n")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        return 1

    print("Display format:")
    print("  1. Table (easy to read)")
    print("  2. JSON (machine readable)")
    format_choice = get_choice("Choice (1 or 2, default: 1): ", ["1", "2", ""])
    fmt = "json" if format_choice == "2" else "table"

    print("\nSort by:")
    print("  1. ID")
    print("  2. Title")
    print("  3. Created date")
    print("  4. Size")
    sort_choice = get_choice("Choice (1-4, default: 1): ", ["1", "2", "3", "4", ""])
    sort_map = {"1": "id", "2": "title", "3": "created", "4": "size", "": "id"}
    sort = sort_map[sort_choice]

    return list_command(vault_path, fmt, sort)


def handle_validate() -> int:
    """Handle vault validation."""
    print("\n" + "=" * 70)
    print("  Validate Vault Integrity")
    print("=" * 70 + "\n")

    print("This checks that your vault hasn't been corrupted or tampered with.\n")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        return 1

    verbose = get_choice("Show detailed information? (yes/no, default: no): ", ["yes", "no", ""])
    verbose_flag = verbose == "yes"

    return validate_command(vault_path, verbose_flag)


def handle_edit() -> int:
    """Handle message title editing."""
    print("\n" + "=" * 70)
    print("  Edit Message Title")
    print("=" * 70 + "\n")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        return 1

    # List messages first
    print("Current messages:")
    list_command(vault_path, "table", "id")
    print()

    # Get message ID
    message_id = input("Enter message ID to edit: ").strip()
    if not message_id:
        print("❌ Message ID required")
        return 1

    # Get new title
    new_title = input("Enter new title: ").strip()
    if not new_title:
        print("❌ Title cannot be empty")
        return 1

    return edit_command(vault_path, message_id, new_title)


def handle_delete() -> int:
    """Handle message deletion."""
    print("\n" + "=" * 70)
    print("  Delete Message")
    print("=" * 70 + "\n")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        return 1

    # List messages first
    print("Current messages:")
    list_command(vault_path, "table", "id")
    print()

    # Get message ID
    message_id = input("Enter message ID to delete: ").strip()
    if not message_id:
        print("❌ Message ID required")
        return 1

    # Confirm deletion
    confirm = input(f"⚠️  Delete message ID {message_id}? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Cancelled.")
        return 0

    return delete_command(vault_path, message_id)


def handle_rotate() -> int:
    """Handle share/passphrase rotation."""
    print("\n" + "=" * 70)
    print("  Rotate Shares or Passphrase")
    print("=" * 70 + "\n")

    print("Rotation allows you to:")
    print("  - Change shares: Create new K/N configuration and shares")
    print("  - Change passphrase: Generate new master passphrase")
    print("")
    print("⚠️  Both operations require K current shares to proceed.\n")

    vault_path = get_vault_path()

    if not os.path.exists(vault_path):
        print(f"\n❌ Vault not found: {vault_path}")
        return 1

    print("What would you like to rotate?")
    print("  1. Shares (change K/N configuration)")
    print("  2. Passphrase (generate new master passphrase)")
    mode_choice = get_choice("Choice (1 or 2): ", ["1", "2"])
    mode = "shares" if mode_choice == "1" else "passphrase"

    # Let rotate_command handle the rest (it prompts for shares and new K/N)
    return rotate_command(vault_path, mode, None, None, None)


def interactive_mode() -> int:
    """Run interactive mode."""
    print_header()

    # Generate valid choices from enum
    valid_choices = [option.value for option in MenuOption]

    # Map choices to handler functions
    handlers = {
        MenuOption.INIT: handle_init,
        MenuOption.ENCRYPT: handle_encrypt,
        MenuOption.DECRYPT: handle_decrypt,
        MenuOption.LIST: handle_list,
        MenuOption.EDIT: handle_edit,
        MenuOption.DELETE: handle_delete,
        MenuOption.VALIDATE: handle_validate,
        MenuOption.ROTATE: handle_rotate,
    }

    while True:
        print_menu()
        choice = get_choice("Enter your choice: ", valid_choices)

        if choice == MenuOption.EXIT.value:
            print("\n👋 Goodbye!\n")
            return 0
        elif choice == MenuOption.HELP.value:
            explain_system()
        else:
            # Find matching option and call handler
            for option, handler in handlers.items():
                if choice == option.value:
                    result = handler()
                    if result != 0:
                        input("\nPress Enter to continue...")
                    break

        print("\n")  # Spacing before next menu
