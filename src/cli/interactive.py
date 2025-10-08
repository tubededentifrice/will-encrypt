"""Interactive mode for will-encrypt - guides users through all operations."""
import os
import sys
from typing import Optional

from src.cli.decrypt import decrypt_command
from src.cli.encrypt import encrypt_command
from src.cli.init import init_command
from src.cli.list import list_command
from src.cli.rotate import rotate_command
from src.cli.validate import validate_command


def print_header() -> None:
    """Print welcome header."""
    print("\n" + "=" * 70)
    print("  Will-Encrypt: Secure Emergency Access System")
    print("  Protect your important messages with threshold cryptography")
    print("=" * 70 + "\n")


def print_menu() -> None:
    """Print main menu options."""
    print("What would you like to do?\n")
    print("  1. Create a new vault")
    print("  2. Add an encrypted message")
    print("  3. Decrypt messages (requires recovery shares)")
    print("  4. View all messages")
    print("  5. Validate vault integrity")
    print("  6. Rotate shares or passphrase")
    print("  7. Learn more about will-encrypt")
    print("  0. Exit\n")


def get_choice(prompt: str, valid_options: list[str]) -> str:
    """Get validated user choice."""
    while True:
        choice = input(prompt).strip()
        if choice in valid_options:
            return choice
        print(f"❌ Invalid choice. Please enter one of: {', '.join(valid_options)}\n")


def get_vault_path() -> str:
    """Get vault path from user."""
    default = "vault.yaml"
    path = input(f"Vault file path (default: {default}): ").strip()
    return path if path else default


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

    vault_path = get_vault_path()

    # Check if vault exists
    if os.path.exists(vault_path):
        print(f"\n⚠️  Vault already exists at: {vault_path}")
        overwrite = get_choice("Do you want to overwrite it? (yes/no): ", ["yes", "no"])
        if overwrite == "no":
            print("❌ Cancelled.")
            return 0
        force = True
    else:
        force = False

    print("\nDo you want to:")
    print("  1. Create a new vault with new shares")
    print("  2. Import existing shares to create a vault with the same passphrase")
    choice = get_choice("Choice (1 or 2): ", ["1", "2"])

    if choice == "2":
        print("\n📋 Import Mode: You'll need to provide K existing shares.")
        print("This creates a new vault that uses the same master passphrase.")
        source_input = input("\nSource vault path (optional, for share index recovery): ").strip()
        source_vault: Optional[str] = source_input if source_input else None

        print("\nYou'll be prompted to enter shares during initialization.")
        return init_command(None, None, vault_path, force, None, source_vault)

    # New vault mode - let init_command handle the prompts
    print("\nYou'll be prompted for K (threshold) and N (total shares) next.")
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

    while True:
        print_menu()
        choice = get_choice("Enter your choice (0-7): ", ["0", "1", "2", "3", "4", "5", "6", "7"])

        if choice == "0":
            print("\n👋 Goodbye!\n")
            return 0
        elif choice == "1":
            result = handle_init()
            if result != 0:
                input("\nPress Enter to continue...")
        elif choice == "2":
            result = handle_encrypt()
            if result != 0:
                input("\nPress Enter to continue...")
        elif choice == "3":
            result = handle_decrypt()
            if result != 0:
                input("\nPress Enter to continue...")
        elif choice == "4":
            result = handle_list()
            if result != 0:
                input("\nPress Enter to continue...")
        elif choice == "5":
            result = handle_validate()
            if result != 0:
                input("\nPress Enter to continue...")
        elif choice == "6":
            result = handle_rotate()
            if result != 0:
                input("\nPress Enter to continue...")
        elif choice == "7":
            explain_system()

        print("\n")  # Spacing before next menu
