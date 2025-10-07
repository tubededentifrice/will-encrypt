"""Main CLI entry point."""
import argparse
import sys

from src.cli.decrypt import decrypt_command
from src.cli.encrypt import encrypt_command
from src.cli.init import init_command
from src.cli.list import list_command
from src.cli.rotate import rotate_command
from src.cli.validate import validate_command


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Will-encrypt: Threshold cryptography for emergency access"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize vault")
    init_parser.add_argument("--k", type=int, help="Threshold (K) - prompts if not provided")
    init_parser.add_argument("--n", type=int, help="Total shares (N) - prompts if not provided")
    init_parser.add_argument(
        "--vault", default="vault.yaml", help="Vault file path"
    )
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing")

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt message")
    encrypt_parser.add_argument("--vault", default="vault.yaml", help="Vault file")
    encrypt_parser.add_argument("--title", help="Message title - prompts if not provided")
    encrypt_parser.add_argument("--message", help="Message content - prompts if not provided")
    encrypt_parser.add_argument("--stdin", action="store_true", help="Read from stdin")

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt messages")
    decrypt_parser.add_argument("--vault", default="vault.yaml", help="Vault file")
    decrypt_parser.add_argument("--shares", nargs="+", help="BIP39 shares")

    # List command
    list_parser = subparsers.add_parser("list", help="List messages")
    list_parser.add_argument("--vault", default="vault.yaml", help="Vault file")
    list_parser.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )
    list_parser.add_argument(
        "--sort", choices=["id", "title", "created", "size"], default="id", help="Sort by"
    )

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate vault")
    validate_parser.add_argument("--vault", default="vault.yaml", help="Vault file")
    validate_parser.add_argument("--verbose", action="store_true", help="Verbose output")

    # Rotate command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate keys/shares")
    rotate_parser.add_argument("--vault", default="vault.yaml", help="Vault file")
    rotate_parser.add_argument(
        "--mode", choices=["shares", "passphrase"], required=True, help="Rotation mode"
    )
    rotate_parser.add_argument("--shares", nargs="+", help="Current shares")
    rotate_parser.add_argument("--new-k", type=int, help="New threshold (for rotation)")
    rotate_parser.add_argument("--new-n", type=int, help="New total shares (for rotation)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to command handlers
    if args.command == "init":
        return init_command(args.k, args.n, args.vault, args.force)
    elif args.command == "encrypt":
        return encrypt_command(
            args.vault, args.title, args.message, args.stdin
        )
    elif args.command == "decrypt":
        return decrypt_command(args.vault, args.shares)
    elif args.command == "list":
        return list_command(args.vault, args.format, args.sort)
    elif args.command == "validate":
        return validate_command(args.vault, args.verbose)
    elif args.command == "rotate":
        new_k = getattr(args, 'new_k', None)
        new_n = getattr(args, 'new_n', None)
        return rotate_command(args.vault, args.mode, new_k, new_n, args.shares)


if __name__ == "__main__":
    sys.exit(main())
