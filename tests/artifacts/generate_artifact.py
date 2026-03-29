#!/usr/bin/env python3
"""Generate frozen vault artifacts for backward compatibility testing.

Standalone script — run manually when the vault format or crypto pipeline changes.
Generated artifacts are immutable; the script refuses to overwrite existing directories.

Usage:
    python tests/artifacts/generate_artifact.py --name v1.0_initial --messages 1
    python tests/artifacts/generate_artifact.py --name v1.0_multi_message --messages 3
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Ensure project root is on sys.path so imports work when run standalone
_project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_project_root))

from tests.test_helpers import extract_shares_from_output  # noqa: E402


# Deterministic test messages — same content every run for a given index
def _test_title(n: int) -> str:
    return f"Backward Compat Test Message {n}"


def _test_plaintext(n: int) -> str:
    return f"This is test message {n} for backward compatibility."


def generate_artifact(name: str, num_messages: int, k: int = 3, n: int = 5) -> None:
    artifacts_dir = Path(__file__).resolve().parent
    target_dir = artifacts_dir / name

    if target_dir.exists():
        print(
            f"Error: {target_dir} already exists. Frozen artifacts are immutable.\n"
            f"Delete manually if you really need to regenerate: rm -rf {target_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Late imports so the project doesn't need to be installed to parse --help
    import tempfile

    from src.cli.encrypt import encrypt_command
    from src.cli.init import init_command

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = str(Path(tmpdir) / "vault.yaml")

        # 1. Init vault, capture stdout to extract shares
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            rc = init_command(k=k, n=n, vault_path=vault_path, import_shares=[])
        finally:
            sys.stdout = old_stdout

        if rc != 0:
            print(f"Error: init_command returned {rc}", file=sys.stderr)
            sys.exit(1)

        output = captured.getvalue()
        shares = extract_shares_from_output(output)
        if len(shares) != n:
            print(
                f"Error: expected {n} shares, extracted {len(shares)}",
                file=sys.stderr,
            )
            sys.exit(1)

        # 2. Encrypt messages
        messages_meta: list[dict] = []
        for i in range(1, num_messages + 1):
            title = _test_title(i)
            plaintext = _test_plaintext(i)

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()  # suppress encrypt output
            try:
                rc = encrypt_command(
                    vault_path=vault_path, title=title, message_text=plaintext,
                )
            finally:
                sys.stdout = old_stdout

            if rc != 0:
                print(f"Error: encrypt_command returned {rc} for message {i}", file=sys.stderr)
                sys.exit(1)

            plaintext_bytes = plaintext.encode("utf-8")
            messages_meta.append({
                "id": i,
                "title": title,
                "plaintext": plaintext,
                "size_bytes": len(plaintext_bytes),
            })

        # 3. Write artifact directory
        target_dir.mkdir(parents=True)

        # Copy vault
        import shutil
        shutil.copy2(str(vault_path), str(target_dir / "vault.yaml"))

        # Write shares.json
        shares_data = {"k": k, "n": n, "shares": shares}
        (target_dir / "shares.json").write_text(
            json.dumps(shares_data, indent=2) + "\n", encoding="utf-8",
        )

        # Write metadata.json
        metadata = {
            "format_version": "1.0",
            "description": f"{num_messages}-message vault for backward compat testing",
            "created_by": "generate_artifact.py",
            "created_at": datetime.now(UTC).isoformat(),
            "threshold": {"k": k, "n": n},
            "messages": messages_meta,
        }
        (target_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8",
        )

    print(f"Artifact generated: {target_dir}")
    print("  vault.yaml, shares.json, metadata.json")
    print(f"  {num_messages} message(s), k={k}, n={n}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate frozen vault artifacts for backward compatibility testing.",
    )
    parser.add_argument(
        "--name", required=True,
        help="Artifact directory name (e.g. v1.0_initial)",
    )
    parser.add_argument(
        "--messages", type=int, default=1,
        help="Number of test messages to encrypt (default: 1)",
    )
    parser.add_argument("--k", type=int, default=3, help="Threshold (default: 3)")
    parser.add_argument("--n", type=int, default=5, help="Total shares (default: 5)")

    args = parser.parse_args()
    generate_artifact(name=args.name, num_messages=args.messages, k=args.k, n=args.n)


if __name__ == "__main__":
    main()
