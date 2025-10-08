# will-encrypt Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-10-07

## Active Technologies
- Python 3.11+ (standard library preferred)
- Dependencies: pyyaml>=6.0, cryptography>=41.0, mnemonic>=0.20, secretsharing>=0.2.6

## Project Structure
```
will-encrypt/
├── src/
│   ├── crypto/          # Cryptographic primitives
│   │   ├── shamir.py    # Shamir Secret Sharing over GF(256)
│   │   ├── bip39.py     # BIP39 mnemonic encoding/decoding
│   │   ├── passphrase.py # 256-bit passphrase generation
│   │   ├── keypair.py   # Hybrid RSA-4096 + Kyber-1024
│   │   └── encryption.py # AES-256-GCM message encryption
│   ├── storage/         # Data persistence
│   │   ├── models.py    # Type-safe data classes
│   │   ├── vault.py     # YAML vault operations
│   │   └── manifest.py  # Fingerprints and rotation
│   ├── cli/             # Command implementations
│   │   ├── init.py      # Initialize vault (with share import)
│   │   ├── encrypt.py   # Encrypt messages
│   │   ├── decrypt.py   # Decrypt with K shares
│   │   ├── list.py      # List messages
│   │   ├── validate.py  # Verify vault integrity
│   │   ├── rotate.py    # Rotate shares/passphrase
│   │   └── interactive.py # Interactive mode UI
│   ├── docs/            # Generated documentation
│   └── main.py          # CLI entry point
├── tests/
│   ├── unit/            # 88 unit tests
│   ├── contract/        # 45 contract tests
│   ├── integration/     # 38 integration tests
│   └── test_helpers.py  # Shared test utilities
├── README.md            # Comprehensive user guide (1,333 lines)
├── EXAMPLE_IMPORT_SHARES.md
└── IMPLEMENTATION_SUMMARY.md
```

## Commands

### Development
```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install in editable mode
pip install -e .

# Run tests
pytest                              # All tests (defaults to -n auto across available cores)
pytest -n 12                        # Force 12 workers when auto-detection is unavailable
pytest tests/unit/ -v               # Unit tests only (parallel by default)
pytest tests/integration/ -v        # Integration tests only (parallel by default)
pytest tests/contract/ -v           # Contract tests (CLI flows)
pytest --cov=src                    # With coverage report (htmlcov/) - ~74% coverage
python -m pytest tests/ -v --tb=short

# Linting and type checking
ruff check src tests                # Lint and auto-format hints (100-char lines)
mypy src tests                      # Enforce typing rules

# Run CLI experiments
./will-encrypt <command>              # After pip install -e .
python -m src.main <command>        # Alternative invocation

# Interactive mode (no arguments)
./will-encrypt                        # Launches guided menu for all operations
```

### CLI Usage
```bash
# Interactive mode (recommended for non-technical users)
./will-encrypt                        # Launches guided menu system

# Initialize vault (supports --import-share for reusing BIP39 shares)
./will-encrypt init --k 3 --n 5 --vault vault.yaml

# Import existing shares to create vault with same passphrase
./will-encrypt init --k 3 --n 5 --vault vault2.yaml \
  --source-vault vault1.yaml \
  --import-share "word1 word2 ... word24" \
  --import-share "word1 word2 ... word24" \
  --import-share "word1 word2 ... word24"

# Encrypt message (interactive prompts if args omitted)
./will-encrypt encrypt --vault vault.yaml --title "Title" --message "Text"

# Decrypt messages with K shares
./will-encrypt decrypt --vault vault.yaml --shares "share1..." "share2..." "share3..."

# List messages
./will-encrypt list --vault vault.yaml --format table --sort created

# Validate vault integrity
./will-encrypt validate --vault vault.yaml --verbose

# Rotate shares or passphrase
./will-encrypt rotate --vault vault.yaml --mode shares --new-k 4 --new-n 7
./will-encrypt rotate --vault vault.yaml --mode passphrase
```

## Code Style
- Python 3.11+ with explicit type hints throughout
- Ruff enforces 100-character lines, import order, and dead-code trimming
- Run `ruff check src tests` before committing
- `mypy` rejects untyped definitions and implicit optionals
- snake_case for modules, functions, and variables
- PascalCase only for classes
- Use dataclasses for models
- Prefer standard library over external dependencies
- Keep docstrings concise, focus on cryptographic assumptions or side effects
- All cryptographic operations must be auditable
- Error messages must include recovery suggestions
- Progress indicators for operations > 1 second
- Ensure concise comments are added (favor conciseness over grammar) whenever what/why/intent isn't trivially self-explanatory.

## Testing Requirements
- TDD approach: write tests before implementation
- Pytest discovers files named `test_*.py`, classes starting with `Test`, functions beginning `test_`
- Mirror production modules in matching directories (e.g., `src/crypto/shamir.py` → `tests/unit/test_shamir.py`)
- 100% test coverage for cryptographic primitives
- All CLI commands must have contract tests in `tests/contract/`
- Contract tests should exercise CLI flows end-to-end using CLI entry points
- Integration tests for full workflows in `tests/integration/`
- Use `tests/test_helpers.py` for shared test utilities (vault creation, message encryption, etc.)
- Maintain current coverage with `pytest --cov=src`; treat drops as blockers
- Parallel test execution is required; default configuration runs with `-n auto --dist loadscope`
- Override worker count with `PYTEST_ADDOPTS="-n 12"` when needed (CI, constrained hosts)
- Current status: **171/171 tests passing (100% pass rate), 74% code coverage**
- IMPORTANT: After making changes, before returning to the user:
  - Ensure all tests are still passing and iterate until everything passes
  - Ensure documentations are up to date (AGENTS.md and README.md)

## Security Requirements
- 256-bit passphrase entropy minimum
- PBKDF2-HMAC-SHA512 with 600K iterations
- Shares never written to disk
- Private keys encrypted at rest
- File permissions: 0600 for vault files
- BIP39 checksums for error detection
- Vault fingerprints for tamper detection
- **Never commit real vaults, mnemonic shares, or private keys**
- Use demo artifacts only for docs and reproducible tests
- Environment overrides belong in ignored `.env` files, not tracked configs
- When touching encryption or storage, confirm temporary files are removed
- Mention any deviation from zero-trust assumptions in code reviews

## Implementation Status
✅ Core Features (Production-Ready):
- K-of-N threshold vault initialization
- Hybrid RSA-4096 + Kyber-1024 encryption
- Shamir Secret Sharing over GF(256)
- BIP39 24-word mnemonics for shares
- AES-256-GCM authenticated encryption
- Share and passphrase rotation
- Vault integrity validation
- Share import for multi-vault scenarios

✅ UX Enhancements:
- Interactive prompts (K, N, title, message, shares)
- Progress indicators ([1/4] Task... ✓ Done)
- Enhanced error messages with recovery suggestions
- BIP39 checksum validation with retry logic
- Pretty-printed output with boxes and emojis
- Share index auto-recovery via manifest-managed fingerprints (supports unlabeled imports)
  - `init --source-vault` flag overrides environment-based manifest detection

✅ Test Coverage (171 tests, 74% code coverage):
- **Unit Tests (88)**: Crypto primitives, storage, CLI wiring
- **Contract Tests (45)**: CLI commands (init, encrypt, decrypt, list, validate, rotate)
- **Integration Tests (38)**: Full lifecycle, emergency recovery, share rotation, validation audit
- All tests passing with comprehensive coverage of security features

## Commit & Pull Request Guidelines
- History favors short, imperative subjects (e.g., "Add comprehensive UX enhancements")
- Include focused bodies explaining reasoning or follow-ups
- Group related changes per commit
- PRs should provide:
  - Concise summary
  - Linked spec or issue
  - Documentation updates when behavior shifts
  - Command transcripts or screenshots for user-facing changes
- Call out security-sensitive adjustments (key handling, share rotation, secret storage)
- List manual verification steps

## Known Limitations
- No CLI colors yet (future enhancement)
- Command-line only (by design)
