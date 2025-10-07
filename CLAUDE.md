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
│   │   └── rotate.py    # Rotate shares/passphrase
│   ├── docs/            # Generated documentation
│   └── main.py          # CLI entry point
├── tests/
│   ├── unit/            # 50 unit tests
│   ├── contract/        # 35 contract tests
│   └── integration/     # 42 integration tests
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
pytest                              # All 127 tests
pytest tests/unit/ -v               # Unit tests only
pytest tests/integration/ -v        # Integration tests only
python -m pytest tests/ -v --tb=short

# Linting
ruff check .
```

### CLI Usage
```bash
# Initialize vault (supports --import-share for reusing BIP39 shares)
will-encrypt init --k 3 --n 5 --vault vault.yaml

# Import existing shares to create vault with same passphrase
will-encrypt init --k 3 --n 5 --vault vault2.yaml \
  --import-share "word1 word2 ... word24" \
  --import-share "word1 word2 ... word24" \
  --import-share "word1 word2 ... word24"

# Encrypt message (interactive prompts if args omitted)
will-encrypt encrypt --vault vault.yaml --title "Title" --message "Text"

# Decrypt messages with K shares
will-encrypt decrypt --vault vault.yaml --shares "share1..." "share2..." "share3..."

# List messages
will-encrypt list --vault vault.yaml --format table --sort created

# Validate vault integrity
will-encrypt validate --vault vault.yaml --verbose

# Rotate shares or passphrase
will-encrypt rotate --vault vault.yaml --mode shares --new-k 4 --new-n 7
will-encrypt rotate --vault vault.yaml --mode passphrase
```

## Code Style
- Python 3.11+ with type hints throughout
- Follow PEP 8 conventions
- Use dataclasses for models
- Prefer standard library over external dependencies
- All cryptographic operations must be auditable
- Error messages must include recovery suggestions
- Progress indicators for operations > 1 second

## Testing Requirements
- TDD approach: write tests before implementation
- 100% test coverage for cryptographic primitives
- All CLI commands must have contract tests
- Integration tests for full workflows
- Current status: 127/127 tests passing (100%)

## Security Requirements
- 256-bit passphrase entropy minimum
- PBKDF2-HMAC-SHA512 with 600K iterations
- Shares never written to disk
- Private keys encrypted at rest
- File permissions: 0600 for vault files
- BIP39 checksums for error detection
- Vault fingerprints for tamper detection

## Recent Changes
- 001-1-purpose-scope: Initial implementation
  - Complete threshold cryptography system
  - All 6 CLI commands functional
  - 127/127 tests passing
  - Comprehensive README (1,333 lines)
  - Interactive CLI with progress indicators
  - Share import feature for multi-vault passphrase reuse

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

## Known Limitations
- Kyber-1024 currently simulated with RSA (architecture ready for pqcrypto)
- No CLI colors yet (future enhancement)
- Command-line only (by design)

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->