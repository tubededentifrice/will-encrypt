# Emergency Vault Share

This is a share used to decrypt the emergency vault.

## Important Information

- **This share alone cannot decrypt anything** - you need K shares (as specified in the vault) to access the encrypted data
- The vault.yaml file contains the encrypted data and is typically stored in a secure but shared location
- **You do NOT need to track the share number** - the system automatically detects which share this is using secure fingerprints

## How to Use

1. Install the decryption tool from: https://github.com/tubededentifrice/will-encrypt
2. Gather K shares from other key holders (minimum required shares specified in vault)
3. Run: `./will-encrypt decrypt --vault vault.yaml`
4. Enter your 24-word share when prompted (just the words - share number is detected automatically)
5. The vault will decrypt if enough valid shares are provided

## Storage Recommendations

- Store in a password manager (1Password, Bitwarden, etc.)
- Write on paper and keep in a fireproof safe
- Hardware security module (YubiKey, Ledger)
- Never share with other key holders
- Never store together with the vault file

## Questions?

See the full documentation at: https://github.com/tubededentifrice/will-encrypt
