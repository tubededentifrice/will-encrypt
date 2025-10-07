# Security Review

## Priority: Critical

### Replace simulated Kyber layer with an actual post-quantum KEM
- **What to change**: Swap the RSA placeholder in `generate_kyber_keypair` and the hybrid wrap/unwrap routines with a real NIST-selected CRYSTALS-Kyber implementation (e.g., via `liboqs`/`pqcrypto`), persist the genuine Kyber public key material, and update load/save paths to treat it as such (`src/crypto/keypair.py:52-188`, `src/cli/encrypt.py:54-77`, `src/cli/decrypt.py:85-124`). Keep the RSA leg for classical resilience, but ensure the Kyber path actually exercises lattice-based encapsulation/decapsulation.
- **Why**: Right now both “RSA” and “Kyber” legs are the same RSA-4096 keypair, so defeating RSA breaks the entire hybrid (`src/crypto/keypair.py:63-78`). A quantum-capable adversary can run Shor’s algorithm to recover the private key, making long-term secrecy (<40 years) impossible.
- **Risks associated with the change**: Additional dependency on PQ libraries, larger key material, and the need for new serialization/compatibility tests. Watch for FIPS requirements and side-channel hardening in the chosen bindings.
- **Threat model concerned**: Nation-state or future adversaries capturing ciphertext today for “harvest-now, decrypt-later” attacks once scalable quantum computers exist.

## Priority: High

### Preserve Shamir share indices through BIP39 encoding
- **What to change**: Include the 1-byte share index when producing mnemonics (e.g., prefix the index or encode 33 bytes) and require callers to submit the original index during reconstruction (`src/cli/init.py:170-187`, `src/cli/decrypt.py:85-91`). Update decoding to use the stored index instead of reassigning sequential counters.
- **Why**: Encoding drops the index (`encode_share(share[1:])`), and decryption blindly re-numbers shares (`share_bytes.append(bytes([i]) + decoded)`). Any reconstruction that omits an original “Share 1..k” or presents shares out of order uses the wrong x-coordinates, causing permanent data loss despite having K valid shares—violating the availability promise of K-of-N secret sharing.
- **Risks associated with the change**: Regenerating fixtures/tests and reprinting any demo mnemonics. No migration risk today, but future backwards compatibility must be considered once artifacts exist.
- **Threat model concerned**: Operational failures or malicious reordering that denies recovery (availability attack) even when enough honest share holders participate.

## Priority: Medium

### Align passphrase entropy claims with the actual implementation
- **What to change**: Update user-facing messaging and manifest metadata to reflect a 256-bit passphrase, or restore 384-bit entropy end-to-end if that level is required (`src/cli/init.py:175`, `src/crypto/passphrase.py:7-24`, manifest generation at `src/cli/init.py:194-204`).
- **Why**: The CLI announces “Generating 384-bit passphrase...” and the manifest records `passphrase_entropy: 384`, but `generate_passphrase()` returns 32 random bytes (256 bits). The mismatch can derail audits and lead defenders to overestimate brute-force margins.
- **Risks associated with the change**: Documentation churn and potential need to resize shares/tests if you revert to 384 bits; sticking with 256 bits simply needs consistent wording.
- **Threat model concerned**: Governance/compliance reviewers making risk decisions based on overstated entropy, potentially relaxing other compensating controls.
