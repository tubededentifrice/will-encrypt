## Priority: Critical

### Replace simulated Kyber layer with an actual post-quantum KEM
- **What to change**: Swap the RSA placeholder in `generate_kyber_keypair` and the hybrid wrap/unwrap routines with a real NIST-selected CRYSTALS-Kyber implementation (e.g., via `liboqs`/`pqcrypto`), persist the genuine Kyber public key material, and update load/save paths to treat it as such (`src/crypto/keypair.py:52-188`, `src/cli/encrypt.py:54-77`, `src/cli/decrypt.py:85-124`). Keep the RSA leg for classical resilience, but ensure the Kyber path actually exercises lattice-based encapsulation/decapsulation.
- **Why**: Right now both “RSA” and “Kyber” legs are the same RSA-4096 keypair, so defeating RSA breaks the entire hybrid (`src/crypto/keypair.py:63-78`). A quantum-capable adversary can run Shor’s algorithm to recover the private key, making long-term secrecy (<40 years) impossible.
- **Risks associated with the change**: Additional dependency on PQ libraries, larger key material, and the need for new serialization/compatibility tests. Watch for FIPS requirements and side-channel hardening in the chosen bindings.
- **Threat model concerned**: Nation-state or future adversaries capturing ciphertext today for “harvest-now, decrypt-later” attacks once scalable quantum computers exist.
