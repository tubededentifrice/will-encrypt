"""Unit tests for storage manifest helpers."""

import base64
from datetime import UTC, datetime

import pytest

from src.storage.manifest import (
    compute_fingerprints,
    create_share_fingerprint,
    create_share_fingerprints,
    match_share_fingerprint,
    validate_fingerprints,
)
from src.storage.models import Keypair, Manifest, ShareFingerprint, Vault


def _build_sample_vault() -> Vault:
    keypair = Keypair(
        rsa_public="-----BEGIN PUBLIC KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQCy\n-----END PUBLIC KEY-----",
        rsa_private_encrypted=base64.b64encode(b"rsa-private").decode(),
        kyber_public=base64.b64encode(b"kyber-public").decode(),
        kyber_private_encrypted=base64.b64encode(b"kyber-private").decode(),
        kdf_salt=base64.b64encode(b"salt" * 8).decode(),
    )
    manifest = Manifest(k=3, n=5)
    return Vault(
        version="1.0",
        created=datetime.now(UTC).isoformat(),
        keys=keypair,
        manifest=manifest,
    )


def test_compute_and_validate_fingerprints() -> None:
    vault = _build_sample_vault()
    fingerprints = compute_fingerprints(vault)
    assert set(fingerprints) == {
        "rsa_public_key_sha256",
        "kyber_public_key_sha256",
        "vault_sha256",
    }

    assert vault.manifest is not None
    vault.manifest.fingerprints = fingerprints
    assert validate_fingerprints(vault) is True

    vault.manifest.fingerprints["rsa_public_key_sha256"] = "deadbeef"
    assert validate_fingerprints(vault) is False

    vault.manifest = None
    assert validate_fingerprints(vault) is False


def test_create_share_fingerprint_validates_inputs() -> None:
    with pytest.raises(TypeError, match="share_data must be bytes"):
        create_share_fingerprint(1, "not-bytes")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="share_data must be 32 bytes"):
        create_share_fingerprint(1, b"short")

    salt = b"s" * 32
    share = b"a" * 32
    fingerprint = create_share_fingerprint(7, share, salt=salt)
    assert fingerprint.index == 7
    assert fingerprint.algorithm == "sha256"
    # Deterministic when salt provided.
    assert fingerprint.hash == create_share_fingerprint(7, share, salt=salt).hash


def test_create_share_fingerprints_enforces_structure() -> None:
    valid_share = bytes([1]) + (b"a" * 32)
    fingerprints = create_share_fingerprints([valid_share])
    assert len(fingerprints) == 1
    assert fingerprints[0].index == 1

    with pytest.raises(TypeError, match="Each share must be bytes"):
        create_share_fingerprints(["not-bytes"])  # type: ignore[list-item]

    with pytest.raises(ValueError, match="Each share must be 33 bytes"):
        create_share_fingerprints([b"too-short"])


def test_match_share_fingerprint_handles_variants() -> None:
    share_payload = b"p" * 32
    explicit_salt = b"salt" * 8
    good = create_share_fingerprint(3, share_payload, salt=explicit_salt)
    wrong_algo = ShareFingerprint(index=4, salt=good.salt, hash=good.hash, algorithm="sha1")
    malformed = ShareFingerprint(index=5, salt="zz", hash="00", algorithm="sha256")

    match = match_share_fingerprint([wrong_algo, malformed, good], share_payload)
    assert match is good

    no_match = match_share_fingerprint([wrong_algo], share_payload)
    assert no_match is None

    with pytest.raises(TypeError, match="share_data must be bytes"):
        match_share_fingerprint([good], "not-bytes")  # type: ignore[arg-type]
