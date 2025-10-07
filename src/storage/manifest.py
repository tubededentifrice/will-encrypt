"""Manifest operations."""
import hashlib
import secrets
from typing import Dict, Iterable, List, Optional

import yaml

from .models import Manifest, RotationEvent, ShareFingerprint, Vault


def compute_fingerprints(vault: Vault) -> Dict[str, str]:
    """Compute SHA-256 fingerprints."""
    return {
        "rsa_public_key_sha256": hashlib.sha256(
            vault.keys.rsa_public.encode()
        ).hexdigest(),
        "kyber_public_key_sha256": hashlib.sha256(
            vault.keys.kyber_public.encode()
        ).hexdigest(),
        "vault_sha256": hashlib.sha256(
            yaml.dump(vault.to_dict()).encode()
        ).hexdigest(),
    }


def validate_fingerprints(vault: Vault) -> bool:
    """Validate vault fingerprints."""
    if not vault.manifest:
        return False
    computed = compute_fingerprints(vault)
    stored = vault.manifest.fingerprints
    return (
        computed["rsa_public_key_sha256"] == stored.get("rsa_public_key_sha256")
        and computed["kyber_public_key_sha256"]
        == stored.get("kyber_public_key_sha256")
    )


def append_rotation_event(manifest: Manifest, event: RotationEvent) -> Manifest:
    """Append rotation event to manifest."""
    manifest.rotation_history.append(event)
    return manifest


def create_rotation_event(date: str, event_type: str, k: int, n: int) -> RotationEvent:
    """Create a rotation event."""
    return RotationEvent(date=date, event_type=event_type, k=k, n=n)


def _compute_share_hash(salt_hex: str, share_data: bytes) -> str:
    """Compute SHA-256 digest for the provided share bytes using hex salt."""
    salt_bytes = bytes.fromhex(salt_hex)
    return hashlib.sha256(salt_bytes + share_data).hexdigest()


def create_share_fingerprint(index: int, share_data: bytes, *, salt: Optional[bytes] = None) -> ShareFingerprint:
    """Create a salted fingerprint entry for a single share payload."""
    if not isinstance(share_data, (bytes, bytearray)):
        raise TypeError("share_data must be bytes")
    if len(share_data) != 32:
        raise ValueError(f"share_data must be 32 bytes, got {len(share_data)}")
    random_salt = salt or secrets.token_bytes(32)
    salt_hex = random_salt.hex()
    digest = _compute_share_hash(salt_hex, share_data)
    return ShareFingerprint(index=index, salt=salt_hex, hash=digest, algorithm="sha256")


def create_share_fingerprints(shares: Iterable[bytes]) -> List[ShareFingerprint]:
    """Generate fingerprint entries for an iterable of indexed shares."""
    fingerprints: List[ShareFingerprint] = []
    for share in shares:
        if not isinstance(share, (bytes, bytearray)):
            raise TypeError("Each share must be bytes")
        if len(share) != 33:
            raise ValueError(f"Each share must be 33 bytes, got {len(share)}")
        index = share[0]
        data = bytes(share[1:])
        fingerprints.append(create_share_fingerprint(index, data))
    return fingerprints


def match_share_fingerprint(
    fingerprints: Iterable[ShareFingerprint], share_data: bytes
) -> Optional[ShareFingerprint]:
    """Match share payload against stored fingerprints to recover index."""
    if not isinstance(share_data, (bytes, bytearray)):
        raise TypeError("share_data must be bytes")
    for fingerprint in fingerprints:
        if fingerprint.algorithm != "sha256":
            continue
        try:
            digest = _compute_share_hash(fingerprint.salt, share_data)
        except ValueError:
            # Skip malformed salt entries gracefully
            continue
        if digest == fingerprint.hash:
            return fingerprint
    return None
