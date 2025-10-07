"""Manifest operations."""
import hashlib
from datetime import datetime, timezone
from typing import Dict

import yaml

from .models import Manifest, RotationEvent, Vault


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
