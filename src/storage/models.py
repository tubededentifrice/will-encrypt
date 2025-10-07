"""
Data models for vault storage.

Based on: specs/001-1-purpose-scope/data-model.md
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Keypair:
    """Keypair with encrypted private keys."""

    rsa_public: str  # PEM format
    rsa_private_encrypted: str  # Base64
    kyber_public: str  # Base64
    kyber_private_encrypted: str  # Base64
    encryption_algorithm: str = "AES-256-GCM"
    kdf_algorithm: str = "PBKDF2-HMAC-SHA512"
    kdf_iterations: int = 600000
    kdf_salt: str = ""  # Base64

    def to_dict(self) -> Dict:
        return {
            "public": {
                "rsa_4096": self.rsa_public,
                "kyber_1024": self.kyber_public,
            },
            "encrypted_private": {
                "rsa_4096": self.rsa_private_encrypted,
                "kyber_1024": self.kyber_private_encrypted,
                "encryption": self.encryption_algorithm,
                "kdf": self.kdf_algorithm,
                "iterations": self.kdf_iterations,
                "salt": self.kdf_salt,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Keypair":
        return cls(
            rsa_public=data["public"]["rsa_4096"],
            kyber_public=data["public"]["kyber_1024"],
            rsa_private_encrypted=data["encrypted_private"]["rsa_4096"],
            kyber_private_encrypted=data["encrypted_private"]["kyber_1024"],
            encryption_algorithm=data["encrypted_private"]["encryption"],
            kdf_algorithm=data["encrypted_private"]["kdf"],
            kdf_iterations=data["encrypted_private"]["iterations"],
            kdf_salt=data["encrypted_private"]["salt"],
        )


@dataclass
class Message:
    """Encrypted message."""

    id: int
    title: str
    ciphertext: str  # Base64
    rsa_wrapped_kek: str  # Base64
    kyber_wrapped_kek: str  # Base64
    nonce: str  # Base64
    auth_tag: str  # Base64
    created: str  # ISO 8601
    size_bytes: int

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "created": self.created,
            "ciphertext": self.ciphertext,
            "rsa_wrapped_kek": self.rsa_wrapped_kek,
            "kyber_wrapped_kek": self.kyber_wrapped_kek,
            "nonce": self.nonce,
            "tag": self.auth_tag,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Message":
        return cls(
            id=data["id"],
            title=data["title"],
            created=data["created"],
            ciphertext=data["ciphertext"],
            rsa_wrapped_kek=data["rsa_wrapped_kek"],
            kyber_wrapped_kek=data["kyber_wrapped_kek"],
            nonce=data["nonce"],
            auth_tag=data["tag"],
            size_bytes=data["size_bytes"],
        )


@dataclass
class RotationEvent:
    """Key rotation history entry."""

    date: str  # ISO 8601
    event_type: str
    k: int
    n: int
    operator: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict:
        result = {
            "date": self.date,
            "event": self.event_type,
            "k": self.k,
            "n": self.n,
        }
        if self.operator:
            result["operator"] = self.operator
        if self.notes:
            result["notes"] = self.notes
        return result


@dataclass
class Manifest:
    """Vault manifest with metadata."""

    k: int
    n: int
    algorithms: Dict[str, str] = field(default_factory=dict)
    fingerprints: Dict[str, str] = field(default_factory=dict)
    rotation_history: List[RotationEvent] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "threshold": {"k": self.k, "n": self.n},
            "algorithms": self.algorithms,
            "fingerprints": self.fingerprints,
            "rotation_history": [e.to_dict() for e in self.rotation_history],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Manifest":
        rotation_events = []
        for e in data.get("rotation_history", []):
            # Handle both 'event' and 'event_type' keys
            event_type = e.get('event_type') or e.get('event', 'unknown')
            rotation_events.append(
                RotationEvent(
                    date=e['date'],
                    event_type=event_type,
                    k=e['k'],
                    n=e['n'],
                    operator=e.get('operator'),
                    notes=e.get('notes')
                )
            )

        return cls(
            k=data["threshold"]["k"],
            n=data["threshold"]["n"],
            algorithms=data.get("algorithms", {}),
            fingerprints=data.get("fingerprints", {}),
            rotation_history=rotation_events,
        )


@dataclass
class Vault:
    """Complete vault structure."""

    version: str
    created: str  # ISO 8601
    keys: Keypair
    messages: List[Message] = field(default_factory=list)
    manifest: Optional[Manifest] = None
    recovery_guide: str = ""
    policy_document: str = ""
    crypto_notes: str = ""

    def to_dict(self) -> Dict:
        result = {
            "version": self.version,
            "created": self.created,
            "keys": self.keys.to_dict(),
            "messages": [m.to_dict() for m in self.messages],
        }
        if self.manifest:
            result["manifest"] = self.manifest.to_dict()
        if self.recovery_guide:
            result["recovery_guide"] = self.recovery_guide
        if self.policy_document:
            result["policy_document"] = self.policy_document
        if self.crypto_notes:
            result["crypto_notes"] = self.crypto_notes
        return result
