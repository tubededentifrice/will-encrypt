"""Vault YAML operations."""
import os
from datetime import UTC, datetime

import yaml

from .models import Keypair, Manifest, Message, Vault


def create_vault(
    keypair_data: dict, manifest: Manifest, guides: dict[str, str]
) -> Vault:
    """Create new vault with keypair and manifest."""
    keypair = Keypair(
        rsa_public=keypair_data["rsa_public"],
        rsa_private_encrypted=keypair_data["rsa_private_encrypted"],
        kyber_public=keypair_data["kyber_public"],
        kyber_private_encrypted=keypair_data["kyber_private_encrypted"],
        kdf_salt=keypair_data["kdf_salt"],
        kdf_iterations=keypair_data.get("kdf_iterations", 600000),
    )

    vault = Vault(
        version="1.0",
        created=datetime.now(UTC).isoformat(),
        keys=keypair,
        manifest=manifest,
        recovery_guide=guides.get("recovery_guide", ""),
        policy_document=guides.get("policy_document", ""),
        crypto_notes=guides.get("crypto_notes", ""),
    )
    return vault


class LiteralString(str):
    """String subclass to force YAML literal block scalar style."""
    pass


def literal_representer(dumper: yaml.Dumper, data: str) -> yaml.ScalarNode:
    """Represent LiteralString as literal block scalar (|) in YAML."""
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


# Create custom dumper class to ensure representer is used
class LiteralDumper(yaml.SafeDumper):
    pass


LiteralDumper.add_representer(LiteralString, literal_representer)


def save_vault(vault: Vault, path: str) -> None:
    """Save vault to YAML file with 0600 permissions."""
    data = vault.to_dict()

    # Convert multi-line text fields to use literal block scalar style
    if data.get('recovery_guide'):
        data['recovery_guide'] = LiteralString(data['recovery_guide'])
    if data.get('policy_document'):
        data['policy_document'] = LiteralString(data['policy_document'])
    if data.get('crypto_notes'):
        data['crypto_notes'] = LiteralString(data['crypto_notes'])

    with open(path, "w") as f:
        yaml.dump(
            data,
            f,
            Dumper=LiteralDumper,
            default_flow_style=False,
            sort_keys=False,
            width=float('inf'),
            allow_unicode=True
        )
    os.chmod(path, 0o600)


def load_vault(path: str) -> Vault:
    """Load vault from YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    keypair = Keypair.from_dict(data["keys"])
    messages = [Message.from_dict(m) for m in data.get("messages", [])]
    manifest = Manifest.from_dict(data["manifest"]) if "manifest" in data else None

    return Vault(
        version=data["version"],
        created=data["created"],
        keys=keypair,
        messages=messages,
        manifest=manifest,
        recovery_guide=data.get("recovery_guide", ""),
        policy_document=data.get("policy_document", ""),
        crypto_notes=data.get("crypto_notes", ""),
    )


def append_message(vault: Vault, message: Message) -> Vault:
    """Append message to vault."""
    vault.messages.append(message)
    return vault


def update_manifest(vault: Vault, manifest: Manifest) -> Vault:
    """Update vault manifest."""
    vault.manifest = manifest
    return vault


def _normalize_message_id(message_id: int | str) -> int:
    """Convert message_id to int if string."""
    return int(message_id) if isinstance(message_id, str) else message_id


def delete_message(vault: Vault, message_id: int | str) -> Vault:
    """Delete message from vault by ID."""
    msg_id = _normalize_message_id(message_id)

    original_count = len(vault.messages)
    vault.messages = [m for m in vault.messages if m.id != msg_id]
    if len(vault.messages) == original_count:
        raise ValueError(f"Message with ID '{msg_id}' not found in vault")
    return vault


def edit_message_title(vault: Vault, message_id: int | str, new_title: str) -> Vault:
    """Edit message title by ID."""
    msg_id = _normalize_message_id(message_id)

    for message in vault.messages:
        if message.id == msg_id:
            message.title = new_title
            return vault
    raise ValueError(f"Message with ID '{msg_id}' not found in vault")
