"""Credential Vault with Envelope Encryption for upstream MCP servers."""

import os
from typing import Any, Dict, Literal, Optional
from cryptography.fernet import Fernet
from pydantic import BaseModel

from mcp_shield.vault.kms import BaseKMSProvider, FernetKMSProvider

CredentialMode = Literal["pat", "oauth"]


class EncryptedEnvelope(BaseModel):
    """Envelope-encrypted credential container."""
    server_uri: str
    mode: CredentialMode
    wrapped_dek: str  # Base64 string of KMS-encrypted DEK
    ciphertext: str   # Base64 string of DEK-encrypted secret
    metadata: Dict[str, Any] = {}


class CredentialVault:
    """Secure credential vault using envelope encryption.
    
    Generates a per-secret Data Encryption Key (DEK), encrypts the secret with the DEK,
    and wraps the DEK with the KMS provider's Key Encryption Key (KEK).
    Decryption happens in-memory only during authorized upstream request dispatch.
    """

    def __init__(self, kms_provider: Optional[BaseKMSProvider] = None):
        self.kms: BaseKMSProvider = kms_provider or FernetKMSProvider()
        self._store: Dict[str, EncryptedEnvelope] = {}
        self._init_default_github_credentials()

    def _init_default_github_credentials(self) -> None:
        """Loads GitHub PAT and test repo from environment if present."""
        pat = os.getenv("GITHUB_PAT")
        test_repo = os.getenv("GITHUB_TEST_REPO", "shreenithi23/mcp-shield-test")
        if pat:
            self.store_credential(
                server_uri="https://api.githubcopilot.com/mcp/",
                mode="pat",
                secret=pat,
                metadata={"scoped_repo": test_repo, "provider": "github"},
            )
        # Seed demo servers credentials
        self.store_credential(
            server_uri="http://slack-mcp/mcp",
            mode="pat",
            secret="xoxb-mock-slack-token",
            metadata={"provider": "slack"},
        )
        self.store_credential(
            server_uri="http://postgres-mcp/mcp",
            mode="pat",
            secret="postgres://app:secret@localhost:5432/main",
            metadata={"provider": "postgres"},
        )
        self.store_credential(
            server_uri="http://malicious-mcp/mcp",
            mode="pat",
            secret="malicious-upstream-token-123",
            metadata={"provider": "malicious"},
        )

    def store_credential(
        self,
        server_uri: str,
        mode: CredentialMode,
        secret: str,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> EncryptedEnvelope:
        """Stores a credential using envelope encryption."""
        # 1. Generate unique random DEK for this credential
        dek = Fernet.generate_key()
        fernet = Fernet(dek)

        # 2. Encrypt secret payload with DEK
        ciphertext = fernet.encrypt(secret.encode("utf-8")).decode("utf-8")

        # 3. Wrap (encrypt) the DEK using KMS KEK
        wrapped_dek = self.kms.encrypt_dek(dek).decode("utf-8")

        key = f"{server_uri}:{user_id or 'global'}"
        envelope = EncryptedEnvelope(
            server_uri=server_uri,
            mode=mode,
            wrapped_dek=wrapped_dek,
            ciphertext=ciphertext,
            metadata=metadata or {},
        )
        self._store[key] = envelope
        return envelope

    def get_credential(
        self,
        server_uri: str,
        user_id: Optional[str] = None,
    ) -> Optional[str]:
        """Unwraps the DEK and decrypts the secret strictly in-memory."""
        # Check user-specific credential first (for OAuth), then global (for PAT)
        key = f"{server_uri}:{user_id}" if user_id and f"{server_uri}:{user_id}" in self._store else f"{server_uri}:global"
        envelope = self._store.get(key)
        if not envelope:
            return None

        # 1. Unwrap DEK using KMS
        dek = self.kms.decrypt_dek(envelope.wrapped_dek.encode("utf-8"))

        # 2. Decrypt ciphertext using DEK
        fernet = Fernet(dek)
        decrypted = fernet.decrypt(envelope.ciphertext.encode("utf-8")).decode("utf-8")
        return decrypted

    def get_metadata(
        self,
        server_uri: str,
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves non-sensitive metadata for the credential."""
        key = f"{server_uri}:{user_id}" if user_id and f"{server_uri}:{user_id}" in self._store else f"{server_uri}:global"
        envelope = self._store.get(key)
        return envelope.metadata if envelope else None


# Global singleton vault instance
credential_vault = CredentialVault()
