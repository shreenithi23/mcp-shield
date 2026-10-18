"""Key Management Service (KMS) abstractions and Fernet provider for envelope encryption."""

import base64
import os
from abc import ABC, abstractmethod
from typing import Optional
from cryptography.fernet import Fernet

from mcp_shield.config import settings


class BaseKMSProvider(ABC):
    """Abstract KMS Provider for wrapping and unwrapping Data Encryption Keys (DEKs)."""

    @abstractmethod
    def encrypt_dek(self, dek: bytes) -> bytes:
        """Wraps (encrypts) a Data Encryption Key using the Key Encryption Key (KEK)."""
        pass

    @abstractmethod
    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        """Unwraps (decrypts) an encrypted Data Encryption Key using the Key Encryption Key."""
        pass


class FernetKMSProvider(BaseKMSProvider):
    """Prototype KMS provider utilizing Fernet symmetric encryption."""

    def __init__(self, master_key: Optional[str] = None):
        # Master key (KEK) can be configured via environment or generated locally
        raw_key = master_key or os.getenv("VAULT_MASTER_KEY")
        if not raw_key:
            # Generate deterministic fallback or random key for dev/test
            raw_key = Fernet.generate_key().decode("utf-8")
        if isinstance(raw_key, str):
            raw_key = raw_key.encode("utf-8")
        self._fernet = Fernet(raw_key)

    def encrypt_dek(self, dek: bytes) -> bytes:
        return self._fernet.encrypt(dek)

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        return self._fernet.decrypt(encrypted_dek)
