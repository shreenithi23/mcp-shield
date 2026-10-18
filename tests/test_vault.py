"""Tests for Credential Vault and envelope encryption."""

import pytest
from mcp_shield.vault.kms import FernetKMSProvider
from mcp_shield.vault.vault import CredentialVault


def test_envelope_encryption_stores_and_decrypts_secret():
    """Vault must encrypt with unique DEK, wrap with KMS KEK, and decrypt only in memory."""
    kms = FernetKMSProvider()
    vault = CredentialVault(kms_provider=kms)

    secret_pat = "github_pat_super_secret_canary_value_12345"
    server = "https://api.githubcopilot.com/mcp/"

    envelope = vault.store_credential(
        server_uri=server,
        mode="pat",
        secret=secret_pat,
        metadata={"repo": "owner/repo"},
    )

    # 1. Ciphertext must NOT contain plaintext secret
    assert secret_pat not in envelope.ciphertext
    assert secret_pat not in envelope.wrapped_dek

    # 2. Retrieval successfully decrypts
    decrypted = vault.get_credential(server_uri=server)
    assert decrypted == secret_pat


def test_vault_user_specific_credential_isolation():
    """User-specific OAuth credentials take precedence over global PAT."""
    vault = CredentialVault()
    server = "http://localhost:8001/mcp"

    vault.store_credential(server_uri=server, mode="pat", secret="global_secret")
    vault.store_credential(server_uri=server, mode="oauth", secret="alice_oauth_secret", user_id="user_alice")

    # Alice gets her specific credential
    assert vault.get_credential(server, user_id="user_alice") == "alice_oauth_secret"
    # Bob falls back to global
    assert vault.get_credential(server, user_id="user_bob") == "global_secret"
