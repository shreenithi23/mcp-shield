"""Pydantic schemas for OAuth 2.1, DCR (RFC 7591), and Protected Resource Metadata (RFC 9728)."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl


class ClientRegistrationRequest(BaseModel):
    """RFC 7591 Dynamic Client Registration Request."""
    client_name: str = Field(..., description="Human-readable name of the agent or client")
    redirect_uris: List[str] = Field(..., min_length=1, description="Array of registered redirect URIs")
    grant_types: Optional[List[str]] = Field(
        default=["authorization_code"], description="OAuth grant types requested"
    )
    response_types: Optional[List[str]] = Field(
        default=["code"], description="OAuth response types requested"
    )
    token_endpoint_auth_method: Optional[str] = Field(
        default="none", description="Client authentication method ('none' for public PKCE agents)"
    )
    scope: Optional[str] = Field(default="mcp", description="Requested default scopes")


class ClientRegistrationResponse(BaseModel):
    """RFC 7591 Dynamic Client Registration Response."""
    client_id: str
    client_secret: Optional[str] = None
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str]
    response_types: List[str]
    token_endpoint_auth_method: str
    scope: Optional[str] = None
    client_id_issued_at: int


class TokenResponse(BaseModel):
    """OAuth 2.1 Token Response."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 300
    scope: str
    resource: str = Field(description="RFC 8707 resource indicator audience")


class IntrospectRequest(BaseModel):
    """RFC 7662 Introspection Request."""
    token: str
    token_type_hint: Optional[str] = None


class IntrospectResponse(BaseModel):
    """RFC 7662 Introspection Response."""
    active: bool
    sub: Optional[str] = None
    client_id: Optional[str] = None
    aud: Optional[str] = None
    task_id: Optional[str] = None
    scope: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None
    act: Optional[Dict[str, Any]] = None


class RevokeRequest(BaseModel):
    """RFC 7009 Revocation Request."""
    token: str
    token_type_hint: Optional[str] = None


class ProtectedResourceMetadata(BaseModel):
    """RFC 9728 Protected Resource Metadata."""
    resource: str = Field(description="The protected resource identifier URI")
    authorization_servers: List[str] = Field(
        description="List of OAuth 2.0 authorization server issuer URLs"
    )
    scopes_supported: Optional[List[str]] = Field(
        default=["mcp"], description="Scopes supported by the resource"
    )
    bearer_methods_supported: Optional[List[str]] = Field(
        default=["header"], description="Bearer token presentation methods"
    )
    resource_documentation: Optional[str] = None
