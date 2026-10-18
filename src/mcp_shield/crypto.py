"""Cryptographic utilities for RS256 JWT, JWKS, and PKCE RFC 7636."""

import base64
import hashlib
import time
import uuid
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import ExpiredTokenError, JoseError

from mcp_shield.config import settings


class CryptoManager:
    """Manages RSA keys, JWKS export, and RS256 token signing/verification."""

    def __init__(self, key_id: Optional[str] = None):
        self.kid = key_id or settings.JWT_KEY_ID
        self._private_key: rsa.RSAPrivateKey = self._init_private_key()
        self._public_key: rsa.RSAPublicKey = self._private_key.public_key()
        self._jwk: Dict[str, Any] = self._init_jwk()

    def _init_private_key(self) -> rsa.RSAPrivateKey:
        if settings.JWT_PRIVATE_KEY_PEM:
            return serialization.load_pem_private_key(
                settings.JWT_PRIVATE_KEY_PEM.encode("utf-8"),
                password=None,
            )
        if settings.JWT_PRIVATE_KEY_PATH:
            with open(settings.JWT_PRIVATE_KEY_PATH, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        
        # Generate persistent or in-memory 2048-bit RSA key
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    def _init_jwk(self) -> Dict[str, Any]:
        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key = JsonWebKey.import_key(pub_pem, {"kty": "RSA"})
        jwk_dict = key.as_dict()
        jwk_dict.update({
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
        })
        return jwk_dict

    def get_jwks(self) -> Dict[str, Any]:
        """Returns standard RFC 7517 JWKS dictionary."""
        return {"keys": [self._jwk]}

    def get_private_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign_access_token(
        self,
        sub: str,
        client_id: str,
        aud: str,
        task_id: str,
        act: Optional[Dict[str, Any]] = None,
        scope: str = "mcp",
        expires_in: Optional[int] = None,
        jti: Optional[str] = None,
        dpop_jkt: Optional[str] = None,
        authorization_details: Optional[Any] = None,
    ) -> str:
        """Issues an RS256-signed JWT access token bound to a single audience and optional DPoP key."""
        now = int(time.time())
        exp = now + (expires_in if expires_in is not None else settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        
        header = {
            "alg": "RS256",
            "typ": "at+jwt",
            "kid": self.kid,
        }
        payload = {
            "iss": settings.BASE_URL,
            "sub": sub,
            "client_id": client_id,
            "aud": aud,  # RFC 8707 Resource Indicator (single resource URI)
            "task_id": task_id,
            "scope": scope,
            "jti": jti or str(uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "exp": exp,
        }
        if act:
            payload["act"] = act
        if dpop_jkt:
            payload["cnf"] = {"jkt": dpop_jkt}
        if authorization_details:
            payload["authorization_details"] = authorization_details

        encoded = jwt.encode(header, payload, self.get_private_pem())
        return encoded.decode("utf-8") if isinstance(encoded, bytes) else encoded

    def verify_access_token(
        self,
        token: str,
        expected_audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verifies RS256 signature, expiry, issuer, and audience binding."""
        claims = jwt.decode(token, self._jwk)
        claims.validate()  # Validates iat, exp, nbf

        # Validate issuer
        if claims.get("iss") != settings.BASE_URL:
            raise ValueError(f"Issuer mismatch: expected {settings.BASE_URL}, got {claims.get('iss')}")

        # Validate single-resource audience binding (RFC 8707)
        if expected_audience:
            token_aud = claims.get("aud")
            # If audience does not match exactly, fail-closed
            if token_aud != expected_audience:
                raise ValueError(
                    f"Audience mismatch: token issued for '{token_aud}', but requested resource is '{expected_audience}'"
                )

        return dict(claims)


def verify_pkce_challenge(
    code_verifier: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
) -> bool:
    """Verifies RFC 7636 PKCE code_verifier against code_challenge.
    
    OAuth 2.1 strictly mandates S256. 'plain' is forbidden.
    """
    if code_challenge_method != "S256":
        return False
    
    if not code_verifier or not code_challenge:
        return False

    # S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return computed_challenge == code_challenge


def generate_pkce_pair() -> tuple[str, str]:
    """Generates a random verifier and S256 challenge for clients/tests."""
    import secrets
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


# Global crypto manager instance
crypto_manager = CryptoManager()
