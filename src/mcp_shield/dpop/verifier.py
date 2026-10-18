"""RFC 9449 Demonstrating Proof-of-Possession at the Application Layer (DPoP)."""

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from mcp_shield.database import ephemeral_cache


def compute_jwk_thumbprint(jwk_dict: Dict[str, Any]) -> str:
    """Computes RFC 7638 JWK SHA-256 Thumbprint."""
    kty = jwk_dict.get("kty")
    if kty == "RSA":
        canonical = json.dumps(
            {"e": jwk_dict["e"], "kty": "RSA", "n": jwk_dict["n"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    elif kty == "EC":
        canonical = json.dumps(
            {"crv": jwk_dict["crv"], "kty": "EC", "x": jwk_dict["x"], "y": jwk_dict["y"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    else:
        raise ValueError(f"Unsupported key type for thumbprint: {kty}")

    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def normalize_dpop_url(url: str) -> str:
    """Normalizes HTTP URI for DPoP htu comparison (scheme + host + path)."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


class DPoPVerifier:
    """Validates RFC 9449 DPoP proofs, replay protection, and token thumbprint binding."""

    def __init__(self, max_skew_seconds: int = 300):
        self.max_skew_seconds = max_skew_seconds

    async def verify(
        self,
        dpop_header: Optional[str],
        http_method: str,
        http_url: str,
        token_claims: Optional[Dict[str, Any]] = None,
        expected_nonce: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Verifies DPoP proof header.
        
        Returns:
            (is_valid, jkt_thumbprint, error_reason)
        """
        if not dpop_header:
            return False, None, "missing_dpop_header"

        # 1. Parse unverified header to extract jwk and alg
        try:
            # DPoP proof is a JWT
            parts = dpop_header.strip().split(".")
            if len(parts) != 3:
                return False, None, "invalid_dpop_jwt_format"
            
            # Base64 decode header
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_bytes)
        except Exception:
            return False, None, "malformed_dpop_header"

        # 2. Check typ header
        if header.get("typ") != "dpop+jwt":
            return False, None, "invalid_dpop_typ"

        alg = header.get("alg")
        if not alg or alg == "none":
            return False, None, "unsupported_dpop_algorithm"

        # 3. Check jwk in header
        jwk_dict = header.get("jwk")
        if not jwk_dict:
            return False, None, "missing_dpop_jwk"

        # 4. Verify signature and decode claims using the public jwk
        try:
            claims = jwt.decode(dpop_header, jwk_dict)
            claims.validate()
        except Exception as exc:
            return False, None, f"dpop_signature_invalid: {str(exc)}"

        # 5. Check htm (HTTP Method)
        htm = claims.get("htm")
        if not htm or htm.upper() != http_method.upper():
            return False, None, f"htm_mismatch: expected {http_method.upper()}, got {htm}"

        # 6. Check htu (HTTP URI)
        htu = claims.get("htu")
        if not htu or normalize_dpop_url(htu) != normalize_dpop_url(http_url):
            return False, None, f"htu_mismatch: expected {normalize_dpop_url(http_url)}, got {htu}"

        # 7. Check iat freshness
        now = int(time.time())
        iat = claims.get("iat")
        if not iat or abs(now - iat) > self.max_skew_seconds:
            return False, None, "dpop_proof_expired"

        # 8. Check replay protection on jti
        jti = claims.get("jti")
        if not jti:
            return False, None, "missing_dpop_jti"

        cache_key = f"dpop_jti:{jti}"
        if await ephemeral_cache.get(cache_key):
            return False, None, "dpop_proof_replayed"

        # Record jti to prevent replay within freshness window
        await ephemeral_cache.set(cache_key, "1", ex=self.max_skew_seconds)

        # 9. Compute JWK thumbprint (jkt)
        jkt = compute_jwk_thumbprint(jwk_dict)

        # 10. Check cnf.jkt binding if access token claims provided
        if token_claims:
            cnf = token_claims.get("cnf")
            if cnf:
                expected_jkt = cnf.get("jkt")
                if expected_jkt and expected_jkt != jkt:
                    return False, jkt, f"dpop_jkt_mismatch: token bound to {expected_jkt}, proof presented {jkt}"

        # 11. Check server nonce if required
        if expected_nonce:
            proof_nonce = claims.get("nonce")
            if proof_nonce != expected_nonce:
                return False, jkt, "dpop_nonce_mismatch"

        return True, jkt, None


# Helper to generate DPoP keypair and signed proof for clients and tests
class DPoPClientKey:
    """Client utility to generate DPoP proofs."""

    def __init__(self):
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()
        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key = JsonWebKey.import_key(pub_pem, {"kty": "RSA"})
        self.jwk = key.as_dict()
        self.jwk.update({"use": "sig", "alg": "RS256"})
        self.jkt = compute_jwk_thumbprint(self.jwk)

    def generate_proof(
        self,
        http_method: str,
        http_url: str,
        access_token: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        """Generates an RFC 9449 compliant DPoP proof JWT."""
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": self.jwk,
        }
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": http_method.upper(),
            "htu": normalize_dpop_url(http_url),
            "iat": int(time.time()),
        }
        if access_token:
            ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest()).decode("ascii").rstrip("=")
            payload["ath"] = ath
        if nonce:
            payload["nonce"] = nonce

        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encoded = jwt.encode(header, payload, private_pem)
        return encoded.decode("utf-8") if isinstance(encoded, bytes) else encoded


dpop_verifier = DPoPVerifier()
