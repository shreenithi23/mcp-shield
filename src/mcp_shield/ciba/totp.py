"""RFC 6238 Time-Based One-Time Password (TOTP) step-up implementation."""

import base64
import hashlib
import hmac
import struct
import time


DEFAULT_DEV_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # Standard RFC 3548 Base32 test secret


def generate_totp_code(secret: str = DEFAULT_DEV_TOTP_SECRET, interval: int = 30) -> str:
    """Generates a 6-digit TOTP code for the current time."""
    key = base64.b32decode(secret, casefold=True)
    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp_code(code: str, secret: str = DEFAULT_DEV_TOTP_SECRET, interval: int = 30, window: int = 1) -> bool:
    """Verifies a 6-digit TOTP code within a +/- window of intervals."""
    if not code or len(code.strip()) != 6 or not code.strip().isdigit():
        return False

    target_code = code.strip()
    key = base64.b32decode(secret, casefold=True)
    current_counter = int(time.time() // interval)

    for offset in range(-window, window + 1):
        counter = current_counter + offset
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        idx = digest[19] & 0x0F
        computed = (struct.unpack(">I", digest[idx : idx + 4])[0] & 0x7FFFFFFF) % 1000000
        if f"{computed:06d}" == target_code:
            return True

    return False
