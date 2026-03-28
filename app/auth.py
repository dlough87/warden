"""
Authentication helpers for Warden.

Session secret is persisted to /data/session_secret on first run so that
sessions survive container restarts. Password hash is stored in the settings
table via database.py helpers.
"""
import base64
import hashlib
import hmac
import os
import binascii
import secrets
import struct
import time
from pathlib import Path
from urllib.parse import quote

_SECRET_FILE = "/data/session_secret"


def get_session_secret() -> str:
    """Return the persistent session secret, creating one if it does not exist."""
    p = Path(_SECRET_FILE)
    if p.exists():
        s = p.read_text().strip()
        if s:
            return s
    secret = secrets.token_hex(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(secret)
    return secret


def hash_password(password: str) -> str:
    """Return a PBKDF2-SHA256 hash string: '<salt_hex>:<dk_hex>'."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260_000)
    return binascii.hexlify(salt).decode() + ":" + binascii.hexlify(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    """Constant-time compare of a plaintext password against a stored hash."""
    try:
        salt_hex, dk_hex = stored.split(":", 1)
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(dk_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260_000)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ── TOTP (pure stdlib — no pyotp or qrcode required) ─────────────────────────

def generate_totp_secret() -> str:
    """Return a new random base-32 TOTP secret (20 random bytes)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def get_totp_uri(secret: str, issuer: str = "Warden") -> str:
    """Return an otpauth:// URI suitable for QR code scanning."""
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(issuer)}"
        f"?secret={secret}&issuer={quote(issuer)}"
    )


def _totp_code(secret: str, t: int) -> int:
    """Compute the TOTP code for time-step t (RFC 6238 / HOTP RFC 4226)."""
    padded = secret.upper() + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack(">Q", t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return code % 1_000_000


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code. Allows ±1 window to accommodate clock drift."""
    try:
        given = int(code.strip().replace(" ", ""))
        t = int(time.time()) // 30
        return any(_totp_code(secret, t + delta) == given for delta in (-1, 0, 1))
    except Exception:
        return False


# ── Backup codes ──────────────────────────────────────────────────────────────

def generate_backup_codes(count: int = 8) -> list[str]:
    """Return a list of human-readable backup codes (shown to user once)."""
    return [
        secrets.token_hex(3).upper() + "-" + secrets.token_hex(3).upper()
        for _ in range(count)
    ]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.upper().replace("-", "").encode()).hexdigest()


def verify_and_consume_backup_code(plain: str, hashes: list[str]) -> tuple[bool, list[str]]:
    """
    Check plain against the stored hashes.
    Returns (matched, remaining_hashes) — matched code is removed (one-time use).
    """
    h = hash_backup_code(plain)
    if h in hashes:
        remaining = [x for x in hashes if x != h]
        return True, remaining
    return False, hashes


# Evaluated once at import time so SessionMiddleware can use it immediately.
SESSION_SECRET: str = get_session_secret()
