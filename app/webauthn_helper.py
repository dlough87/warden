"""
Self-contained WebAuthn helper for Warden.
Implements registration and authentication using only cbor2 + cryptography.
No external webauthn library required.
"""
import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass


# ── Base64url ───────────────────────────────────────────────────────────────

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ── Registration ─────────────────────────────────────────────────────────────

def generate_registration_options(
    rp_id: str,
    rp_name: str,
    user_id: bytes,
    user_name: str,
    user_display_name: str,
    exclude_credentials: list = None,
) -> tuple:
    """Return (options_dict, challenge_bytes)."""
    challenge = secrets.token_bytes(32)
    options = {
        "rp": {"id": rp_id, "name": rp_name},
        "user": {
            "id": _b64url_encode(user_id),
            "name": user_name,
            "displayName": user_display_name,
        },
        "challenge": _b64url_encode(challenge),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},    # ES256 (P-256)
            {"type": "public-key", "alg": -257},  # RS256
        ],
        "timeout": 60000,
        "excludeCredentials": [
            {
                "type": "public-key",
                "id": _b64url_encode(c["credential_id"]),
            }
            for c in (exclude_credentials or [])
        ],
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "required",
        },
        "attestation": "none",
    }
    return options, challenge


@dataclass
class VerifiedRegistration:
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int


def verify_registration_response(
    credential: dict,
    expected_challenge: bytes,
    expected_rp_id: str,
    expected_origin: str,
) -> VerifiedRegistration:
    import cbor2

    response = credential["response"]

    # Verify clientDataJSON
    client_data = json.loads(_b64url_decode(response["clientDataJSON"]))
    if client_data.get("type") != "webauthn.create":
        raise ValueError("Invalid type in clientDataJSON")
    if _b64url_decode(client_data["challenge"]) != expected_challenge:
        raise ValueError("Challenge mismatch")
    if client_data.get("origin") != expected_origin:
        raise ValueError(f"Origin mismatch: got {client_data.get('origin')!r}, expected {expected_origin!r}")

    # Parse attestationObject
    att_obj = cbor2.loads(_b64url_decode(response["attestationObject"]))
    auth_data = att_obj["authData"]

    if len(auth_data) < 37:
        raise ValueError("authData too short")

    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]

    if rp_id_hash != hashlib.sha256(expected_rp_id.encode()).digest():
        raise ValueError("rpId hash mismatch")
    if not (flags & 0x40):  # AT flag — attested credential data present
        raise ValueError("Attested credential data flag not set")

    # Parse attested credential data
    # 16 bytes aaguid | 2 bytes credIdLen | credId | credPublicKey (CBOR)
    if len(auth_data) < 55:
        raise ValueError("authData too short for attested credential data")

    cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
    if len(auth_data) < 55 + cred_id_len:
        raise ValueError("authData too short for credentialId")

    credential_id = auth_data[55:55 + cred_id_len]
    cose_key_bytes = auth_data[55 + cred_id_len:]

    # Validate key is parseable
    _cose_to_crypto_key(cbor2.loads(cose_key_bytes))

    return VerifiedRegistration(
        credential_id=credential_id,
        credential_public_key=cose_key_bytes,
        sign_count=sign_count,
    )


# ── Authentication ───────────────────────────────────────────────────────────

def generate_authentication_options(rp_id: str) -> tuple:
    """Return (options_dict, challenge_bytes)."""
    challenge = secrets.token_bytes(32)
    options = {
        "rpId": rp_id,
        "challenge": _b64url_encode(challenge),
        "timeout": 60000,
        "allowCredentials": [],
        "userVerification": "required",
    }
    return options, challenge


@dataclass
class VerifiedAuthentication:
    new_sign_count: int


def verify_authentication_response(
    credential: dict,
    expected_challenge: bytes,
    expected_rp_id: str,
    expected_origin: str,
    credential_public_key: bytes,
    credential_current_sign_count: int,
) -> VerifiedAuthentication:
    import cbor2

    response = credential["response"]

    # Verify clientDataJSON
    client_data_raw = _b64url_decode(response["clientDataJSON"])
    client_data = json.loads(client_data_raw)
    if client_data.get("type") != "webauthn.get":
        raise ValueError("Invalid type in clientDataJSON")
    if _b64url_decode(client_data["challenge"]) != expected_challenge:
        raise ValueError("Challenge mismatch")
    if client_data.get("origin") != expected_origin:
        raise ValueError(f"Origin mismatch: got {client_data.get('origin')!r}, expected {expected_origin!r}")

    # Parse authenticatorData
    auth_data = _b64url_decode(response["authenticatorData"])
    if len(auth_data) < 37:
        raise ValueError("authenticatorData too short")

    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    new_sign_count = struct.unpack(">I", auth_data[33:37])[0]

    if rp_id_hash != hashlib.sha256(expected_rp_id.encode()).digest():
        raise ValueError("rpId hash mismatch")
    if not (flags & 0x01):  # UP flag
        raise ValueError("User presence flag not set")

    # Verify signature
    signature = _b64url_decode(response["signature"])
    verification_data = auth_data + hashlib.sha256(client_data_raw).digest()
    cose_key = cbor2.loads(credential_public_key)
    _verify_signature(cose_key, verification_data, signature)

    # Check sign count (0 means authenticator doesn't track it)
    if new_sign_count != 0 and credential_current_sign_count != 0:
        if new_sign_count <= credential_current_sign_count:
            raise ValueError("Sign count decreased — possible cloned authenticator")

    return VerifiedAuthentication(new_sign_count=new_sign_count)


# ── COSE key helpers ─────────────────────────────────────────────────────────

def _cose_to_crypto_key(cose_key: dict):
    """Parse a COSE key dict into a cryptography public key object."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.backends import default_backend

    kty = cose_key.get(1)

    if kty == 2:  # EC2
        crv = cose_key.get(-1)
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        curves = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}
        curve = curves.get(crv)
        if curve is None:
            raise ValueError(f"Unsupported EC curve: {crv}")
        return ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=curve,
        ).public_key(default_backend())

    elif kty == 3:  # RSA
        n = cose_key.get(-1)
        e = cose_key.get(-2)
        return rsa.RSAPublicNumbers(
            e=int.from_bytes(e, "big"),
            n=int.from_bytes(n, "big"),
        ).public_key(default_backend())

    else:
        raise ValueError(f"Unsupported COSE key type: {kty}")


def _verify_signature(cose_key: dict, data: bytes, signature: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives import hashes

    kty = cose_key.get(1)
    public_key = _cose_to_crypto_key(cose_key)

    if kty == 2:  # EC2
        crv = cose_key.get(-1)
        hash_alg = {1: hashes.SHA256(), 2: hashes.SHA384(), 3: hashes.SHA512()}.get(crv, hashes.SHA256())
        public_key.verify(signature, data, ec.ECDSA(hash_alg))
    elif kty == 3:  # RSA
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError(f"Unsupported COSE key type: {kty}")
