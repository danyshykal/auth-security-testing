"""
Helpers for building and breaking JWTs.

A JWT is three base64url strings joined by dots:  header.payload.signature
These helpers split, edit and re-join them so tests can forge bad tokens.
"""
import base64
import json
import time
import uuid

import jwt

from app import config


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))   # add back stripped padding


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_parts(token: str):
    """Read header and payload WITHOUT verifying the signature (just to inspect them)."""
    header, payload, _signature = token.split(".")
    return json.loads(b64url_decode(header)), json.loads(b64url_decode(payload))


def build(header: dict, payload: dict, signature: str = "") -> str:
    """Assemble a token from parts. Used to forge tokens the server must reject."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def valid_claims(username="alice", role="user", token_type="access", **overrides) -> dict:
    """A correct set of claims. Tests change one thing at a time to isolate each check."""
    now = int(time.time())
    claims = {
        "iss": config.ISSUER,
        "aud": config.AUDIENCE,
        "sub": username,
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + config.ACCESS_TOKEN_TTL,
        "jti": uuid.uuid4().hex,
    }
    claims.update(overrides)
    return claims


def sign(claims: dict, secret: str = config.SECRET_KEY) -> str:
    """Sign claims with HS256. With the real secret this makes a genuine token."""
    return jwt.encode(claims, secret, algorithm="HS256")


def bearer(token: str) -> dict:
    """Authorization header for a token."""
    return {"Authorization": f"Bearer {token}"}
