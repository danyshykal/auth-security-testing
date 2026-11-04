"""Inspect the JWT the server issues: format, header, claims, lifetime, no secrets inside."""
from app import config
from tests.jwt_tools import decode_parts


def test_TC_JWT_01_token_has_three_parts(tokens):
    parts = tokens["access_token"].split(".")
    assert len(parts) == 3                        # header.payload.signature
    assert all(parts)


def test_TC_JWT_02_header_uses_hs256(tokens):
    header, _ = decode_parts(tokens["access_token"])
    assert header == {"alg": "HS256", "typ": "JWT"}


def test_TC_JWT_03_payload_has_required_claims(tokens):
    _, payload = decode_parts(tokens["access_token"])
    for claim in ("iss", "aud", "sub", "role", "type", "iat", "exp", "jti"):
        assert claim in payload, f"missing claim: {claim}"
    assert payload["sub"] == "alice"
    assert payload["role"] == "user"
    assert payload["type"] == "access"
    assert payload["iss"] == config.ISSUER
    assert payload["aud"] == config.AUDIENCE


def test_TC_JWT_04_access_token_lifetime_is_15_minutes(tokens):
    _, payload = decode_parts(tokens["access_token"])
    assert payload["exp"] - payload["iat"] == config.ACCESS_TOKEN_TTL


def test_TC_JWT_05_no_sensitive_data_in_payload(tokens):
    """Anyone can base64-decode a JWT payload, so it must never hold secrets."""
    _, payload = decode_parts(tokens["access_token"])
    text = str(payload).lower()
    for word in ("password", "pwd", "hash", "secret"):
        assert word not in text, f"payload contains '{word}'"
    assert "Alice@123" not in str(payload)


def test_TC_JWT_06_each_login_gets_unique_token_id(login):
    first = decode_parts(login("alice", "Alice@123").json()["access_token"])[1]
    second = decode_parts(login("alice", "Alice@123").json()["access_token"])[1]
    assert first["jti"] != second["jti"]
