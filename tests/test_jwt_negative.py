"""
Send broken, forged and tampered tokens to the protected GET /auth/me endpoint.
Every one must be rejected with 401. A 200 means the server trusted a token it shouldn't.
"""
import time

import pytest

from tests.jwt_tools import bearer, build, decode_parts, sign, valid_claims


def test_TC_NEG_01_valid_token_is_accepted(tokens, me):
    """Control test: proves the endpoint works, so the 401s below are meaningful."""
    response = me(bearer(tokens["access_token"]))
    assert response.status_code == 200
    assert response.json() == {"username": "alice", "role": "user"}


def test_TC_NEG_02_no_authorization_header(me):
    assert me().status_code == 401


def test_TC_NEG_03_wrong_auth_scheme(tokens, me):
    response = me({"Authorization": f"Token {tokens['access_token']}"})
    assert response.status_code == 401


def test_TC_NEG_04_bearer_with_empty_token(me):
    assert me({"Authorization": "Bearer "}).status_code == 401


@pytest.mark.parametrize(
    "token",
    ["not.a.jwt", "abc123", "a.b.c.d", "...."],
    ids=["TC_NEG_05a_garbage_parts", "TC_NEG_05b_one_part", "TC_NEG_05c_four_parts", "TC_NEG_05d_dots_only"],
)
def test_malformed_token(me, token):
    assert me(bearer(token)).status_code == 401


@pytest.mark.security
def test_TC_NEG_06_tampered_payload_role_escalation(tokens, me):
    """Change role to admin but keep the original signature: classic privilege escalation attempt."""
    header, payload = decode_parts(tokens["access_token"])
    original_signature = tokens["access_token"].split(".")[2]
    payload["role"] = "admin"
    forged = build(header, payload, original_signature)
    assert me(bearer(forged)).status_code == 401


@pytest.mark.security
def test_TC_NEG_07_tampered_signature(tokens, me):
    head, body, signature = tokens["access_token"].split(".")
    flipped = signature[:-4] + ("AAAA" if not signature.endswith("AAAA") else "BBBB")
    assert me(bearer(f"{head}.{body}.{flipped}")).status_code == 401


@pytest.mark.security
def test_TC_NEG_08_signed_with_wrong_secret(me):
    forged = sign(valid_claims(), secret="attacker-guessed-secret-key-0000000000000000")
    assert me(bearer(forged)).status_code == 401


@pytest.mark.security
def test_TC_NEG_09_alg_none_attack(me):
    """'alg: none' means 'no signature'. A server that accepts it lets anyone forge any token."""
    forged = build({"alg": "none", "typ": "JWT"}, valid_claims(role="admin"))
    assert me(bearer(forged)).status_code == 401


@pytest.mark.security
def test_TC_NEG_10_expired_token(me):
    """Correctly signed, but expired an hour ago."""
    now = int(time.time())
    expired = sign(valid_claims(iat=now - 7200, exp=now - 3600))
    response = me(bearer(expired))
    assert response.status_code == 401
    assert response.json()["error"] == "Token expired"


@pytest.mark.security
def test_TC_NEG_11_token_without_expiry(me):
    claims = valid_claims()
    del claims["exp"]                       # a token that never expires
    assert me(bearer(sign(claims))).status_code == 401


@pytest.mark.security
def test_TC_NEG_12_wrong_issuer(me):
    assert me(bearer(sign(valid_claims(iss="evil-issuer")))).status_code == 401


@pytest.mark.security
def test_TC_NEG_13_wrong_audience(me):
    assert me(bearer(sign(valid_claims(aud="some-other-api")))).status_code == 401


def test_TC_NEG_14_token_in_query_string_ignored(tokens, me):
    """Tokens in URLs end up in logs and browser history, so only the header is accepted."""
    response = me(params={"token": tokens["access_token"]})
    assert response.status_code == 401


def test_TC_NEG_15_token_for_nonexistent_user(me):
    assert me(bearer(sign(valid_claims(username="ghost")))).status_code == 401
