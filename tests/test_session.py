"""Session lifecycle: refresh tokens, token types, logout and revocation."""
import requests

from tests.jwt_tools import bearer


def refresh(base_url, token):
    return requests.post(f"{base_url}/auth/refresh", json={"refresh_token": token}, timeout=10)


def test_TC_SESS_01_refresh_token_gives_new_access_token(base_url, tokens, me):
    response = refresh(base_url, tokens["refresh_token"])
    assert response.status_code == 200
    new_access = response.json()["access_token"]
    assert new_access != tokens["access_token"]
    assert me(bearer(new_access)).status_code == 200


def test_TC_SESS_02_access_token_cannot_be_used_to_refresh(base_url, tokens):
    assert refresh(base_url, tokens["access_token"]).status_code == 401


def test_TC_SESS_03_refresh_token_cannot_be_used_as_access_token(tokens, me):
    """A long-lived refresh token must not open protected endpoints."""
    assert me(bearer(tokens["refresh_token"])).status_code == 401


def test_TC_SESS_04_token_rejected_after_logout(base_url, tokens, me):
    headers = bearer(tokens["access_token"])
    assert me(headers).status_code == 200
    assert requests.post(f"{base_url}/auth/logout", headers=headers, timeout=10).status_code == 200
    assert me(headers).status_code == 401


def test_TC_SESS_05_logout_without_token(base_url):
    assert requests.post(f"{base_url}/auth/logout", timeout=10).status_code == 401


def test_TC_SESS_06_logout_only_ends_that_session(base_url, login, me):
    phone = login("alice", "Alice@123").json()["access_token"]
    laptop = login("alice", "Alice@123").json()["access_token"]
    requests.post(f"{base_url}/auth/logout", headers=bearer(phone), timeout=10)
    assert me(bearer(phone)).status_code == 401
    assert me(bearer(laptop)).status_code == 200
