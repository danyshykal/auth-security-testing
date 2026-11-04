"""Login endpoint: valid login, invalid credentials, input validation, brute-force protection."""
import uuid

import pytest
import requests

from app import config

GENERIC_ERROR = "Invalid username or password"


@pytest.mark.smoke
def test_TC_LOGIN_01_valid_login_returns_tokens(login):
    response = login("alice", "Alice@123")
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == config.ACCESS_TOKEN_TTL
    assert body["access_token"] and body["refresh_token"]


@pytest.mark.negative
def test_TC_LOGIN_02_wrong_password(login):
    response = login("bob", "WrongPass@1")
    assert response.status_code == 401
    assert response.json()["error"] == GENERIC_ERROR
    assert "access_token" not in response.json()


@pytest.mark.negative
def test_TC_LOGIN_03_unknown_user(login):
    response = login(f"ghost_{uuid.uuid4().hex[:8]}", "Whatever@1")
    assert response.status_code == 401
    assert response.json()["error"] == GENERIC_ERROR


@pytest.mark.negative
@pytest.mark.security
def test_TC_LOGIN_04_no_user_enumeration(login):
    """Wrong password and unknown user must look identical, or attackers learn which usernames exist."""
    wrong_password = login("bob", "WrongPass@2")
    unknown_user = login(f"ghost_{uuid.uuid4().hex[:8]}", "WrongPass@2")
    assert wrong_password.status_code == unknown_user.status_code
    assert wrong_password.json() == unknown_user.json()


@pytest.mark.negative
def test_TC_LOGIN_05_password_is_case_sensitive(login):
    response = login("bob", "bob@123")   # real password is Bob@123
    assert response.status_code == 401


@pytest.mark.negative
@pytest.mark.parametrize(
    "body",
    [
        {"password": "Alice@123"},
        {"username": "alice"},
        {"username": "", "password": "Alice@123"},
        {"username": "alice", "password": ""},
    ],
    ids=["TC_LOGIN_06_missing_username", "TC_LOGIN_07_missing_password",
         "TC_LOGIN_08_empty_username", "TC_LOGIN_09_empty_password"],
)
def test_missing_or_empty_fields(base_url, body):
    response = requests.post(f"{base_url}/auth/login", json=body, timeout=10)
    assert response.status_code == 400            # a 500 here means the server crashed
    assert "error" in response.json()


@pytest.mark.negative
def test_TC_LOGIN_10_non_json_body(base_url):
    response = requests.post(f"{base_url}/auth/login", data="username=alice&password=Alice@123",
                             headers={"Content-Type": "text/plain"}, timeout=10)
    assert response.status_code == 400
    assert "Traceback" not in response.text      # no internal error details leaked


@pytest.mark.negative
def test_TC_LOGIN_11_wrong_data_types(base_url):
    response = requests.post(f"{base_url}/auth/login",
                             json={"username": 12345, "password": True}, timeout=10)
    assert response.status_code == 400


@pytest.mark.negative
@pytest.mark.security
@pytest.mark.parametrize(
    "username",
    ["' OR '1'='1", "admin'--", "' OR 1=1; DROP TABLE users;--"],
    ids=["TC_LOGIN_12_sqli_or_true", "TC_LOGIN_13_sqli_comment", "TC_LOGIN_14_sqli_drop"],
)
def test_sql_injection_in_username(login, username):
    response = login(username, "anything")
    assert response.status_code == 401           # not 200 (bypassed) and not 500 (crashed)
    assert "access_token" not in response.text


@pytest.mark.negative
def test_TC_LOGIN_15_very_long_username(login):
    response = login("a" * 10_000, "Alice@123")
    assert response.status_code in (400, 401)    # rejected cleanly, not a 500
    assert response.status_code != 500


@pytest.mark.security
def test_TC_LOGIN_16_password_not_echoed(login):
    for password in ("Alice@123", "WrongPass@3"):
        response = login("alice" if password == "Alice@123" else "dave", password)
        assert password not in response.text


@pytest.mark.negative
def test_TC_LOGIN_17_get_method_not_allowed(base_url):
    response = requests.get(f"{base_url}/auth/login", timeout=10)
    assert response.status_code == 405


@pytest.mark.security
def test_TC_LOGIN_18_tokens_not_cached(login):
    response = login("alice", "Alice@123")
    assert response.headers.get("Cache-Control") == "no-store"


@pytest.mark.security
def test_TC_LOGIN_19_account_locks_after_failed_attempts(login):
    """Brute-force protection: after 5 wrong passwords even the right password is refused."""
    for _ in range(config.MAX_FAILED_ATTEMPTS):
        assert login("lockme", "WrongPass@9").status_code == 401
    response = login("lockme", "Lock@123")       # correct password
    assert response.status_code == 423
    assert "access_token" not in response.text
