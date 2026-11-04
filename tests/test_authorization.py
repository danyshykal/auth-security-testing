"""Authorization: who may access the admin endpoint. 401 = not logged in, 403 = logged in but not allowed."""
import requests

from tests.jwt_tools import bearer


def test_TC_AUTHZ_01_admin_can_access_admin_endpoint(base_url, admin_tokens):
    response = requests.get(f"{base_url}/admin/users", headers=bearer(admin_tokens["access_token"]), timeout=10)
    assert response.status_code == 200
    usernames = [u["username"] for u in response.json()["users"]]
    assert "alice" in usernames
    assert "password" not in response.text.lower()


def test_TC_AUTHZ_02_normal_user_is_forbidden(base_url, tokens):
    response = requests.get(f"{base_url}/admin/users", headers=bearer(tokens["access_token"]), timeout=10)
    assert response.status_code == 403


def test_TC_AUTHZ_03_no_token_is_unauthorized_not_forbidden(base_url):
    response = requests.get(f"{base_url}/admin/users", timeout=10)
    assert response.status_code == 401
