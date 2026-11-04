import threading

import pytest
import requests
from werkzeug.serving import make_server

from app import config
from app.auth_app import create_app


def pytest_addoption(parser):
    parser.addoption("--vulnerable", action="store_true",
                     help="Run the tests against the API with its security flaws switched on")


@pytest.fixture(scope="session")
def base_url(request):
    """Start the API in a background thread on a free port, once per test run."""
    vulnerable = request.config.getoption("--vulnerable")
    server = make_server("127.0.0.1", 0, create_app(vulnerable=vulnerable))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def login(base_url):
    """Call login(username, password) -> requests.Response"""
    def _login(username, password):
        return requests.post(f"{base_url}/auth/login",
                             json={"username": username, "password": password}, timeout=10)
    return _login


@pytest.fixture
def tokens(login):
    """Fresh tokens for alice (a normal user) for each test."""
    response = login("alice", config.USERS["alice"][0])
    assert response.status_code == 200, "Setup failed: alice could not log in"
    return response.json()


@pytest.fixture
def admin_tokens(login):
    response = login("admin", config.USERS["admin"][0])
    assert response.status_code == 200, "Setup failed: admin could not log in"
    return response.json()


@pytest.fixture
def me(base_url):
    """Call me(headers) -> response from the protected GET /auth/me endpoint."""
    def _me(headers=None, **kwargs):
        return requests.get(f"{base_url}/auth/me", headers=headers or {}, timeout=10, **kwargs)
    return _me

