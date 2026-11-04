# Login & Authentication Security Testing

A security-focused test suite for a JWT login API, written in **Python + pytest + requests**.
It covers **JWT validation** (forged, tampered, expired and alg=none tokens) and **negative testing**
of login, authorization and sessions.

The API under test is a small Flask service in `app/`, so every attack is run against a server I own.
It has two modes:

- **Secure mode**: the real implementation. **All 52 tests pass.**
- **Vulnerable mode**: the same API with 10 deliberate security flaws. **25 tests fail**, and every flaw is caught.

## What's covered
| Area | Tests | Examples |
|---|---|---|
| Login & input validation | 19 | wrong password, user enumeration, missing/empty fields, wrong types, SQL injection strings, oversized input, account lockout |
| JWT structure | 6 | 3 parts, HS256 header, required claims, 15-minute lifetime, no secrets in payload |
| JWT validation (negative) | 18 | no header, wrong scheme, malformed tokens, tampered payload, tampered signature, wrong secret, **alg=none**, expired, no `exp`, wrong issuer/audience |
| Authorization | 3 | admin allowed, user gets 403, no token gets 401 |
| Session | 6 | refresh flow, token-type confusion, logout revokes the token |

Manual test cases: [`docs/test_cases.csv`](docs/test_cases.csv)

## Flaws caught in vulnerable mode
| ID | Flaw | Caught by |
|---|---|---|
| V1 | JWT signature not verified | TC_NEG_06 to 09 |
| V2 | Expiry, issuer, audience not checked | TC_NEG_10 to 13 |
| V3 | Different errors reveal which usernames exist | TC_LOGIN_02 to 04 |
| V4 | No account lockout (brute force possible) | TC_LOGIN_19 |
| V5 | Missing or bad input crashes the server (500) | TC_LOGIN_06 to 11 |
| V6 | Logout doesn't revoke the token | TC_SESS_04, 06 |
| V7 | Refresh and access tokens interchangeable | TC_SESS_02, 03 |
| V8 | No role check on admin endpoint | TC_AUTHZ_02 |
| V9 | Password hash stored inside the JWT | TC_JWT_05 |
| V10 | Auth responses may be cached | TC_LOGIN_18 |

## Run it
```bash
python -m venv venv
venv\Scripts\activate          # Windows  (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt

pytest                          # secure mode: all pass
pytest --vulnerable             # vulnerable mode: see the flaws get caught
pytest -m security              # only the security tests
```
Report: `reports/report.html`. The tests start the API themselves; no separate server needed.

To explore the API by hand (e.g. in Postman), run `python run_server.py` and use `http://127.0.0.1:5000`.

## Project structure
```
app/           # The API under test (Flask + PyJWT)
tests/         # Test suite + jwt_tools.py (helpers to build and break tokens)
docs/          # Test cases
```

## CI
GitHub Actions runs both modes on every push: secure mode must pass, and vulnerable mode must fail,
which proves the tests really detect each flaw.

> Demo credentials and the signing key in `app/config.py` are for local testing only.
