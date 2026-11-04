"""
A small JWT login API used as the system under test.

create_app(vulnerable=False) -> secure version (all tests should pass)
create_app(vulnerable=True)  -> same API with deliberate security flaws switched on,
                                so you can see which tests catch which flaw.

The flaws are marked [V1]..[V9] in the code.
"""
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from app import config


def create_app(vulnerable: bool = False) -> Flask:
    app = Flask(__name__)

    users = {
        name: {"password_hash": generate_password_hash(pw), "role": role}
        for name, (pw, role) in config.USERS.items()
    }
    failed_logins = {}   # username -> {"count": int, "locked_until": epoch seconds}
    revoked_jtis = set()  # token IDs that were logged out

    # ---------- helpers ----------

    def error(status, message):
        return jsonify(error=message), status

    def make_token(username, token_type, ttl):
        now = datetime.now(timezone.utc)
        payload = {
            "iss": config.ISSUER,
            "aud": config.AUDIENCE,
            "sub": username,
            "role": users[username]["role"],
            "type": token_type,
            "iat": now,
            "exp": now + timedelta(seconds=ttl),
            "jti": uuid.uuid4().hex,
        }
        if vulnerable:
            payload["pwd_hash"] = users[username]["password_hash"]   # [V9] sensitive data in token
        return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)

    def decode_token(token, expected_type):
        if vulnerable:
            # [V1] signature not verified  ->  forged, tampered and alg=none tokens accepted
            # [V2] expiry, issuer and audience not checked
            # [V6] revoked tokens not checked
            # [V7] token type not checked (refresh token works as access token)
            return jwt.decode(token, options={"verify_signature": False})

        claims = jwt.decode(
            token,
            config.SECRET_KEY,
            algorithms=[config.ALGORITHM],          # only HS256 is allowed, never "none"
            audience=config.AUDIENCE,
            issuer=config.ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "type"]},
        )
        if claims["type"] != expected_type:
            raise jwt.InvalidTokenError("Wrong token type")
        if claims["jti"] in revoked_jtis:
            raise jwt.InvalidTokenError("Token revoked")
        return claims

    def authenticate(expected_type="access"):
        """Return (claims, None) on success or (None, error_response)."""
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        if scheme != "Bearer" or not token.strip():
            return None, error(401, "Missing or invalid Authorization header")
        try:
            claims = decode_token(token.strip(), expected_type)
        except jwt.ExpiredSignatureError:
            return None, error(401, "Token expired")
        except jwt.InvalidTokenError:
            return None, error(401, "Invalid token")
        if claims.get("sub") not in users:
            return None, error(401, "Invalid token")
        return claims, None

    # ---------- routes ----------

    @app.post("/auth/login")
    def login():
        if vulnerable:
            data = request.get_json(force=True, silent=True) or {}
            username, password = data["username"], data["password"]   # [V5] missing field -> 500 crash
        else:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return error(400, "Request body must be a JSON object")
            username, password = data.get("username"), data.get("password")
            if not isinstance(username, str) or not isinstance(password, str) \
                    or not username.strip() or not password:
                return error(400, "username and password are required")
            if len(username) > 100 or len(password) > 200:
                return error(400, "Input too long")

        now = time.time()
        if not vulnerable:   # [V4] no account lockout in vulnerable mode
            record = failed_logins.get(username)
            if record and record["locked_until"] > now:
                return error(423, "Account locked. Try again later.")

        user = users.get(username)
        if user is None or not check_password_hash(user["password_hash"], password):
            if vulnerable:
                # [V3] different messages reveal which usernames exist
                return error(401, "User not found" if user is None else "Wrong password")
            record = failed_logins.setdefault(username, {"count": 0, "locked_until": 0})
            record["count"] += 1
            if record["count"] >= config.MAX_FAILED_ATTEMPTS:
                record["count"] = 0
                record["locked_until"] = now + config.LOCKOUT_SECONDS
            return error(401, "Invalid username or password")

        failed_logins.pop(username, None)
        return jsonify(
            access_token=make_token(username, "access", config.ACCESS_TOKEN_TTL),
            refresh_token=make_token(username, "refresh", config.REFRESH_TOKEN_TTL),
            token_type="Bearer",
            expires_in=config.ACCESS_TOKEN_TTL,
        )

    @app.get("/auth/me")
    def me():
        claims, err = authenticate()
        if err:
            return err
        return jsonify(username=claims["sub"], role=claims.get("role"))

    @app.post("/auth/refresh")
    def refresh():
        data = request.get_json(silent=True) or {}
        token = data.get("refresh_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            return error(400, "refresh_token is required")
        try:
            claims = decode_token(token, "refresh")
        except jwt.ExpiredSignatureError:
            return error(401, "Token expired")
        except jwt.InvalidTokenError:
            return error(401, "Invalid token")
        if claims.get("sub") not in users:
            return error(401, "Invalid token")
        return jsonify(
            access_token=make_token(claims["sub"], "access", config.ACCESS_TOKEN_TTL),
            token_type="Bearer",
            expires_in=config.ACCESS_TOKEN_TTL,
        )

    @app.post("/auth/logout")
    def logout():
        claims, err = authenticate()
        if err:
            return err
        if not vulnerable:
            revoked_jtis.add(claims["jti"])
        return jsonify(message="Logged out")

    @app.get("/admin/users")
    def admin_users():
        claims, err = authenticate()
        if err:
            return err
        if not vulnerable and claims.get("role") != "admin":   # [V8] no role check in vulnerable mode
            return error(403, "Admin role required")
        return jsonify(users=[{"username": u, "role": d["role"]} for u, d in users.items()])

    @app.after_request
    def security_headers(response):
        if not vulnerable:   # [V10] auth responses may be cached in vulnerable mode
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(404)
    def not_found(_):
        return error(404, "Not found")

    @app.errorhandler(405)
    def method_not_allowed(_):
        return error(405, "Method not allowed")

    return app
