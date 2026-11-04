"""Settings for the demo auth API. Values here are for local testing only."""

# HS256 signing key. In a real system this comes from a secret manager, never from code.
SECRET_KEY = "local-demo-secret-key-change-me-0123456789abcdef"
ALGORITHM = "HS256"
ISSUER = "auth-lab"
AUDIENCE = "auth-lab-api"

ACCESS_TOKEN_TTL = 900        # 15 minutes
REFRESH_TOKEN_TTL = 86400     # 24 hours

MAX_FAILED_ATTEMPTS = 5       # failed logins before the account locks
LOCKOUT_SECONDS = 900         # 15 minutes

# username: (password, role) -- demo accounts only
USERS = {
    "admin": ("Admin@123", "admin"),
    "alice": ("Alice@123", "user"),
    "bob": ("Bob@123", "user"),
    "dave": ("Dave@123", "user"),
    "lockme": ("Lock@123", "user"),
}
