"""Password hashing and token helpers for the recipe API."""

import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

# scrypt is unavailable on this machine: its Python links against
# LibreSSL rather than OpenSSL. pbkdf2:sha256 is supported everywhere.
HASH_METHOD = "pbkdf2:sha256"


def hash_password(plain_password: str) -> str:
    """Return a one-way hash of plain_password, safe to store."""
    return generate_password_hash(plain_password, method=HASH_METHOD)


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Return True if candidate_password matches stored_hash."""
    return check_password_hash(stored_hash, candidate_password)


JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = timedelta(hours=1)


def create_access_token(user_id: int, username: str) -> str:
    """Return a signed JWT identifying the given user."""
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + TOKEN_LIFETIME,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
