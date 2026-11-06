"""Password hashing helpers for the recipe API."""

from werkzeug.security import check_password_hash, generate_password_hash

# scrypt is unavailable on this machine: its Python links against
# LibreSSL rather than OpenSSL. pbkdf2:sha256 is supported everywhere.
HASH_METHOD = "pbkdf2:sha256"


def hash_password(plain_password: str) -> str:
    """Return a one-way hash of plain_password, safe to store."""
    return generate_password_hash(plain_password, method=HASH_METHOD)


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Return True if candidate_password matches stored_hash."""
    return check_password_hash(stored_hash, candidate_password)
