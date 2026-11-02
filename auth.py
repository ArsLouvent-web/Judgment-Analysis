"""
Secure Authentication Module — Database-backed with constant-time bcrypt verification.

Credentials are stored as bcrypt-hashed values in the SQLite database (`cases.db`).
Users can change their credentials through the Settings page.
All password comparisons use bcrypt's constant-time comparison with a precomputed
dummy hash to prevent username-enumeration timing attacks and CPU exhaustion.
"""

import bcrypt

try:
    from app.database import get_db_connection
except ImportError:
    from database import get_db_connection

# Precompute dummy hash once at startup so failed lookups perform exactly 1 verification pass,
# eliminating the timing delta and preventing CPU exhaustion from dynamic salt generation.
DUMMY_HASH = bcrypt.hashpw(b"dummy_auth_password_constant", bcrypt.gensalt()).decode("utf-8")


def _hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash (constant-time)."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user by username and password against the SQLite database.
    Returns True if credentials match, False otherwise.

    Security: Parameterized SQL prevents injection. Uses constant-time bcrypt verification.
    """
    if not username or not password:
        return False

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()

    if not user or not user["password_hash"]:
        # Verify against precomputed dummy hash to maintain constant response time
        _verify_password(password, DUMMY_HASH)
        return False

    return _verify_password(password, user["password_hash"])


def get_display_name(username: str) -> str:
    """Get the display name for a user from the database."""
    if not username:
        return ""

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT display_name FROM users WHERE username = ?", (username,)
        ).fetchone()
        return user["display_name"] if user and user["display_name"] else username
    finally:
        conn.close()
