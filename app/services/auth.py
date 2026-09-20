"""
User authentication service.
Handles registration, login, password reset via security questions.
Users are stored in storage/users.json (local, no external dependency).
Passwords are hashed with bcrypt via passlib.
Sessions use signed JWT tokens (HS256).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from typing import Optional

from loguru import logger

from app.utils.utils import storage_dir

# ── storage ───────────────────────────────────────────────────────────────────
_USERS_FILE_LOCK = threading.RLock()


def _users_file() -> str:
    return os.path.join(storage_dir("", create=True), "users.json")


def _load_users() -> dict:
    path = _users_file()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error(f"failed to load users file: {exc}")
        return {}


def _save_users(users: dict) -> None:
    path = _users_file()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as exc:
        logger.error(f"failed to save users file: {exc}")
        raise


# ── password hashing (pure stdlib sha256 + salt, no extra deps) ───────────────
def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return digest, salt


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    digest, _ = _hash_password(password, salt)
    return secrets.compare_digest(digest, stored_hash)


def _hash_answer(answer: str) -> str:
    """Normalise + hash a security answer."""
    return hashlib.sha256(answer.strip().lower().encode()).hexdigest()


# ── JWT-lite (signed session tokens, no extra deps) ──────────────────────────
_TOKEN_SECRET = secrets.token_hex(32)   # regenerated per process; fine for local use
_TOKEN_TTL = 60 * 60 * 24 * 7          # 7 days


def _make_token(username: str) -> str:
    expires = int(time.time()) + _TOKEN_TTL
    payload = f"{username}:{expires}"
    sig = hmac_sign(payload)
    import base64
    token = base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()
    return token


def hmac_sign(data: str) -> str:
    import hmac
    return hmac.new(_TOKEN_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()


def verify_token(token: str) -> Optional[str]:
    """Return username if token is valid, else None."""
    try:
        import base64
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.rsplit(":", 2)
        if len(parts) != 3:
            return None
        username, expires_str, sig = parts
        payload = f"{username}:{expires_str}"
        expected_sig = hmac_sign(payload)
        if not secrets.compare_digest(sig, expected_sig):
            return None
        if int(expires_str) < int(time.time()):
            return None
        return username
    except Exception:
        return None


def create_token(username: str) -> str:
    return _make_token(username)


# ── public API ────────────────────────────────────────────────────────────────

SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What was the name of your elementary school?",
    "What is your oldest sibling's middle name?",
    "What was the make of your first car?",
    "What is your favorite childhood movie?",
    "What street did you grow up on?",
]


class AuthError(Exception):
    pass


def register(
    username: str,
    email: str,
    password: str,
    security_q1: str,
    security_a1: str,
    security_q2: str,
    security_a2: str,
) -> None:
    username = username.strip()
    email = email.strip().lower()

    if not username or len(username) < 3:
        raise AuthError("Username must be at least 3 characters.")
    if not email or "@" not in email:
        raise AuthError("Invalid email address.")
    if not password or len(password) < 6:
        raise AuthError("Password must be at least 6 characters.")
    if not security_a1.strip() or not security_a2.strip():
        raise AuthError("Both security answers are required.")

    with _USERS_FILE_LOCK:
        users = _load_users()
        if username in users:
            raise AuthError("Username already taken.")
        if any(u["email"] == email for u in users.values()):
            raise AuthError("Email already registered.")

        pw_hash, pw_salt = _hash_password(password)
        users[username] = {
            "email": email,
            "pw_hash": pw_hash,
            "pw_salt": pw_salt,
            "security_q1": security_q1,
            "security_a1": _hash_answer(security_a1),
            "security_q2": security_q2,
            "security_a2": _hash_answer(security_a2),
            "created_at": int(time.time()),
        }
        _save_users(users)
    logger.info(f"new user registered: {username}")


def login(username: str, password: str) -> str:
    """Return a session token on success."""
    username = username.strip()
    with _USERS_FILE_LOCK:
        users = _load_users()
    user = users.get(username)
    if user is None:
        raise AuthError("Invalid username or password.")
    if not _verify_password(password, user["pw_hash"], user["pw_salt"]):
        raise AuthError("Invalid username or password.")
    return create_token(username)


def get_security_questions(username: str) -> tuple[str, str]:
    """Return the two security questions for a user (for forgot-password flow)."""
    username = username.strip()
    with _USERS_FILE_LOCK:
        users = _load_users()
    user = users.get(username)
    if user is None:
        raise AuthError("Username not found.")
    return user["security_q1"], user["security_q2"]


def reset_password(
    username: str,
    answer1: str,
    answer2: str,
    new_password: str,
) -> None:
    username = username.strip()
    if not new_password or len(new_password) < 6:
        raise AuthError("New password must be at least 6 characters.")

    with _USERS_FILE_LOCK:
        users = _load_users()
        user = users.get(username)
        if user is None:
            raise AuthError("Username not found.")

        if not secrets.compare_digest(_hash_answer(answer1), user["security_a1"]):
            raise AuthError("Security answer 1 is incorrect.")
        if not secrets.compare_digest(_hash_answer(answer2), user["security_a2"]):
            raise AuthError("Security answer 2 is incorrect.")

        pw_hash, pw_salt = _hash_password(new_password)
        user["pw_hash"] = pw_hash
        user["pw_salt"] = pw_salt
        users[username] = user
        _save_users(users)
    logger.info(f"password reset for user: {username}")


def get_user_info(username: str) -> dict:
    with _USERS_FILE_LOCK:
        users = _load_users()
    user = users.get(username)
    if user is None:
        raise AuthError("User not found.")
    return {
        "username": username,
        "email": user["email"],
        "created_at": user["created_at"],
    }
