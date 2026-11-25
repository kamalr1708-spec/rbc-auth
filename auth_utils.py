import time
import secrets
import random
import bcrypt
import jwt
from typing import Optional, Dict, Any
from config import settings

import re

def normalize_phone(phone: str) -> str:
    """Strips spaces, dashes, parentheses and cleans phone numbers."""
    if not phone:
        return ""
    # Keep leading + if present, strip all other non-digits
    has_plus = phone.strip().startswith("+")
    digits = re.sub(r"[^\d]", "", phone)
    return f"+{digits}" if has_plus else digits

# ----------------- PASSWORD HASHING (BCRYPT) -----------------
def hash_password(password: str) -> str:
    """Hashes a password with a secure salt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

# ----------------- JWT TOKENS (SESSION & RESET) -----------------
def create_state_token() -> str:
    """Generates a short-lived signed JWT state token for stateless OAuth CSRF protection."""
    return create_access_token({"purpose": "oauth_state", "nonce": secrets.token_urlsafe(12)}, expires_minutes=10)

def verify_state_token(state: Optional[str]) -> bool:
    """Verifies an OAuth state token without requiring shared in-memory state."""
    if not state:
        return False
    payload = decode_access_token(state)
    return bool(payload and payload.get("purpose") == "oauth_state")
def create_access_token(data: Dict[str, Any], expires_minutes: Optional[int] = None) -> str:
    """Creates a signed JWT session token."""
    to_encode = data.copy()
    # RFC 7519: 'sub' (Subject) must always be a string
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])
    expire_time = int(time.time() + (expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60)
    to_encode.update({"exp": expire_time})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and verifies a JWT token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except Exception as e:
        return None

def create_password_reset_token(email: str) -> str:
    """Generates a secure random 32-byte token for password reset."""
    return secrets.token_urlsafe(32)

# ----------------- UNIFIED OAUTH ACCOUNT LINKING -----------------
def get_or_create_oauth_user(provider: str, provider_user_id: str, email: str, name: str) -> Dict[str, Any]:
    """
    Centralized, bulletproof OAuth handler:
    1. Returns existing user if already linked via this provider.
    2. Links provider to existing user if email already registered.
    3. Creates new user if brand new (first user gets 'admin', others get 'user').
    Always returns: {'id': user_id, 'email': email, 'role': role}
    """
    from database import get_db

    conn = get_db()
    cursor = conn.cursor()

    # Step 1: Check if this provider account is already linked
    cursor.execute(
        "SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?",
        (provider, str(provider_user_id))
    )
    linked = cursor.fetchone()

    if linked:
        user_id = linked["user_id"]
        cursor.execute("SELECT email, role FROM users WHERE id = ?", (user_id,))
        u = cursor.fetchone()
        user_email = u["email"] if u else email
        user_role = u["role"] if (u and "role" in u.keys() and u["role"]) else "user"
        conn.close()
        return {"id": user_id, "email": user_email, "role": user_role}

    # Step 2: Check if a user with this email already exists
    cursor.execute("SELECT id, email, role FROM users WHERE email = ?", (email.lower(),))
    existing = cursor.fetchone()

    if existing:
        user_id = existing["id"]
        user_email = existing["email"]
        user_role = existing["role"] if ("role" in existing.keys() and existing["role"]) else "user"
    else:
        # Step 3: Brand new user
        cursor.execute("SELECT COUNT(*) as count FROM users")
        is_first = cursor.fetchone()["count"] == 0
        user_role = "admin" if is_first else "user"
        user_email = email.lower()

        cursor.execute(
            "INSERT INTO users (email, full_name, role, created_at) VALUES (?, ?, ?, ?)",
            (user_email, name, user_role, time.time())
        )
        user_id = cursor.lastrowid

    # Record the provider link
    cursor.execute(
        "INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_user_id, created_at) VALUES (?, ?, ?, ?)",
        (user_id, provider, str(provider_user_id), time.time())
    )
    conn.commit()
    conn.close()

    return {"id": user_id, "email": user_email, "role": user_role}

# ----------------- OTP GENERATOR -----------------
def generate_otp() -> str:
    """Generates a secure 6-digit numeric OTP."""
    return f"{random.randint(100000, 999999)}"
