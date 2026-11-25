import sqlite3
import os
from config import settings

DB_PATH = "users.db"

def get_db():
    # If a PostgreSQL database URL is configured, support it seamlessly
    db_url = settings.DATABASE_URL
    if db_url.startswith("postgresql://") or db_url.startswith("postgres://"):
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
            return conn
        except ImportError:
            raise RuntimeError("psycopg2 is required for PostgreSQL. Run: pip install psycopg2-binary")

    # Default: SQLite with WAL (Write-Ahead-Logging) mode enabled for high-performance concurrent writes
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode: allows simultaneous reads and writes without locking
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        phone TEXT UNIQUE,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        created_at REAL
    )
    """)

    # Check and add role column if missing in existing table
    cursor.execute("PRAGMA table_info(users)")
    cols = [col[1] for col in cursor.fetchall()]
    if "role" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")

    # Linked OAuth Accounts Table (Supports Google, GitHub, Facebook linked to one user)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        provider TEXT,
        provider_user_id TEXT,
        created_at REAL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(provider, provider_user_id)
    )
    """)

    # OTP Table with Cooldown and Attempt Limits
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS otps (
        phone TEXT PRIMARY KEY,
        otp TEXT,
        expires_at REAL,
        last_requested_at REAL,
        attempts INTEGER DEFAULT 0
    )
    """)

    # Password Reset Tokens Table (One-time use)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        token TEXT PRIMARY KEY,
        email TEXT,
        expires_at REAL,
        is_used INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()

init_db()
