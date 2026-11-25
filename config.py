import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    ENV: str = os.getenv("ENV", "development")
    APP_NAME: str = os.getenv("APP_NAME", "Auth Application")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "fallback-secret-key-32-chars-long!")
    API_DOMAIN: str = os.getenv("API_DOMAIN", "http://localhost:8000")
    WEBSITE_DOMAIN: str = os.getenv("WEBSITE_DOMAIN", "http://localhost:8000")

    # JWT Config
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

    # OAuth Credentials
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    FACEBOOK_CLIENT_ID: str = os.getenv("FACEBOOK_CLIENT_ID", "")
    FACEBOOK_CLIENT_SECRET: str = os.getenv("FACEBOOK_CLIENT_SECRET", "")

    # Database Configuration (Defaults to local SQLite, or switches to PostgreSQL in production)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./users.db")

    # Fast2SMS — Phone OTP delivery (India, ~₹0.15/SMS)
    FAST2SMS_API_KEY: str = os.getenv("FAST2SMS_API_KEY", "")

    # Brevo — Transactional email (password reset)
    BREVO_API_KEY: str = os.getenv("BREVO_API_KEY", "")
    BREVO_SENDER_EMAIL: str = os.getenv("BREVO_SENDER_EMAIL", "noreply@yourdomain.com")

settings = Settings()
