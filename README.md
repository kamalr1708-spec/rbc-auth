# FastAPI Multi-Provider Authentication System

A lightweight, self-contained, and production-ready authentication service built with **FastAPI**, **SQLite**, **Bcrypt**, and **PyJWT**.

---

## 🌟 Highlights

- **Multiple Sign-in Methods:**
  - 📧 **Email & Password** (Salted `bcrypt` hashing)
  - 📱 **Phone + OTP** (Rate-limited, brute-force guarded, test fallback)
  - 🌐 **Google OAuth** (Live account linking & CSRF state verification)
  - 🐙 **GitHub OAuth** (Live account linking & CSRF state verification)
  - 👥 **Facebook OAuth** (Meta Graph API + automated dev mock fallback)
- **Security & Session Management:**
  - Standard signed JWT tokens stored in `localStorage`
  - 15-minute single-use Password Reset (Terminal fallback + SMTP ready)
  - Role-Based Access Control (**RBAC**): `admin` vs `user` roles with protected admin panel
  - Smart Account Merging (link phone/email across disparate logins)
  - Phone number normalization and active account enforcement

---

## 📁 Project Layout

```text
rbc_prj/
├── config.py         # Environment variables & application settings
├── database.py       # SQLite database initialization & table schemas
├── auth_utils.py     # Password hashing, JWT creation, OTP & OAuth helpers
├── main.py           # FastAPI routes, OAuth callbacks, protected APIs
├── static/
│   └── index.html    # Interactive login page & authenticated Dashboard
├── requirements.txt  # Python dependencies
├── .env.example      # Environment variables template
├── .gitignore        # Ignores .env and SQLite DB from Git
├── README.md         # Project quickstart guide
└── PROJECT_DOCS.md   # In-depth engineering docs & problem-solving history
```

---

## 🚀 Quickstart Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)
Create a `.env` file based on `.env.example`:
```env
ENV=development
APP_NAME="Auth Application"
SECRET_KEY="your-secret-key-at-least-32-chars-long"
API_DOMAIN=http://localhost:8000
WEBSITE_DOMAIN=http://localhost:8000

# Social Logins (Google & GitHub)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
FACEBOOK_CLIENT_ID=
FACEBOOK_CLIENT_SECRET=

# Fast2SMS — Phone OTP SMS delivery (~₹0.15/SMS, India)
FAST2SMS_API_KEY=your_fast2sms_api_key

# Brevo — Transactional email (password reset)
BREVO_API_KEY=your_brevo_api_key
BREVO_SENDER_EMAIL=noreply@yourdomain.com
```

### 3. Start Application
```bash
uvicorn main:app --reload
```
Open **`http://localhost:8000`** in your web browser.

---

## 🧪 Testing Features (Zero Cost / Eval Mode)

- **Phone OTP:** The OTP displays directly on screen and prints in your terminal console.
- **Password Reset:** The reset link prints to terminal and screen; open the link to set a new password.
- **First Registered User:** Automatically becomes the system **Admin** with access to the 🛡️ Admin Panel.
- **Facebook Login:** Includes an automated dev mock fallback if real Meta credentials are not provided.
