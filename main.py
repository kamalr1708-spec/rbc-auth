import time
import httpx
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

from config import settings
from database import get_db, init_db
from auth_utils import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    create_password_reset_token,
    create_state_token,
    verify_state_token,
    generate_otp,
    get_or_create_oauth_user,
    normalize_phone,
)

init_db()

app = FastAPI(title=settings.APP_NAME)

allowed_origins = [settings.WEBSITE_DOMAIN] if settings.ENV == "production" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- PYDANTIC SCHEMAS -----------------
class EmailRegisterRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None

class EmailLoginRequest(BaseModel):
    email: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class SendOTPRequest(BaseModel):
    phone: str

class VerifyOTPRequest(BaseModel):
    phone: str
    otp: str

# ----------------- DEPENDENCY: CURRENT USER -----------------
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token")

    token = authorization.split(" ")[1]
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    user_id = payload["sub"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, phone, full_name, role, is_active FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User account not found")

    if user["is_active"] == 0:
        raise HTTPException(status_code=403, detail="Your account has been deactivated. Please contact support.")

    return dict(user)

def require_role(allowed_roles: list[str]):
    """Role-based access guard dependency."""
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role", "user")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: Requires one of roles {allowed_roles}, your role is '{user_role}'"
            )
        return current_user
    return role_checker

# ----------------- FRONTEND UI -----------------
@app.get("/", response_class=HTMLResponse)
async def serve_login_page():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()

# ----------------- 1. EMAIL & PASSWORD -----------------
@app.post("/api/auth/register")
async def register_email(req: EmailRegisterRequest):
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (req.email.lower(),))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    # First registered user becomes admin automatically, others default to 'user'
    cursor.execute("SELECT COUNT(*) as count FROM users")
    is_first_user = cursor.fetchone()["count"] == 0
    role = "admin" if is_first_user else "user"

    pwd_hash = hash_password(req.password)
    cursor.execute(
        "INSERT INTO users (email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (req.email.lower(), pwd_hash, req.full_name or "", role, time.time())
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    token = create_access_token({"sub": user_id, "email": req.email.lower(), "role": role})
    return {"status": "OK", "message": f"Registration successful (Role: {role})", "access_token": token, "role": role}

@app.post("/api/auth/login")
async def login_email(req: EmailLoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, role FROM users WHERE email = ?", (req.email.lower(),))
    user = cursor.fetchone()
    conn.close()

    if not user or not user["password_hash"] or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    user_role = user["role"] or "user"
    token = create_access_token({"sub": user["id"], "email": req.email.lower(), "role": user_role})
    return {"status": "OK", "message": "Login successful", "access_token": token, "role": user_role}

# ----------------- 2. PASSWORD RESET (FORGOT PASSWORD) -----------------
@app.post("/api/auth/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    email = req.email.lower().strip()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    reset_token = create_password_reset_token(email)
    expires_at = time.time() + 900  # 15 minutes validity

    if user:
        cursor.execute(
            "INSERT INTO password_resets (token, email, expires_at) VALUES (?, ?, ?)",
            (reset_token, email, expires_at)
        )
        conn.commit()
    conn.close()

    # --- DELIVERY — Brevo REST API (or console fallback) ---
    reset_link = f"{settings.WEBSITE_DOMAIN}/?reset_token={reset_token}"
    email_sent = False

    if settings.BREVO_API_KEY:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={
                        "api-key": settings.BREVO_API_KEY,
                        "Content-Type": "application/json",
                    },
                    json={
                        "sender": {
                            "name": settings.APP_NAME,
                            "email": settings.BREVO_SENDER_EMAIL,
                        },
                        "to": [{"email": email}],
                        "subject": f"Password Reset – {settings.APP_NAME}",
                        "textContent": (
                            f"Hello,\n\n"
                            f"We received a request to reset your password.\n"
                            f"Click the link below (valid for 15 minutes):\n\n"
                            f"{reset_link}\n\n"
                            f"If you did not request this, ignore this email."
                        ),
                    },
                    timeout=10,
                )
            if resp.status_code in (200, 201):
                email_sent = True
                print(f"[Brevo] Reset email delivered to {email}")
            else:
                print(f"[Brevo Error] status={resp.status_code} body={resp.text}")
        except Exception as e:
            print(f"[Brevo Error] {e}. Falling back to console.")

    response_data = {
        "status": "OK",
        "message": "If this email is registered, a password reset link has been sent to your inbox." if email_sent else "If this email is registered, a password reset link has been sent.",
    }
    if settings.ENV != "production":
        print("\n" + "="*60)
        print(f" [PASSWORD RESET LINK] For {email}:")
        print(f" {reset_link}")
        print("="*60 + "\n")
        response_data["test_reset_link"] = reset_link
        response_data["test_token"] = reset_token

    return response_data

@app.post("/api/auth/reset-password")
async def reset_password(req: ResetPasswordRequest):
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT email, expires_at, is_used FROM password_resets WHERE token = ?", (req.token,))
    record = cursor.fetchone()

    if not record or record["is_used"] == 1:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    if time.time() > record["expires_at"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Reset token has expired. Request a new one.")

    # Update Password and mark token as used
    new_hash = hash_password(req.new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (new_hash, record["email"]))
    cursor.execute("UPDATE password_resets SET is_used = 1 WHERE token = ?", (req.token,))
    conn.commit()
    conn.close()

    return {"status": "OK", "message": "Password updated successfully! You can now log in."}

# ----------------- 3. PHONE OTP (WITH RATE LIMIT & BRUTE-FORCE GUARD) -----------------
@app.post("/api/auth/phone/send-otp")
async def send_phone_otp(req: SendOTPRequest):
    phone = normalize_phone(req.phone)
    if len(phone) < 8:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    now = time.time()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT last_requested_at FROM otps WHERE phone = ?", (phone,))
    row = cursor.fetchone()

    # 60s Rate limit cooldown
    if row and (now - row["last_requested_at"]) < 60:
        remaining = int(60 - (now - row["last_requested_at"]))
        conn.close()
        raise HTTPException(status_code=429, detail=f"Please wait {remaining} seconds before requesting a new OTP")

    otp = generate_otp()
    expires_at = now + 300  # 5 minutes

    cursor.execute(
        "INSERT OR REPLACE INTO otps (phone, otp, expires_at, last_requested_at, attempts) VALUES (?, ?, ?, ?, 0)",
        (phone, otp, expires_at, now)
    )
    conn.commit()
    conn.close()

    # --- DELIVERY — Fast2SMS (or console fallback) ---
    sms_sent = False
    if settings.FAST2SMS_API_KEY:
        # Fast2SMS needs 10-digit number only (strip country code)
        phone_digits = phone.lstrip("+").removeprefix("91") if phone.startswith(("+91", "91")) else phone.lstrip("+")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://www.fast2sms.com/dev/bulkV2",
                    headers={"authorization": settings.FAST2SMS_API_KEY},
                    params={
                        "route": "otp",
                        "variables_values": otp,
                        "numbers": phone_digits,
                    },
                    timeout=10,
                )
            data = resp.json()
            if data.get("return") is True:
                sms_sent = True
                print(f"[Fast2SMS] OTP dispatched to {phone_digits}")
            else:
                print(f"[Fast2SMS Error] {data}")
        except Exception as e:
            print(f"[Fast2SMS Error] {e}. Falling back to console.")

    response_data = {
        "status": "OK",
        "message": f"OTP sent via SMS to {phone}" if sms_sent else "OTP sent successfully! Check terminal.",
    }
    if settings.ENV != "production":
        print("\n" + "="*50)
        print(f" [PHONE OTP] Sent to {phone}: {otp}")
        print("="*50 + "\n")
        response_data["otp_test_hint"] = otp

    return response_data

@app.post("/api/auth/phone/verify-otp")
async def verify_phone_otp(req: VerifyOTPRequest):
    phone = normalize_phone(req.phone)
    user_otp = req.otp.strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT otp, expires_at, attempts FROM otps WHERE phone = ?", (phone,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="No OTP requested for this phone number")

    if row["attempts"] >= 5:
        conn.close()
        raise HTTPException(status_code=429, detail="Too many failed attempts. Please request a new OTP.")

    if time.time() > row["expires_at"]:
        conn.close()
        raise HTTPException(status_code=400, detail="OTP has expired. Please request a new one.")

    if row["otp"] != user_otp:
        cursor.execute("UPDATE otps SET attempts = attempts + 1 WHERE phone = ?", (phone,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Incorrect OTP entered")

    # OTP Verified: Clean up OTP table
    cursor.execute("DELETE FROM otps WHERE phone = ?", (phone,))

    # Find or Create User
    cursor.execute("SELECT id, role FROM users WHERE phone = ?", (phone,))
    user = cursor.fetchone()
    if not user:
        cursor.execute("SELECT COUNT(*) as count FROM users")
        is_first = cursor.fetchone()["count"] == 0
        role = "admin" if is_first else "user"
        cursor.execute("INSERT INTO users (phone, role, created_at) VALUES (?, ?, ?)", (phone, role, time.time()))
        user_id = cursor.lastrowid
    else:
        user_id = user["id"]
        role = user["role"] or "user"

    conn.commit()
    conn.close()

    token = create_access_token({"sub": user_id, "phone": phone, "role": role})
    return {"status": "OK", "message": "Phone login successful", "access_token": token, "role": role}

# ----------------- 4. SOCIAL OAUTH (GOOGLE, GITHUB, FACEBOOK) -----------------
@app.get("/api/auth/oauth/github")
async def oauth_github_redirect():
    if not settings.GITHUB_CLIENT_ID:
        return JSONResponse({"status": "info", "message": "Set GITHUB_CLIENT_ID & GITHUB_CLIENT_SECRET in .env for live GitHub login."})
    state = create_state_token()
    github_url = f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&scope=user:email&state={state}"
    return RedirectResponse(github_url)

@app.get("/api/auth/github/callback")
async def oauth_github_callback(code: str = Query(...), state: Optional[str] = Query(None)):
    if settings.ENV == "production" and not verify_state_token(state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state (CSRF detected)")

    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            }
        )
        token_data = token_res.json()
        gh_token = token_data.get("access_token")
        if not gh_token:
            raise HTTPException(status_code=400, detail="Failed to fetch GitHub token")

        user_res = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {gh_token}"}
        )
        gh_user = user_res.json()
        gh_id = str(gh_user.get("id"))
        email = gh_user.get("email") or f"{gh_user.get('login')}@github.local"
        name = gh_user.get("name") or gh_user.get("login")

    # Unified Account Linking & Role Resolution
    user_info = get_or_create_oauth_user(provider="github", provider_user_id=gh_id, email=email, name=name)

    token = create_access_token({"sub": user_info["id"], "email": user_info["email"], "role": user_info["role"]})
    return RedirectResponse(f"/?token={token}")

@app.get("/api/auth/oauth/google")
async def oauth_google_redirect():
    if not settings.GOOGLE_CLIENT_ID:
        return JSONResponse({"status": "info", "message": "Set GOOGLE_CLIENT_ID in .env for live Google login."})
    state = create_state_token()
    google_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.API_DOMAIN}/api/auth/google/callback"
        f"&response_type=code&scope=openid%20email%20profile"
        f"&access_type=offline&prompt=select_account"
        f"&state={state}"
    )
    return RedirectResponse(google_url)

@app.get("/api/auth/google/callback")
async def oauth_google_callback(code: str = Query(...), state: Optional[str] = Query(None)):
    if settings.ENV == "production" and not verify_state_token(state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state (CSRF detected)")

    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": f"{settings.API_DOMAIN}/api/auth/google/callback",
            }
        )
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to fetch Google access token")

        # Fetch Google user profile
        user_res = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        g_user = user_res.json()
        g_id = str(g_user.get("sub"))
        email = g_user.get("email")
        name = g_user.get("name") or g_user.get("given_name") or email.split("@")[0]

    # Unified Account Linking & Role Resolution
    user_info = get_or_create_oauth_user(provider="google", provider_user_id=g_id, email=email, name=name)

    token = create_access_token({"sub": user_info["id"], "email": user_info["email"], "role": user_info["role"]})
    return RedirectResponse(f"/?token={token}")

@app.get("/api/auth/oauth/facebook")
async def oauth_facebook_redirect():
    if not settings.FACEBOOK_CLIENT_ID or not settings.FACEBOOK_CLIENT_SECRET:
        if settings.ENV == "production":
            raise HTTPException(status_code=503, detail="Facebook OAuth is not configured")
        user_info = get_or_create_oauth_user(
            provider="facebook",
            provider_user_id="fb_mock_998877",
            email="demo_facebook_user@meta.local",
            name="Demo Facebook User"
        )
        token = create_access_token({"sub": user_info["id"], "email": user_info["email"], "role": user_info["role"]})
        return RedirectResponse(f"/?token={token}")

    fb_url = (
        f"https://www.facebook.com/v19.0/dialog/oauth?client_id={settings.FACEBOOK_CLIENT_ID}"
        f"&redirect_uri={settings.API_DOMAIN}/api/auth/facebook/callback"
        f"&scope=email,public_profile"
        f"&response_type=code"
    )
    return RedirectResponse(fb_url)

@app.get("/api/auth/facebook/callback")
async def oauth_facebook_callback(code: str = Query(...)):
    async with httpx.AsyncClient() as client:
        # 1. Exchange code for user access token
        token_res = await client.get(
            "https://graph.facebook.com/v19.0/oauth/access_token",
            params={
                "client_id": settings.FACEBOOK_CLIENT_ID,
                "client_secret": settings.FACEBOOK_CLIENT_SECRET,
                "redirect_uri": f"{settings.API_DOMAIN}/api/auth/facebook/callback",
                "code": code,
            }
        )
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to fetch Facebook access token")

        # 2. Fetch Facebook profile and email
        user_res = await client.get(
            "https://graph.facebook.com/me",
            params={
                "fields": "id,name,email",
                "access_token": access_token
            }
        )
        fb_user = user_res.json()
        fb_id = str(fb_user.get("id"))
        email = fb_user.get("email") or f"fb_{fb_id}@facebook.local"
        name = fb_user.get("name") or "Facebook User"

    # Unified Account Linking & Role Resolution
    user_info = get_or_create_oauth_user(provider="facebook", provider_user_id=fb_id, email=email, name=name)

    token = create_access_token({"sub": user_info["id"], "email": user_info["email"], "role": user_info["role"]})
    return RedirectResponse(f"/?token={token}")

# ----------------- 5. PROTECTED ROUTES & RBAC -----------------
@app.get("/api/user/me")
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT provider FROM oauth_accounts WHERE user_id = ?", (user_id,))
    linked_providers = [row["provider"] for row in cursor.fetchall()]
    conn.close()

    return {
        "status": "authenticated",
        "user": current_user,
        "linked_providers": linked_providers,
        "message": "Access granted to user profile"
    }

# ADMIN ONLY: View all users and their roles
@app.get("/api/admin/users")
async def get_all_users_admin(admin_user: dict = Depends(require_role(["admin"]))):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, phone, full_name, role, is_active, created_at FROM users ORDER BY id ASC")
    users_list = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "status": "OK",
        "users": users_list,
        "total_users": len(users_list),
        "requested_by": admin_user["email"] or admin_user["phone"]
    }

# ----------------- 6. ACCOUNT MERGING / LINKING (DASHBOARD) -----------------
class LinkEmailRequest(BaseModel):
    email: str
    password: str

class LinkPhoneRequest(BaseModel):
    phone: str
    otp: str

@app.post("/api/user/link-email")
async def link_email_to_account(req: LinkEmailRequest, current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    email = req.email.strip().lower()
    
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, role, full_name FROM users WHERE email = ? AND id != ?", (email, user_id))
    other_user = cursor.fetchone()

    pwd_hash = hash_password(req.password)

    if other_user:
        # SMART MERGE: Migrate OAuth accounts and delete orphaned other_user
        other_id = other_user["id"]
        cursor.execute("UPDATE oauth_accounts SET user_id = ? WHERE user_id = ?", (user_id, other_id))
        cursor.execute("DELETE FROM users WHERE id = ?", (other_id,))
        cursor.execute("UPDATE users SET email = ?, password_hash = ? WHERE id = ?", (email, pwd_hash, user_id))
        conn.commit()
        conn.close()
        return {"status": "OK", "message": f"Accounts merged! Email '{email}' and its linked providers have been merged into this account."}

    cursor.execute("UPDATE users SET email = ?, password_hash = ? WHERE id = ?", (email, pwd_hash, user_id))
    conn.commit()
    conn.close()

    return {"status": "OK", "message": f"Email '{email}' successfully linked to your account!"}

@app.post("/api/user/link-phone")
async def link_phone_to_account(req: LinkPhoneRequest, current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    phone = normalize_phone(req.phone)
    user_otp = req.otp.strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT otp, expires_at FROM otps WHERE phone = ?", (phone,))
    row = cursor.fetchone()

    if not row or time.time() > row["expires_at"] or row["otp"] != user_otp:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    cursor.execute("DELETE FROM otps WHERE phone = ?", (phone,))

    # Check if this phone number is registered under another user
    cursor.execute("SELECT id, role FROM users WHERE phone = ? AND id != ?", (phone, user_id))
    other_user = cursor.fetchone()

    if other_user:
        # SMART MERGE: Reassign oauth accounts and merge other_user into current_user
        other_id = other_user["id"]
        cursor.execute("UPDATE oauth_accounts SET user_id = ? WHERE user_id = ?", (user_id, other_id))
        cursor.execute("DELETE FROM users WHERE id = ?", (other_id,))
        cursor.execute("UPDATE users SET phone = ? WHERE id = ?", (phone, user_id))
        conn.commit()
        conn.close()
        return {"status": "OK", "message": f"Accounts merged! Phone '{phone}' and previous data have been merged into this account."}

    cursor.execute("UPDATE users SET phone = ? WHERE id = ?", (phone, user_id))
    conn.commit()
    conn.close()

    return {"status": "OK", "message": f"Phone '{phone}' successfully linked to your account!"}
class UpdateRoleRequest(BaseModel):
    user_id: int
    new_role: str

@app.post("/api/admin/change-role")
async def change_user_role(req: UpdateRoleRequest, admin_user: dict = Depends(require_role(["admin"]))):
    if req.new_role not in ["user", "admin", "moderator"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'user', 'admin', or 'moderator'.")

    # Guard: Prevent admin from accidentally demoting their own account
    if req.user_id == admin_user["id"] and req.new_role != "admin":
        raise HTTPException(status_code=400, detail="Safety check: You cannot demote your own admin account.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id = ?", (req.user_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (req.new_role, req.user_id))
    conn.commit()
    conn.close()

    return {"status": "OK", "message": f"User {req.user_id} role updated to '{req.new_role}'"}
