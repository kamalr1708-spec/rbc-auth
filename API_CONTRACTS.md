# API Contract & Specification Document

## 1. Project Objective
Build a lightweight, production-grade, multi-provider authentication service in FastAPI. The system supports:
- **Email & Password Authentication** with salted `bcrypt` password hashing.
- **Phone Number Authentication** with rate-limited 6-digit numeric OTPs.
- **Social OAuth Authentication** (Google, GitHub, Facebook) with automatic account linking and CSRF state validation.
- **15-Minute Tokenized Password Reset** with single-use invalidation.
- **Role-Based Access Control (RBAC)** distinguishing `admin` vs `user` roles.
- **Smart Account Merging** allowing disparate phone and email records to merge into a single account.
- **Eval Fallback Architecture** permitting zero-cost, offline local testing.

---

## 2. API Endpoints & Contracts

---

### Endpoint 1: User Registration (Email & Password)
* **Objective:** Register a new user using email and password, hash credentials securely, assign role, and return a signed JWT session token.
* **Method & Path:** `POST /api/auth/register`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `email` | `string` | Yes | Valid email address |
  | `password` | `string` | Yes | Plaintext password (min 6 characters) |
  | `full_name` | `string` | No | User's display name |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Operation status (`OK`) |
  | `message` | `string` | Success notification and assigned role |
  | `access_token`| `string` | Signed RFC 7519 JWT session token |
  | `role` | `string` | Assigned role (`admin` for 1st user, `user` for others) |
* **Sample Input:**
  ```json
  {
    "email": "kamalr1501@gmail.com",
    "password": "SecurePassword123",
    "full_name": "Kamal R"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "Registration successful (Role: admin)",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJrYW1hbHIxNTAxQGdtYWlsLmNvbSIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc5NTUzNzYxNX0.signature_hash",
    "role": "admin"
  }
  ```

---

### Endpoint 2: User Login (Email & Password)
* **Objective:** Authenticate existing users by verifying bcrypt password hashes and return a JWT session token.
* **Method & Path:** `POST /api/auth/login`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `email` | `string` | Yes | Registered email address |
  | `password` | `string` | Yes | Plaintext password |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Success message |
  | `access_token`| `string` | Signed JWT session token |
  | `role` | `string` | Current user role |
* **Sample Input:**
  ```json
  {
    "email": "kamalr1501@gmail.com",
    "password": "SecurePassword123"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "Login successful",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJrYW1hbHIxNTAxQGdtYWlsLmNvbSIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc5NTUzNzYxNX0.signature_hash",
    "role": "admin"
  }
  ```

---

### Endpoint 3: Request Phone OTP
* **Objective:** Generate a secure 6-digit OTP, apply 60-second rate-limiting cooldown, and dispatch via SMS (or console fallback).
* **Method & Path:** `POST /api/auth/phone/send-otp`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `phone` | `string` | Yes | Phone number (supports international format) |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Confirmation message |
  | `otp_test_hint`| `string` | 6-digit OTP code (returned in dev mode for testing) |
* **Sample Input:**
  ```json
  {
    "phone": "+91 98421 98334"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "OTP sent successfully! Check terminal.",
    "otp_test_hint": "492817"
  }
  ```

---

### Endpoint 4: Verify Phone OTP & Login
* **Objective:** Verify user input code, guard against brute-force attacks (max 5 attempts), create or fetch user, and return JWT token.
* **Method & Path:** `POST /api/auth/phone/verify-otp`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `phone` | `string` | Yes | Target phone number |
  | `otp` | `string` | Yes | 6-digit numeric OTP code |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Confirmation message |
  | `access_token`| `string` | Signed JWT session token |
  | `role` | `string` | User role |
* **Sample Input:**
  ```json
  {
    "phone": "+91 98421 98334",
    "otp": "492817"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "Phone login successful",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicGhvbmUiOiIrOTE5ODQyMTk4MzM0Iiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzk1NTM3NjE1fQ.signature_hash",
    "role": "admin"
  }
  ```

---

### Endpoint 5: Request Password Reset Link
* **Objective:** Generate a secure 32-byte timed token valid for 15 minutes and dispatch via SMTP email (or console fallback).
* **Method & Path:** `POST /api/auth/forgot-password`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `email` | `string` | Yes | Registered account email |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Safe user-facing confirmation message |
  | `test_reset_link`| `string` | Direct clickable URL with reset token (dev mode) |
  | `test_token` | `string` | Raw 32-byte URL-safe reset token |
* **Sample Input:**
  ```json
  {
    "email": "kamalr1501@gmail.com"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "If this email is registered, a password reset link has been sent.",
    "test_reset_link": "http://localhost:8000/?reset_token=W5k_9zM4t7PxQ2Y1a8B3c6D0eF-uHvJ8K_L9mNoP",
    "test_token": "W5k_9zM4t7PxQ2Y1a8B3c6D0eF-uHvJ8K_L9mNoP"
  }
  ```

---

### Endpoint 6: Confirm Password Reset
* **Objective:** Validate reset token lifetime, ensure single-use invalidation, update password hash with `bcrypt`, and invalidate token.
* **Method & Path:** `POST /api/auth/reset-password`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `token` | `string` | Yes | 32-byte reset token from link |
  | `new_password`| `string` | Yes | New password (min 6 characters) |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Confirmation message |
* **Sample Input:**
  ```json
  {
    "token": "W5k_9zM4t7PxQ2Y1a8B3c6D0eF-uHvJ8K_L9mNoP",
    "new_password": "NewSecretPassword2026"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "Password updated successfully! You can now log in."
  }
  ```

---

### Endpoint 7: Get Authenticated User Profile (Protected)
* **Objective:** Retrieve authenticated user profile and all linked OAuth providers via JWT bearer token.
* **Method & Path:** `GET /api/user/me`
* **Headers:** `Authorization: Bearer <jwt_access_token>`
* **Input Fields:** None
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Authentication status (`authenticated`) |
  | `user` | `object` | Profile record (`id`, `email`, `phone`, `full_name`, `role`) |
  | `linked_providers` | `array` | List of linked OAuth platforms (`["google", "github"]`) |
  | `message` | `string` | Status message |
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "authenticated",
    "user": {
      "id": 1,
      "email": "kamalr1501@gmail.com",
      "phone": "+919842198334",
      "full_name": "Kamal R",
      "role": "admin"
    },
    "linked_providers": ["google", "github"],
    "message": "Access granted to user profile"
  }
  ```

---

### Endpoint 8: Smart Merge / Link Phone Number (Protected)
* **Objective:** Verify ownership of phone via OTP, attach to active account, or merge two disparate accounts if phone is registered elsewhere.
* **Method & Path:** `POST /api/user/link-phone`
* **Headers:** `Authorization: Bearer <jwt_access_token>`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `phone` | `string` | Yes | Target phone number |
  | `otp` | `string` | Yes | Verified OTP code |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Merge / linking confirmation message |
* **Sample Input:**
  ```json
  {
    "phone": "+91 98421 98334",
    "otp": "492817"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "Accounts merged! Phone '+919842198334' and previous data have been merged into this account."
  }
  ```

---

### Endpoint 9: Admin User List (RBAC Protected)
* **Objective:** Provide a listing of all registered accounts, roles, and status strictly for users possessing the `admin` role.
* **Method & Path:** `GET /api/admin/users`
* **Headers:** `Authorization: Bearer <admin_jwt_token>`
* **Input Fields:** None
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `users` | `array` | List of all user objects in database |
  | `total_users` | `integer` | Count of registered users |
  | `requested_by` | `string` | Identity of the requesting administrator |
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "users": [
      {
        "id": 1,
        "email": "kamalr1501@gmail.com",
        "phone": "+919842198334",
        "full_name": "Kamal R",
        "role": "admin",
        "is_active": 1,
        "created_at": 1795537000.12
      }
    ],
    "total_users": 1,
    "requested_by": "kamalr1501@gmail.com"
  }
  ```
* **Sample Error Output (HTTP 403 Forbidden - if called by regular user):**
  ```json
  {
    "detail": "Access denied: Requires one of roles ['admin'], your role is 'user'"
  }
  ```

---

### Endpoint 10: Change User Role (RBAC Protected)
* **Objective:** Allow an administrator to promote or demote user roles while enforcing safety guards against self-demotion.
* **Method & Path:** `POST /api/admin/change-role`
* **Headers:** `Authorization: Bearer <admin_jwt_token>`
* **Input Fields:**
  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `user_id` | `integer`| Yes | Target user ID |
  | `new_role` | `string` | Yes | Target role (`user`, `admin`, `moderator`) |
* **Output Fields:**
  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `status` | `string` | Status code (`OK`) |
  | `message` | `string` | Confirmation message |
* **Sample Input:**
  ```json
  {
    "user_id": 2,
    "new_role": "admin"
  }
  ```
* **Sample Output (HTTP 200):**
  ```json
  {
    "status": "OK",
    "message": "User 2 role updated to 'admin'"
  }
  ```
