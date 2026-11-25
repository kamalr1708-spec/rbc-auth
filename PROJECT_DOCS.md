# Authentication System Engineering Documentation & Incident Retrospective

## 1. Executive Summary
This document provides a comprehensive engineering record of the authentication system built with **FastAPI**, **SQLite**, **Bcrypt**, and **PyJWT**. It details the original architectural decisions, every technical roadblock encountered during development, the root-cause analyses, and the exact engineering fixes applied.

---

## 2. Architecture & Tech Stack Decisions

### 2.1 The Core Dilemma: Managed Tool vs. Pure Python
* **Manager's Brief:** Use the best ready-made custom tool without writing everything from scratch.
* **Exploration of SuperTokens:**
  * SuperTokens was evaluated for drop-in UI and managed session handling.
  * *Constraint Discovered:* SuperTokens Core is written in Java and requires either an external managed cloud instance or a local Docker daemon. The network environment blocked outbound connections to `try.supertokens.com`, and Docker was unavailable.
* **Final Architectural Decision:**
  * Build a **100% self-contained, pure Python solution** using FastAPI, PyJWT, and SQLite.
  * Provides zero third-party vendor lock-in, zero external infrastructure dependencies, and 100% data ownership while following RFC standards (RFC 7519 for JWT).

---

## 3. Engineering Challenges, Root Causes & Solutions

### Problem 1: Cloud Core Network Timeout
* **Symptom:** When triggering Phone OTP, the request hung indefinitely and timed out.
* **Root Cause:** The SuperTokens Python adapter was attempting to contact `https://try.supertokens.com/hello`. Network boundaries prevented access to external demo cores.
* **Solution:** Replaced external network calls with a local Python-native auth service backed by SQLite (`users.db`). Implemented an **Eval Fallback** that prints OTP codes to the terminal console and browser screen for zero-cost, offline development.

---

### Problem 2: SQLite Schema Mismatch (`otps` table)
* **Symptom:** OTP generation stopped working silently after adding rate limiting.
* **Root Cause:** The `otps` table was initially created with 3 columns (`phone`, `otp`, `expires_at`). Later rate-limiting enhancements introduced queries expecting 5 columns (`last_requested_at`, `attempts`). SQLite failed on the missing columns.
* **Solution:** Dropped and recreated the `otps` schema with all 5 columns:
  ```sql
  CREATE TABLE otps (
      phone TEXT PRIMARY KEY,
      otp TEXT,
      expires_at REAL,
      last_requested_at REAL,
      attempts INTEGER DEFAULT 0
  );
  ```

---

### Problem 3: Password Column Naming Mismatch (`password` vs `password_hash`)
* **Symptom:** Frontend reported `Error communicating with server` during Email/Password registration.
* **Root Cause:** The early prototype table used a `password` column, but production security hardening transitioned to `password_hash` for salted `bcrypt` storage. The mismatch resulted in an uncaught SQLite operational error.
* **Solution:** Standardized the schema to `password_hash` with `bcrypt.gensalt(12)`, ensuring raw passwords are never written to disk.

---

### Problem 4: Frontend Displaying `[object Object]`
* **Symptom:** Validation errors appeared as `[object Object]` instead of readable error text.
* **Root Cause:** FastAPI returns validation errors as an array of objects (`{"detail": [{"loc": [...], "msg": "..."}]}`). The frontend directly interpolated `data.detail` into innerHTML.
* **Solution:** Implemented `formatErrorMessage(detail)` in JavaScript to dynamically parse strings, arrays, and error dictionaries into plain English.

---

### Problem 5: Internal Server Error on Secondary OAuth Login
* **Symptom:** User registered via Email, logged out, and logged in via Google OAuth with the same email, resulting in a 500 Internal Server Error.
* **Root Cause:** In the OAuth callback, if the account was already linked or existed, the `role` variable was unassigned before being passed to `create_access_token()`, triggering a Python `NameError: name 'role' is not defined`.
* **Solution:** Extracted all account linking and role resolution into a unified, reusable function:
  ```python
  get_or_create_oauth_user(provider, provider_user_id, email, name)
  ```
  This function guarantees that `id`, `email`, and `role` are always returned under all scenarios (new user, existing user, returning user).

---

### Problem 6: Post-Logout OTP State Desynchronization
* **Symptom:** After logging out, attempting Phone OTP login resulted in `No OTP requested for this phone number`.
* **Root Cause:** The frontend JavaScript state variable `otpRequested` remained `true` after logout. Clicking the button immediately triggered the `/verify-otp` endpoint instead of requesting a new OTP first.
* **Solution:** Created `resetPhoneForm()` which resets `otpRequested = false`, hides the OTP input field, and restores button text to "Send OTP" upon logout, tab switch, or successful verification.

---

### Problem 7: Split Identity Collision on Account Linking
* **Symptom:** A user who logged in via Phone OTP and later registered via Email could not link their phone number, receiving `Phone number is already linked to another account`.
* **Root Cause:** Two distinct database rows existed: User A (Phone only) and User B (Email only). The system rejected linking because the unique constraint on phone was already claimed by User A.
* **Solution:** Implemented **Smart Account Merging**:
  1. Once User B proves ownership of the phone via OTP verification, the backend transfers all OAuth credentials from User A to User B.
  2. Updates User B's phone number.
  3. Deletes the orphaned User A record.

---

### Problem 8: Phone Number Formatting Inconsistency
* **Symptom:** `+91 98421 98334`, `9842198334`, and `+91-98421-98334` could resolve to separate database accounts.
* **Solution:** Implemented `normalize_phone()` using regex to strip all spaces, dashes, and parentheses while preserving international country codes.

---

### Problem 9: Admin Self-Lockout
* **Symptom:** An admin could demote themselves to a standard `user` role via the `/api/admin/change-role` endpoint, leaving the application without administrative access.
* **Solution:** Added a safety guard in `change_user_role` preventing admins from demoting their own active session ID.

---

## 4. Security Architecture Summary

| Security Feature | Implementation Mechanism |
| :--- | :--- |
| **Password Storage** | `bcrypt` with work factor 12 (salted, irreversible) |
| **Session Security** | RFC 7519 signed JWTs using `HS256`, 24-hour expiration |
| **CSRF Defense** | Cryptographic random `state` parameter verification on OAuth callbacks |
| **SMS Toll Fraud Defense** | 60-second cooldown timer + 5 failed attempts lockout |
| **Password Reset Security** | URL-safe 32-byte tokens, 15-minute validity, single-use invalidation |
| **RBAC Authorization** | FastAPI `require_role(["admin"])` dependency guard |
| **Account State Enforcement**| `is_active` check on every token resolution |
