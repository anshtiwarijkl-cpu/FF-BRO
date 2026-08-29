# ScannerAPI Secure Admin + Real Database Health

This package replaces the old client-side/mock security and database status logic with a backend-controlled flow.

## Real security flow

1. `POST /api/admin/login` verifies admin credentials on the server.
2. If Firebase `settings.two_fa_enabled` is true, a short-lived login challenge is returned.
3. `POST /api/admin/login/2fa` verifies a real RFC-style TOTP generated from the stored Base32 secret, or consumes one hashed backup code.
4. Server-side IP verification is then evaluated from `settings.ip_verification_enabled` and `settings.allowed_ips`.
5. Successful login creates an HttpOnly session cookie stored server-side in Firebase.
6. Logout revokes the current session.
7. “Terminate all sessions” increments a server-side session version, invalidating every prior admin session.

## Real 2FA setup

The dashboard calls `/api/admin/2fa/setup`, which creates a random TOTP secret and a real `otpauth://` URI plus QR image. `/api/admin/2fa/enable` requires a current authenticator code before enabling it. Backup codes are stored as scrypt-derived hashes and are removed after one successful use.

## Real API-key verification / rate limiting

`POST /api/scanner/verify-key` performs API-key lookup server-side and applies a per-minute limiter. Redis is used when configured; an in-memory fallback exists for development only.

## Real database health

`GET /api/health` checks Firebase, MongoDB, MySQL and Redis with actual operations. `GET /api/health/stream` pushes a fresh snapshot every few seconds.

## Destructive operations

The `/api/admin/databases/:db/clear` and `/api/admin/databases/delete-all` endpoints are genuinely destructive and require an authenticated admin session plus an exact confirmation string. Do not point them at production data until you have verified the environment variables.

## Setup

```bash
npm install
copy .env.example .env
npm start
```

Open `http://localhost:3000/login.html`.

For production, set `ADMIN_PASSWORD_HASH` instead of `ADMIN_PASSWORD`, use HTTPS, and store Firebase/Mongo/MySQL/Redis credentials only on the server.
