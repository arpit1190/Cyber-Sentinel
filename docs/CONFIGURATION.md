# CYBER SENTINEL — CONFIGURATION MANAGEMENT GUIDE

**Architecture Document**: Centralized Configuration & Environment Security  
**Version**: 2.0  
**Security Level**: High-Assurance Fail-Closed System  

---

## 1. ARCHITECTURAL OVERVIEW

Cyber Sentinel implements a **centralized, fail-closed configuration management system** located at [`backend/src/config/index.js`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/src/config/index.js).

### Core Design Principles
1. **Zero Secret Leakage**: Plaintext credentials, JWT secrets, and API keys are never written to server logs, stdout, or client error messages.
2. **Fail-Closed in Production**: If any security-critical environment variable is missing, malformed, or uses a known predictable default in `NODE_ENV=production`, the server halts startup immediately with an actionable validation report.
3. **Safe Local Development**: In `development` and `test` environments, safe local-only fallbacks allow zero-configuration startup while issuing non-fatal diagnostic warnings.
4. **Strict Type & Boundary Validation**: Ports are verified as valid integer ranges (1–65535), URLs must enforce valid protocols (`http:`/`https:`), and emails are regex-validated.
5. **Immutable Export**: The active configuration object is frozen with `Object.freeze()` to prevent runtime tampering or prototype manipulation.

---

## 2. ENVIRONMENT VARIABLE SPECIFICATION MATRIX

| Variable Name | Type | Required in Prod | Development Default | Description & Validation Rules |
| :--- | :---: | :---: | :--- | :--- |
| `NODE_ENV` | String | Yes | `development` | Runtime mode: `development`, `test`, `staging`, or `production`. |
| `PORT` | Integer | No | `5000` / `10000` | HTTP listening port (Integer between 1 and 65535). |
| `FRONTEND_URL` | URL | Yes | `http://localhost:5173` | Allowed frontend origin for reset links and redirects (Must be valid URL). |
| `CORS_ORIGIN` | String (CSV) | Yes | `http://localhost:5173,...` | Comma-separated allowed CORS origins. Wildcard (`*`) is **strictly forbidden** in production. |
| `JWT_SECRET` | String | **Yes** | `[Dev Fallback]` | Secret key for signing operator access JWTs. **Minimum 32 characters** in production. |
| `JWT_EXPIRES_IN` | String | No | `2h` (dev) / `1h` (prod) | Lifetime of operator access JWTs (e.g. `15m`, `1h`, `2h`). |
| `REFRESH_TOKEN_SECRET`| String | No | `[Derived from JWT]` | Secret key for signing rotating refresh tokens (**Minimum 32 characters**). |
| `REFRESH_TOKEN_EXPIRES_IN`| String | No | `7d` | Lifetime of rotating session refresh tokens. |
| `DEVICE_SECRET` | String | **Yes** | `[Dev Device Key]` | Token for authenticating endpoint telemetry agent streams (**Minimum 16 characters**). |
| `DATABASE_URL` | URL | No | `""` (Offline Mode) | PostgreSQL URI (`postgres://...` or `postgresql://...`). If omitted, activates local persistent JSON mode. |
| `INITIAL_ADMIN_EMAIL` | Email | No | `admin@sentinel.local` | Seed email address for the initial primary SOC administrator account. |
| `INITIAL_ADMIN_PASSWORD`| String | No | `[Generated 32-char]` | Bootstrap password (**12+ characters** in prod). If omitted, an ephemeral bootstrap key is generated. |
| `GEMINI_API_KEY` | String | No | `null` (Offline Rules) | Google Gemini API key for autonomous ReAct agent and threat explanation. |
| `GEMINI_MODEL` | String | No | `gemini-2.0-flash` | Gemini model version string (Default: `gemini-2.0-flash`). |
| `METRICS_TOKEN` | String | No | `null` (Unprotected) | Bearer token required to scrape `/api/metrics` Prometheus telemetry. |
| `SMTP_HOST` | String | No | `null` | SMTP mail server hostname for OTP & password reset delivery. |
| `SMTP_PORT` | Integer | No | `587` | SMTP port (Typically `587` for STARTTLS, `465` for SSL). |
| `SMTP_USER` | String | No | `null` | SMTP authentication username. |
| `SMTP_PASS` | String | No | `null` | SMTP authentication password. |
| `SMTP_FROM` | String | No | `Cyber Sentinel...` | Sender display name and email address. |
| `TWILIO_ACCOUNT_SID` | String | No | `null` | Twilio Account SID for international cellular SMS OTPs. |
| `TWILIO_AUTH_TOKEN` | String | No | `null` | Twilio Auth Token. |
| `TWILIO_PHONE_NUMBER` | String | No | `null` | Registered Twilio phone number. |
| `FAST2SMS_API_KEY` | String | No | `null` | Fast2SMS Gateway key for Indian (+91) cellular SMS OTPs. |

---

## 3. FAIL-CLOSED PRODUCTION RULES

When `NODE_ENV=production`, the server executes strict pre-flight checks before listening on any network socket.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PRODUCTION STARTUP VALIDATION                        │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Is JWT_SECRET configured?                                           │
│    └── FAIL: If empty, missing, or length < 32 characters              │
│ 2. Is JWT_SECRET using a predictable/default development secret?        │
│    └── FAIL: If matching known insecure string list                   │
│ 3. Is CORS_ORIGIN configured with valid explicit domains?              │
│    └── FAIL: If empty or containing wildcard (*) with credentials     │
│ 4. Is DEVICE_SECRET configured and >= 16 characters?                  │
│    └── FAIL: If missing or < 16 characters                             │
│ 5. Are PORT, FRONTEND_URL, and DATABASE_URL syntactically valid?       │
│    └── FAIL: If port out of 1-65535 range or invalid protocol         │
└────────────────────────────────────────────────────────────────────────┘
```

### Insecure Secret Blocklist
The configuration system maintains a hash of known default/insecure development strings that are **banned** in production:
* `cyber-sentinel-dev-only-secret-do-not-use-in-production`
* `cyber-sentinel-dev-super-secure-random-key-12345`
* `change_this_to_a_long_random_secret`
* `secret`, `jwt_secret`, `password`, `123456`
* `sentinel-device-auth-key`

---

## 4. SAFE DIAGNOSTIC LOGGING

The configuration engine exposes `config.getSafeSummary()`, which creates a masked summary for logging startup state without exposing credentials:

```javascript
const config = require('./config');

console.log('[CONFIG] Startup environment:', config.getSafeSummary());
```

**Output Example**:
```json
{
  "environment": "production",
  "port": 10000,
  "frontendUrl": "https://cyber-sentinel.vercel.app",
  "corsOrigins": ["https://cyber-sentinel.vercel.app"],
  "database": "PostgreSQL Configured",
  "aiEngine": "Enabled (gemini-2.0-flash)",
  "jwtSecretStatus": "[ACTIVE KEY] (64 chars)",
  "refreshTokenSecretStatus": "[ACTIVE KEY] (64 chars)",
  "deviceSecretStatus": "[ACTIVE KEY] (32 chars)",
  "metricsAuthProtected": true,
  "smtpConfigured": true,
  "smsConfigured": false
}
```

---

## 5. ENVIRONMENT SEPARATION

### Local Development (`NODE_ENV=development`)
* Copy `.env.example` to `backend/.env`.
* Missing secrets automatically fall back to safe development keys.
* Default storage runs in local offline JSON repository mode if `DATABASE_URL` is empty.
* Rate limits are relaxed (1,000 req/15min) to prevent throttling development workflows.

### Testing (`NODE_ENV=test`)
* Automated test suites (`npm test`, `test:worst-case`, `test:adversarial`) run with deterministic test keys.
* Rate limiters operate with elevated thresholds to accommodate high-frequency burst tests.

### Production (`NODE_ENV=production`)
* All secrets must be provisioned via cloud platform environment settings (Render, Railway, AWS ECS, Kubernetes Secrets).
* Strict rate limits enforced (50 auth req/15min, 60 general req/min).
* HTTPS protocols and strict CORS whitelists required.

---

## 6. PRODUCTION DEPLOYMENT CHECKLIST

- [ ] `NODE_ENV=production` is set.
- [ ] `JWT_SECRET` generated using `openssl rand -hex 32` (at least 64 hex characters).
- [ ] `REFRESH_TOKEN_SECRET` generated using `openssl rand -hex 32`.
- [ ] `DEVICE_SECRET` generated using `openssl rand -hex 16` and provisioned to endpoint agents.
- [ ] `CORS_ORIGIN` points strictly to the production frontend URL without trailing slashes.
- [ ] `DATABASE_URL` contains valid PostgreSQL credentials with SSL required.
- [ ] `INITIAL_ADMIN_PASSWORD` configured with 16+ characters or recorded from one-time bootstrap output.
- [ ] `METRICS_TOKEN` set to protect Prometheus metrics from unauthenticated scraping.
- [ ] `GEMINI_API_KEY` configured and verified against `gemini-2.0-flash`.
