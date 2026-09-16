# Cyber Sentinel — Complete API Security & Hardening Reference

## 1. Security Architecture & Threat Model

Cyber Sentinel APIs enforce defense-in-depth security across all ingestion, detection, incident, and administrative endpoints:

```
Inbound HTTP Request
  │
  ├──► [1] Transport Hardening (Helmet, Strict CORS, X-Request-ID)
  ├──► [2] Request-Size & Strict JSON Parser (Rejects prototypes, 10MB bounds)
  ├──► [3] Rate Limiting (IP & user-scoped rate limiters with 429 backoff)
  ├──► [4] Authentication (HS256 JWT, rotating refresh tokens, device HMAC tokens)
  ├──► [5] Authorization & RBAC (ADMIN, SOC_ANALYST, AUDITOR, READONLY)
  ├──► [6] Input Validation & Mass-Assignment Defense (Schema allowlists)
  ├──► [7] Safe Execution (Parameterized SQL, 0o600 isolated quarantine, zero shell execution)
  ├──► [8] Safe Error Handling (Zero stack trace leaks in responses)
  └──► [9] Cryptographic Audit Logging (Distributed tracing, tamper-evident hash chains)
```

---

## 2. API Security Controls

### A. Authentication & Session Security
- **JWT Verification**: Strict HS256 algorithm enforcement, 15-minute access token expiration.
- **Refresh Token Rotation**: SHA-256 hashed refresh tokens with family-based reuse detection.
- **Device Authentication**: Enrolled endpoints authenticate via `X-Device-Id` and `X-Device-Token` with HMAC-SHA256 signature verification.

### B. Authorization & IDOR Protection
- **Role-Based Access Control**:
  - `ADMIN`: Full configuration, device revocation, user management.
  - `SOC_ANALYST`: Incident response, proposal approvals, malware scans, quarantine management.
  - `AUDITOR`: Read-only access to immutable audit logs and compliance timelines.
  - `READONLY`: Telemetry inspection and overview dashboards.
- **IDOR Defense**: All mutating endpoints verify that the target resource belongs to or is assignable by the authenticated user.

### C. Mass-Assignment & Injection Protection
- **Mass-Assignment Defense**: Request validators strictly extract allowlisted properties, ignoring attempts to inject `role: "ADMIN"` or internal flags during registration or profile updates.
- **SQL Injection Defense**: All PostgreSQL interactions utilize parameterized queries (`$1, $2, ...`), completely forbidding string concatenation.
- **Command Injection Defense**: Dynamic evaluation (`eval`, `exec`, `spawn`, `Function`) is prohibited on user input.

### D. Safe Error Handling
- **No Stack Traces**: All unhandled exceptions catch at top-level middleware, logging details internally with `X-Request-ID` and returning standardized client errors (`{"error": "...", "requestId": "..."}`).

---

## 3. Endpoint Security Matrix

| Route Group | Endpoints | Auth & RBAC | Input/Output Bounds | Protection Mechanisms |
| :--- | :--- | :--- | :--- | :--- |
| **`/api/auth`** | `/login`, `/register`, `/me`, `/profile` | Public / JWT Auth | Password complexity, 128-char limit | Brute-force lockout, TOTP MFA, Mass-assignment stripping |
| **`/api/incidents`** | `GET /`, `POST /`, `PATCH /:id`, `/status` | `requireAuth`, RBAC | NIST 8-state machine schema | Immutable timeline chains, state transition validation |
| **`/api/response-actions`** | `/request`, `/:id/approve`, `/:id/execute`| `SOC_ANALYST` / `ADMIN` | Allowlisted structured operations | Mandatory human approval, idempotency, 30s timeout |
| **`/api/malware`** | `/analyze`, `/quarantine`, `/quarantine/:id` | `SOC_ANALYST` / `ADMIN` | Magic bytes, 10MB bounds | Non-executable `0o600` storage, random UUID naming |
| **`/api/chatbot`** | `/message`, `/recommend`, `/proposals` | `requireAuth` | Prompt injection sanitizer | Inert evidence delimiters, outbound secret scrubber |
| **`/api/events`** | `/`, `/rules`, `/detections`, `/analytics` | Telemetry HMAC / JWT | Canonical event schema | Anti-prototype pollution, UUID validation |
| **`/api/audit-logs`** | `GET /` | `AUDITOR` / `ADMIN` | Pagination bounds | Tamper-evident read-only audit logs |
