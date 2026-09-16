# Cyber Sentinel — Complete OpenAPI & API Reference Documentation

This document provides complete, exhaustive, endpoint-by-endpoint reference documentation for the Cyber Sentinel REST and Telemetry APIs, generated directly from the live route implementations in the codebase.

---

## 🔐 1. Global Security Schemes & Authorization Model

### Authentication Methods
1. **Bearer JWT Access Token**:
   - Header: `Authorization: Bearer <JWT_ACCESS_TOKEN>`
   - Algorithm: `HS256` (HMAC-SHA256 with cryptographically verified signature and claims)
   - Lifetime: 2 hours (configurable via `JWT_EXPIRES_IN`)
   - Claims: `{ "sub": "<user_id>", "email": "<email>", "role": "<ROLE>", "iat": <timestamp>, "exp": <timestamp> }`

2. **Telemetry HMAC-SHA256 Signature**:
   - Required on: `POST /api/events`
   - Headers:
     - `X-Device-Id`: Unique registered endpoint device identifier (e.g., `DEV-9F8A1234BC`)
     - `X-Timestamp`: Epoch timestamp in milliseconds ($\pm 300\text{s}$ drift maximum)
     - `X-Nonce`: Random high-entropy unique string (prevents replay attacks)
     - `X-Signature`: Hex-encoded HMAC-SHA256 signature computed over canonical string:
       ```
       METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256
       ```

3. **Metrics Token**:
   - Required on: `GET /metrics` and `GET /api/metrics`
   - Header: `Authorization: Bearer <METRICS_TOKEN>` or Admin/Auditor JWT

4. **Request Tracing**:
   - Inbound & Outbound: `X-Request-ID: req-<uuid>`

---

### Role-Based Access Control (RBAC) Permission Matrix

Cyber Sentinel enforces strict role-based access control across 5 primary operator roles:

| Permission Code | Description | `ADMIN` | `SOC_ANALYST` | `SECURITY_ENGINEER` | `ENDPOINT_OPERATOR` | `VIEWER` |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `incidents:read` | View security incidents & timelines | ✅ | ✅ | ✅ | ✅ | ✅ |
| `incidents:write` | Create manual incidents | ✅ | ✅ | ✅ | ❌ | ❌ |
| `incidents:update` | Update fields, notes, status, approval | ✅ | ✅ | ✅ | ❌ | ❌ |
| `incidents:delete` | Close or archive incidents | ✅ | ✅ | ❌ | ❌ | ❌ |
| `devices:read` | View enrolled endpoints & status | ✅ | ✅ | ✅ | ✅ | ✅ |
| `devices:write` | Enroll endpoints & rotate credentials | ✅ | ❌ | ✅ | ✅ | ❌ |
| `devices:delete` | Revoke & decommission endpoints | ✅ | ❌ | ✅ | ❌ | ❌ |
| `rules:read` | Inspect detection rule definitions | ✅ | ✅ | ✅ | ❌ | ✅ |
| `rules:write` | Create & update SIEM detection rules | ✅ | ❌ | ✅ | ❌ | ❌ |
| `actions:execute` | Execute containment response actions | ✅ | ✅ | ✅ | ❌ | ❌ |
| `audit:read` | Inspect immutable security audit log | ✅ | ❌ | ❌ | ❌ | ❌ |
| `system:admin` | Manage users, roles & system config | ✅ | ❌ | ❌ | ❌ | ❌ |
| `telemetry:ingest`| Ingest endpoint telemetry streams | ✅ | ✅ | ✅ | ✅ | ❌ |

---

## 📋 2. Comprehensive Endpoint Index

```
Health & Observability:
  GET  /health                                 - Liveness probe and subsystem status
  GET  /api/health                             - Liveness probe alias
  GET  /api/health/live                        - Lightweight uptime liveness check
  GET  /ready                                  - Readiness probe with database check
  GET  /api/ready                              - Readiness probe alias
  GET  /api/health/ready                       - Readiness probe alias
  GET  /metrics                                - Prometheus & JSON telemetry metrics
  GET  /api/metrics                            - Prometheus & JSON telemetry metrics alias

Authentication & User Identity:
  POST /api/auth/register                      - Register new operator account
  POST /api/auth/login                         - Authenticate credentials (constant-time)
  POST /api/auth/refresh                       - Rotate refresh token & issue new JWT
  POST /api/auth/verify-mfa                    - Complete TOTP MFA challenge
  POST /api/auth/logout                        - Revoke active session refresh token
  POST /api/auth/logout-all                    - Revoke all active operator sessions
  GET  /api/auth/me                            - Retrieve authenticated operator profile
  PUT  /api/auth/profile                       - Update name, email, phone, or password
  GET  /api/auth/mfa/setup                     - Generate Base32 secret & QR URI
  POST /api/auth/mfa/enable                    - Verify and activate RFC 6238 TOTP
  POST /api/auth/forgot-password               - Request password reset email / SMS OTP
  POST /api/auth/reset-password                - Reset password with token or OTP
  POST /api/auth/send-verification             - Send verification token
  POST /api/auth/verify-code                   - Verify phone/email verification code

Devices & Endpoint Fleet:
  POST /api/devices/enroll                     - Enroll endpoint & issue credentials
  GET  /api/devices                            - List all enrolled endpoint devices
  GET  /api/devices/:id                        - Get detailed endpoint device record
  POST /api/devices/:id/revoke                 - Permanently revoke endpoint device
  POST /api/devices/:id/rotate-credential      - Rotate endpoint HMAC device secret
  GET  /api/system/devices                     - Enumerate local machine network adapters

Telemetry & Event Ingestion:
  POST /api/events                             - Ingest HMAC-signed telemetry batch
  GET  /api/events                             - Query recent normalized event buffer
  GET  /api/events/analytics                   - Ingestion rate, top IOCs, MITRE stats
  GET  /api/events/rules                       - List detection rules in registry
  GET  /api/events/detections                  - Query recent detection alerts buffer

Incidents & Forensic Timelines:
  GET  /api/incidents                          - List / filter incidents (status, severity)
  POST /api/incidents                          - Create manual security incident
  GET  /api/incidents/:id                      - Get incident details & forensic timeline
  PATCH /api/incidents/:id                     - Update incident fields
  PUT  /api/incidents/:id                      - Update incident fields (full replace)
  PATCH /api/incidents/:id/status              - Update status (NIST state machine)
  POST /api/incidents/:id/status               - Update status alias
  POST /api/incidents/:id/assign               - Assign incident to SOC analyst
  PATCH /api/incidents/:id/assign              - Assign incident alias
  POST /api/incidents/:id/close                - Close incident with resolution note
  POST /api/incidents/:id/notes                - Append analyst forensic note
  POST /api/incidents/:id/response-actions     - Record containment action on incident
  GET  /api/incidents/:id/timeline             - Paginated incident timeline query
  POST /api/incidents/:id/timeline             - Append manual timeline event
  GET  /api/incidents/:id/timeline/verify      - Verify SHA-256 hash chain integrity
  DELETE /api/incidents/:id/timeline           - 405 Method Not Allowed (Immutable)

Response Actions Framework:
  POST /api/response-actions/request           - Propose response action (PENDING state)
  POST /api/response-actions/:id/approve       - Human operator approves action
  POST /api/response-actions/:id/reject        - Human operator rejects action
  POST /api/response-actions/:id/execute       - Execute approved response action
  GET  /api/response-actions                   - List response actions
  GET  /api/response-actions/:id               - Get response action details

Threat Intelligence & Blocklists:
  GET  /api/threats/dashboard                  - SOC overview metrics & active threats
  GET  /api/threats/cves                       - Official CISA KEV vulnerability feed
  GET  /api/threats/blocked                    - List actively contained IP addresses
  POST /api/threats/block-ip                   - Contain malicious IP address
  POST /api/threats/unblock-ip                 - Revoke IP containment rule

Malware Static Analysis & Quarantine:
  POST /api/malware/analyze                    - Safe in-memory PE static analysis
  GET  /api/malware/history                    - List recent malware scan reports
  GET  /api/malware/quarantine                 - List quarantined binary samples
  GET  /api/malware/quarantine/:id             - Get quarantined file metadata
  DELETE /api/malware/quarantine/:id           - Permanently delete quarantined sample
  POST /api/malware/quarantine/prune           - Prune expired quarantine records

AI Security Assistant & Copilot:
  POST /api/chatbot/message                    - Send message to Sentinel AI Copilot
  POST /api/chatbot/recommend                  - Generate structured investigation steps
  GET  /api/chatbot/proposals                  - List AI advisory action proposals
  POST /api/chatbot/proposals/:id/approve      - Human operator approves AI proposal
  POST /api/chatbot/proposals/:id/reject       - Human operator rejects AI proposal
  DELETE /api/chatbot/session/:sessionId       - Clear conversation session history
  GET  /api/chatbot/stats                      - Get chatbot session performance metrics

Security Audit Trail:
  GET  /api/audit-logs                         - Query immutable security audit logs

Security Protection Scanners & Sandbox:
  POST /api/protection/scan-email              - Scan email for phishing & BEC keywords
  POST /api/protection/scan-link               - Scan URL for hostile indicators
  POST /api/protection/scan-file               - Validate file magic bytes & extension
  POST /api/protection/explain                 - Explain protection scan findings
  POST /api/logs/analyze                       - Parse server logs for SQLi / XSS
  POST /api/logs/explain                       - Explain log analysis findings
  POST /api/logs/ask                           - Ask security question about log analysis
  POST /api/sandbox/simulate                   - Interactive web exploit sandbox
  POST /api/sandbox/explain                    - Explain sandbox exploit execution
  POST /api/vuln/scan                          - Scan host security configuration
  GET  /api/system/metrics                     - Collect real-time OS hardware metrics
```

---

## 📡 3. Detailed Endpoint Reference

---

### A. Health & Observability

#### `GET /health` & `GET /api/health`
- **Method**: `GET`
- **Path**: `/health` (also mounted at `/api/health`)
- **Authentication**: None (Public)
- **Authorization**: None
- **Parameters**: None
- **Request Body**: None
- **Successful Response (`200 OK`)**:
```json
{
  "status": "ok",
  "timestamp": "2026-09-16T03:30:00.000Z",
  "service": "cyber-sentinel-api",
  "uptime": 3600.5,
  "websocket": "enabled",
  "websocketUrl": "http://localhost:5000",
  "components": {
    "database": "connected",
    "aiCopilot": "agentic",
    "threatIntel": "live",
    "correlationEngine": "active",
    "realtimeEngine": "active"
  }
}
```
- **Error Responses**: None (fails only on severe host failure).

---

#### `GET /ready` & `GET /api/ready`
- **Method**: `GET`
- **Path**: `/ready` (also mounted at `/api/ready`, `/api/health/ready`)
- **Authentication**: None (Public)
- **Authorization**: None
- **Parameters**: None
- **Request Body**: None
- **Successful Response (`200 OK`)**:
```json
{
  "status": "ready",
  "database": "connected",
  "uptime": 3600.5,
  "timestamp": "2026-09-16T03:30:00.000Z"
}
```
- **Error Response (`503 Service Unavailable`)**:
```json
{
  "status": "degraded",
  "error": "Database connection failed",
  "timestamp": "2026-09-16T03:30:00.000Z"
}
```

---

#### `GET /metrics` & `GET /api/metrics`
- **Method**: `GET`
- **Path**: `/metrics` (also mounted at `/api/metrics`)
- **Authentication**: Bearer Token (`METRICS_TOKEN` or Admin JWT)
- **Authorization**: `ADMIN`, `AUDITOR`, `SUPERADMIN`
- **Parameters**:
  - `format` *(query, optional)*: `json` or `prometheus` (default: `prometheus`)
- **Request Body**: None
- **Successful Response (`200 OK` - Prometheus Text Format)**:
```text
# HELP http_requests_total Total HTTP requests handled
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/health",status="200"} 4210
http_requests_total{method="POST",path="/api/events",status="202"} 154200
http_request_duration_ms_bucket{le="5"} 154000
http_request_duration_ms_bucket{le="10"} 154180
http_request_duration_ms_bucket{le="+Inf"} 154200
```
- **Successful Response (`200 OK` - JSON Format with `?format=json`)**:
```json
{
  "uptimeSeconds": 3600.5,
  "timestamp": "2026-09-16T03:30:00.000Z",
  "http": {
    "totalRequests": 158410,
    "activeRequests": 3,
    "statusCodes": { "200": 4210, "201": 500, "202": 153000, "400": 600, "401": 80, "403": 20 }
  },
  "telemetry": { "accepted": 153000, "rejected": 600 },
  "detections": { "totalAlerts": 1420 },
  "incidents": { "totalCreated": 38 },
  "process": { "heapUsedMB": 48.33, "rssMB": 172.21 }
}
```
- **Error Response (`401 Unauthorized`)**:
```json
{ "error": "Unauthorized: Valid METRICS_TOKEN or Admin Bearer token required." }
```

---

### B. Authentication & User Identity

#### `POST /api/auth/register`
- **Method**: `POST`
- **Path**: `/api/auth/register`
- **Authentication**: None (Public with rate limiter: 50 requests / 15 min)
- **Authorization**: Role parameter is ignored; default assigned role is `ANALYST`
- **Request Body**:
```json
{
  "name": "Sarah Connor",
  "email": "sarah.connor@sentinel.defense",
  "password": "Cyb3r$entinel#2026!SecOps",
  "phone": "+1-555-0199"
}
```
- **Successful Response (`201 Created`)**:
```json
{
  "message": "Account registered successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "e7c10b49281a9f023847291a...",
  "user": {
    "id": "USR-492810-84",
    "name": "Sarah Connor",
    "email": "sarah.connor@sentinel.defense",
    "role": "ANALYST",
    "phone": "+1-555-0199",
    "isEmailVerified": true,
    "isPhoneVerified": true,
    "mfaEnabled": false,
    "createdAt": "2026-09-16T03:30:00.000Z"
  }
}
```
- **Error Responses**:
  - `400 Bad Request`: `{ "error": "Password must be at least 8 characters and include uppercase, lowercase, numbers, and symbols." }`
  - `409 Conflict`: `{ "error": "An operator with this email already exists." }`

---

#### `POST /api/auth/login`
- **Method**: `POST`
- **Path**: `/api/auth/login`
- **Authentication**: None
- **Request Body**:
```json
{
  "email": "sarah.connor@sentinel.defense",
  "password": "Cyb3r$entinel#2026!SecOps"
}
```
- **Successful Response (`200 OK` - Standard Login)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "84a10c9481fe92841938...",
  "user": {
    "id": "USR-492810-84",
    "name": "Sarah Connor",
    "email": "sarah.connor@sentinel.defense",
    "role": "ANALYST",
    "mfaEnabled": false
  }
}
```
- **Successful Response (`200 OK` - MFA Challenge Triggered)**:
```json
{
  "mfaRequired": true,
  "mfaTicket": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "message": "TOTP MFA verification required."
}
```
- **Error Responses**:
  - `401 Unauthorized`: `{ "error": "Invalid email or password." }`
  - `429 Too Many Requests`: `{ "error": "Account temporarily locked due to excessive failed attempts. Try again in 15 minutes." }`

---

#### `POST /api/auth/verify-mfa`
- **Method**: `POST`
- **Path**: `/api/auth/verify-mfa`
- **Authentication**: None (Requires `mfaTicket` from login response)
- **Request Body**:
```json
{
  "mfaTicket": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "code": "492810"
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "a9841029c819fe...",
  "user": {
    "id": "USR-492810-84",
    "name": "Sarah Connor",
    "email": "sarah.connor@sentinel.defense",
    "role": "ANALYST",
    "mfaEnabled": true
  }
}
```
- **Error Response (`401 Unauthorized`)**:
```json
{ "error": "Invalid or expired authenticator code." }
```

---

#### `POST /api/auth/refresh`
- **Method**: `POST`
- **Path**: `/api/auth/refresh`
- **Authentication**: None (Requires `refreshToken`)
- **Request Body**:
```json
{
  "refreshToken": "84a10c9481fe92841938..."
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "c9284019bf81726a..."
}
```
- **Error Response (`401 Unauthorized`)**:
```json
{ "error": "Invalid, revoked, or expired refresh token." }
```

---

#### `GET /api/auth/me`
- **Method**: `GET`
- **Path**: `/api/auth/me`
- **Authentication**: `Bearer <JWT_ACCESS_TOKEN>`
- **Authorization**: Any authenticated operator
- **Request Body**: None
- **Successful Response (`200 OK`)**:
```json
{
  "user": {
    "id": "USR-492810-84",
    "name": "Sarah Connor",
    "email": "sarah.connor@sentinel.defense",
    "role": "ANALYST",
    "profilePic": null,
    "phone": "+1-555-0199",
    "isEmailVerified": true,
    "isPhoneVerified": true,
    "mfaEnabled": false,
    "createdAt": "2026-09-16T03:30:00.000Z"
  }
}
```
- **Error Response (`401 Unauthorized`)**:
```json
{ "error": "Authentication token missing or invalid." }
```

---

#### `PUT /api/auth/profile`
- **Method**: `PUT`
- **Path**: `/api/auth/profile`
- **Authentication**: `Bearer <JWT_ACCESS_TOKEN>`
- **Request Body**:
```json
{
  "name": "Sarah Connor, Lead Analyst",
  "phone": "+1-555-0200",
  "currentPassword": "Cyb3r$entinel#2026!SecOps",
  "newPassword": "New$ecurePassword#2026!"
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "message": "Profile updated successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "USR-492810-84",
    "name": "Sarah Connor, Lead Analyst",
    "email": "sarah.connor@sentinel.defense",
    "role": "ANALYST"
  }
}
```

---

#### `GET /api/auth/mfa/setup` & `POST /api/auth/mfa/enable`
- **`GET /api/auth/mfa/setup`**:
  - **Auth**: `Bearer <JWT>`
  - **Response `200 OK`**: `{ "secret": "JBSWY3DPEHPK3PXP", "otpauthUri": "otpauth://totp/CyberSentinel:user@sentinel?secret=JBSWY3DPEHPK3PXP&issuer=CyberSentinel", "mfaEnabled": false }`
- **`POST /api/auth/mfa/enable`**:
  - **Auth**: `Bearer <JWT>`
  - **Body**: `{ "secret": "JBSWY3DPEHPK3PXP", "code": "123456" }`
  - **Response `200 OK`**: `{ "success": true, "message": "TOTP Multi-Factor Authentication successfully activated." }`

---

### C. Devices & Endpoint Fleet

#### `POST /api/devices/enroll`
- **Method**: `POST`
- **Path**: `/api/devices/enroll`
- **Authentication**: `Bearer <JWT>`
- **Authorization**: `ADMIN`, `SECURITY_ENGINEER`, `ENDPOINT_OPERATOR` (`devices:write`)
- **Request Body**:
```json
{
  "name": "Workstation-Finance-01",
  "hostname": "FIN-WS-01.corp.sentinel",
  "platform": "Windows 11 Enterprise (23H2)",
  "agentVersion": "2.0.0",
  "ipAddress": "192.168.1.105"
}
```
- **Successful Response (`201 Created`)**:
```json
{
  "success": true,
  "device": {
    "id": "DEV-A819C028FE",
    "name": "Workstation-Finance-01",
    "hostname": "FIN-WS-01.corp.sentinel",
    "platform": "Windows 11 Enterprise (23H2)",
    "status": "ACTIVE",
    "agentVersion": "2.0.0",
    "createdAt": "2026-09-16T03:30:00.000Z"
  },
  "credential": {
    "keyIdentifier": "key-9481fe",
    "deviceSecret": "sec-a9481fe8294c8109bf...",
    "note": "Save this deviceSecret securely. It is only returned once upon enrollment."
  }
}
```

---

#### `GET /api/devices`
- **Method**: `GET`
- **Path**: `/api/devices`
- **Authentication**: `Bearer <JWT>`
- **Authorization**: `devices:read`
- **Parameters**:
  - `status` *(query, optional)*: `ACTIVE`, `REVOKED`, `OFFLINE`
  - `limit` *(query, optional)*: default `50`, max `200`
- **Successful Response (`200 OK`)**:
```json
{
  "success": true,
  "total": 42,
  "devices": [
    {
      "id": "DEV-A819C028FE",
      "name": "Workstation-Finance-01",
      "hostname": "FIN-WS-01.corp.sentinel",
      "status": "ACTIVE",
      "agentVersion": "2.0.0",
      "lastSeen": "2026-09-16T03:34:00.000Z"
    }
  ]
}
```

---

#### `POST /api/devices/:id/revoke` & `POST /api/devices/:id/rotate-credential`
- **Revoke**: `POST /api/devices/DEV-A819C028FE/revoke` (`devices:delete`)
  - **Response `200 OK`**: `{ "success": true, "message": "Device DEV-A819C028FE revoked." }`
- **Rotate**: `POST /api/devices/DEV-A819C028FE/rotate-credential` (`devices:write`)
  - **Response `200 OK`**: `{ "success": true, "credential": { "deviceSecret": "sec-new-secret..." } }`

---

### D. Telemetry & Event Ingestion

#### `POST /api/events`
- **Method**: `POST`
- **Path**: `/api/events`
- **Authentication**: HMAC-SHA256 Signature (Headers: `X-Device-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`)
- **Request Body**: Array of events or single event object.
```json
[
  {
    "event_type": "PROCESS_EXECUTION",
    "source_ip": "192.168.1.105",
    "dest_ip": "198.51.100.42",
    "dest_port": 443,
    "device_id": "DEV-A819C028FE",
    "user": "jdoe",
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell.exe -ExecutionPolicy Bypass -enc JABjAGwAaQBl...",
      "pid": 4812
    },
    "observed_at": "2026-09-16T03:34:00.000Z"
  }
]
```
- **Successful Response (`202 Accepted`)**:
```json
{
  "success": true,
  "processed": 1,
  "detectionsCount": 1,
  "detections": [
    {
      "id": "DET-849102",
      "rule_id": "RULE_SUSPICIOUS_POWERSHELL_001",
      "title": "Encoded PowerShell Execution Detected",
      "severity": "HIGH",
      "incident_id": "INC-48192"
    }
  ],
  "incidentsCreated": 1,
  "incidents": [
    {
      "id": "INC-48192",
      "title": "Suspicious Execution: powershell.exe",
      "severity": "HIGH",
      "status": "NEW"
    }
  ]
}
```
- **Error Responses**:
  - `401 Unauthorized`: `{ "error": "Invalid HMAC signature or timestamp skew exceeded 300 seconds." }`
  - `400 Bad Request`: `{ "error": "Telemetry payload validation failed: must contain valid event_type." }`

---

#### `GET /api/events/analytics`
- **Method**: `GET`
- **Path**: `/api/events/analytics`
- **Authentication**: `Bearer <JWT>`
- **Successful Response (`200 OK`)**:
```json
{
  "success": true,
  "totalEventsBuffered": 1000,
  "totalDetections": 45,
  "ingestionRateEventsPerSec": 94.8,
  "bySeverity": { "CRITICAL": 5, "HIGH": 18, "MEDIUM": 15, "LOW": 7 },
  "byMitre": { "T1059.001": 18, "T1110": 12, "T1071.001": 10 },
  "topDevices": [{ "device": "DEV-A819C028FE", "count": 14 }],
  "topIndicators": [{ "indicator": "198.51.100.42", "count": 10, "type": "IPv4" }]
}
```

---

### E. Incidents & Cryptographic Timelines

#### `GET /api/incidents`
- **Method**: `GET`
- **Path**: `/api/incidents`
- **Authentication**: `Bearer <JWT>`
- **Parameters**:
  - `status` *(query, optional)*: `NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `RESOLVED`, `CLOSED`
  - `severity` *(query, optional)*: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
  - `search` *(query, optional)*: Free-text search over title, description, and related IPs
  - `limit` *(query, optional)*: default `50`
  - `offset` *(query, optional)*: default `0`
- **Successful Response (`200 OK`)**:
```json
{
  "success": true,
  "total": 12,
  "limit": 50,
  "offset": 0,
  "incidents": [
    {
      "id": "INC-48192",
      "title": "Encoded PowerShell Execution on DEV-A819C028FE",
      "severity": "HIGH",
      "status": "INVESTIGATING",
      "category": "Execution",
      "assignee": "sarah.connor@sentinel.defense",
      "relatedIps": ["198.51.100.42"],
      "mitreTechniques": ["T1059.001"],
      "evidenceHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "createdAt": "2026-09-16T03:30:00.000Z"
    }
  ]
}
```

---

#### `POST /api/incidents/:id/status` & `PATCH /api/incidents/:id/status`
- **Method**: `POST` / `PATCH`
- **Path**: `/api/incidents/:id/status`
- **Authentication**: `Bearer <JWT>`
- **Authorization**: `incidents:update`
- **Request Body**:
```json
{
  "status": "CONTAINMENT",
  "note": "Host isolated from network; outbound C2 IP blocked on perimeter gateway."
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "success": true,
  "incident": {
    "id": "INC-48192",
    "status": "CONTAINMENT",
    "updatedAt": "2026-09-16T03:35:00.000Z"
  }
}
```
- **Error Response (`400 Bad Request` - Invalid NIST State Transition)**:
```json
{ "error": "Invalid state transition from CLOSED to NEW. Use REOPENING workflow." }
```

---

#### `GET /api/incidents/:id/timeline/verify`
- **Method**: `GET`
- **Path**: `/api/incidents/:id/timeline/verify`
- **Authentication**: `Bearer <JWT>`
- **Description**: Recalculates and validates the cryptographic SHA-256 hash chain for all timeline events.
- **Successful Response (`200 OK` - Valid Chain)**:
```json
{
  "success": true,
  "incidentId": "INC-48192",
  "verified": true,
  "eventsCount": 8,
  "rootHash": "8f948190284c81b09284...",
  "latestHash": "4918290ab91827c81920...",
  "message": "Cryptographic timeline hash chain is fully intact. Zero tampering detected."
}
```
- **Error Response (`400 Bad Request` - Tampered Chain)**:
```json
{
  "success": false,
  "incidentId": "INC-48192",
  "verified": false,
  "tamperedEventId": "EVT-004",
  "error": "Hash mismatch detected at sequence index 4. Evidence has been altered."
}
```

---

### F. Response Actions Framework

#### `POST /api/response-actions/request`
- **Method**: `POST`
- **Path**: `/api/response-actions/request`
- **Authentication**: `Bearer <JWT>`
- **Request Body**:
```json
{
  "actionType": "BLOCK_IP",
  "incidentId": "INC-48192",
  "parameters": {
    "ip": "198.51.100.42",
    "reason": "Hostile C2 infrastructure beacon"
  },
  "idempotencyKey": "idem-block-198-51-100-42"
}
```
- **Successful Response (`201 Created`)**:
```json
{
  "success": true,
  "action": {
    "id": "ACT-948102",
    "actionType": "BLOCK_IP",
    "target": "198.51.100.42",
    "status": "PENDING",
    "requiresHumanApproval": true,
    "requestedBy": "sarah.connor@sentinel.defense",
    "createdAt": "2026-09-16T03:35:00.000Z"
  }
}
```

---

#### `POST /api/response-actions/:id/approve` & `POST /api/response-actions/:id/execute`
- **`POST /api/response-actions/ACT-948102/approve`**:
  - **Auth**: `Bearer <JWT>` (`incidents:update`)
  - **Response `200 OK`**: `{ "success": true, "action": { "id": "ACT-948102", "status": "APPROVED", "approvedBy": "admin@sentinel.defense" } }`
- **`POST /api/response-actions/ACT-948102/execute`**:
  - **Auth**: `Bearer <JWT>` (`incidents:update`)
  - **Response `200 OK`**: `{ "success": true, "action": { "id": "ACT-948102", "status": "EXECUTED", "executedAt": "2026-09-16T03:36:00.000Z" } }`

---

### G. Threat Intelligence & Blocklists

#### `GET /api/threats/dashboard`
- **Method**: `GET`
- **Path**: `/api/threats/dashboard`
- **Authentication**: `Bearer <JWT>`
- **Successful Response (`200 OK`)**:
```json
{
  "stats": {
    "threatScore": 42,
    "liveAttacks": 15,
    "activeDevices": 4,
    "networkHealth": 94,
    "blockedToday": 18,
    "criticalAlerts": 3,
    "cpuUsage": 14,
    "memoryUsage": 52,
    "hostname": "SENTINEL-SOC-01",
    "platform": "win32",
    "riskLevel": "MEDIUM"
  },
  "liveAttacks": [
    {
      "id": "threatfox-1726457400-0",
      "sourceIp": "47.95.207.79",
      "type": "Cobalt Strike C2 Beacon",
      "severity": "CRITICAL",
      "blocked": false,
      "mitreTechnique": "T1071.001",
      "threatIntelMatch": "Verified ThreatFox IOC [Confidence 100%]"
    }
  ],
  "systemFindings": []
}
```

---

#### `POST /api/threats/block-ip` & `POST /api/threats/unblock-ip`
- **`POST /api/threats/block-ip`**:
  - **Auth**: `Bearer <JWT>` (`ADMIN` or `SENIOR_ANALYST`)
  - **Body**: `{ "ip": "198.51.100.42", "reason": "Active C2 beacon" }`
  - **Response `200 OK`**: `{ "success": true, "message": "IP 198.51.100.42 contained successfully." }`
- **`POST /api/threats/unblock-ip`**:
  - **Auth**: `Bearer <JWT>` (`ADMIN` or `SENIOR_ANALYST`)
  - **Body**: `{ "ip": "198.51.100.42" }`
  - **Response `200 OK`**: `{ "success": true, "message": "IP containment revoked." }`

---

### H. Malware Static Analysis & Quarantine

#### `POST /api/malware/analyze`
- **Method**: `POST`
- **Path**: `/api/malware/analyze`
- **Authentication**: `Bearer <JWT>` (Rate limited: 20 req/min)
- **Request Body**:
```json
{
  "filename": "invoice_attachment.exe",
  "contentBase64": "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAA...",
  "quarantine": true
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "success": true,
  "analysis": {
    "metadata": {
      "filename": "invoice_attachment.exe",
      "fileSize": 65536,
      "sha256": "4a821908bf291a0c84...",
      "md5": "9e107d9d372bb6826bd81d3542a419d6",
      "isPE": true
    },
    "entropy": {
      "score": 7.42,
      "interpretation": "HIGH_ENTROPY_PACKED_OR_ENCRYPTED"
    },
    "riskAssessment": {
      "score": 85,
      "severity": "CRITICAL",
      "mitreTechniques": ["T1027", "T1055", "T1106"]
    },
    "findings": {
      "detectedAPIs": [{ "name": "VirtualAllocEx", "risk": "HIGH" }],
      "matchedRules": [{ "name": "Suspicious_Process_Injection_API" }]
    }
  },
  "quarantine": {
    "sampleId": "smpl-9481-42",
    "vaultPath": "quarantine/smpl-9481-42.bin",
    "permissions": "0o600"
  },
  "incident": {
    "id": "INC-84910",
    "title": "Malware Detected: invoice_attachment.exe (CRITICAL)"
  }
}
```

---

### I. AI Assistant & Security Copilot

#### `POST /api/chatbot/message`
- **Method**: `POST`
- **Path**: `/api/chatbot/message`
- **Authentication**: `Bearer <JWT>`
- **Request Body**:
```json
{
  "message": "Analyze incident INC-48192 and suggest containment steps.",
  "sessionId": "sess-49182"
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "reply": "### Incident Investigation: INC-48192\n\n- **Threat**: Encoded PowerShell execution communicating with `198.51.100.42`.\n- **MITRE Technique**: T1059.001 (PowerShell).\n- **Recommendation**: Propose host isolation on `DEV-A819C028FE` and perimeter firewall block for `198.51.100.42`.",
  "steps": [
    { "tool": "getIncidentDetails", "input": { "id": "INC-48192" }, "output": "..." }
  ],
  "toolsUsed": ["getIncidentDetails", "queryThreatIntel"],
  "sessionId": "sess-49182",
  "mode": "agentic"
}
```
- **Prompt Injection Defense Response (`200 OK`)**:
```json
{
  "reply": "🛡️ **Sentinel AI Security Notice**:\n\nYour message contained prompt injection patterns or system instruction override tokens (`Ignore all previous instructions`). Instruction was disarmed.",
  "steps": [],
  "mode": "guarded",
  "securityNotice": "PROMPT_INJECTION_DEFENSE_TRIGGERED"
}
```

---

### J. Security Audit Trail

#### `GET /api/audit-logs`
- **Method**: `GET`
- **Path**: `/api/audit-logs`
- **Authentication**: `Bearer <JWT>`
- **Authorization**: `ADMIN`, `SENIOR_ANALYST` (`audit:read`)
- **Parameters**:
  - `limit` *(query, optional)*: default `100`, max `500`
  - `action` *(query, optional)*: filter by action name (e.g. `IP_BLOCKED`, `LOGIN`)
- **Successful Response (`200 OK`)**:
```json
{
  "success": true,
  "total": 50,
  "logs": [
    {
      "id": "AUDIT-491028-14",
      "actor": "admin@sentinel.defense",
      "actorRole": "ADMIN",
      "action": "IP_BLOCKED",
      "target": "198.51.100.42",
      "result": "SUCCESS",
      "sourceIp": "127.0.0.1",
      "timestamp": "2026-09-16T03:36:00.000Z",
      "details": { "reason": "Hostile C2 beacon" }
    }
  ]
}
```

---

### K. Security Protection Scanners & Sandbox

#### `POST /api/protection/scan-email`
- **Method**: `POST`
- **Path**: `/api/protection/scan-email`
- **Authentication**: `Bearer <JWT>`
- **Request Body**:
```json
{
  "emailSubject": "Urgent: Wire Transfer Authorization Required",
  "emailSender": "ceo-wire-transfer@executive-finance-portal.com",
  "emailText": "Please execute the attached urgent international wire transfer of $85,000 immediately before COB."
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "score": 88,
  "verdict": "SUSPICIOUS_PHISHING_ATTEMPT",
  "tags": ["BUSINESS_EMAIL_COMPROMISE", "URGENCY_TRIGGER", "FINANCIAL_IMPERSONATION"],
  "summary": { "threatScore": 88, "status": "SUSPICIOUS" }
}
```

---

#### `POST /api/sandbox/simulate`
- **Method**: `POST`
- **Path**: `/api/sandbox/simulate`
- **Authentication**: `Bearer <JWT>`
- **Request Body**:
```json
{
  "type": "sqli",
  "payload": "admin' OR 1=1; --",
  "securityEnabled": true
}
```
- **Successful Response (`200 OK`)**:
```json
{
  "type": "sqli",
  "payload": "admin' OR 1=1; --",
  "securityEnabled": true,
  "blocked": true,
  "status": "SECURED",
  "logs": [
    "[03:36:00] SERVER: Applying Parameterized Prepared Statement."
  ],
  "executionResult": "Query bound as literal parameter. 0 records returned."
}
```

---

## 📑 4. Machine-Readable OpenAPI 3.1.0 Specification

The complete machine-readable OpenAPI specification is maintained in YAML format at:
- **[`docs/openapi.yaml`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/openapi.yaml)**

You can import this file into Postman, Insomnia, Swagger UI, or any OpenAPI 3.1 compatible tooling to interact with the Cyber Sentinel API.
