# Cyber Sentinel — Endpoint Telemetry Security Specification

## Overview

Cyber Sentinel enforces strict cryptographic authentication, request integrity verification, replay protection, and device lifecycle validation across all endpoint telemetry ingestion streams. Every event stream transmitted from enrolled agents is verified server-side prior to SIEM normalization, IOC threat intelligence enrichment, or real-time broadcast.

---

## 1. Threat Model & Security Objectives

| Threat Vector | Attack Mechanism | Cyber Sentinel Mitigation |
| :--- | :--- | :--- |
| **Telemetry Forgery & Impersonation** | Rogue actor transmits false events to pollute SIEM or evade detection. | Mandatory device-specific **HMAC-SHA256** request signing using cryptographically random keys issued during enrollment. |
| **In-Transit Payload Tampering** | Man-in-the-middle modifies event details, IP addresses, or alert severities. | Canonical message includes the **SHA-256 digest** of the raw request payload; tampering invalidates the HMAC signature. |
| **Replay Attacks** | Attacker intercepts a valid telemetry packet and replays it to flood alerts. | Mandatory **`X-Nonce`** tracked in a sliding-window cache; duplicate nonces within the validity window are rejected (`401 Unauthorized`). |
| **Delayed Packet Injection** | Attacker re-broadcasts old captured telemetry hours or days later. | Mandatory **`X-Timestamp`** checked against a strict freshness window ($\pm 300\text{s}$ tolerance); expired or future timestamps are rejected. |
| **Compromised Endpoint Injection** | Revoked or decommissioned host attempts to report events. | Real-time device lifecycle status validation; `REVOKED` and `DECOMMISSIONED` endpoints are rejected (`403 Forbidden`). |
| **Denial of Service & Buffer Flooding** | Attacker floods telemetry with multi-megabyte payloads or burst traffic. | Strict payload size limits ($1\text{ MB}$) and per-device rate limiting ($120\text{ req/min}$). |
| **Timing Attacks** | Attacker exploits byte comparison latency differences to extract signatures. | Constant-time signature verification using `crypto.timingSafeEqual`. |
| **Secret Exfiltration** | Endpoint secret inadvertently leaked in logs or error traces. | Zero-secret logging policy; secrets and raw signatures are never written to stdout, logs, or audit records. |

---

## 2. Telemetry HTTP Headers

All HTTP requests to telemetry ingestion endpoints (`POST /api/events`) must include the following headers:

| Header | Format / Example | Description |
| :--- | :--- | :--- |
| `X-Device-ID` | `DEV-4F2A19BC80DE4E12` | Unique device identifier assigned during enrollment. |
| `X-Timestamp` | `2026-09-15T16:50:00.000Z` or `1789491000000` | ISO-8601 string or Unix millisecond epoch timestamp. |
| `X-Nonce` | `9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d` | Cryptographically unique UUIDv4 or random $\ge 16$-byte hex string per request. |
| `X-Signature` | `a3f5b8c9d0e1...` (64-character hex) | Hex-encoded HMAC-SHA256 signature calculated over the canonical message using the device's shared secret. |
| `Content-Type` | `application/json` | Request content type. |

---

## 3. Cryptographic Signature Protocol

### 3.1 Canonical String Format
The signature is computed over a canonical string constructed by concatenating request metadata separated by newline (`\n`) characters:

$$\text{CanonicalString} = \text{METHOD} + \texttt{"\\n"} + \text{PATH} + \texttt{"\\n"} + \text{TIMESTAMP} + \texttt{"\\n"} + \text{NONCE} + \texttt{"\\n"} + \text{BODY\_HASH}$$

Where:
- **`METHOD`**: Uppercase HTTP method (e.g. `POST`).
- **`PATH`**: Normalized request path without query strings (e.g. `/api/events`).
- **`TIMESTAMP`**: The exact value passed in the `X-Timestamp` header.
- **`NONCE`**: The exact value passed in the `X-Nonce` header.
- **`BODY_HASH`**: Lowercase hexadecimal SHA-256 hash of the raw request body:
  $$\text{BODY\_HASH} = \text{SHA-256}(\text{rawBodyString})$$
  *(If the body is empty or null, compute the SHA-256 of an empty string `""`)*.

### 3.2 Signature Calculation

$$\text{X-Signature} = \text{HMAC-SHA256}(\text{deviceSecret}, \text{CanonicalString})$$

---

## 4. Server-Side Verification Pipeline

```
Inbound Request (POST /api/events)
   │
   ├── 1. Device Lookup: Does X-Device-ID exist? ──► [No] ──► 401 Unauthorized
   │
   ├── 2. Device Status: Is status REVOKED or DECOMMISSIONED? ──► [Yes] ──► 403 Forbidden
   │
   ├── 3. Freshness Check: Is |now - X-Timestamp| <= 300s? ──► [No] ──► 401 Unauthorized
   │
   ├── 4. Nonce Replay: Has X-Nonce already been seen for this device? ──► [Yes] ──► 401 Unauthorized
   │
   ├── 5. Body Digest: Compute SHA-256 of raw request payload
   │
   ├── 6. HMAC Signature: Compute HMAC-SHA256 with deviceSecret and timingSafeEqual ──► [Mismatch] ──► 401 Unauthorized
   │
   ├── 7. Size & Rate Check: Payload <= 1MB and device requests <= 120/min? ──► [Exceeded] ──► 413 / 429
   │
   ├── 8. Schema Validation: Valid event structure and prototype clean? ──► [Malformed] ──► 400 Bad Request
   │
   └── 9. Ingest & Correlate: Normalize -> IOC Enrichment -> Correlation Engine -> 202 Accepted
```

---

## 5. Implementation Examples for Endpoint Agents

### Node.js / JavaScript Example
```javascript
const crypto = require('crypto');
const http = require('http');

async function sendTelemetry({ deviceId, deviceSecret, events, serverUrl = 'http://localhost:5000' }) {
  const method = 'POST';
  const path = '/api/events';
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const rawBody = JSON.stringify(events);

  // 1. Compute Body SHA-256 Hash
  const bodyHash = crypto.createHash('sha256').update(rawBody).digest('hex');

  // 2. Form Canonical String
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;

  // 3. Compute HMAC-SHA256 Signature
  const signature = crypto.createHmac('sha256', deviceSecret).update(canonical).digest('hex');

  // 4. Dispatch Ingestion Request
  const res = await fetch(`${serverUrl}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    },
    body: rawBody,
  });

  return await res.json();
}
```

### Python 3 Example
```python
import hmac
import hashlib
import json
import uuid
import datetime
import requests

def send_telemetry(device_id: str, device_secret: str, events: list, base_url: str = "http://localhost:5000"):
    method = "POST"
    path = "/api/events"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    raw_body = json.dumps(events)

    # 1. Compute Body SHA-256 Digest
    body_hash = hashlib.sha256(raw_body.encode("utf-8")).hexdigest()

    # 2. Form Canonical Message
    canonical = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"

    # 3. Compute HMAC-SHA256 Signature
    signature = hmac.new(
        device_secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # 4. Dispatch Telemetry Request
    headers = {
        "Content-Type": "application/json",
        "X-Device-ID": device_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }

    response = requests.post(f"{base_url}{path}", data=raw_body, headers=headers)
    return response.status_code, response.json()
```

### cURL CLI Example
```bash
DEVICE_ID="DEV-EXAMPLE1234"
DEVICE_SECRET="sec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
NONCE=$(uuidgen || cat /proc/sys/kernel/random/uuid)
PAYLOAD='{"eventType":"HEARTBEAT","hostname":"srv-agent-01"}'

BODY_HASH=$(printf "%s" "$PAYLOAD" | sha256sum | awk '{print $1}')
CANONICAL=$(printf "POST\n/api/events\n%s\n%s\n%s" "$TIMESTAMP" "$NONCE" "$BODY_HASH")
SIGNATURE=$(printf "%s" "$CANONICAL" | openssl dgst -sha256 -hmac "$DEVICE_SECRET" | awk '{print $2}')

curl -X POST http://localhost:5000/api/events \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: $DEVICE_ID" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIGNATURE" \
  -d "$PAYLOAD"
```

---

## 6. Credential Rotation & Lifecycle Operations

1. **Credential Invalidation upon Rotation**:
   When an operator rotates an endpoint credential via `POST /api/devices/:id/rotate-credential`, all previous keys and tokens for that endpoint are immediately marked inactive. Any subsequent telemetry signed with the previous secret is rejected with `401 Unauthorized`.
2. **Device Revocation**:
   When an endpoint is compromised or decommissioned (`POST /api/devices/:id/revoke`), the device status is set to `REVOKED` and credentials are permanently purged. Ingestion attempts are blocked with `403 Forbidden`.

---

## 7. Security Verification Matrix

The test suite in [`backend/test_telemetry_security.js`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/test_telemetry_security.js) executes 14 automated security verifications:

```bash
npm run test:telemetry
```

- `[PROVISION]`: Validates device provisioning and secret assignment.
- `[VALID]`: Validates HMAC-SHA256 signed ingestion (`202 Accepted`).
- `[INVALID-SIG]`: Validates forged/invalid signature rejection (`401 Unauthorized`).
- `[MODIFIED-BODY]`: Validates in-transit payload tampering rejection (`401 Unauthorized`).
- `[MODIFIED-PATH]`: Validates path tampering rejection (`401 Unauthorized`).
- `[EXPIRED-TS]`: Validates expired timestamp rejection (`401 Unauthorized`).
- `[FUTURE-TS]`: Validates future timestamp rejection (`401 Unauthorized`).
- `[REPLAY-NONCE]`: Validates nonce replay defense (`401 Unauthorized`).
- `[REVOKED-DEVICE]`: Validates revoked endpoint containment (`403 Forbidden`).
- `[UNKNOWN-DEVICE]`: Validates unregistered device rejection (`401 Unauthorized`).
- `[OVERSIZED-PAYLOAD]`: Validates payload size limitation (`413 Payload Too Large`).
- `[MALFORMED-PAYLOAD]`: Validates schema structure validation (`400 Bad Request`).
- `[RATE-LIMIT]`: Validates ingestion rate limiting (`429 Too Many Requests`).
- `[ROTATION]`: Validates seamless post-rotation cryptographic transition.
