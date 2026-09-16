# Cyber Sentinel — Immutable Incident Timeline Specification

## 1. Overview & Architectural Principles

The **Cyber Sentinel Incident Timeline** is an append-only, tamper-evident audit record that reconstructs the complete chronological chain of evidence, actions, and decisions across the Security Operations Center (SOC) lifecycle.

### Core Guarantees:
1. **Append-Only Immutability**: Historical timeline events cannot be modified, overwritten, or deleted by any user or automated role.
2. **Cryptographic SHA-256 Hash Chaining**: Every timeline event $E_i$ stores the hash of its preceding event ($prevHash_{i} = hash_{i-1}$), creating a blockchain-like hash chain anchored to a deterministic Genesis hash (`0000000000000000000000000000000000000000000000000000000000000000`).
3. **Forensic Tamper Detection**: Any modification to historical event timestamps, actors, descriptions, or payload metadata immediately invalidates all downstream hashes and is identified via `/api/incidents/:id/timeline/verify`.
4. **Deep Object Freezing**: In-memory event structures are deeply frozen (`Object.freeze`) to prevent runtime state pollution or pointer tampering.
5. **High-Volume Pagination & Filtering**: Multi-criteria search and pagination for incidents with hundreds of event logs.

---

## 2. Complete SOC Event Lifecycle

```
[ Telemetry Ingestion ]
         │
         ▼
[ Detection Alert ]
         │
         ▼
[ Incident Creation ] (Genesis Chain)
         │
         ▼
[ Analyst Assignment ]
         │
         ▼
[ Investigation Started ]
         │
         ▼
[ AI Recommendation ]
         │
         ▼
[ Analyst Approval ]
         │
         ▼
[ Response Action Execution ] (Containment / Isolation)
         │
         ▼
[ Eradication & Recovery ]
         │
         ▼
[ Incident Resolution & Closure ]
```

---

## 3. Canonical Event Schema

Each timeline event record conforms to the following strict structure:

| Field | Type | Description |
|---|---|---|
| `id` | `String` | Unique timeline entry ID formatted as `tle-<timestamp>-<hex>` |
| `sequence` | `Integer` | Monotonically increasing sequential index ($1, 2, 3...$) |
| `timestamp` | `String` | ISO-8601 UTC timestamp |
| `eventType` | `Enum` | Canonical event type (e.g. `TELEMETRY_INGESTED`, `DETECTION_ALERT`, `AI_RECOMMENDATION`) |
| `actor` | `String` | Actor identity (e.g. `'analyst@sentinel.local'`, `'AI_COPILOT'`, `'ENDPOINT_AGENT'`) |
| `source` | `String` | Originating component (e.g. `'ENDPOINT_AGENT'`, `'DETECTION_ENGINE'`, `'SOAR_ENGINE'`) |
| `description` | `String` | Detailed forensic explanation of the event |
| `relatedEvent` | `Object \| Null` | Associated raw endpoint telemetry event ID and payload metadata |
| `relatedDetection` | `Object \| Null` | Associated detection rule ID, MITRE ATT&CK mapping, and confidence |
| `relatedResponseAction` | `Object \| Null` | Associated SOAR response action ID, target device/IP, and parameters |
| `metadata` | `Object` | Additional structured state change context |
| `prevHash` | `String` | SHA-256 hash of previous event in chain |
| `hash` | `String` | SHA-256 hash of this event's canonical fields combined with `prevHash` |

---

## 4. Cryptographic Hash Calculation

```javascript
hashPayload = [
  prevHash,
  sequence,
  timestamp,
  eventType,
  actor,
  source,
  description,
  canonicalJson(relatedEvent),
  canonicalJson(relatedDetection),
  canonicalJson(relatedResponseAction),
  canonicalJson(metadata)
].join('|');

hash = SHA256(hashPayload);
```

---

## 5. API Reference

### 1. Paginated Timeline Retrieval
`GET /api/incidents/:id/timeline`

**Query Parameters**:
- `page` (default `1`): Page number
- `limit` (default `20`, max `100`): Items per page
- `order` (`asc` \| `desc`, default `asc`): Chronological order
- `eventType` (optional): Filter by canonical event type
- `actor` (optional): Filter by actor substring
- `source` (optional): Filter by source component
- `search` (optional): Free-text search across descriptions and metadata

**Response**:
```json
{
  "success": true,
  "incidentId": "INC-12345",
  "total": 48,
  "page": 1,
  "limit": 20,
  "totalPages": 3,
  "order": "asc",
  "integrity": {
    "verified": true,
    "hashChainValid": true,
    "genesisHash": "d41d8cd98f00b204e9800998ecf8427e...",
    "latestHash": "79054025255fb1a26e4bc422aef54eb4...",
    "totalChainedEvents": 48
  },
  "events": [ ... ]
}
```

### 2. Append Timeline Event
`POST /api/incidents/:id/timeline`

**Request Body**:
```json
{
  "eventType": "AI_RECOMMENDATION",
  "description": "AI recommendation: Isolate endpoint ws-fin-02 due to ransomware heuristic",
  "source": "AI_COPILOT",
  "metadata": {
    "recommendedAction": "HOST_ISOLATION",
    "confidence": 0.98
  }
}
```

### 3. Cryptographic Hash Chain Verification
`GET /api/incidents/:id/timeline/verify`

**Response**:
```json
{
  "success": true,
  "incidentId": "INC-12345",
  "valid": true,
  "count": 48,
  "genesisHash": "d41d8cd98f00b204...",
  "latestHash": "79054025255fb1a2...",
  "verifiedAt": "2026-09-15T18:15:00.000Z"
}
```

### 4. Tamper Rejection (Fail Closed)
`PUT /api/incidents/:id/timeline/:eventId`
`PATCH /api/incidents/:id/timeline/:eventId`
`DELETE /api/incidents/:id/timeline/:eventId`

**Response (`405 Method Not Allowed`)**:
```json
{
  "success": false,
  "error": "Timeline events are immutable audit records and cannot be modified or deleted.",
  "code": "IMMUTABLE_RECORD_RESTRICTION"
}
```

---

## 6. Automated Test Suite

```powershell
# Run immutable timeline verification suite
npm run test:timeline
```
