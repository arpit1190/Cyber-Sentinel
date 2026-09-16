# Cyber Sentinel — Secure Response-Action Framework

## 1. Overview & Architectural Principles

The Response-Action Framework enables controlled containment, eradication, and remediation actions across enrolled devices and perimeter firewalls:
- **Allowlisted Operations Only**: Shell execution and dynamic command strings are strictly forbidden.
- **Finite State Machine**: State transitions strictly follow `PENDING -> APPROVED/REJECTED -> EXECUTING -> SUCCESS/FAILED`.
- **RBAC & Operator Clearance**: Action creation and approval require authenticated SOC operators with appropriate permissions (`SOC_ANALYST` or `ADMIN`).
- **Idempotency Guarantees**: Replayed requests using the same `idempotencyKey` return existing action records without re-execution.
- **Execution Timeout & Safe Failure**: Operations exceeding 30 seconds fail safely and write audit entries.

---

## 2. Allowlisted Response Actions

| Action Identifier | Target Entity | Action Semantics | Parameters |
| :--- | :--- | :--- | :--- |
| `ISOLATE_ENDPOINT` | Host / Device | Isolates endpoint network access to SOC telemetry VLAN only. | `{"deviceId": "DEV-01", "ip": "192.168.1.100"}` |
| `REVOKE_DEVICE_CREDENTIAL` | Enrolled Device | Invalidates device token, blocking future telemetry ingestion. | `{"deviceId": "DEV-01"}` |
| `TERMINATE_SUSPICIOUS_PROCESS` | Endpoint Process | Sends termination signal to malicious process PID/name. | `{"pid": 1337, "processName": "miner.exe"}` |
| `QUARANTINE_FILE` | Endpoint File | Moves malicious payload to isolated quarantine vault (`0o600`). | `{"filePath": "C:\\temp\\evil.bin", "sha256": "..."}` |

---

## 3. Response Action Data Structure

```json
{
  "actionId": "ACT-1742300000000-a1b2c3d4",
  "incidentId": "INC-2026-0042",
  "deviceId": "DEV-WIN-09",
  "actionType": "ISOLATE_ENDPOINT",
  "parameters": {
    "ip": "10.0.4.15",
    "deviceId": "DEV-WIN-09"
  },
  "requester": "analyst@sentinel.internal",
  "approver": "sec_lead@sentinel.internal",
  "status": "SUCCESS",
  "timestamps": {
    "requestedAt": "2026-09-15T22:40:00.000Z",
    "approvedAt": "2026-09-15T22:40:15.000Z",
    "rejectedAt": null,
    "executedAt": "2026-09-15T22:40:16.000Z",
    "completedAt": "2026-09-15T22:40:17.500Z"
  },
  "result": {
    "action": "ISOLATE_ENDPOINT",
    "target": "10.0.4.15",
    "networkState": "ISOLATED_QUARANTINE_VLAN",
    "firewallRule": "DROP_ALL_EXCEPT_SOC_TELEMETRY"
  },
  "idempotencyKey": "idem-isolate-dev-win-09"
}
```

---

## 4. API Endpoints

- `POST /api/response-actions/request`: Request an action (Enters `PENDING`).
- `POST /api/response-actions/:id/approve`: Human operator approval (Transitions to `APPROVED`).
- `POST /api/response-actions/:id/reject`: Human operator rejection (Transitions to `REJECTED`).
- `POST /api/response-actions/:id/execute`: Execute action (Transitions to `EXECUTING` $\to$ `SUCCESS`/`FAILED`).
- `GET /api/response-actions`: List actions with filtering.
- `GET /api/response-actions/:id`: Get action details.
