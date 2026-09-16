# Cyber Sentinel — Production Observability Guide

## 1. Overview & Architecture

Cyber Sentinel implements end-to-end production telemetry and observability:
- **Structured JSON Logging**: All HTTP transactions are emitted as single-line structured JSON logs with distributed trace IDs (`X-Request-ID`), execution latencies, status codes, and safe actor identifiers.
- **Sensitive Credential Sanitization**: Passwords, JWTs, API keys, Bearer tokens, device secrets, and raw malware buffers are automatically scrubbed prior to logging.
- **Liveness & Readiness Probes**: Dual healthcheck probes (`/health`, `/ready`) support Kubernetes, Docker Compose, and cloud orchestrators.
- **Prometheus & JSON Metrics**: Standardized OpenMetrics/Prometheus 0.0.4 text exposition and JSON snapshots protected by access controls.

---

## 2. Structured JSON Log Schema

Every HTTP request generates a structured log record with the following schema:

```json
{
  "timestamp": "2026-09-15T22:30:00.123Z",
  "service": "cyber-sentinel-api",
  "requestId": "req-9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "endpoint": "/api/incidents",
  "method": "POST",
  "status": 201,
  "latencyMs": 14,
  "safeActor": "analyst@sentinel.internal",
  "ip": "192.168.1.50",
  "userAgent": "CyberSentinel-SOC/2.0",
  "errorCode": null
}
```

### Sensitive Data Redaction Rules
- **Passwords**: Any key matching `/password/i` is masked as `"[REDACTED]"`.
- **JWT / Bearer Tokens**: Automatically matched via regex and replaced with `"[REDACTED_JWT]"` or `"[REDACTED_TOKEN]"`.
- **API Keys / Secrets**: Masked as `"[REDACTED]"`.
- **Binary Payloads**: Replaced with `"[BINARY_BUFFER_N_BYTES]"`.

---

## 3. Health & Readiness Endpoints

| Endpoint | Method | Purpose | Response Format |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | **Liveness Probe**: Verifies HTTP server is responding and core engine modules are initialized. | `{"status":"ok","uptime":120.4,...}` |
| `/ready` | `GET` | **Readiness Probe**: Verifies database connectivity and state storage ready for traffic. | `{"status":"ready","database":"connected",...}` |

---

## 4. Telemetry Metrics Matrix

Accessible at `GET /metrics` or `GET /api/metrics` (Requires `METRICS_TOKEN` header or Admin Bearer Token). Add `?format=json` for JSON snapshot.

| Metric Identifier | Type | Description |
| :--- | :--- | :--- |
| `cs_http_requests_total` | Counter | Total processed HTTP transactions |
| `cs_http_requests_status_total` | Counter | Requests partitioned by status code (`2xx`, `3xx`, `4xx`, `5xx`) |
| `cs_http_latency_ms` | Gauge | Request latency percentiles (`p50`, `p95`, `p99`) |
| `cs_auth_failures_total` | Counter | Total failed authentication attempts (brute-force monitoring) |
| `cs_telemetry_accepted_total` | Counter | Successfully normalized endpoint telemetry events |
| `cs_telemetry_rejected_total` | Counter | Rejected or malformed telemetry events |
| `cs_detections_total` | Counter | Threat detections triggered by rules engine |
| `cs_incidents_total` | Counter | Security incidents created |
| `cs_malware_analyses_total` | Counter | Static malware PE/hash analysis jobs executed |
| `cs_response_actions_total` | Counter | Containment response actions requested and executed |
| `cs_database_errors_total` | Counter | Total database query exceptions |
