# Changelog

All notable changes to the **Cyber Sentinel** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-16

### Initial Production-Grade Release

#### Added
- **Zero-Trust Identity & Session Core**:
  - Bcrypt password hashing ($cost=12$) enforcing NIST SP 800-63B complexity standards.
  - Short-lived HS256 JWT access tokens (15m in production) with explicit algorithm pinning.
  - Rotating SHA-256 hashed refresh tokens with RFC 6819 family-based reuse and replay attack detection.
  - RFC 6238 TOTP Multi-Factor Authentication with time-step drift tolerance.
  - Progressive account and IP brute-force lockout (5 consecutive failed attempts trigger a 15-minute lock).
  - Fine-grained server-side Role-Based Access Control (RBAC) across `ADMIN`, `SOC_ANALYST`, `SECURITY_ENGINEER`, `ENDPOINT_OPERATOR`, and `VIEWER`.
  - Insecure Direct Object Reference (IDOR) defense middleware.
- **Cryptographic Telemetry Ingestion Engine**:
  - Canonical request signing with HMAC-SHA256 (`METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH`).
  - Sliding-window nonce replay protection with 60-second pruning.
  - Clock skew enforcement ($\pm 300\text{s}$) and device lifecycle state gating (`PENDING`, `ACTIVE`, `REVOKED`, `DECOMMISSIONED`).
  - Automated dynamic IOC enrichment against live ThreatFox (abuse.ch) and CISA KEV catalogs.
- **Modular Detection & Correlation Engine**:
  - Rule-based evaluation supporting Single-Event, Multi-Event Threshold, and Sliding-Window Temporal sequence rules.
  - Full MITRE ATT&CK Enterprise Matrix alignment across 14 tactical phases.
  - Multi-stage attack correlation correlating authentication brute-force, web exploits, and process execution into unified security incidents.
- **SOC Incident Lifecycle Management**:
  - Validated 8-state transition finite state machine (`NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `ERADICATED`, `RECOVERED`, `CLOSED`, `REOPENED`).
  - Cryptographic SHA-256 hash chaining across incident timeline events to ensure tamper-evident forensic records.
  - Read-only historical timeline immutability returning `HTTP 405 Method Not Allowed` on mutation attempts.
- **Advisory AI Security Boundary & Copilot**:
  - Inert delimiter boundary encapsulation for untrusted telemetry and log forensic artifacts.
  - Direct and indirect prompt injection heuristics.
  - Outbound secret and credential scrubbing from LLM responses.
  - Human-in-the-loop authorization gating: AI recommendations remain in `PENDING` state and require explicit operator confirmation for execution.
- **Response Engine & Perimeter Containment**:
  - Allowlisted response action execution (`ISOLATE_ENDPOINT`, `TERMINATE_SUSPICIOUS_PROCESS`, `QUARANTINE_FILE`, `REVOKE_DEVICE_CREDENTIAL`).
  - Strict shell metacharacter blocking (`[;&|\`$><]`) to prevent Command Injection.
  - Idempotency key tracking to eliminate duplicate action execution.
- **File Upload & Static Malware Analysis**:
  - Magic-byte sniffing independent of user-supplied MIME types.
  - Zip Slip path traversal and archive decompression bomb ($>100:1$ ratio) defense.
  - Double-extension neutralization and null-byte stripping.
  - Safe in-memory PE static analysis (DOS header, PE header, machine type, section table, Shannon entropy, import DLL resolution).
  - Quarantined file storage with `0o600` permissions, random UUID filenames, and 24-hour lifecycle retention pruning.
- **Observability, Logging & Disaster Recovery**:
  - Prometheus-compatible metrics endpoint (`/metrics`) protected by Bearer token authorization.
  - Single-line structured JSON logger with automated regex credential scrubbing.
  - Disaster Recovery snapshot utility with SHA-256 archive manifest verification and atomic restoration drill capabilities.
  - Comprehensive documentation suite: OpenAPI 3.1.0 specification, STRIDE Threat Model, Performance Benchmarks, Data Privacy Manifesto, and Disaster Recovery Strategy.

#### Security Hardening
- Enforced fail-closed secret length ($\ge 32$ characters) and default-secret blacklisting across `production` and `staging` environments.
- Prohibited shared static fallback tokens in production telemetry ingestion.
- Zero raw SQL concatenation in database repositories using parameterized `$1, $2, ...` query placeholders.
- Sanitized error handlers preventing internal database or driver stack traces from leaking to clients.
- Rate limiting on authentication (`/api/auth`) and general API endpoints.
- Docker containers run as unprivileged users (`USER node`, `nginx-unprivileged`) with `no-new-privileges:true`.

---
*Generated for Cyber Sentinel v1.0.0 Release.*
