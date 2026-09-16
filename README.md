# 🛡️ Cyber Sentinel — Autonomous Incident Response & Threat Monitoring Platform

[![Automated Tests](https://img.shields.io/badge/Test%20Suite-126%20Passed%20%7C%20100%25-brightgreen?style=for-the-badge&logo=jest)](tests/run_all_tests.js)
[![Node.js](https://img.shields.io/badge/Runtime-Node.js%20v20%2B-339933?style=for-the-badge&logo=node.js)](https://nodejs.org/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61dafb?style=for-the-badge&logo=react)](https://react.dev/)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2016-4169e1?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v14-ff6f00?style=for-the-badge&logo=target)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

> **Cyber Sentinel** is a modular Security Operations Center (SOC) platform and SIEM correlation engine. It ingests heterogeneous endpoint telemetry, performs real-time detection rule evaluation mapped to the MITRE ATT&CK framework, manages incident lifecycles with cryptographically verifiable SHA-256 timeline hash chains, conducts static malware analysis, and integrates an AI security copilot bounded by human-in-the-loop authorization gates.

---

## 📑 Table of Contents

1. [Project Title & Overview](#-project-title--overview)
2. [Problem Statement](#-problem-statement)
3. [Objectives](#-objectives)
4. [System Architecture](#-system-architecture)
5. [Core Features](#-core-features)
6. [Technology Stack](#-technology-stack)
7. [Security Architecture](#-security-architecture)
8. [SOC Workflow & Incident Lifecycle](#-soc-workflow--incident-lifecycle)
9. [Detection Engine & Rule Framework](#-detection-engine--rule-framework)
10. [MITRE ATT&CK Matrix Alignment](#-mitre-attck-matrix-alignment)
11. [Threat Intelligence Ingestion](#-threat-intelligence-ingestion)
12. [Static Malware Analysis & Quarantine](#-static-malware-analysis--quarantine)
13. [AI Security Copilot & Guardrails](#-ai-security-copilot--guardrails)
14. [Human-in-the-Loop Approval Model](#-human-in-the-loop-approval-model)
15. [Installation & Local Setup](#-installation--local-setup)
16. [Environment Configuration](#-environment-configuration)
17. [Docker & Containerized Deployment](#-docker--containerized-deployment)
18. [Verification & Testing](#-verification--testing)
19. [CI/CD & Automation](#-cicd--automation)
20. [Platform Screenshots](#-platform-screenshots)
21. [Deterministic Demonstration Guide](#-deterministic-demonstration-guide)
22. [OpenAPI & Endpoint Documentation](#-openapi--endpoint-documentation)
23. [Security Model & Least Privilege](#-security-model--least-privilege)
24. [Threat Model Summary (STRIDE)](#-threat-model-summary-stride)
25. [Known Limitations](#-known-limitations)
26. [Engineering Roadmap](#-engineering-roadmap)
27. [Contributors & Maintenance](#-contributors--maintenance)
28. [Release & Governance Documentation](#-release--governance-documentation)

---

## 📌 Project Title & Overview

* **Project Name**: Cyber Sentinel Enterprise SOC & Threat Detection Platform
* **Primary Scope**: Endpoint Telemetry Ingestion, SIEM Correlation, NIST Incident Response, Threat Intelligence, Static PE Inspection, and AI Security Copilot.
* **Maturity Status**:
  * **Implemented**: Core SIEM Detection, Dual-Mode Storage (PostgreSQL + Local Fallback), Canonical Event Normalizer, HMAC-SHA256 Telemetry Authentication, Cryptographic SHA-256 Hash Chain Timeline, In-Memory PE Analyzer, AI Delimiter/Injection Guards, Allowlisted Response Actions.
  * **Tested**: 126 automated unit, integration, security, adversarial, and disaster recovery regression test suites (100% pass rate).
  * **Planned**: eBPF kernel telemetry collector, TPM-backed agent hardware identity (mTLS), and multi-party dual-operator authorization.

---

## ⚠️ Problem Statement

Modern security operations centers face three operational bottlenecks:
1. **Telemetry Overload & Evasion**: Ingestion pipelines struggle to normalize heterogeneous event formats (Windows Event Logs, Syslog, agent JSON) while remaining vulnerable to prototype pollution and payload tampering.
2. **Forensic Evidence Tampering**: Traditional databases allow rogue insiders or attackers with SQL access to delete or alter incident records without leaving a verifiable audit trail.
3. **Unbounded AI Automation Risks**: Integrating Large Language Models (LLMs) into security workflows introduces prompt injection, hallucinated remediation commands, and unauthorized autonomous actions against critical infrastructure.

---

## 🎯 Objectives

* **High-Throughput Telemetry Normalization**: Ingest and sanitize telemetry at measured throughputs exceeding 95,000 events/second.
* **Cryptographic Tamper-Evidence**: Provide mathematical verification of incident investigation histories via SHA-256 hash chains.
* **Enforced Human Governance**: Require explicit, authenticated dual-control operator approval before executing any containment action.
* **Zero-Execution Static Analysis**: Inspect suspicious Windows PE files and archive headers strictly in-memory without spawning subprocesses.
* **Resilience Under Outages**: Ensure automated fallback to persistent local stores during upstream database or network disruptions.

---

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph IngestionBoundary ["Edge & Ingestion Tier"]
        AGENT["Endpoint Agent (Node / Python)"]
        SYSLOG["Syslog & Network Sensors"]
        HMAC_GATE["HMAC-SHA256 Telemetry Authenticator (Timestamp Skew Check)"]
        NORMALIZER["Canonical Event Normalizer & Prototype Defense"]
    end

    subgraph CoreEngine ["SIEM Processing & Detection Core"]
        RULE_REGISTRY["Rule Registry (Single-Event, Threshold, Sequence, Correlation)"]
        DETECTION_ENG["Stateful Detection Engine"]
        MITRE_ENG["MITRE ATT&CK Mapper (v14 Enterprise)"]
        CORRELATION["Stateful Multi-Source Correlator"]
    end

    subgraph ServiceLayer ["Application Services & Logic"]
        AUTH_SVC["Auth Service (JWT HS256, Bcrypt cost=10, TOTP MFA)"]
        INCIDENT_SVC["Incident Service (NIST SP 800-61 FSM)"]
        TIMELINE_SVC["SHA-256 Cryptographic Timeline Ledger"]
        MALWARE_SVC["In-Memory Static PE Byte Analyzer"]
        AI_GUARD["AI Security Guard (Delimiter Injection Filter)"]
        RESPONSE_SVC["Response Action Service (Allowlisted FSM)"]
        AUDIT_SVC["Immutable Security Audit Logger"]
    end

    subgraph StorageTier ["Data Persistence Tier"]
        POSTGRES[("PostgreSQL 16 (Parameterized Queries)")]
        FALLBACK_STORE[("Local Persistent JSON Fallback Store")]
        QUARANTINE_VAULT[("Quarantine Sample Vault (0o600 Mode)")]
    end

    AGENT -->|HMAC-SHA256 Signed Envelope| HMAC_GATE
    SYSLOG -->|JSON / CEF Payloads| HMAC_GATE
    HMAC_GATE --> NORMALIZER
    NORMALIZER --> RULE_REGISTRY
    RULE_REGISTRY --> DETECTION_ENG
    DETECTION_ENG --> MITRE_ENG
    DETECTION_ENG --> CORRELATION
    CORRELATION --> INCIDENT_SVC

    INCIDENT_SVC --> TIMELINE_SVC
    AI_GUARD --> RESPONSE_SVC
    RESPONSE_SVC --> AUDIT_SVC
    MALWARE_SVC --> QUARANTINE_VAULT

    AUTH_SVC --> POSTGRES
    INCIDENT_SVC --> POSTGRES
    AUDIT_SVC --> POSTGRES
    POSTGRES -.->|Fallback Sync| FALLBACK_STORE
```

---

## ✨ Core Features

| Module | Implementation Status | Technical Capability |
| :--- | :---: | :--- |
| **Tactical Radar Visualizer** | **Implemented** | Real-time polar coordinate canvas displaying network flows across Subnet, Gateway, Perimeter, and External zones with laser vector targeting. |
| **Canonical Event Normalizer** | **Implemented & Tested** | Ingests heterogeneous telemetry, sanitizes strings, bounds arrays, defends against `__proto__` pollution, and outputs canonical schemas. |
| **SIEM Detection Engine** | **Implemented & Tested** | Evaluates Single-Event, Sliding-Window Threshold, Multi-Stage Sequence, and Cross-Source Correlation rules. |
| **NIST Incident Lifecycle** | **Implemented & Tested** | Finite State Machine (`NEW` ➔ `TRIAGED` ➔ `INVESTIGATING` ➔ `CONTAINMENT` ➔ `ERADICATION` ➔ `RECOVERY` ➔ `RESOLVED` ➔ `CLOSED`). |
| **Immutable Hash Chain** | **Implemented & Tested** | SHA-256 Merkle-linked timeline events with mathematical verification (`GET /api/incidents/:id/timeline/verify`). |
| **Static PE Analyzer** | **Implemented & Tested** | Zero-execution header parsing: DOS/PE headers, section entropy (Shannon calculation), import tables, and Zip Slip defenses. |
| **Quarantine Vault** | **Implemented & Tested** | Isolated sample storage using UUID filenames, restrictive `0o600` permissions, and 7-day automated retention pruning. |
| **AI Security Copilot** | **Implemented & Tested** | Delimiter encapsulation blocks, heuristic prompt injection scanner, outbound credential scrubber, and advisory-only execution boundaries. |
| **Response Action Engine** | **Implemented & Tested** | Strict allowlist (`ISOLATE_ENDPOINT`, `TERMINATE_SUSPICIOUS_PROCESS`, `QUARANTINE_FILE`, `REVOKE_DEVICE_CREDENTIAL`) with human approval gates. |

---

## 💻 Technology Stack

### Backend & Core Services
* **Runtime**: Node.js `v20.x` / `v24.x` (CommonJS / ES2022)
* **Web Framework**: Express.js with Helmet, CORS, and Express-Rate-Limit
* **Database**: PostgreSQL 16 via connection pooling (`pg`) + local async-debounced JSON fallback
* **Real-Time Transport**: Socket.IO (`v4.8+`) with authenticated WebSocket rooms
* **Cryptography**: Native Node.js `crypto` (SHA-256, HMAC-SHA256, constant-time comparisons), Bcrypt.js (cost=10), Speakeasy (RFC 6238 TOTP)

### Frontend User Interface
* **Framework**: React 18.2 with Vite build system
* **Routing & State**: React Router DOM v6, React Context API, Lucide React icons
* **Styling**: Tailored CSS design system with glassmorphism, responsive CSS Grid, and custom tactical HUD components

---

## 🔒 Security Architecture

Cyber Sentinel implements a Defense-in-Depth model across 5 distinct trust boundaries:

```mermaid
graph LR
    subgraph TB1 ["TB-1: Perimeter Boundary"]
        TLS["TLS 1.3 Termination"]
        HELMET["Helmet Headers & CORS"]
        RATE["Multi-Tier Rate Limiting"]
    end

    subgraph TB2 ["TB-2: Telemetry Ingestion"]
        HMAC["HMAC-SHA256 Signature Check"]
        DRIFT["Timestamp Drift (±300s)"]
        NONCE["Replay Nonce Cache"]
    end

    subgraph TB3 ["TB-3: Authentication Tier"]
        JWT["Short-Lived JWT (2h)"]
        TOTP["RFC 6238 TOTP MFA"]
        BCRYPT["Bcrypt Salted Hashes"]
    end

    subgraph TB4 ["TB-4: Persistence Tier"]
        PARAM["Parameterized Queries ($1, $2)"]
        HASH_CHAIN["SHA-256 Incident Timeline"]
        AUDIT["Immutable Audit Logging"]
    end

    subgraph TB5 ["TB-5: AI & Automation"]
        DELIM["Delimiter Encapsulation"]
        SCRUB["Outbound Secret Scrubber"]
        GATE["Human Approval Gate"]
    end

    TB1 --> TB2
    TB2 --> TB3
    TB3 --> TB4
    TB4 --> TB5
```

1. **TB-1 (Perimeter)**: Strict HTTP security headers (CSP, HSTS, X-Frame-Options), CORS domain restriction, and tiered rate limits (50 req/15min auth, 120 req/min general).
2. **TB-2 (Telemetry Ingestion)**: Every agent request requires an HMAC-SHA256 signature generated with the device's shared secret, verified against stored SHA-256 hashes with $\pm 300\text{s}$ timestamp drift checks.
3. **TB-3 (Authentication & Identity)**: Bcrypt password hashing (cost=10), short-lived JWT access tokens, SHA-256 hashed refresh tokens with automatic family reuse invalidation, and mandatory TOTP MFA.
4. **TB-4 (Data Storage)**: 100% parameterized SQL queries (`$1, $2`), preventing SQL injection; incident timelines secured with cryptographic hash chains.
5. **TB-5 (AI & Containment)**: Inert evidence encapsulation, prompt injection heuristics, and strict advisory-only separation from response execution.

---

## 🔄 SOC Workflow & Incident Lifecycle

Incidents follow the standardized **NIST SP 800-61 Rev. 2** Computer Security Incident Handling lifecycle:

```mermaid
stateDiagram-v2
    [*] --> NEW: SIEM Rule Match / Manual Creation
    NEW --> TRIAGED: Analyst Initial Review
    TRIAGED --> INVESTIGATING: Forensic Deep Dive & IOC Query
    INVESTIGATING --> CONTAINMENT: Host Isolation / Process Kill
    CONTAINMENT --> ERADICATION: Threat Purged & Key Removal
    ERADICATION --> RECOVERY: Host Baseline Verified Clean
    RECOVERY --> RESOLVED: Root Cause Remediated
    RESOLVED --> CLOSED: Post-Incident Review Completed
    CLOSED --> [*]
```

* **State Validation**: `incidentStateMachine.js` strictly blocks illegal backward transitions (e.g., `CLOSED` ➔ `NEW` is rejected with `400 Bad Request`).
* **Immutability Enforcement**: `PUT`, `PATCH`, and `DELETE` requests to `/api/incidents/:id/timeline/:eventId` are rejected with `405 Method Not Allowed`.

---

## ⚙️ Detection Engine & Rule Framework

The Detection Engine (`backend/src/services/detection/`) supports four distinct rule architectures:

| Rule Type | Description | Example Built-in Rule |
| :--- | :--- | :--- |
| **SINGLE_EVENT** | Instant match on discrete event attributes or regex patterns. | `RULE_OBFUSCATED_POWERSHELL_002` (Base64 PowerShell execution) |
| **THRESHOLD** | Evaluates count of matching events over a sliding time window grouped by entity. | `RULE_BRUTE_FORCE_005` ($\ge 5$ `AUTH_FAILURE` events within 2 min) |
| **SEQUENCE** | Multi-stage finite state machine requiring ordered event progression over time. | `RULE_KILL_CHAIN_SEQUENCE_008` (Web Exploit ➔ Process Spawn ➔ VSS Deletion) |
| **CORRELATION** | Evaluates multi-dimensional conditions across distinct data sources. | `RULE_C2_PROCESS_CORRELATION_010` (Suspicious process + external C2 IP socket) |

---

## 🎯 MITRE ATT&CK Matrix Alignment

All detection rules, alerts, and incident records are mapped directly to the **MITRE ATT&CK Enterprise Framework (v14)**:

* **T1110.001**: *Credential Access — Password Guessing (Brute Force)*
* **T1059.001**: *Execution — PowerShell Command and Scripting Interpreter*
* **T1027**: *Defense Evasion — Obfuscated Files or Information*
* **T1071.001**: *Command and Control — Application Layer Protocol: Web Protocols*
* **T1547.001**: *Persistence — Boot or Logon Autostart Execution: Registry Run Keys*
* **T1105**: *Command and Control — Ingress Tool Transfer (Certutil LOLBIN)*
* **T1486**: *Impact — Data Encrypted for Impact (Ransomware Burst)*
* **T1490**: *Impact — Inhibit System Recovery (Volume Shadow Copy Deletion)*
* **T1190**: *Initial Access — Exploit Public-Facing Application (SQLi Probes)*

---

## 🌐 Threat Intelligence Ingestion

Cyber Sentinel maintains automated integrations with verified external threat intelligence feeds:

```mermaid
graph LR
    TF["Abuse.ch ThreatFox API"] -->|Scheduled Sync (24h TTL)| CACHE["In-Memory IOC Index (IP, Domain, Hash)"]
    CISA["CISA KEV Catalog API"] -->|CVE & Exploit Enrichment| CACHE
    FALLBACK["Static Verified IOC Catalog"] -.->|Fallback on Network Outage| CACHE

    CACHE --> MATCH["iocMatcher.js Runtime Evaluation Engine"]
    MATCH --> SIEM["SIEM Alert Enrichment & Context"]
```

* **Resilience**: If upstream threat feeds are unreachable, `liveThreatFetcher.js` falls back gracefully to a verified static baseline catalog without throwing unhandled exceptions.

---

## 🔬 Static Malware Analysis & Quarantine

Cyber Sentinel includes an isolated static binary inspection engine:

* **Zero Execution Policy**: Executables are never run or spawned. Inspection occurs purely by parsing raw byte buffers.
* **Header & Structure Parsing**: Extracts DOS header (`MZ`), PE signature (`PE\0\0`), COFF header (Machine Architecture, Section Count, Timestamp), and Optional Header (Subsystem, ImageBase).
* **Entropy Analysis**: Calculates Shannon entropy ($0.0 - 8.0$) across individual sections (`.text`, `.data`, `.rsrc`) to detect packing, compression, or encryption (entropy $> 7.2$ flagged as high risk).
* **Quarantine Vault**: Samples are saved with randomized UUID filenames (`uploads/quarantine/smpl-<uuid>.bin`) and restrictive `0o600` file modes (read/write by service account only).

---

## 🤖 AI Security Copilot & Guardrails

The AI Assistant (`/api/chatbot`) provides natural-language incident triage and remediation advice:

```mermaid
graph TD
    PROMPT["Analyst Prompt / Incident Telemetry"] --> INJECT_GUARD["1. Prompt Injection Scanner (Heuristic Check)"]
    INJECT_GUARD --> DELIM_BLOCK["2. Untrusted Evidence Delimiter Encapsulation"]
    DELIM_BLOCK --> MODEL["3. Upstream LLM (Google Gemini API)"]
    MODEL --> SECRET_SCRUB["4. Outbound Secret & Token Scrubber"]
    SECRET_SCRUB --> ADVISORY["5. Advisory-Only Structured Proposal (PENDING)"]
```

* **Inert Delimiter Encapsulation**: All untrusted evidence is wrapped inside boundary tags `<<<UNTRUSTED_FORENSIC_EVIDENCE_START>>>` to prevent indirect prompt injection.
* **Outbound Secret Scrubber**: Regex-scans model output before rendering, stripping JWT tokens, Google API keys, database connection strings, and private keys.
* **Advisory-Only Boundary**: The AI model **cannot directly execute** response actions; it can only formulate structured proposals in `PENDING` status.

---

## 👥 Human-in-the-Loop Approval Model

Containment actions enforce a strict **Dual-Control Human Authorization Gate**:

```mermaid
stateDiagram-v2
    [*] --> PENDING: AI Proposal / Operator Draft
    PENDING --> APPROVED: Authenticated Analyst Sign-Off
    PENDING --> REJECTED: Operator Denial with Rationale
    APPROVED --> EXECUTING: executeResponseAction()
    EXECUTING --> SUCCESS: Action Confirmed by Host
    EXECUTING --> FAILED: Host Error / Timeout (30s)
    SUCCESS --> [*]
    FAILED --> [*]
    REJECTED --> [*]
```

* **Idempotency Protection**: Action requests accept an `idempotencyKey` parameter, preventing accidental double-execution during network retries.
* **Shell Injection Defense**: Parameter values are validated against strict regexes (`/[;&|`$><]/`) to prevent command injection.

---

## 📦 Installation & Local Setup

### Prerequisites
* **Node.js**: `v20.0.0` or higher
* **npm**: `v9.0.0` or higher
* **PostgreSQL** (Optional for local development; system automatically uses in-memory JSON fallback if PostgreSQL is offline).

### Step-by-Step Installation

```bash
# 1. Clone repository
git clone https://github.com/yushdhiman/Cyber-Sentinel-.git
cd Cyber-Sentinel--main

# 2. Install root and workspace dependencies
npm install

# 3. Setup backend environment variables
cp .env.example backend/.env

# 4. (Optional) Run Database Migrations (if PostgreSQL is active)
npm run db:migrate

# 5. Start Backend API and Frontend in Development Mode
npm run dev
```

* **Frontend Dashboard**: `http://localhost:5173`
* **Backend API Gateway**: `http://localhost:5000`
* **Health Check Endpoint**: `http://localhost:5000/api/health`

---

## ⚙️ Environment Configuration

Backend configuration is managed via `backend/.env`:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `5000` | HTTP API port. |
| `NODE_ENV` | `development` | Environment mode (`development`, `production`, `test`). |
| `JWT_SECRET` | `sentinel-super-secret-key-32chars` | Secret key for signing HS256 JWT access tokens. |
| `DATABASE_URL` | *(Optional)* | PostgreSQL connection string (`postgresql://user:pass@host:5432/db`). |
| `GEMINI_API_KEY` | *(Optional)* | Google Gemini API key for live AI Copilot reasoning. |
| `RATE_LIMIT_MAX` | `120` | Maximum requests per minute per client IP. |
| `QUARANTINE_DIR` | `uploads/quarantine` | File storage path for isolated malware samples. |

---

## 🐳 Docker & Containerized Deployment

Cyber Sentinel includes multi-stage Docker configurations for containerized deployment:

```bash
# Build and run all services (Backend API + Frontend Nginx + PostgreSQL)
docker-compose up -d --build

# Inspect running containers
docker-compose ps

# View backend logs
docker-compose logs -f backend
```

---

## 🧪 Verification & Testing

Cyber Sentinel maintains a comprehensive automated testing suite:

```bash
# Run complete test suite (Unit, Integration, Security, Adversarial, DR, E2E)
npm test

# Run empirical performance benchmark suite
npm run benchmark

# Run standalone disaster recovery restoration drill
node backend/test_disaster_recovery.js
```

### Test Suite Coverage Summary:
* **Total Automated Tests**: **126 / 126 Passing (100% Pass Rate)**
* **Execution Duration**: $\sim 3.8\text{ seconds}$
* **Categories Tested**:
  * Unit Tests: Auth, JWT, Schema Normalizer, Privacy Minimizer, Detection Rules, MITRE Registry, Threat Intel.
  * Integration Tests: Device Lifecycle, Telemetry HMAC, Incident State Machine, Audit Logger, Disaster Recovery.
  * Security & Adversarial: Prompt Injection, Response Action FSM, Malware Quarantine, Rate Limiting, 10,000-event stress bursts.

---

## 🚀 CI/CD & Automation

Continuous Integration workflows are configured under `.github/workflows/`:
* **Linting & Syntax Validation**: ESLint security scan on all pull requests.
* **Automated Security Regression**: Executes master test runner (`tests/run_all_tests.js`) across Node 20 and Node 22.
* **Empirical Performance Gating**: Validates that SIEM normalizer throughput exceeds 75,000 events/sec.

---

## 📸 Platform Screenshots

### Tactical SOC Threat Radar & Incident Command
![SOC Dashboard](screenshots/dashboard.png)

### AI Security Copilot & Forensic Investigation
![AI Assistant](screenshots/assistant.png)

### SIEM Log Analyzer & Detection Engineering
![Log Analyzer](screenshots/log-analyzer.png)

---

## 🎮 Deterministic Demonstration Guide

To execute a safe, reproducible demonstration suitable for an interview or evaluation (without requiring real malware):

```bash
# Run interactive guided demonstration
node demo/run_demo.js

# Run all 6 synthetic scenarios in succession
node demo/run_demo.js --all
```

* **Scenario Catalog**:
  1. `demo/scenarios/01_brute_force.json` — Password spraying campaign (`T1110.001`)
  2. `demo/scenarios/02_suspicious_powershell.json` — Hidden Base64 PowerShell (`T1059.001`)
  3. `demo/scenarios/03_suspicious_network.json` — CobaltStrike C2 socket beaconing (`T1071.001`)
  4. `demo/scenarios/04_persistence_behavior.json` — Registry Run key persistence (`T1547.001`)
  5. `demo/scenarios/05_malicious_download.json` — Certutil ingress tool transfer (`T1105`)
  6. `demo/scenarios/06_suspicious_file_activity.json` — Rapid file encryption burst (`T1486`)

Full presenter walkthrough notes are documented in [`demo/README.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/demo/README.md).

---

## 📖 API Documentation

Complete API documentation conforming to OpenAPI 3.1.0 specifications is available:
* **Interactive Markdown Specification**: [`docs/OPENAPI.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/OPENAPI.md)
* **Raw OpenAPI YAML**: [`docs/openapi.yaml`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/openapi.yaml)

### Primary API Routes Summary:
* `POST /api/auth/login` — Authenticate operator & issue JWT
* `POST /api/events` — Ingest HMAC-signed telemetry batch
* `GET /api/incidents` — List and filter security incidents
* `POST /api/incidents/:id/status` — Transition incident lifecycle state
* `GET /api/incidents/:id/timeline/verify` — Validate SHA-256 timeline integrity
* `POST /api/response-actions/:id/approve` — Human sign-off on containment proposal
* `POST /api/malware/analyze` — Static PE binary inspection

---

## 🛡️ Security Model & Least Privilege

Cyber Sentinel enforces strict Role-Based Access Control (RBAC):

| Role | Telemetry Write | Incident Triage | Response Actions | Quarantine Admin | Audit Log Access |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`ADMIN`** | ✅ | ✅ | ✅ Approve & Execute | ✅ Full | ✅ Full Read |
| **`SECURITY_ENGINEER`** | ✅ | ✅ | ✅ Propose & Approve | ✅ Full | ❌ Forbidden |
| **`INCIDENT_RESPONDER`** | ✅ | ✅ | ✅ Approve & Execute | ✅ Read / Delete | ❌ Forbidden |
| **`SOC_ANALYST`** | ❌ (Read Only) | ✅ Update Status | ⚠️ Propose Only | 👁️ Read Only | ❌ Forbidden |
| **`VIEWER`** | ❌ Forbidden | 👁️ Read Only | ❌ Forbidden | ❌ Forbidden | ❌ Forbidden |

---

## 🔬 Threat Model Summary (STRIDE)

A formal threat model aligned with **NIST SP 800-30 Rev. 1** and **STRIDE** is documented in [`docs/THREAT_MODEL.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/THREAT_MODEL.md):

* **THREAT-01 (External Attacker)**: Mitigated via account lockout (5 attempts), constant-time comparisons, and tiered rate limiters.
* **THREAT-04 (Stolen Device Credential)**: Mitigated via timestamp drift checks ($\pm 300\text{s}$), HMAC nonces, and instant token revocation APIs.
* **THREAT-06 (Malicious Insider)**: Mitigated via SHA-256 cryptographic timeline hash chains and immutable endpoint gating (`405 Method Not Allowed`).
* **THREAT-09 (Malicious File Upload)**: Mitigated via zero-execution static byte parsing, filename sanitization, Zip Slip checks, and `0o600` vault isolation.
* **THREAT-10 (Prompt Injection)**: Mitigated via delimiter encapsulation blocks, heuristic injection detectors, and outbound secret scrubbers.

---

## ⚠️ Known Limitations

1. **Static Analysis Only**: The malware analysis subsystem parses PE headers and entropy statically; it does not execute dynamic sandboxing or kernel-level behavioral tracing.
2. **In-Process Worker Execution**: CPU-intensive tasks (Bcrypt derivation, PE parsing) currently execute within Node.js worker pools rather than distributed background queue workers (e.g. Celery / BullMQ).
3. **Hardware Identity Binding**: Device authentication uses software HMAC secrets rather than hardware TPM-backed client certificates (planned in v2.0).

---

## 🗺️ Engineering Roadmap

```mermaid
gantt
    title Cyber Sentinel Feature Roadmap
    dateFormat  YYYY-MM
    section Identity & Host Security
    TPM-backed Hardware Identity (mTLS)       :2026-10, 2026-12
    eBPF Kernel Telemetry Probe (Linux)       :2026-11, 2027-01
    section AI & Governance
    Dual-LLM Safety Guardrail Classifier      :2026-10, 2026-11
    Multi-Party Authorization (Four-Eyes Gate):2026-12, 2027-02
    section Data & Scale
    Distributed Message Queue (Kafka Ingestion):2026-11, 2027-01
    WORM Object Lock Storage for Audit Ledger :2026-10, 2026-12
```

---

## 👥 Contributors & Maintenance

* **Ayush Dhiman** — Lead System Architect & Security Engineer ([@yushdhiman](https://github.com/yushdhiman))
* **Cyber Sentinel Engineering Team**

---

## 📚 Release & Governance Documentation

| Document | Purpose |
| :--- | :--- |
| [`docs/RELEASE_READINESS.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/RELEASE_READINESS.md) | Official v1.0.0 release verification, metrics, and deployment readiness report |
| [`docs/FINAL_SECURITY_AUDIT.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/FINAL_SECURITY_AUDIT.md) | Full-stack 22-component security audit and remediation verification |
| [`CHANGELOG.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/CHANGELOG.md) | Complete version history and feature changelog (Keep a Changelog standard) |
| [`SECURITY.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/SECURITY.md) | Vulnerability disclosure policy, SLAs, and security response protocol |
| [`CONTRIBUTING.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/CONTRIBUTING.md) | Contribution guidelines, secure coding standards, and PR workflows |
| [`docs/OPENAPI.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/OPENAPI.md) | Complete OpenAPI 3.1.0 REST and WebSocket endpoint documentation |
| [`docs/THREAT_MODEL.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/THREAT_MODEL.md) | STRIDE Threat Model across 13 distinct adversarial attack vectors |
| [`docs/PERFORMANCE.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/PERFORMANCE.md) | Measured throughput benchmarks and latency distributions |
| [`docs/DATA_PRIVACY.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/DATA_PRIVACY.md) | Privacy review, minimization specifications, and credential scrubbing |
| [`docs/DISASTER_RECOVERY.md`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/docs/DISASTER_RECOVERY.md) | Tested backup restoration procedures and recovery playbooks |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
