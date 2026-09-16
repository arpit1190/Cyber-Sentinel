# CYBER SENTINEL — PRODUCTION POSTGRESQL ARCHITECTURE & SCHEMA SPECIFICATION

**Architecture Specification**: Enterprise Relational Database Layer  
**Engine**: PostgreSQL 14+ / 15+ / 16+  
**Target Schema**: Public  
**Classification**: Enterprise SOC Data Layer  

---

## 1. ARCHITECTURAL OVERVIEW

Cyber Sentinel implements a **high-concurrency, normalized relational data layer** on PostgreSQL with automatic versioned migrations, connection pooling, and atomic transaction isolation.

### Key Capabilities
* **UUID & Deterministic Keys**: High-entropy UUIDs (`gen_random_uuid()`) for entities alongside human-readable prefixed identifiers (`INC-XXXX`, `DEV-XXXX`, `RULE-XXXX`).
* **Strict Referential Integrity**: Foreign keys with cascaded deletes on dependent records (e.g. `refresh_tokens` $\rightarrow$ `users`, `device_credentials` $\rightarrow$ `devices`, `incident_events` $\rightarrow$ `incidents`).
* **Query-Optimized Indexing**: B-tree, Compound, and GIN (JSONB) indexes aligned with high-frequency SOC query patterns.
* **Versioned Migration System**: Deterministic SQL migrations tracked with SHA-256 checksums in `schema_migrations`.
* **Atomic Transactions**: Full `BEGIN`/`COMMIT`/`ROLLBACK` lifecycle management via `withTransaction(client => ...)`.
* **Dual-Mode Fallback**: When running without `DATABASE_URL` (offline or zero-dependency dev), the system gracefully transitions to persistent local repository mode.

---

## 2. ENTITY-RELATIONSHIP DIAGRAM

```
┌─────────────────┐       ┌────────────────────────┐       ┌───────────────────────┐
│      roles      │◄──────┤    role_permissions    ├──────►│      permissions      │
└────────┬────────┘       └────────────────────────┘       └───────────────────────┘
         │
         │ 1:N
         ▼
┌─────────────────┐       1:N ┌────────────────────────┐
│      users      ├──────────►│     refresh_tokens     │
└────────┬────────┘           └────────────────────────┘
         │
         │ 1:N (Assignee)
         ▼
┌─────────────────┐       1:N ┌────────────────────────┐
│    incidents    ├──────────►│    incident_events     │
└────────┬────────┘           └────────────────────────┘
         │
         │ 1:N
         ▼
┌─────────────────┐           ┌────────────────────────┐
│ response_actions│           │    audit_logs          │
└─────────────────┘           └────────────────────────┘

┌─────────────────┐       1:N ┌────────────────────────┐
│     devices     ├──────────►│   device_credentials   │
└────────┬────────┘           └────────────────────────┘
         │
         │ 1:N
         ▼
┌─────────────────┐       1:N ┌────────────────────────┐
│telemetry_events ├──────────►│       detections       │
└─────────────────┘           └───────────▲────────────┘
                                          │ 1:N
                              ┌───────────┴────────────┐
                              │    detection_rules     │
                              └────────────────────────┘

┌─────────────────┐       1:N ┌────────────────────────┐
│ malware_samples ├──────────►│malware_analysis_results│
└─────────────────┘           └────────────────────────┘

┌─────────────────┐           ┌────────────────────────┐
│threat_indicators│           │   schema_migrations    │
└─────────────────┘           └────────────────────────┘
```

---

## 3. COMPREHENSIVE TABLE SPECIFICATIONS

### 1. `roles`
Defines role-based access control tiers.
* `id` (`UUID`, PK, default `gen_random_uuid()`): Unique role identifier.
* `name` (`VARCHAR(64)`, UNIQUE, NOT NULL): Canonical role name (`ADMIN`, `SENIOR_ANALYST`, `ANALYST`, `VIEWER`).
* `description` (`TEXT`): Role permissions and operational scope.
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `updated_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 2. `permissions`
Granular privilege definitions.
* `id` (`UUID`, PK, default `gen_random_uuid()`): Unique permission identifier.
* `code` (`VARCHAR(64)`, UNIQUE, NOT NULL): Permission token (e.g. `incidents:write`, `containment:execute`, `audit:read`).
* `description` (`TEXT`): Human-readable permission explanation.
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 3. `role_permissions`
Many-to-many junction between roles and permissions.
* `role_id` (`UUID`, FK `roles.id` ON DELETE CASCADE).
* `permission_id` (`UUID`, FK `permissions.id` ON DELETE CASCADE).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* **Primary Key**: `(role_id, permission_id)`.

### 4. `users`
Operator and administrator identities.
* `id` (`VARCHAR(64)`, PK): Unique user identifier (`USR-XXXX`).
* `email` (`VARCHAR(255)`, UNIQUE, NOT NULL): Login email (lowercased).
* `password_hash` (`VARCHAR(255)`, NOT NULL): Bcrypt password hash (cost factor 12).
* `name` (`VARCHAR(255)`, NOT NULL): Operator display name.
* `role_id` (`UUID`, FK `roles.id` ON DELETE SET NULL).
* `role` (`VARCHAR(32)`, NOT NULL, default `'ANALYST'`): Normalized uppercase role token.
* `status` (`VARCHAR(32)`, NOT NULL, default `'active'`): Account state (`active`, `suspended`, `locked`).
* `mfa_enabled` (`BOOLEAN`, NOT NULL, default `FALSE`): Multi-factor authentication flag.
* `totp_secret` (`VARCHAR(128)`): Base32 encoded RFC 6238 TOTP seed.
* `phone` (`VARCHAR(32)`): Contact mobile number for SMS OTP delivery.
* `is_email_verified` (`BOOLEAN`, default `TRUE`).
* `is_phone_verified` (`BOOLEAN`, default `TRUE`).
* `must_change_password` (`BOOLEAN`, default `FALSE`).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `updated_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 5. `refresh_tokens`
Active rotating session tokens.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `user_id` (`VARCHAR(64)`, NOT NULL, FK `users.id` ON DELETE CASCADE).
* `token_hash` (`VARCHAR(64)`, UNIQUE, NOT NULL): SHA-256 hash of refresh token.
* `ip_address` (`VARCHAR(64)`): Client IP address during issuance.
* `user_agent` (`TEXT`): Browser user agent string.
* `expires_at` (`TIMESTAMPTZ`, NOT NULL): Absolute expiration timestamp (7 days default).
* `revoked_at` (`TIMESTAMPTZ`): Token invalidation timestamp.
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 6. `devices`
Enrolled endpoint agents streaming host telemetry.
* `id` (`VARCHAR(64)`, PK): Hardware-derived device identifier (`DEV-XXXX`).
* `name` (`VARCHAR(255)`): Friendly device name.
* `platform` (`VARCHAR(128)`): Operating system and kernel release.
* `hostname` (`VARCHAR(255)`): Network hostname.
* `status` (`VARCHAR(32)`, NOT NULL, default `'ACTIVE'`): State (`ACTIVE`, `OFFLINE`, `CONTAINED`).
* `agent_version` (`VARCHAR(32)`): Installed Sentinel agent release.
* `last_seen` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `updated_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 7. `device_credentials`
Cryptographic authentication tokens for endpoint agents.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `device_id` (`VARCHAR(64)`, NOT NULL, FK `devices.id` ON DELETE CASCADE).
* `token_hash` (`VARCHAR(64)`, UNIQUE, NOT NULL): SHA-256 hash of device authentication secret.
* `key_identifier` (`VARCHAR(64)`): Public key identifier.
* `is_active` (`BOOLEAN`, default `TRUE`).
* `revoked_at` (`TIMESTAMPTZ`).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 8. `detection_rules`
Stateful SIEM correlation rules and behavioral triggers.
* `id` (`VARCHAR(64)`, PK): Rule code (e.g. `RULE_SQLI_SUCCESS_002`).
* `name` (`VARCHAR(255)`, NOT NULL): Rule title.
* `description` (`TEXT`): Logic description and MITRE mapping.
* `severity` (`VARCHAR(32)`, NOT NULL, default `'HIGH'`): Incident severity on match.
* `category` (`VARCHAR(64)`, NOT NULL): Attack category.
* `mitre_technique` (`VARCHAR(64)`): ATT&CK technique code (e.g. `T1190`).
* `rule_type` (`VARCHAR(64)`, NOT NULL, default `'STATEFUL_CORRELATION'`).
* `parameters` (`JSONB`, default `'{}'`): Thresholds and window specifications.
* `is_active` (`BOOLEAN`, default `TRUE`).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `updated_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 9. `telemetry_events`
Normalized telemetry ingested from agents, syslog, and network taps.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `event_id` (`VARCHAR(64)`, UNIQUE, NOT NULL): Deduplicated event identifier.
* `device_id` (`VARCHAR(64)`, FK `devices.id` ON DELETE SET NULL).
* `event_type` (`VARCHAR(64)`, NOT NULL): Standardized event type (`AUTH_FAILURE`, `PROCESS_EXECUTION`, `EXPLOIT_PROBE`).
* `source` (`VARCHAR(64)`, NOT NULL): Originating subsystem (`endpoint-agent`, `waf`, `suricata`).
* `severity` (`VARCHAR(32)`, NOT NULL, default `'MEDIUM'`).
* `source_ip` (`VARCHAR(64)`): Originating network coordinates.
* `source_port` (`INTEGER`).
* `dest_ip` (`VARCHAR(64)`): Target network coordinates.
* `dest_port` (`INTEGER`).
* `protocol` (`VARCHAR(16)`, default `'TCP'`).
* `process_name` (`VARCHAR(255)`): Executed process binary.
* `command_line` (`TEXT`): Full process execution command string.
* `user_identity` (`VARCHAR(255)`): Logged-in user context.
* `is_simulation` (`BOOLEAN`, default `FALSE`): Sandbox simulation marker.
* `raw_payload` (`JSONB`, default `'{}'`): Full unparsed ingestion JSON payload.
* `observed_at` (`TIMESTAMPTZ`, NOT NULL): Event occurrence timestamp.
* `ingested_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 10. `detections`
Individual rule match records.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `rule_id` (`VARCHAR(64)`, FK `detection_rules.id` ON DELETE SET NULL).
* `event_id` (`VARCHAR(64)`, FK `telemetry_events.event_id` ON DELETE SET NULL).
* `title` (`VARCHAR(255)`, NOT NULL): Detection header.
* `severity` (`VARCHAR(32)`, NOT NULL).
* `source_ip` (`VARCHAR(64)`).
* `details` (`JSONB`, default `'{}'`).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 11. `incidents`
Correlated security incidents requiring analyst triage and response.
* `id` (`VARCHAR(64)`, PK): Incident identifier (`INC-XXXX`).
* `title` (`VARCHAR(255)`, NOT NULL): Incident summary.
* `severity` (`VARCHAR(32)`, NOT NULL, default `'HIGH'`): Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* `category` (`VARCHAR(64)`, NOT NULL): Threat classification.
* `status` (`VARCHAR(32)`, NOT NULL, default `'NEW'`): State (`NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `CLOSED`, `FALSE_POSITIVE`).
* `description` (`TEXT`): Detailed forensic description.
* `assignee` (`VARCHAR(255)`, default `'Unassigned'`).
* `assignee_id` (`VARCHAR(64)`, FK `users.id` ON DELETE SET NULL).
* `related_ips` (`JSONB`, default `'[]'`): Array of associated attacker/target IPs.
* `related_alerts` (`JSONB`, default `'[]'`): Triggered alert messages.
* `mitre_techniques` (`JSONB`, default `'[]'`): Associated ATT&CK techniques.
* `evidence` (`JSONB`, default `'{}'`): Preserved forensic payload.
* `evidence_hash` (`VARCHAR(64)`): Cryptographic SHA-256 hash of preserved evidence.
* `timeline` (`JSONB`, default `'[]'`): Chronological audit log of state changes.
* `created_by` (`VARCHAR(255)`, default `'system'`).
* `created_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `updated_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 12. `incident_events`
Individual timeline entries and analyst investigative notes.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `incident_id` (`VARCHAR(64)`, NOT NULL, FK `incidents.id` ON DELETE CASCADE).
* `action` (`VARCHAR(64)`, NOT NULL): Timeline action (`STATUS_CHANGE`, `ANALYST_NOTE`, `CONTAINMENT_APPLIED`).
* `actor` (`VARCHAR(255)`, NOT NULL): Analyst or system agent.
* `note` (`TEXT`): Investigative note.
* `details` (`JSONB`, default `'{}'`).
* `timestamp` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 13. `threat_indicators`
High-speed IOC matching repository.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `indicator_type` (`VARCHAR(32)`, NOT NULL): Type (`ipv4`, `domain`, `sha256`, `url`).
* `value` (`VARCHAR(255)`, NOT NULL): IOC value.
* `malware_family` (`VARCHAR(255)`): Associated threat actor / malware strain.
* `threat_type` (`VARCHAR(64)`): Category (`botnet_cc`, `payload_delivery`, `c2`).
* `severity` (`VARCHAR(32)`, NOT NULL, default `'HIGH'`).
* `confidence` (`INTEGER`, NOT NULL, default `90`): Accuracy confidence score (0–100).
* `mitre_technique` (`VARCHAR(64)`): ATT&CK technique reference.
* `source` (`VARCHAR(64)`, NOT NULL, default `'ThreatFox'`): Feed provider.
* `reporter` (`VARCHAR(64)`): Feed submitter.
* `reference_url` (`TEXT`): External advisory reference.
* `is_active` (`BOOLEAN`, default `TRUE`).
* `first_seen` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `last_seen` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* **Unique Constraint**: `UNIQUE(indicator_type, value)`.

### 14. `malware_samples`
Forensic archive of submitted binary files.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `sha256` (`VARCHAR(64)`, UNIQUE, NOT NULL): Primary SHA-256 fingerprint.
* `md5` (`VARCHAR(32)`).
* `sha1` (`VARCHAR(40)`).
* `filename` (`VARCHAR(255)`, NOT NULL): Sanitized filename.
* `file_size_bytes` (`BIGINT`, NOT NULL).
* `file_type` (`VARCHAR(64)`): Detected MIME / container format.
* `uploader` (`VARCHAR(255)`, default `'anonymous'`).
* `uploaded_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 15. `malware_analysis_results`
Static PE and heuristic analysis reports.
* `id` (`VARCHAR(64)`, PK): Scan identifier (`SCAN-XXXX`).
* `sample_id` (`UUID`, FK `malware_samples.id` ON DELETE CASCADE).
* `filename` (`VARCHAR(255)`, NOT NULL).
* `sha256` (`VARCHAR(64)`, NOT NULL).
* `score` (`INTEGER`, NOT NULL): Risk score (0–100).
* `severity` (`VARCHAR(32)`, NOT NULL): Threat level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* `entropy` (`NUMERIC(6,4)`): Shannon entropy score (0.0 to 8.0).
* `is_pe` (`BOOLEAN`, default `FALSE`): PE executable flag.
* `mitre_techniques` (`JSONB`, default `'[]'`).
* `findings` (`JSONB`, default `'{}'`): Extracted strings, suspicious APIs, and section headers.
* `details` (`JSONB`, default `'{}'`).
* `analyzed_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 16. `response_actions`
Firewall containment rules and defensive automated responses.
* `id` (`UUID`, PK, default `gen_random_uuid()`).
* `action_type` (`VARCHAR(64)`, NOT NULL, default `'BLOCK_IP'`).
* `target` (`VARCHAR(255)`, NOT NULL): Contained IP or domain.
* `reason` (`TEXT`): Justification / triggering incident reference.
* `status` (`VARCHAR(32)`, NOT NULL, default `'ACTIVE'`): State (`ACTIVE`, `REVOKED`, `EXPIRED`).
* `executed_by` (`VARCHAR(255)`, NOT NULL): Operator or autonomous copilot.
* `incident_id` (`VARCHAR(64)`, FK `incidents.id` ON DELETE SET NULL).
* `expires_at` (`TIMESTAMPTZ`).
* `executed_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `revoked_at` (`TIMESTAMPTZ`).

### 17. `firewall_rules`
Compatibility structure for legacy firewall containment queries.
* `ip` (`VARCHAR(64)`, PK): Blocked IP address.
* `reason` (`TEXT`): Containment reason.
* `blocked_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).
* `blocked_by` (`VARCHAR(255)`, NOT NULL).
* `active` (`BOOLEAN`, NOT NULL, default `TRUE`).
* `unblocked_at` (`TIMESTAMPTZ`).

### 18. `audit_logs`
Immutable compliance and security event ledger.
* `id` (`VARCHAR(64)`, PK): Audit identifier (`AUDIT-XXXX`).
* `actor` (`VARCHAR(255)`, NOT NULL): Email or subsystem initiating action.
* `actor_role` (`VARCHAR(64)`, NOT NULL): Role at time of execution.
* `action` (`VARCHAR(64)`, NOT NULL): Action verb (`LOGIN`, `IP_BLOCKED`, `STATUS_CHANGE`).
* `target` (`VARCHAR(255)`): Target system, user, or IP address.
* `result` (`VARCHAR(32)`, NOT NULL, default `'SUCCESS'`): Outcome (`SUCCESS`, `FAILURE`).
* `source_ip` (`VARCHAR(64)`): Originating client IP.
* `details` (`JSONB`, default `'{}'`): Structured metadata.
* `timestamp` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

### 19. `schema_migrations`
Tracks applied database migrations.
* `version` (`INTEGER`, PK): Ordered sequence number (`1`, `2`, `3`).
* `name` (`VARCHAR(255)`, NOT NULL): Migration file basename.
* `checksum` (`VARCHAR(64)`, NOT NULL): SHA-256 hash of migration SQL file.
* `applied_at` (`TIMESTAMPTZ`, default `CURRENT_TIMESTAMP`).

---

## 4. INDEXING STRATEGY

| Index Name | Table | Columns / Expressions | Type | Query Pattern Optimized |
| :--- | :--- | :--- | :--- | :--- |
| `idx_users_email` | `users` | `LOWER(email)` | B-tree | Sub-millisecond case-insensitive login lookups |
| `idx_refresh_tokens_token_hash`| `refresh_tokens`| `token_hash` | B-tree | Immediate session token rotation validation |
| `idx_telemetry_type_time` | `telemetry_events`| `(event_type, observed_at DESC)`| Compound B-tree| SIEM sliding correlation window lookups |
| `idx_incidents_related_ips`| `incidents` | `related_ips` | GIN | Fast JSON array IP containment searches |
| `idx_threat_indicators_lookup`| `threat_indicators`| `(indicator_type, LOWER(value))`| Compound B-tree| Live stream IOC enrichment (< 0.05ms) |
| `idx_malware_analysis_score`| `malware_analysis_results`| `score DESC` | B-tree | Highest severity threat ranking |
| `idx_audit_logs_timestamp`| `audit_logs` | `timestamp DESC` | B-tree | SOC compliance audit trail pagination |
| `idx_response_actions_target`| `response_actions` | `target WHERE status = 'ACTIVE'` | Partial B-tree | Instant active IP firewall filter checks |

---

## 5. MIGRATION SYSTEM WORKFLOW

Migrations are stored in [`backend/src/data/migrations/`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/src/data/migrations/) and managed by [`backend/src/data/migrator.js`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/src/data/migrator.js).

### Executing Migrations
```bash
# In backend directory
npm run db:migrate
```

### Programmatic Invocation on Startup
```javascript
const { initDb } = require('./data/db');

// Connects to pool and automatically applies all pending migrations in transaction
await initDb();
```

---

## 6. TRANSACTION SAFETY & CONCURRENCY

All database state modifications should be wrapped in `withTransaction` blocks:

```javascript
const db = require('./data/db');

await db.withTransaction(async (client) => {
  // 1. Create incident
  await client.query(
    'INSERT INTO incidents (id, title, severity) VALUES ($1, $2, $3)',
    [incidentId, title, severity]
  );

  // 2. Append forensic event
  await client.query(
    'INSERT INTO incident_events (incident_id, action, actor) VALUES ($1, $2, $3)',
    [incidentId, 'INCIDENT_CREATED', actor]
  );
});
// Automatically commits on success, rolls back on any exception
```
