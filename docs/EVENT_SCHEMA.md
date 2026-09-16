# Cyber Sentinel — Canonical Cybersecurity Event Schema Specification

## 1. Overview & Purpose

Cyber Sentinel implements a standardized, robust **Canonical Event Schema** for all incoming endpoint, network, and system telemetry. Heterogeneous event streams from diverse sources (such as Endpoint Agents, Windows Event Logs, Syslog CEF/LEEF collectors, Firewalls, and Threat Feeds) are ingested, dynamically sanitized, validated, and normalized into a unified structure prior to SIEM correlation, Threat Intelligence IOC enrichment, and automated containment dispatch.

> **Zero-Trust Ingestion Principle**: Telemetry is never trusted solely because it originated from an authenticated endpoint. Every packet is subjected to deep runtime schema validation, prototype pollution defense, type enforcement, and boundary constraints.

---

## 2. Canonical Event Structure

```json
{
  "event_id": "123e4567-e89b-12d3-a456-426614174000",
  "timestamp": "2026-09-15T16:45:00.000Z",
  "device_id": "DEV-WORKSTATION-01",
  "event_type": "PROCESS_EXECUTION",
  "severity": "HIGH",
  "source": "endpoint-agent",
  
  "process": {
    "name": "powershell.exe",
    "pid": 4088,
    "ppid": 1024,
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -enc JABz...",
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "parent_name": "cmd.exe"
  },

  "network": {
    "source_ip": "192.168.1.100",
    "source_port": 54321,
    "dest_ip": "185.220.101.5",
    "dest_port": 443,
    "protocol": "TCP",
    "direction": "OUTBOUND",
    "domain": "c2.evil-corp.com",
    "bytes_sent": 1024,
    "bytes_received": 4096
  },

  "file": {
    "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\malware.exe",
    "name": "malware.exe",
    "action": "CREATED",
    "size_bytes": 65536,
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "extension": "exe"
  },

  "user": {
    "name": "sec-admin",
    "domain": "CORP",
    "id": "S-1-5-21-1234567890",
    "email": "admin@corp.local",
    "is_admin": true
  },

  "metadata": {
    "schema_version": "1.0.0",
    "ingested_at": "2026-09-15T16:45:00.012Z",
    "tags": ["T1059.001", "CobaltStrike", "C2"],
    "mitre_technique": "T1059.001",
    "ioc_match": null,
    "is_simulation": false,
    "custom": {
      "unrecognizedVendorField": "rawData"
    }
  }
}
```

---

## 3. Schema Fields & Constraints

### 3.1 Top-Level Core Attributes

| Field | Type | Required | Constraints / Description |
| :--- | :--- | :--- | :--- |
| `event_id` | `string` | **Yes** | UUIDv4 format (`^[0-9a-f]{8}-...-[0-9a-f]{12}$`) or `evt-...` format. Max length: 64 chars. Malformed IDs are automatically replaced with a cryptographic UUIDv4. |
| `timestamp` | `string` | **Yes** | ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`). Millisecond and second epoch timestamps are automatically converted to standard ISO format. Dates outside 2000–2100 default safely to current UTC time. |
| `device_id` | `string` | **Yes** | Identifier of the originating endpoint (e.g. `DEV-4F2A19BC80DE4E12`). Max length: 128 chars. |
| `event_type` | `enum` | **Yes** | Canonical uppercase event classification. See Section 4. |
| `severity` | `enum` | **Yes** | Canonical risk classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`). Defaults to `MEDIUM`. |
| `source` | `string` | **Yes** | Originating telemetry channel (`endpoint-agent`, `syslog-collector`, `windows-event-log`, `network-probe`, `cyber-sentinel-simulator`). Max length: 128 chars. |

---

### 3.2 Process Sub-Object (`process`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `process.name` | `string \| null` | Executable process name (e.g. `powershell.exe`, `curl`, `nginx`). Max length: 256 chars. |
| `process.pid` | `number \| null` | Process Identifier (positive integer). |
| `process.ppid` | `number \| null` | Parent Process Identifier (positive integer). |
| `process.path` | `string \| null` | Full path to executable. Max length: 1024 chars. |
| `process.command_line` | `string \| null` | Full invocation command line with arguments. Max length: 1,048,576 bytes (1 MB). |
| `process.hash` | `string \| null` | Process image SHA-256 or MD5 hash. Max length: 128 chars. |
| `process.parent_name` | `string \| null` | Parent process name (e.g. `cmd.exe`, `explorer.exe`). Max length: 256 chars. |

---

### 3.3 Network Sub-Object (`network`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `network.source_ip` | `string` | Valid IPv4 or IPv6 source address. Defaults to `127.0.0.1`. Automatically unbrackets IPv6 addresses (e.g., `[::1]`). |
| `network.source_port` | `number \| null` | Source port number (bounded integer: 1–65535). |
| `network.dest_ip` | `string \| null` | Valid IPv4 or IPv6 destination address. |
| `network.dest_port` | `number \| null` | Destination port number (bounded integer: 1–65535). |
| `network.protocol` | `enum` | Transport/Application protocol (`TCP`, `UDP`, `ICMP`, `HTTP`, `HTTPS`, `DNS`, `SSH`, `SMB`, `RDP`, `TLS`, `UNKNOWN`). Defaults to `TCP`. |
| `network.direction` | `enum` | Flow direction (`INBOUND`, `OUTBOUND`, `INTERNAL`, `UNKNOWN`). |
| `network.domain` | `string \| null` | FQDN or target hostname. Max length: 253 chars. |
| `network.bytes_sent` | `number \| null` | Total bytes transmitted. |
| `network.bytes_received`| `number \| null` | Total bytes received. |

---

### 3.4 File Sub-Object (`file`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `file.path` | `string \| null` | Full target file system path. Max length: 1024 chars. |
| `file.name` | `string \| null` | Base filename. Max length: 256 chars. |
| `file.action` | `enum` | File action (`CREATED`, `MODIFIED`, `DELETED`, `ACCESSED`, `RENAMED`, `COPIED`, `PERMISSION_CHANGED`, `UNKNOWN`). |
| `file.size_bytes` | `number \| null` | File size in bytes. |
| `file.hash` | `string \| null` | SHA-256 / SHA-1 / MD5 hash of the file. Max length: 128 chars. |
| `file.extension` | `string \| null` | File extension (e.g. `exe`, `dll`, `ps1`, `sh`). Max length: 16 chars. |

---

### 3.5 User Sub-Object (`user`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `user.name` | `string` | Account or principal username. Max length: 128 chars. Defaults to `system`. |
| `user.domain` | `string \| null` | Active Directory domain or host domain. Max length: 256 chars. |
| `user.id` | `string \| null` | Windows SID or POSIX UID/GID. Max length: 64 chars. |
| `user.email` | `string \| null` | User email address. Max length: 128 chars. |
| `user.is_admin` | `boolean` | True if the account possesses administrative/root privileges. |

---

### 3.6 Metadata Sub-Object (`metadata`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `metadata.schema_version` | `string` | Canonical schema version (`1.0.0`). |
| `metadata.ingested_at` | `string` | ISO-8601 UTC timestamp recording exact ingestion time on the Sentinel cluster. |
| `metadata.tags` | `string[]` | Array of security tags (max 20 tags, max 64 chars each). |
| `metadata.mitre_technique` | `string \| null` | MITRE ATT&CK technique code (e.g. `T1059.001`, `T1078`). |
| `metadata.ioc_match` | `object \| null` | Threat intelligence match details from ThreatFox / CISA KEV. |
| `metadata.is_simulation` | `boolean` | True if telemetry was generated by simulation or training routines. |
| `metadata.custom` | `object` | Safe key-value container for vendor-specific or unmapped fields. Guarded by depth (max 4 levels), key count (max 50 keys), and size (max 32 KB). |

---

## 4. Canonical Enums Reference

### Event Types (`EventTypes`)
- `AUTH_FAILURE`: Failed authentication attempt (e.g., Windows Event 4625, SSH failed password).
- `AUTH_SUCCESS`: Successful authentication attempt (e.g., Windows Event 4624).
- `NETWORK_CONNECTION`: Socket establishment, inbound probe, or outbound beaconing.
- `PROCESS_EXECUTION`: Process creation, command-line invocation, or child spawn.
- `FILE_MODIFICATION`: File creation, modification, deletion, or permission change.
- `IOC_MATCH`: Direct telemetry match against known C2 indicators or malware hashes.
- `EXPLOIT_PROBE`: Web exploit, SQL injection, Cross-Site Scripting, or RCE attempt.
- `PORT_SCAN`: Network reconnaissance or SYN scan probe.
- `SYSTEM_ANOMALY`: Generic anomaly or unclassified operational event.
- `PRIVILEGE_ESCALATION`: Sudo abuse, UAC bypass, or token impersonation.
- `PERSISTENCE`: Registry autorun, cron job, or scheduled task installation.
- `LATERAL_MOVEMENT`: PsExec, WMI execution, or SMB relay.
- `DEFENSE_EVASION`: Log clearing, process injection, or AMSI bypass.

### Severity Levels (`SeverityLevels`)
- `CRITICAL`: Immediate high-confidence threat requiring automated or urgent SOC response.
- `HIGH`: Confirmed exploit probe, active malware signature, or repeated brute force.
- `MEDIUM`: Suspicious execution, untrusted network connection, or policy violation.
- `LOW`: Informational security event or single authentication anomaly.
- `INFORMATIONAL`: Normal operational log or diagnostic heartbeat.

---

## 5. Runtime Sanitization & Security Defenses

### 5.1 Prototype Pollution Defense
The normalizer engine uses prototype-free object allocations (`Object.create(null)`) for all nested maps, and explicitly strips `__proto__`, `constructor`, and `prototype` keys from every object depth to prevent prototype poisoning attacks.

### 5.2 Bounded Recursion & Cycle Guards
All nested objects (such as `metadata.custom` and `details`) are recursively sanitized with a `WeakSet` cycle tracker and a strict depth limit of **4 levels**. Circular references are safely replaced with `"[Circular Reference]"` and excessive nesting is bounded with `"[Max Depth Exceeded]"`.

### 5.3 Malicious Types & Payload Defense
Functions, symbols, getters/setters, and non-serializable objects embedded in inbound payloads are automatically stripped. Null bytes (`\0`) and non-printable control characters are removed from all string fields.

---

## 6. Backward Compatibility Layer

To maintain seamless compatibility with legacy SOC components, real-time WebSocket emitters, and SIEM correlation rules, the canonical event object simultaneously provides direct camelCase accessors:

| Legacy Property | Maps To |
| :--- | :--- |
| `event.eventId` | `event.event_id` |
| `event.deviceId` / `event.hostname` | `event.device_id` |
| `event.eventType` | `event.event_type` |
| `event.observedAt` | `event.timestamp` |
| `event.ingestedAt` | `event.metadata.ingested_at` |
| `event.sourceIp` | `event.network.source_ip` |
| `event.destIp` | `event.network.dest_ip` |
| `event.sourcePort` | `event.network.source_port` |
| `event.destPort` | `event.network.dest_port` |
| `event.processName` | `event.process.name` |
| `event.commandLine` | `event.process.command_line` |
| `event.filePath` | `event.file.path` |
| `event.fileName` | `event.file.name` |
| `event.details` | `event.metadata.custom` |

---

## 7. Verification & Automated Test Suite

The test suite in [`backend/test_event_schema_security.js`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/test_event_schema_security.js) verifies 13 automated schema security and fuzzing vectors:

```bash
npm run test:schema
```

- `[SCHEMA-COMPLETENESS]`: Validates full 11-block canonical schema conversion.
- `[TYPE-RESILIENCE]`: Validates handling of null, undefined, primitives, arrays.
- `[UUID-VALIDATION]`: Validates malformed/SQLi/traversal ID rejection and UUIDv4 generation.
- `[TIMESTAMP-VALIDATION]`: Validates ISO, epoch ms, epoch s conversions and date guards.
- `[STRING-SANITIZATION]`: Validates control char and null byte stripping.
- `[FIELD-LIMITS]`: Validates boundary enforcement on oversized inputs.
- `[PROTOTYPE-POLLUTION]`: Validates `__proto__` and `constructor` defense.
- `[DANGEROUS-STRUCTURES]`: Validates stripping of functions, symbols, and circular references.
- `[UNKNOWN-FIELDS]`: Validates harvesting unrecognized fields into `metadata.custom`.
- `[NESTING-DEPTH]`: Validates depth bounding (max 4 levels).
- `[HETEROGENEOUS-SOURCES]`: Validates Windows Event Log and Syslog format translations.
- `[BACKWARD-COMPATIBILITY]`: Validates dual camelCase/snake_case accessors.
