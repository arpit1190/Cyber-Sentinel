# Cyber Sentinel — Modular Detection Engine Specification

## 1. Architecture Overview

Cyber Sentinel implements a decoupled, high-performance **Modular Detection Engine** designed to evaluate, correlate, and escalate security signals across large-scale enterprise telemetry streams.

```
┌────────────────────────┐
│  Heterogeneous Stream  │ (Agent, Windows Events, Syslog, Network Probes)
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│  Event Normalizer &    │ (Canonical 11-Block Event Schema)
│  Runtime Validator     │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│   Rule Evaluator &     │ (Rule Registry: Single-Event, Threshold,
│   Correlation Engine   │  Sequence, Cross-Source Correlation)
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│  Detection Generation  │ (Standardized Detection Payload with Evidence,
│  & Severity/Confidence │  MITRE ATT&CK Mapping & Investigation Playbook)
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│  Automated Incident    │ (SecurityStore / PostgreSQL Incidents &
│  Escalation & Alerts   │  WebSocket Real-Time Broadcasts)
└────────────────────────┘
```

---

## 2. Supported Rule Types

The detection engine supports four distinct analytical rule models:

### 2.1 Single-Event Rules (`SINGLE_EVENT`)
Evaluates instantaneous conditions against a single normalized canonical event.
- **Use Case**: Atomic indicators, malicious commands, known exploit payloads, specific tools.
- **Example**: `RULE_MIMIKATZ_CRED_DUMP_001` (flags `sekurlsa::logonpasswords` or LSASS dumping).

### 2.2 Threshold Rules (`THRESHOLD`)
Aggregates matching events grouped by target entities (`device_id`, `network.source_ip`, `user.name`) across a sliding time window.
- **Use Case**: Brute force login campaigns, horizontal/vertical port scans, mass file encryption bursts.
- **Example**: `RULE_BRUTE_FORCE_005` (5 failed logins from the same source IP within a 2-minute window).

### 2.3 Sequence Rules (`SEQUENCE`)
Tracks an ordered state machine of multi-stage attack steps occurring within a defined time window.
- **Use Case**: Multi-stage attack kill chains (e.g. Web Exploit Probe $\rightarrow$ PowerShell Execution $\rightarrow$ Shadow Copy Deletion).
- **Example**: `RULE_KILL_CHAIN_SEQUENCE_008` (detects Stage 1 $\rightarrow$ Stage 2 $\rightarrow$ Stage 3 in sequence within 5 minutes).

### 2.4 Cross-Source Correlation Rules (`CORRELATION`)
Correlates heterogeneous events across different telemetry dimensions and data sources for the same entity within a time window.
- **Use Case**: Correlating an endpoint process execution with an outbound network socket connection to a malicious C2 IP.
- **Example**: `RULE_C2_PROCESS_CORRELATION_010` (process execution + external socket connection within 60 seconds).

---

## 3. Rule Definition Model & Registry

Rules are managed centrally via [`ruleRegistry.js`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/src/services/detection/ruleRegistry.js).

### Rule Schema

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `id` | `string` | Unique rule identifier (e.g., `RULE_SHADOW_COPY_DELETION_003`). |
| `name` | `string` | Human-readable title. |
| `description` | `string` | Detailed threat explanation and operational context. |
| `version` | `string` | SemVer string (e.g., `1.2.0`). |
| `enabled` | `boolean` | Rule activation state (`true` or `false`). |
| `type` | `enum` | `SINGLE_EVENT`, `THRESHOLD`, `SEQUENCE`, or `CORRELATION`. |
| `severity` | `enum` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`. |
| `confidence` | `number` | Confidence rating (0 to 100). |
| `mitreTechniques` | `string[]` | Array of MITRE ATT&CK techniques (e.g., `['T1059.001', 'T1490']`). |
| `timeWindowMs` | `number` | Sliding time window in milliseconds (for Threshold, Sequence, and Correlation rules). |
| `threshold` | `number` | Event count required to trigger a Threshold rule. |
| `groupBy` | `string[]` | Fields to partition sliding state by (e.g., `['network.source_ip']`, `['device_id']`). |
| `sequence` | `object[]` | Ordered array of match stages for Sequence rules. |
| `match` | `function` | Evaluation function `(event, state) => boolean`. |
| `recommendedInvestigation` | `string[]` | Prescriptive analyst triage playbook steps. |

---

## 4. Detection Output Specification

When a rule fires, the engine generates a standardized `Detection` object:

```json
{
  "detection_id": "det-7f2a18b9-4c12-4a0b-9d41-3b7c8e9f01a2",
  "rule_id": "RULE_MIMIKATZ_CRED_DUMP_001",
  "rule_name": "Mimikatz LSASS Credential Dumping Activity",
  "rule_version": "1.2.0",
  "severity": "CRITICAL",
  "confidence": 98,
  "event_type": "PROCESS_EXECUTION",
  "device_id": "DEV-FINANCE-01",
  "source_ip": "192.168.1.100",
  "mitre_techniques": [
    "T1003.001 - OS Credential Dumping: LSASS Memory"
  ],
  "detected_at": "2026-09-15T16:45:00.000Z",
  "evidence": {
    "triggeringEventId": "evt-884920-abc",
    "eventType": "PROCESS_EXECUTION",
    "deviceId": "DEV-FINANCE-01",
    "sourceIp": "192.168.1.100",
    "processName": "mimikatz.exe",
    "commandLine": "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
    "user": "attacker",
    "matchedAt": "2026-09-15T16:45:00.000Z"
  },
  "related_events": [
    {
      "event_id": "evt-884920-abc",
      "timestamp": "2026-09-15T16:45:00.000Z",
      "event_type": "PROCESS_EXECUTION",
      "summary": "mimikatz.exe \"sekurlsa::logonpasswords\" exit"
    }
  ],
  "recommended_investigation": [
    "1. Immediately isolate endpoint from the enterprise network.",
    "2. Force enterprise-wide credential resets for accounts active on this workstation.",
    "3. Inspect memory dump locations and purge artifacts from disk."
  ],
  "incident_id": "inc-1789491000"
}
```

---

## 5. Built-in Detection Rules Catalog

| Rule ID | Type | Severity | Confidence | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE_MIMIKATZ_CRED_DUMP_001` | `SINGLE_EVENT` | `CRITICAL` | 98% | `T1003.001` | LSASS memory credential dumping. |
| `RULE_OBFUSCATED_POWERSHELL_002` | `SINGLE_EVENT` | `HIGH` | 90% | `T1059.001` | Encoded, hidden, or bypass PowerShell execution. |
| `RULE_SHADOW_COPY_DELETION_003` | `SINGLE_EVENT` | `CRITICAL` | 99% | `T1490` | Volume shadow copy deletion snapshot destruction. |
| `RULE_SQLI_SUCCESS_004` | `SINGLE_EVENT` | `CRITICAL` | 95% | `T1190` | Web application SQL injection returning HTTP 200. |
| `RULE_BRUTE_FORCE_005` | `THRESHOLD` | `HIGH` | 90% | `T1110.001` | 5+ failed logins from same source IP in 2 minutes. |
| `RULE_PORT_SCAN_006` | `THRESHOLD` | `MEDIUM` | 85% | `T1046` | 8+ port probes from same source IP in 1 minute. |
| `RULE_RANSOMWARE_BURST_007` | `THRESHOLD` | `CRITICAL` | 96% | `T1486` | 10+ rapid file modifications in 30 seconds on host. |
| `RULE_KILL_CHAIN_SEQUENCE_008` | `SEQUENCE` | `CRITICAL` | 99% | `T1190, T1059, T1490` | Multi-stage kill chain: Exploit $\rightarrow$ Script $\rightarrow$ Recovery inhibition. |
| `RULE_ACCOUNT_TAKEOVER_SEQUENCE_009` | `SEQUENCE` | `HIGH` | 92% | `T1110, T1078, T1098` | Failed logins $\rightarrow$ Successful login $\rightarrow$ Privilege change. |
| `RULE_C2_PROCESS_CORRELATION_010` | `CORRELATION` | `CRITICAL` | 98% | `T1059.001, T1071.001` | Suspicious process execution correlated with outbound C2 socket. |

---

## 6. How to Register a Custom Detection Rule

```javascript
const { ruleRegistry, RuleTypes } = require('./services/detection/ruleRegistry');

ruleRegistry.registerRule({
  id: 'RULE_CUSTOM_DNS_TUNNELING_011',
  name: 'DNS Tunneling / Data Exfiltration Probe',
  description: 'Detects high-frequency anomalous DNS queries with high entropy subdomains.',
  version: '1.0.0',
  type: RuleTypes.THRESHOLD,
  severity: 'HIGH',
  confidence: 88,
  threshold: 20,
  timeWindowMs: 60 * 1000,
  groupBy: ['device_id'],
  mitreTechniques: ['T1071.004 - DNS Exfiltration'],
  match: (event) => {
    return event.network?.protocol === 'DNS' && (event.network?.domain || '').length > 50;
  },
  recommendedInvestigation: [
    '1. Inspect DNS query logs for Base64/Base32 encoded subdomains.',
    '2. Sinkhole external destination nameserver IP.',
    '3. Check local endpoint DNS resolution cache.'
  ],
});
```

---

## 7. Automated Test Verification

The test suite in [`backend/test_modular_detection_engine.js`](file:///c:/Users/Ayush/OneDrive/Desktop/Cyber-Sentinel--main/backend/test_modular_detection_engine.js) executes 13 automated verification scenarios:

```bash
npm run test:detection
```

- `[SINGLE-EVENT]`: Evaluates Mimikatz, PowerShell, Shadow Copy, and Web SQLi detections.
- `[THRESHOLD]`: Evaluates Brute Force (5x), Port Scan (8x), and Ransomware Burst (10x).
- `[SEQUENCE]`: Evaluates Multi-Stage Kill Chain and out-of-order sequence prevention.
- `[CORRELATION]`: Evaluates Process + C2 Socket cross-source correlation.
- `[TIME-WINDOW]`: Evaluates sliding window event pruning and expiration.
- `[RULE-TOGGLE]`: Evaluates enable/disable rule lifecycle behavior.
- `[DETECTION-PAYLOAD]`: Evaluates complete detection payload structure and automated incident creation.
