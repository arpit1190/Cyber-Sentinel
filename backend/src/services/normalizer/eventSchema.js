/**
 * eventSchema.js
 * Canonical Cybersecurity Event Schema Definition & Constants.
 * 
 * Defines standard SOC fields, enums, type constraints, and size boundaries
 * for unified telemetry ingestion across Cyber Sentinel.
 */

const EventTypes = Object.freeze({
  AUTH_FAILURE: 'AUTH_FAILURE',
  AUTH_SUCCESS: 'AUTH_SUCCESS',
  NETWORK_CONNECTION: 'NETWORK_CONNECTION',
  PROCESS_EXECUTION: 'PROCESS_EXECUTION',
  FILE_MODIFICATION: 'FILE_MODIFICATION',
  IOC_MATCH: 'IOC_MATCH',
  EXPLOIT_PROBE: 'EXPLOIT_PROBE',
  PORT_SCAN: 'PORT_SCAN',
  SYSTEM_ANOMALY: 'SYSTEM_ANOMALY',
  PRIVILEGE_ESCALATION: 'PRIVILEGE_ESCALATION',
  PERSISTENCE: 'PERSISTENCE',
  LATERAL_MOVEMENT: 'LATERAL_MOVEMENT',
  DEFENSE_EVASION: 'DEFENSE_EVASION',
});

const SeverityLevels = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFORMATIONAL: 'INFORMATIONAL',
});

const NetworkProtocols = Object.freeze({
  TCP: 'TCP',
  UDP: 'UDP',
  ICMP: 'ICMP',
  HTTP: 'HTTP',
  HTTPS: 'HTTPS',
  DNS: 'DNS',
  SSH: 'SSH',
  SMB: 'SMB',
  RDP: 'RDP',
  TLS: 'TLS',
  UNKNOWN: 'UNKNOWN',
});

const NetworkDirections = Object.freeze({
  INBOUND: 'INBOUND',
  OUTBOUND: 'OUTBOUND',
  INTERNAL: 'INTERNAL',
  UNKNOWN: 'UNKNOWN',
});

const FileActions = Object.freeze({
  CREATED: 'CREATED',
  MODIFIED: 'MODIFIED',
  DELETED: 'DELETED',
  ACCESSED: 'ACCESSED',
  RENAMED: 'RENAMED',
  COPIED: 'COPIED',
  PERMISSION_CHANGED: 'PERMISSION_CHANGED',
  UNKNOWN: 'UNKNOWN',
});

const SchemaLimits = Object.freeze({
  MAX_EVENT_ID_LEN: 64,
  MAX_DEVICE_ID_LEN: 128,
  MAX_SOURCE_LEN: 128,
  MAX_NAME_LEN: 256,
  MAX_PATH_LEN: 1024,
  MAX_CMDLINE_LEN: 1024 * 1024, // Up to 1MB command lines without truncation
  MAX_HASH_LEN: 128,
  MAX_USER_LEN: 128,
  MAX_DOMAIN_LEN: 253,
  MAX_NESTING_DEPTH: 4,
  MAX_CUSTOM_KEYS: 50,
  MAX_CUSTOM_SIZE_BYTES: 32 * 1024, // 32 KB for custom metadata
  MAX_TAGS_COUNT: 20,
  MAX_TAG_LEN: 64,
});

module.exports = {
  EventTypes,
  SeverityLevels,
  NetworkProtocols,
  NetworkDirections,
  FileActions,
  SchemaLimits,
};
