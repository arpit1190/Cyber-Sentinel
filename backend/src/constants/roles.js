/**
 * roles.js
 * Canonical RBAC Role Definitions & Permission Mappings.
 * 
 * Standardized roles:
 * - ADMIN: Super Administrator with unrestricted access to all capabilities.
 * - SOC_ANALYST: Incident triage, investigations, evidence notes, status transitions, threat analysis.
 * - SECURITY_ENGINEER: SIEM detection rule creation/tuning, threat intelligence ingestion, malware analysis.
 * - ENDPOINT_OPERATOR: Device fleet management, containment isolation, response action execution.
 * - VIEWER: Read-only observer across telemetry and dashboards with zero mutation capabilities.
 */

const ROLES = {
  ADMIN: 'ADMIN',
  SOC_ANALYST: 'SOC_ANALYST',
  SECURITY_ENGINEER: 'SECURITY_ENGINEER',
  ENDPOINT_OPERATOR: 'ENDPOINT_OPERATOR',
  VIEWER: 'VIEWER',
};

// Granular permission codes
const PERMISSIONS = {
  // Users & Identity
  USERS_READ: 'users:read',
  USERS_WRITE: 'users:write',
  USERS_DELETE: 'users:delete',
  
  // Devices & Endpoints
  DEVICES_READ: 'devices:read',
  DEVICES_WRITE: 'devices:write',
  DEVICES_DELETE: 'devices:delete',
  DEVICES_ISOLATE: 'devices:isolate',

  // Telemetry & Event Streams
  TELEMETRY_READ: 'telemetry:read',
  TELEMETRY_WRITE: 'telemetry:write',
  TELEMETRY_INGEST: 'telemetry:ingest',

  // Detections & Alerts
  DETECTIONS_READ: 'detections:read',
  DETECTIONS_WRITE: 'detections:write',

  // Incident Lifecycle & Evidence
  INCIDENTS_READ: 'incidents:read',
  INCIDENTS_WRITE: 'incidents:write',
  INCIDENTS_STATUS: 'incidents:status',
  INCIDENTS_NOTE: 'incidents:note',
  INCIDENTS_CLOSE: 'incidents:close',

  // Threat Intelligence
  THREATS_READ: 'threats:read',
  THREATS_WRITE: 'threats:write',

  // Malware Analysis
  MALWARE_READ: 'malware:read',
  MALWARE_ANALYZE: 'malware:analyze',

  // Detection & Correlation Rules
  RULES_READ: 'rules:read',
  RULES_WRITE: 'rules:write',
  RULES_DELETE: 'rules:delete',

  // Response Actions & Containment
  RESPONSE_EXECUTE: 'response:execute',
  RESPONSE_APPROVE: 'response:approve',

  // Audit Logs
  AUDIT_READ: 'audit:read',

  // System Administration & Infrastructure
  SYSTEM_READ: 'system:read',
  SYSTEM_WRITE: 'system:write',

  // AI Copilot
  AI_CHAT: 'ai:chat',
};

const ALL_VALID_PERMISSIONS = new Set(Object.values(PERMISSIONS));
const VALID_ROLES = new Set(Object.values(ROLES));

// Role-to-Permissions Mapping (Deny by default)
const ROLE_PERMISSIONS = {
  [ROLES.ADMIN]: Object.values(PERMISSIONS),

  [ROLES.SOC_ANALYST]: [
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.INCIDENTS_WRITE,
    PERMISSIONS.INCIDENTS_STATUS,
    PERMISSIONS.INCIDENTS_NOTE,
    PERMISSIONS.INCIDENTS_CLOSE,
    PERMISSIONS.DETECTIONS_READ,
    PERMISSIONS.DETECTIONS_WRITE,
    PERMISSIONS.TELEMETRY_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.THREATS_READ,
    PERMISSIONS.MALWARE_READ,
    PERMISSIONS.MALWARE_ANALYZE,
    PERMISSIONS.RULES_READ,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.RESPONSE_APPROVE,
    PERMISSIONS.AI_CHAT,
    PERMISSIONS.TELEMETRY_INGEST,
  ],

  [ROLES.SECURITY_ENGINEER]: [
    PERMISSIONS.RULES_READ,
    PERMISSIONS.RULES_WRITE,
    PERMISSIONS.RULES_DELETE,
    PERMISSIONS.THREATS_READ,
    PERMISSIONS.THREATS_WRITE,
    PERMISSIONS.MALWARE_READ,
    PERMISSIONS.MALWARE_ANALYZE,
    PERMISSIONS.DETECTIONS_READ,
    PERMISSIONS.DETECTIONS_WRITE,
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.TELEMETRY_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.AI_CHAT,
  ],

  [ROLES.ENDPOINT_OPERATOR]: [
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.DEVICES_WRITE,
    PERMISSIONS.DEVICES_DELETE,
    PERMISSIONS.DEVICES_ISOLATE,
    PERMISSIONS.RESPONSE_EXECUTE,
    PERMISSIONS.TELEMETRY_READ,
    PERMISSIONS.TELEMETRY_WRITE,
    PERMISSIONS.TELEMETRY_INGEST,
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.INCIDENTS_NOTE,
    PERMISSIONS.MALWARE_READ,
    PERMISSIONS.MALWARE_ANALYZE,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.AI_CHAT,
  ],

  [ROLES.VIEWER]: [
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.DETECTIONS_READ,
    PERMISSIONS.THREATS_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.TELEMETRY_READ,
    PERMISSIONS.AUDIT_READ,
  ],
};

/**
 * Normalizes any legacy or arbitrary case role string to canonical uppercase format.
 */
function normalizeRole(role, fallback = ROLES.SOC_ANALYST) {
  if (!role || typeof role !== 'string') return fallback;
  const upper = role.trim().toUpperCase();

  if (upper === 'ADMIN' || upper === 'ADMINISTRATOR') return ROLES.ADMIN;
  if (upper === 'SOC_ANALYST' || upper === 'SENIOR_ANALYST' || upper === 'ANALYST' || upper === 'OPERATOR') return ROLES.SOC_ANALYST;
  if (upper === 'SECURITY_ENGINEER' || upper === 'SECENG' || upper === 'ENGINEER') return ROLES.SECURITY_ENGINEER;
  if (upper === 'ENDPOINT_OPERATOR' || upper === 'ENDPOINT_ADMIN' || upper === 'DEVICE_ADMIN') return ROLES.ENDPOINT_OPERATOR;
  if (upper === 'VIEWER' || upper === 'READONLY' || upper === 'AUDITOR') return ROLES.VIEWER;

  // Preserve unrecognized role for strict authorization evaluation
  return upper;
}

/**
 * Checks if a given role possesses a specific permission.
 * Denies access by default if permission or role is unrecognized.
 */
function hasPermission(role, permission) {
  if (!role || !permission || !ALL_VALID_PERMISSIONS.has(permission)) {
    return false;
  }
  const normRole = normalizeRole(role, null);
  if (!normRole || !VALID_ROLES.has(normRole)) {
    return false;
  }
  if (normRole === ROLES.ADMIN) return true;
  const perms = ROLE_PERMISSIONS[normRole];
  if (!perms || !Array.isArray(perms)) return false;
  return perms.includes(permission);
}

module.exports = {
  ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  ALL_VALID_PERMISSIONS,
  VALID_ROLES,
  normalizeRole,
  hasPermission,
};
