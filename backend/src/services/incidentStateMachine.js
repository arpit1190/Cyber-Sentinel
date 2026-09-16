/**
 * incidentStateMachine.js
 * Formal SOC Incident Lifecycle State Machine (NIST SP 800-61 / SANS IR Lifecycle).
 * 
 * Canonical Incident States:
 * - NEW
 * - TRIAGED
 * - INVESTIGATING
 * - CONTAINMENT
 * - ERADICATION
 * - RECOVERY
 * - RESOLVED
 * - CLOSED
 * 
 * Enforces strict, server-side state transitions and prevents arbitrary status tampering.
 */

const IncidentStatus = Object.freeze({
  NEW: 'NEW',
  TRIAGED: 'TRIAGED',
  INVESTIGATING: 'INVESTIGATING',
  CONTAINMENT: 'CONTAINMENT',
  ERADICATION: 'ERADICATION',
  RECOVERY: 'RECOVERY',
  RESOLVED: 'RESOLVED',
  CLOSED: 'CLOSED',
});

// Normalize legacy alias states (e.g. CONTAINED -> CONTAINMENT)
const STATUS_ALIASES = Object.freeze({
  CONTAINED: IncidentStatus.CONTAINMENT,
  FALSE_POSITIVE: IncidentStatus.CLOSED,
});

/**
 * Allowed State Transition Graph based on NIST SP 800-61 Computer Security Incident Handling Guide:
 * 
 * NEW -> TRIAGED, CLOSED
 * TRIAGED -> INVESTIGATING, CLOSED
 * INVESTIGATING -> CONTAINMENT, TRIAGED, CLOSED
 * CONTAINMENT -> ERADICATION, INVESTIGATING
 * ERADICATION -> RECOVERY, CONTAINMENT, INVESTIGATING
 * RECOVERY -> RESOLVED, INVESTIGATING
 * RESOLVED -> CLOSED, INVESTIGATING (re-opened)
 * CLOSED -> INVESTIGATING (re-opened upon recurrence or new evidence)
 */
const ALLOWED_TRANSITIONS = Object.freeze({
  [IncidentStatus.NEW]: Object.freeze([
    IncidentStatus.TRIAGED,
    IncidentStatus.CLOSED,
  ]),
  [IncidentStatus.TRIAGED]: Object.freeze([
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CLOSED,
  ]),
  [IncidentStatus.INVESTIGATING]: Object.freeze([
    IncidentStatus.CONTAINMENT,
    IncidentStatus.TRIAGED,
    IncidentStatus.CLOSED,
  ]),
  [IncidentStatus.CONTAINMENT]: Object.freeze([
    IncidentStatus.ERADICATION,
    IncidentStatus.INVESTIGATING,
  ]),
  [IncidentStatus.ERADICATION]: Object.freeze([
    IncidentStatus.RECOVERY,
    IncidentStatus.CONTAINMENT,
    IncidentStatus.INVESTIGATING,
  ]),
  [IncidentStatus.RECOVERY]: Object.freeze([
    IncidentStatus.RESOLVED,
    IncidentStatus.INVESTIGATING,
  ]),
  [IncidentStatus.RESOLVED]: Object.freeze([
    IncidentStatus.CLOSED,
    IncidentStatus.INVESTIGATING,
  ]),
  [IncidentStatus.CLOSED]: Object.freeze([
    IncidentStatus.INVESTIGATING,
  ]),
});

/**
 * Normalizes any incoming status string to canonical form.
 */
function normalizeStatus(status) {
  if (!status || typeof status !== 'string') return null;
  const upper = status.trim().toUpperCase();
  if (STATUS_ALIASES[upper]) return STATUS_ALIASES[upper];
  if (Object.values(IncidentStatus).includes(upper)) return upper;
  return null;
}

/**
 * Validates whether a state transition from currentStatus to targetStatus is permitted.
 * 
 * @param {string} currentStatus 
 * @param {string} targetStatus 
 * @returns {{ valid: boolean, error?: string, from: string, to: string }}
 */
function validateStateTransition(currentStatus, targetStatus) {
  const from = normalizeStatus(currentStatus);
  const to = normalizeStatus(targetStatus);

  if (!from) {
    return {
      valid: false,
      error: `Invalid current incident status '${currentStatus}'. Must be one of: ${Object.values(IncidentStatus).join(', ')}`,
      from: currentStatus,
      to: targetStatus,
    };
  }

  if (!to) {
    return {
      valid: false,
      error: `Invalid target incident status '${targetStatus}'. Must be one of: ${Object.values(IncidentStatus).join(', ')}`,
      from,
      to: targetStatus,
    };
  }

  if (from === to) {
    return {
      valid: false,
      error: `Incident is already in status '${from}'.`,
      from,
      to,
    };
  }

  const allowedNextStates = ALLOWED_TRANSITIONS[from] || [];
  if (!allowedNextStates.includes(to)) {
    return {
      valid: false,
      error: `Illegal state transition from '${from}' to '${to}'. Allowed next states from '${from}' are: ${allowedNextStates.join(', ') || 'None'}.`,
      from,
      to,
      allowedNextStates,
    };
  }

  return { valid: true, from, to };
}

module.exports = {
  IncidentStatus,
  ALLOWED_TRANSITIONS,
  normalizeStatus,
  validateStateTransition,
};
