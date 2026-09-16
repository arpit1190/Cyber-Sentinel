/**
 * auditLogger.js
 * Standardized security audit logger recording every critical event
 * into the persistent SecurityStore with actor, action, target, result, IP, and details.
 */
const { addAuditLog, getAuditLogs } = require('../data/securityStore');
const { sanitizeAuditDetails } = require('./privacyMinimizer');

const AuditActions = {
  LOGIN: 'LOGIN',
  LOGIN_FAILED: 'LOGIN_FAILED',
  MFA_SUCCESS: 'MFA_SUCCESS',
  MFA_FAILED: 'MFA_FAILED',
  LOGOUT: 'LOGOUT',
  PASSWORD_CHANGED: 'PASSWORD_CHANGED',
  PASSWORD_RESET_REQUESTED: 'PASSWORD_RESET_REQUESTED',
  SCAN_STARTED: 'SCAN_STARTED',
  SCAN_COMPLETED: 'SCAN_COMPLETED',
  IP_BLOCKED: 'IP_BLOCKED',
  IP_UNBLOCKED: 'IP_UNBLOCKED',
  INCIDENT_CREATED: 'INCIDENT_CREATED',
  INCIDENT_STATUS_CHANGE: 'INCIDENT_STATUS_CHANGE',
  ANALYST_NOTE_ADDED: 'ANALYST_NOTE_ADDED',
  AI_ACTION_REQUESTED: 'AI_ACTION_REQUESTED',
  AI_ACTION_APPROVED: 'AI_ACTION_APPROVED',
  AI_ACTION_REJECTED: 'AI_ACTION_REJECTED',
};

function logSecurityEvent({ actor, actorRole, action, target, result = 'SUCCESS', req, details = {} }) {
  const sourceIp = req?.ip || req?.headers?.['x-forwarded-for'] || req?.socket?.remoteAddress || '127.0.0.1';
  const cleanIp = typeof sourceIp === 'string' ? sourceIp.split(',')[0].trim() : '127.0.0.1';

  return addAuditLog({
    actor: actor || req?.user?.email || 'anonymous',
    actorRole: actorRole || req?.user?.role || 'unauthenticated',
    action,
    target: String(target || 'SYSTEM'),
    result,
    sourceIp: cleanIp,
    details: sanitizeAuditDetails(details),
  });
}

module.exports = {
  AuditActions,
  logSecurityEvent,
  getAuditLogs,
};
