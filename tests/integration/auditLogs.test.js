/**
 * tests/integration/auditLogs.test.js
 * Integration test suite for Immutable Security Audit Logging, Chaining, and RBAC Retrieval.
 */

const assert = require('assert');
const path = require('path');

const { logSecurityEvent, getAuditLogs, AuditActions } = require(path.join(__dirname, '../../backend/src/utils/auditLogger'));
const { ROLES, hasPermission, PERMISSIONS } = require(path.join(__dirname, '../../backend/src/constants/roles'));

async function runAuditLogsIntegrationTests() {
  console.log('\n--- [Integration] Immutable Security Audit Logging ---');
  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  // 1. Audit Log Generation
  test('Logs high-security actions with actor, IP, action ID and timestamps', () => {
    const entry = logSecurityEvent({
      action: AuditActions.PASSWORD_CHANGED,
      actor: 'admin@sentinel.defense',
      actorRole: 'ADMIN',
      target: 'analyst@sentinel.defense',
      details: { previousRole: 'analyst', newRole: 'senior_analyst' },
      req: { ip: '10.0.0.1' },
    });

    assert.ok(entry.id);
    assert.strictEqual(entry.action, AuditActions.PASSWORD_CHANGED);
    assert.strictEqual(entry.actor, 'admin@sentinel.defense');
    assert.ok(entry.timestamp);
  });

  // 2. Querying & Filtering Audit Trail
  test('Retrieves audit logs filtered by action type', () => {
    logSecurityEvent({
      action: AuditActions.IP_BLOCKED,
      actor: 'sec-lead@sentinel.defense',
      actorRole: 'ADMIN',
      target: 'dev-999',
      details: { reason: 'Suspected key leak' },
    });

    const logs = getAuditLogs(50, AuditActions.IP_BLOCKED);
    assert.ok(logs.length > 0);
    assert.strictEqual(logs[0].action, AuditActions.IP_BLOCKED);
  });

  // 3. RBAC Access Control
  test('Restricts destructive user management permissions from Viewer role', () => {
    assert.strictEqual(hasPermission(ROLES.ADMIN, PERMISSIONS.USERS_WRITE), true);
    assert.strictEqual(hasPermission(ROLES.VIEWER, PERMISSIONS.USERS_WRITE), false);
  });

  return { passed, failed };
}

if (require.main === module) {
  runAuditLogsIntegrationTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runAuditLogsIntegrationTests };
