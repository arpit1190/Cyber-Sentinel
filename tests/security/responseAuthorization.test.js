/**
 * tests/security/responseAuthorization.test.js
 * Security test suite for Response Action Authorization, Allowlist Enforcement,
 * Shell Injection Prevention, and Execution Finite State Machine.
 */

const assert = require('assert');
const path = require('path');

const {
  requestResponseAction,
  approveResponseAction,
  rejectResponseAction,
  executeResponseAction,
  ALLOWED_ACTION_TYPES,
  ACTION_STATUSES,
} = require(path.join(__dirname, '../../backend/src/services/response/responseActionService'));

async function runResponseAuthorizationSecurityTests() {
  console.log('\n--- [Security] Response Action Authorization & FSM Gating ---');
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  // 1. Allowlist Enforcement
  await test('Accepts allowlisted action type (ISOLATE_ENDPOINT) in PENDING state', async () => {
    const action = requestResponseAction({
      incidentId: 'INC-SEC-01',
      actionType: ALLOWED_ACTION_TYPES.ISOLATE_ENDPOINT,
      deviceId: 'dev-win-01',
      parameters: { deviceId: 'dev-win-01', ip: '10.0.0.1' },
      requesterUser: { email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' },
    });

    assert.ok(action.actionId);
    assert.strictEqual(action.status, ACTION_STATUSES.PENDING);
    assert.strictEqual(action.actionType, 'ISOLATE_ENDPOINT');
  });

  await test('Rejects unallowlisted arbitrary command action types (e.g., EXEC_SHELL_CMD)', async () => {
    assert.throws(() => {
      requestResponseAction({
        incidentId: 'INC-SEC-02',
        actionType: 'EXEC_SHELL_CMD',
        parameters: { command: 'rm -rf /' },
        requesterUser: { email: 'attacker@evil.com' },
      });
    }, /Invalid action type/i);
  });

  // 2. Parameter Sanitization & Shell Injection Prevention
  await test('Rejects parameters containing dangerous shell metacharacters (;, &, |, `, $, >, <)', async () => {
    assert.throws(() => {
      requestResponseAction({
        incidentId: 'INC-SEC-03',
        actionType: ALLOWED_ACTION_TYPES.TERMINATE_SUSPICIOUS_PROCESS,
        parameters: { pid: '1337; cat /etc/shadow' },
        requesterUser: { email: 'attacker@evil.com' },
      });
    }, /Dangerous character sequence/i);
  });

  // 3. Idempotency Key Handling
  await test('Returns existing action without duplicate execution when replayed with same idempotency key', async () => {
    const idempotencyKey = `idemp-${Date.now()}-${Math.random()}`;
    const first = requestResponseAction({
      incidentId: 'INC-SEC-04',
      actionType: ALLOWED_ACTION_TYPES.REVOKE_DEVICE_CREDENTIAL,
      deviceId: 'dev-mac-02',
      parameters: { deviceId: 'dev-mac-02' },
      requesterUser: { email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' },
      idempotencyKey,
    });

    const second = requestResponseAction({
      incidentId: 'INC-SEC-04',
      actionType: ALLOWED_ACTION_TYPES.REVOKE_DEVICE_CREDENTIAL,
      deviceId: 'dev-mac-02',
      parameters: { deviceId: 'dev-mac-02' },
      requesterUser: { email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' },
      idempotencyKey,
    });

    assert.strictEqual(first.actionId, second.actionId);
  });

  // 4. Execution Gating (Approval Required)
  await test('Rejects execution attempt on PENDING action without operator approval', async () => {
    const action = requestResponseAction({
      incidentId: 'INC-SEC-05',
      actionType: ALLOWED_ACTION_TYPES.QUARANTINE_FILE,
      parameters: { filePath: 'C:\\temp\\trojan.dll' },
      requesterUser: { email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' },
    });

    await assert.rejects(async () => {
      await executeResponseAction(action.actionId, { email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' });
    }, /pending approval/i);
  });

  // 5. Full Lifecycle Execution (PENDING -> APPROVED -> EXECUTING -> SUCCESS)
  await test('Executes approved response action and records execution audit result', async () => {
    const action = requestResponseAction({
      incidentId: 'INC-SEC-06',
      actionType: ALLOWED_ACTION_TYPES.ISOLATE_ENDPOINT,
      deviceId: 'dev-linux-08',
      parameters: { deviceId: 'dev-linux-08' },
      requesterUser: { email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' },
    });

    const approved = approveResponseAction(action.actionId, { email: 'lead-approver@sentinel.defense', role: 'ADMIN' });
    assert.strictEqual(approved.status, ACTION_STATUSES.APPROVED);

    const executed = await executeResponseAction(action.actionId, { email: 'lead-approver@sentinel.defense', role: 'ADMIN' });
    assert.strictEqual(executed.status, ACTION_STATUSES.SUCCESS);
    assert.ok(executed.result);
    assert.ok(executed.timestamps.completedAt);
  });

  return { passed, failed };
}

if (require.main === module) {
  runResponseAuthorizationSecurityTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runResponseAuthorizationSecurityTests };
