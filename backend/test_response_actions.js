/**
 * test_response_actions.js
 * Adversarial Test Suite for the Secure Response-Action Framework, RBAC & Idempotency.
 */

'use strict';

const assert = require('assert');
const {
  ALLOWED_ACTION_TYPES,
  ACTION_STATUSES,
  requestResponseAction,
  approveResponseAction,
  rejectResponseAction,
  executeResponseAction,
  getResponseAction,
} = require('./src/services/response/responseActionService');

console.log('🧪 Starting Secure Response-Action Framework Test Suite...\n');

let passedTests = 0;
let totalTests = 0;

async function test(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`  ✅ PASS: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ FAIL: ${name}`);
    console.error(`     Error: ${err.message}\n`);
  }
}

(async () => {
  // ── 1. Allowlisted Action Type & Shell Injection Rejection ──
  await test('Requests valid allowlisted action (ISOLATE_ENDPOINT) in PENDING state', () => {
    const action = requestResponseAction({
      incidentId: 'INC-2026-0001',
      deviceId: 'DEV-SRV-01',
      actionType: ALLOWED_ACTION_TYPES.ISOLATE_ENDPOINT,
      parameters: { ip: '10.0.0.99', deviceId: 'DEV-SRV-01' },
      requesterUser: { email: 'analyst@sentinel.internal', role: 'SOC_ANALYST' },
    });

    assert.ok(action.actionId.startsWith('ACT-'));
    assert.strictEqual(action.status, ACTION_STATUSES.PENDING);
    assert.strictEqual(action.actionType, 'ISOLATE_ENDPOINT');
    assert.strictEqual(action.approver, null);
  });

  await test('Rejects unallowlisted arbitrary action types (EXECUTE_SHELL_CMD)', () => {
    assert.throws(
      () => {
        requestResponseAction({
          actionType: 'EXECUTE_SHELL_CMD',
          parameters: { cmd: 'rm -rf /' },
          requesterUser: { email: 'hacker@evil.com' },
        });
      },
      /Invalid action type/
    );
  });

  await test('Rejects parameters containing dangerous shell injection characters', () => {
    assert.throws(
      () => {
        requestResponseAction({
          actionType: ALLOWED_ACTION_TYPES.TERMINATE_SUSPICIOUS_PROCESS,
          parameters: { processName: 'notepad.exe; whoami' },
          requesterUser: { email: 'analyst@sentinel.internal' },
        });
      },
      /Security Exception: Dangerous character sequence detected/
    );
  });

  // ── 2. Idempotency Guarantees ──
  await test('Returns existing action record when replayed with same idempotency key', () => {
    const idemKey = `test-idem-${Date.now()}`;

    const action1 = requestResponseAction({
      actionType: ALLOWED_ACTION_TYPES.REVOKE_DEVICE_CREDENTIAL,
      parameters: { deviceId: 'DEV-COMPROMISED-01' },
      requesterUser: { email: 'analyst@sentinel.internal' },
      idempotencyKey: idemKey,
    });

    const action2 = requestResponseAction({
      actionType: ALLOWED_ACTION_TYPES.REVOKE_DEVICE_CREDENTIAL,
      parameters: { deviceId: 'DEV-COMPROMISED-01' },
      requesterUser: { email: 'analyst@sentinel.internal' },
      idempotencyKey: idemKey,
    });

    assert.strictEqual(action1.actionId, action2.actionId);
  });

  // ── 3. Human Approval Enforcement ──
  await test('Rejects execution attempt on PENDING action without operator approval', async () => {
    const action = requestResponseAction({
      actionType: ALLOWED_ACTION_TYPES.TERMINATE_SUSPICIOUS_PROCESS,
      parameters: { pid: 4444, processName: 'malicious.exe' },
      requesterUser: { email: 'ai_copilot@sentinel.internal' },
    });

    await assert.rejects(
      async () => {
        await executeResponseAction(action.actionId, { email: 'ai_copilot@sentinel.internal' });
      },
      /Human Authorization Exception/
    );
  });

  // ── 4. Full Authorized Execution Lifecycle ──
  await test('Executes response action following explicit operator approval (PENDING -> APPROVED -> EXECUTING -> SUCCESS)', async () => {
    const action = requestResponseAction({
      actionType: ALLOWED_ACTION_TYPES.QUARANTINE_FILE,
      parameters: { filePath: 'C:\\Users\\Victim\\payload.bin', sha256: 'abc123456789' },
      requesterUser: { email: 'analyst@sentinel.internal' },
    });

    // 1. Approve
    const approved = approveResponseAction(action.actionId, { email: 'lead_operator@sentinel.internal', role: 'SOC_ANALYST' });
    assert.strictEqual(approved.status, ACTION_STATUSES.APPROVED);
    assert.strictEqual(approved.approver, 'lead_operator@sentinel.internal');

    // 2. Execute
    const executed = await executeResponseAction(action.actionId, { email: 'lead_operator@sentinel.internal', role: 'SOC_ANALYST' });
    assert.strictEqual(executed.status, ACTION_STATUSES.SUCCESS);
    assert.ok(executed.result !== null);
    assert.strictEqual(executed.result.quarantined, true);
  });

  // ── 5. Action Rejection ──
  await test('Transitions response action to REJECTED when operator denies action', () => {
    const action = requestResponseAction({
      actionType: ALLOWED_ACTION_TYPES.ISOLATE_ENDPOINT,
      parameters: { ip: '10.0.0.12' },
      requesterUser: { email: 'analyst@sentinel.internal' },
    });

    const rejected = rejectResponseAction(action.actionId, { email: 'admin@sentinel.internal' }, 'Device belongs to CEO, verify first');
    assert.strictEqual(rejected.status, ACTION_STATUSES.REJECTED);
    assert.strictEqual(rejected.result.rejected, true);
  });

  console.log(`\n📊 Response Action Framework Test Results: ${passedTests}/${totalTests} Passed\n`);
  if (passedTests !== totalTests) {
    process.exit(1);
  }
})();
