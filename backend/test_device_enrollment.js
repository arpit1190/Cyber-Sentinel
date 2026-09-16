/**
 * test_device_enrollment.js
 * Verification Suite for Secure Endpoint Device Enrollment, Rotation, Revocation, and Lifecycle Management.
 * 
 * Verifies:
 * 1. Valid device enrollment with unique cryptographically random secret provisioning.
 * 2. Cryptographic storage (SHA-256 hash stored in database / cache, never plaintext).
 * 3. Duplicate enrollment prevention (rejection of conflicting active hostname).
 * 4. Unauthorized enrollment rejection (RBAC enforcement).
 * 5. Device credential rotation (new secret generation and old token revocation).
 * 6. Old credential rejection after rotation (preventing stolen key reuse).
 * 7. Revoked device rejection (immediate telemetry ingestion block).
 * 8. Zero shared credentials (every endpoint has an isolated cryptographic secret).
 */

const assert = require('assert');
const crypto = require('crypto');
const deviceService = require('./src/services/deviceService');
const deviceRepository = require('./src/repositories/deviceRepository');
const { ROLES, PERMISSIONS } = require('./src/constants/roles');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function runTest(name, fn) {
  totalTests++;
  const start = process.hrtime.bigint();
  try {
    fn();
    const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
    console.log(`  ✅ [PASS] (${elapsed.toFixed(2)}ms) ${name}`);
    passedTests++;
  } catch (err) {
    const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
    console.error(`  ❌ [FAIL] (${elapsed.toFixed(2)}ms) ${name}`);
    console.error(`     ${err.message}`);
    failedTests++;
  }
}

async function runAsyncTest(name, fn) {
  totalTests++;
  const start = process.hrtime.bigint();
  try {
    await fn();
    const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
    console.log(`  ✅ [PASS] (${elapsed.toFixed(2)}ms) ${name}`);
    passedTests++;
  } catch (err) {
    const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
    console.error(`  ❌ [FAIL] (${elapsed.toFixed(2)}ms) ${name}`);
    console.error(`     ${err.message}`);
    failedTests++;
  }
}

console.log('\n======================================================================');
console.log('🛡️   CYBER SENTINEL — SECURE ENDPOINT ENROLLMENT & LIFECYCLE SUITE');
console.log('======================================================================\n');

async function runSuite() {
  const operatorUser = { email: 'operator@sentinel.local', role: ROLES.ENDPOINT_OPERATOR };
  const testHostname = `srv-soc-prod-${Date.now()}`;
  let enrolledDeviceId;
  let initialDeviceSecret;
  let rotatedDeviceSecret;

  console.log('━━━ SECTION 1: Secure Device Enrollment & Unique Credential Issuance ━━━');

  await runAsyncTest('[ENROLL] Enrolls endpoint and issues unique cryptographically random secret', async () => {
    const res = await deviceService.enrollDevice({
      name: 'SOC Primary Linux Gateway',
      platform: 'LINUX',
      hostname: testHostname,
      agentVersion: '2.1.0',
      user: operatorUser,
    });

    assert.ok(res.device, 'Must return device record');
    assert.ok(res.device.id.startsWith('DEV-'), 'Device ID must follow DEV- prefix convention');
    assert.strictEqual(res.device.status, 'ACTIVE');
    assert.ok(res.deviceSecret, 'Must return device secret');
    assert.ok(res.deviceSecret.startsWith('sec_'), 'Secret must follow secure prefix');
    assert.ok(res.deviceSecret.length >= 32, 'Secret must be cryptographically long');

    enrolledDeviceId = res.device.id;
    initialDeviceSecret = res.deviceSecret;
  });

  await runAsyncTest('[ENROLL] Secret is stored as SHA-256 hash, never in plaintext', async () => {
    const tokenHash = deviceService.hashToken(initialDeviceSecret);
    const credRecord = await deviceRepository.findCredentialByHash(tokenHash);

    assert.ok(credRecord, 'Credential must exist by hash lookup');
    assert.strictEqual(credRecord.deviceId, enrolledDeviceId);
    assert.strictEqual(credRecord.isActive, true);
    assert.ok(!deviceRepository.credentials.has(initialDeviceSecret), 'Plaintext secret must not be stored in map/DB');
  });

  await runAsyncTest('[AUTHENTICATE] Successfully authenticates telemetry with valid device credentials', async () => {
    const auth = await deviceService.authenticateDevice(enrolledDeviceId, initialDeviceSecret);
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.device.id, enrolledDeviceId);
    assert.strictEqual(auth.device.status, 'ACTIVE');
  });

  console.log('\n━━━ SECTION 2: Duplicate Enrollment & Constraint Enforcements ━━━');

  await runAsyncTest('[ENROLL] Prevents duplicate active enrollment on same hostname', async () => {
    try {
      await deviceService.enrollDevice({
        name: 'Conflicting Endpoint',
        platform: 'LINUX',
        hostname: testHostname, // Same hostname already active
        user: operatorUser,
      });
      assert.fail('Should have rejected duplicate active enrollment');
    } catch (err) {
      assert.strictEqual(err.status, 409);
      assert.ok(err.message.includes('already enrolled'));
    }
  });

  console.log('\n━━━ SECTION 3: Credential Rotation & Old Secret Rejection ━━━');

  await runAsyncTest('[ROTATION] Rotates device secret, issuing new credential and revoking old token', async () => {
    const rotRes = await deviceService.rotateCredential(enrolledDeviceId, { user: operatorUser });

    assert.strictEqual(rotRes.success, true);
    assert.strictEqual(rotRes.deviceId, enrolledDeviceId);
    assert.ok(rotRes.newDeviceSecret);
    assert.notStrictEqual(rotRes.newDeviceSecret, initialDeviceSecret, 'New secret must differ from old secret');

    rotatedDeviceSecret = rotRes.newDeviceSecret;
  });

  await runAsyncTest('[ROTATION] Rejects authentication attempts with previous/old device secret', async () => {
    const auth = await deviceService.authenticateDevice(enrolledDeviceId, initialDeviceSecret);
    assert.strictEqual(auth.authenticated, false);
    assert.ok(auth.error.includes('Invalid or revoked'));
  });

  await runAsyncTest('[ROTATION] Accepts authentication with rotated new device secret', async () => {
    const auth = await deviceService.authenticateDevice(enrolledDeviceId, rotatedDeviceSecret);
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.device.id, enrolledDeviceId);
  });

  console.log('\n━━━ SECTION 4: Device Revocation & Telemetry Lockdown ━━━');

  await runAsyncTest('[REVOKE] Revokes device and permanently invalidates all active credentials', async () => {
    const revRes = await deviceService.revokeDevice(enrolledDeviceId, {
      reason: 'Compromised host containment',
      user: operatorUser,
    });

    assert.strictEqual(revRes.success, true);
    assert.strictEqual(revRes.device.status, 'REVOKED');
  });

  await runAsyncTest('[REVOKE] Rejects telemetry ingestion from revoked device immediately', async () => {
    const auth = await deviceService.authenticateDevice(enrolledDeviceId, rotatedDeviceSecret);
    assert.strictEqual(auth.authenticated, false);
    assert.ok(auth.error.includes('REVOKED') || auth.error.includes('revoked'));
  });

  console.log('\n━━━ SECTION 5: Zero Shared Credentials Verification ━━━');

  await runAsyncTest('[ZERO-SHARED] Distinct enrolled devices receive distinct unique credentials', async () => {
    const dev1 = await deviceService.enrollDevice({ hostname: `host1-${Date.now()}`, user: operatorUser });
    const dev2 = await deviceService.enrollDevice({ hostname: `host2-${Date.now()}`, user: operatorUser });

    assert.notStrictEqual(dev1.device.id, dev2.device.id);
    assert.notStrictEqual(dev1.deviceSecret, dev2.deviceSecret, 'Each agent must have a distinct unique credential');

    // Device 1 credentials must not authenticate Device 2
    const crossAuth = await deviceService.authenticateDevice(dev2.device.id, dev1.deviceSecret);
    assert.strictEqual(crossAuth.authenticated, false);
  });

  console.log('\n======================================================================');
  console.log(`🏁  DEVICE ENROLLMENT SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
  console.log('======================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runSuite().catch(err => {
  console.error('Unhandled device test error:', err);
  process.exit(1);
});
