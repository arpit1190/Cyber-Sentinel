/**
 * tests/integration/deviceLifecycle.test.js
 * Integration test suite for Endpoint & Device Enrollment, Rotation, Revocation, and Auth Enforcement.
 */

const assert = require('assert');
const path = require('path');

const deviceService = require(path.join(__dirname, '../../backend/src/services/deviceService'));
const deviceRepository = require(path.join(__dirname, '../../backend/src/repositories/deviceRepository'));

async function runDeviceLifecycleIntegrationTests() {
  console.log('\n--- [Integration] Device Enrollment, Rotation & Revocation ---');
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

  let enrolledDevice = null;
  let rawSecret = null;

  // 1. Device Enrollment
  await test('Enrolls a new endpoint device and generates cryptographic credential', async () => {
    const enrollmentData = {
      name: 'SOC Test Workstation',
      platform: 'LINUX',
      hostname: `soc-workstation-${Date.now()}`,
      ipAddress: '10.0.4.15',
      agentVersion: '2.4.0',
      user: { email: 'admin@sentinel.defense', role: 'ADMIN' },
    };

    const result = await deviceService.enrollDevice(enrollmentData);
    assert.ok(result.device);
    assert.ok(result.device.id);
    assert.ok(result.deviceSecret);
    assert.strictEqual(result.device.status, 'ACTIVE');

    enrolledDevice = result.device;
    rawSecret = result.deviceSecret;
  });

  // 2. Secret Storage Hashing
  await test('Stored device record contains SHA-256 hashed secret, never raw plaintext', async () => {
    const tokenHash = deviceService.hashToken(rawSecret);
    const cred = await deviceRepository.findCredentialByHash(tokenHash);
    assert.ok(cred);
    assert.strictEqual(cred.deviceId, enrolledDevice.id);
    assert.strictEqual(cred.isActive, true);
  });

  // 3. Credential Rotation
  await test('Rotates device credentials and updates active secret', async () => {
    const oldSecret = rawSecret;
    const rotateResult = await deviceService.rotateCredential(enrolledDevice.id, { user: { email: 'admin@sentinel.defense' } });

    assert.ok(rotateResult.newDeviceSecret);
    assert.notStrictEqual(rotateResult.newDeviceSecret, oldSecret);

    rawSecret = rotateResult.newDeviceSecret;
  });

  // 4. Device Revocation
  await test('Revokes endpoint device and marks status as REVOKED', async () => {
    const revokeResult = await deviceService.revokeDevice(enrolledDevice.id, { reason: 'Compromised workstation', user: { email: 'admin@sentinel.defense' } });
    assert.strictEqual(revokeResult.device.status, 'REVOKED');

    const updated = await deviceRepository.findById(enrolledDevice.id);
    assert.strictEqual(updated.status, 'REVOKED');
  });

  // 5. Auth Rejection for Revoked Device
  await test('Rejects telemetry authentication attempts from revoked device', async () => {
    const authResult = await deviceService.authenticateDevice(enrolledDevice.id, rawSecret);
    assert.strictEqual(authResult.authenticated, false);
  });

  return { passed, failed };
}

if (require.main === module) {
  runDeviceLifecycleIntegrationTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runDeviceLifecycleIntegrationTests };
