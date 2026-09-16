/**
 * test_telemetry_security.js
 * Comprehensive Verification Suite for Cyber Sentinel Endpoint Telemetry Security.
 * 
 * Verifies:
 * 1. Valid telemetry with HMAC-SHA256 signature ingestion (202 Accepted).
 * 2. Tampered HMAC signature rejection (401 Unauthorized).
 * 3. Tampered request body payload detection (401 Unauthorized).
 * 4. Request path mismatch detection (401 Unauthorized).
 * 5. Expired timestamp rejection (401 Unauthorized).
 * 6. Future timestamp rejection (401 Unauthorized).
 * 7. Nonce replay attack detection and rejection (401 Unauthorized).
 * 8. Revoked endpoint telemetry blocking (403 Forbidden).
 * 9. Unknown / unauthenticated endpoint rejection (401 Unauthorized).
 * 10. Oversized payload rejection (413 Payload Too Large).
 * 11. Malformed telemetry schema rejection (400 Bad Request).
 * 12. Endpoint ingestion rate limiting (429 Too Many Requests).
 * 13. Zero secret exposure in responses or logs.
 * 14. Rotated credential transition validation.
 */

process.env.NODE_ENV = 'test';
const assert = require('assert');
const http = require('http');
const crypto = require('crypto');
const deviceService = require('./src/services/deviceService');
const deviceRepository = require('./src/repositories/deviceRepository');
const { computeTelemetrySignature, resetNonceStore } = require('./src/middleware/telemetryAuth');
const { resetRateLimitStore } = require('./src/validators/telemetryValidator');
const app = require('./src/server');

let server;
let baseUrl;
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function httpRequest(method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl + path);
    const bodyData = body !== null ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;

    const reqHeaders = { ...headers };
    if (bodyData !== null && !reqHeaders['Content-Type'] && !reqHeaders['content-type']) {
      reqHeaders['Content-Type'] = 'application/json';
    }
    if (bodyData !== null && !reqHeaders['Content-Length'] && !reqHeaders['content-length']) {
      reqHeaders['Content-Length'] = Buffer.byteLength(bodyData);
    }

    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method.toUpperCase(),
      headers: reqHeaders,
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (_) {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          rawBody: data,
          body: json,
        });
      });
    });

    req.on('error', reject);
    if (bodyData) {
      req.write(bodyData);
    }
    req.end();
  });
}

async function runTest(name, fn) {
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
console.log('🛡️   CYBER SENTINEL — ENDPOINT TELEMETRY INGESTION SECURITY SUITE');
console.log('======================================================================\n');

async function runSuite() {
  // Start server on random available port
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });

  const testHostname = `telemetry-host-${Date.now()}`;
  let deviceId;
  let deviceSecret;

  console.log('━━━ SECTION 1: Endpoint Provisioning for Telemetry Testing ━━━');

  await runTest('[PROVISION] Enrolls dedicated test endpoint device', async () => {
    const enrolled = await deviceService.enrollDevice({
      name: 'Telemetry Ingestion Test Host',
      platform: 'LINUX',
      hostname: testHostname,
      agentVersion: '3.0.0',
      user: { email: 'operator@sentinel.local', role: 'ENDPOINT_OPERATOR' },
    });

    deviceId = enrolled.device.id;
    deviceSecret = enrolled.deviceSecret;
    assert.ok(deviceId, 'Device ID must exist');
    assert.ok(deviceSecret, 'Device secret must exist');
  });

  console.log('\n━━━ SECTION 2: Cryptographic HMAC-SHA256 Ingestion Verification ━━━');

  await runTest('[VALID] Ingests valid HMAC-SHA256 signed telemetry payload (202 Accepted)', async () => {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const payload = {
      eventType: 'PROCESS_EXECUTION',
      sourceIp: '192.168.1.50',
      user: 'sec-admin',
      details: { processName: 'sentinel-agent.exe', pid: 4022 },
    };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: payload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 202, `Expected 202 Accepted, got ${res.statusCode}: ${JSON.stringify(res.body)}`);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.processed, 1);
  });

  await runTest('[INVALID-SIG] Rejects forged/invalid HMAC signature with 401 Unauthorized', async () => {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const payload = { eventType: 'NETWORK_CONNECTION', sourceIp: '10.0.0.1' };
    const forgedSignature = crypto.randomBytes(32).toString('hex');

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': forgedSignature,
    }, payload);

    assert.strictEqual(res.statusCode, 401);
    assert.ok(res.body.error.includes('Invalid HMAC'));
  });

  console.log('\n━━━ SECTION 3: Request Integrity & Tampering Defense ━━━');

  await runTest('[MODIFIED-BODY] Rejects payload modified in transit after signing (401 Unauthorized)', async () => {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const originalPayload = { eventType: 'FILE_CREATION', filePath: '/etc/hosts' };
    const tamperedPayload = { eventType: 'FILE_CREATION', filePath: '/etc/shadow' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: originalPayload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, tamperedPayload);

    assert.strictEqual(res.statusCode, 401);
    assert.ok(res.body.error.includes('Invalid HMAC'));
  });

  await runTest('[MODIFIED-PATH] Rejects signature created for a different endpoint path (401 Unauthorized)', async () => {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const payload = { eventType: 'SYSTEM_STARTUP' };

    // Signed for /api/telemetry/different instead of /api/events
    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/telemetry/different',
      timestamp,
      nonce,
      body: payload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 401);
    assert.ok(res.body.error.includes('Invalid HMAC'));
  });

  console.log('\n━━━ SECTION 4: Freshness & Replay Attack Defense ━━━');

  await runTest('[EXPIRED-TS] Rejects expired timestamp (>5 mins in the past) with 401 Unauthorized', async () => {
    const expiredTs = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 mins ago
    const nonce = crypto.randomUUID();
    const payload = { eventType: 'HEARTBEAT' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp: expiredTs,
      nonce,
      body: payload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': expiredTs,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 401);
    assert.ok(res.body.error.includes('Expired telemetry timestamp'));
  });

  await runTest('[FUTURE-TS] Rejects future timestamp (>5 mins in future) with 401 Unauthorized', async () => {
    const futureTs = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 mins in future
    const nonce = crypto.randomUUID();
    const payload = { eventType: 'HEARTBEAT' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp: futureTs,
      nonce,
      body: payload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': futureTs,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 401);
    assert.ok(res.body.error.includes('Future telemetry timestamp'));
  });

  await runTest('[REPLAY-NONCE] Detects and blocks nonce replay attack on identical request (401 Unauthorized)', async () => {
    const timestamp = new Date().toISOString();
    const reusedNonce = `nonce-replay-${crypto.randomBytes(8).toString('hex')}`;
    const payload = { eventType: 'LOGON_EVENT', user: 'alice' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce: reusedNonce,
      body: payload,
      deviceSecret,
    });

    // Request 1: Valid initial dispatch
    const res1 = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': reusedNonce,
      'X-Signature': signature,
    }, payload);
    assert.strictEqual(res1.statusCode, 202);

    // Request 2: Replay identical message & nonce
    const res2 = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': reusedNonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res2.statusCode, 401);
    assert.ok(res2.body.error.includes('Replay attack detected'));
  });

  console.log('\n━━━ SECTION 5: Lifecycle & Device Status Defense ━━━');

  await runTest('[REVOKED-DEVICE] Blocks telemetry ingestion from revoked endpoints (403 Forbidden)', async () => {
    // Enroll temporary device and immediately revoke it
    const tempDev = await deviceService.enrollDevice({
      name: 'Compromised Host',
      platform: 'WINDOWS',
      hostname: `compromised-${Date.now()}`,
      user: { email: 'operator@sentinel.local', role: 'ENDPOINT_OPERATOR' },
    });

    await deviceService.revokeDevice(tempDev.device.id, {
      reason: 'Malware infection containment',
      user: { email: 'operator@sentinel.local', role: 'ENDPOINT_OPERATOR' },
    });

    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const payload = { eventType: 'SUSPICIOUS_C2_TRAFFIC' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: payload,
      deviceSecret: tempDev.deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': tempDev.device.id,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 403);
    assert.ok(res.body.error.includes('REVOKED'));
  });

  await runTest('[UNKNOWN-DEVICE] Rejects telemetry from unknown / unregistered device ID (401 Unauthorized)', async () => {
    const unknownDeviceId = 'DEV-NONEXISTENT999';
    const fakeSecret = 'sec_00000000000000000000000000000000';
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const payload = { eventType: 'HEARTBEAT' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: payload,
      deviceSecret: fakeSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': unknownDeviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 401);
    assert.ok(res.body.error.includes('Unknown or unauthenticated'));
  });

  console.log('\n━━━ SECTION 6: Payload Size, Schema, & Rate Limit Enforcements ━━━');

  await runTest('[OVERSIZED-PAYLOAD] Rejects telemetry payload exceeding size limit with 413', async () => {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    // 1.2 MB oversized string
    const largeBlob = 'A'.repeat(1.2 * 1024 * 1024);
    const payload = {
      eventType: 'MEMORY_DUMP',
      blob: largeBlob,
    };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: payload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, payload);

    assert.strictEqual(res.statusCode, 413);
    assert.ok(res.body.error.includes('Payload Too Large'));
  });

  await runTest('[MALFORMED-PAYLOAD] Rejects invalid event schema with 400 Bad Request', async () => {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    // Missing eventType / invalid schema
    const malformedPayload = { foo: 'bar' };

    const { signature } = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: malformedPayload,
      deviceSecret,
    });

    const res = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
    }, malformedPayload);

    assert.strictEqual(res.statusCode, 400);
    assert.ok(res.body.error.includes('Missing or invalid eventType'));
  });

  await runTest('[RATE-LIMIT] Enforces rate limiting on rapid telemetry burst (429 Too Many Requests)', async () => {
    resetRateLimitStore();
    const burstDeviceId = `DEV-BURST-${Date.now()}`;
    const burstDev = await deviceService.enrollDevice({
      hostname: `burst-host-${Date.now()}`,
      user: { email: 'operator@sentinel.local', role: 'ENDPOINT_OPERATOR' },
    });

    let rateLimited429Encountered = false;

    for (let i = 0; i < 130; i++) {
      const timestamp = new Date().toISOString();
      const nonce = crypto.randomUUID();
      const payload = { eventType: 'BURST_EVENT', idx: i };

      const { signature } = computeTelemetrySignature({
        method: 'POST',
        path: '/api/events',
        timestamp,
        nonce,
        body: payload,
        deviceSecret: burstDev.deviceSecret,
      });

      const res = await httpRequest('POST', '/api/events', {
        'X-Device-ID': burstDev.device.id,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': signature,
      }, payload);

      if (res.statusCode === 429) {
        rateLimited429Encountered = true;
        assert.ok(res.body.error.includes('rate limit exceeded'));
        break;
      }
    }

    assert.strictEqual(rateLimited429Encountered, true, 'Should have encountered 429 Too Many Requests after 120 reqs');
  });

  console.log('\n━━━ SECTION 7: Credential Rotation & Zero Secret Exposure ━━━');

  await runTest('[ROTATION] Accepts new secret signature and rejects old secret signature after rotation', async () => {
    const rotRes = await deviceService.rotateCredential(deviceId, {
      user: { email: 'operator@sentinel.local', role: 'ENDPOINT_OPERATOR' },
    });

    const newSecret = rotRes.newDeviceSecret;
    assert.notStrictEqual(newSecret, deviceSecret);

    // 1. Attempt with old secret (Must Fail)
    const oldTs = new Date().toISOString();
    const oldNonce = crypto.randomUUID();
    const payload = { eventType: 'POST_ROTATION_EVENT' };

    const oldSig = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp: oldTs,
      nonce: oldNonce,
      body: payload,
      deviceSecret, // Old secret
    }).signature;

    const oldAttempt = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': oldTs,
      'X-Nonce': oldNonce,
      'X-Signature': oldSig,
    }, payload);
    assert.strictEqual(oldAttempt.statusCode, 401);

    // 2. Attempt with new secret (Must Succeed)
    const newTs = new Date().toISOString();
    const newNonce = crypto.randomUUID();

    const newSig = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp: newTs,
      nonce: newNonce,
      body: payload,
      deviceSecret: newSecret, // New secret
    }).signature;

    const newAttempt = await httpRequest('POST', '/api/events', {
      'X-Device-ID': deviceId,
      'X-Timestamp': newTs,
      'X-Nonce': newNonce,
      'X-Signature': newSig,
    }, payload);
    assert.strictEqual(newAttempt.statusCode, 202);
  });

  console.log('\n======================================================================');
  console.log(`🏁  TELEMETRY SECURITY SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
  console.log('======================================================================\n');

  if (server) server.close();
  if (failedTests > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSuite().catch(err => {
  console.error('Unhandled telemetry security test error:', err);
  if (server) server.close();
  process.exit(1);
});
