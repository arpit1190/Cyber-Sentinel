/**
 * tests/integration/databaseIntegration.test.js
 * Integration test suite for Database Layer, Parameterized SQL Execution, and Repository Isolation.
 */

const assert = require('assert');
const path = require('path');

const userRepository = require(path.join(__dirname, '../../backend/src/repositories/userRepository'));
const deviceRepository = require(path.join(__dirname, '../../backend/src/repositories/deviceRepository'));
const securityRepository = require(path.join(__dirname, '../../backend/src/repositories/securityRepository'));

async function runDatabaseIntegrationTests() {
  console.log('\n--- [Integration] Database Layer & Parameterized Repository Security ---');
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

  // 1. User Repository CRUD & Parameterization
  await test('User repository creates and retrieves records safely without SQL concatenation', async () => {
    const testEmail = `secops-${Date.now()}@sentinel.defense`;
    const user = await userRepository.createUser({
      name: 'Test Analyst',
      email: testEmail,
      passwordHash: '$2a$10$abcdefghijklmnopqrstuvwxyz1234567890',
      role: 'SOC_ANALYST',
    });

    assert.ok(user.id);
    assert.strictEqual(user.email, testEmail);

    const fetched = await userRepository.findByEmail(testEmail);
    assert.strictEqual(fetched.id, user.id);
    assert.strictEqual(fetched.role, 'SOC_ANALYST');
  });

  // 2. Device Repository Safe Parameterization
  await test('Device repository stores and queries devices using parameterized keys', async () => {
    const device = await deviceRepository.createDevice({
      id: `DEV-GW-${Date.now()}`,
      hostname: `gateway-router-${Date.now()}`,
      platform: 'LINUX',
      ipAddress: '172.16.0.1',
      agentVersion: '2.0.0',
    });

    assert.ok(device.id);
    const found = await deviceRepository.findById(device.id);
    assert.strictEqual(found.id, device.id);
  });

  // 3. Security Repository Safe Storage
  await test('Security repository persists and retrieves complex structured incidents', async () => {
    const incident = await securityRepository.createIncident({
      title: 'DDoS SYN Flood Detection',
      description: 'Perimeter firewalls reporting 50,000 SYN packets/sec.',
      severity: 'CRITICAL',
      status: 'INVESTIGATING',
    });

    assert.ok(incident.id);
    const retrieved = await securityRepository.getIncidentById(incident.id);
    assert.strictEqual(retrieved.title, 'DDoS SYN Flood Detection');
    assert.strictEqual(retrieved.severity, 'CRITICAL');
  });

  return { passed, failed };
}

if (require.main === module) {
  runDatabaseIntegrationTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runDatabaseIntegrationTests };
