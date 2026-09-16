/**
 * tests/unit/detectionRules.test.js
 * Unit test suite for Modular Detection Rules, Rule Registry, and Threshold Logic.
 */

const assert = require('assert');
const path = require('path');

const { ruleRegistry } = require(path.join(__dirname, '../../backend/src/services/detection/ruleRegistry'));
const { detectionEngine } = require(path.join(__dirname, '../../backend/src/services/detection/detectionEngine'));
const { EventTypes } = require(path.join(__dirname, '../../backend/src/services/normalizer/eventNormalizer'));

async function runDetectionRulesUnitTests() {
  console.log('\n--- [Unit] Detection Rules & Engine Evaluation ---');
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

  // 1. Rule Registry Integrity
  test('Rule Registry initializes with core security detection rules', () => {
    const allRules = ruleRegistry.getAllRules();
    assert.ok(allRules.length >= 4, 'Should load at least 4 baseline detection rules');
    
    for (const r of allRules) {
      assert.ok(r.id, 'Rule must have an ID');
      assert.ok(r.name, 'Rule must have a name');
      assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(r.severity), 'Rule severity must be valid');
      assert.ok(Array.isArray(r.mitreTechniques), 'Rule must have MITRE techniques array');
    }
  });

  // 2. Rule Filtering by Severity
  test('Filters rules by severity', () => {
    const criticalRules = ruleRegistry.getAllRules({ severity: 'CRITICAL' });
    for (const r of criticalRules) {
      assert.strictEqual(r.severity, 'CRITICAL');
    }
  });

  // 3. Brute Force Detection Evaluation
  test('Flags brute force attack after threshold failures exceed limit', () => {
    const sourceIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
    let triggered = [];

    for (let i = 0; i < 6; i++) {
      const event = {
        event_id: `evt-bf-${i}`,
        event_type: EventTypes.AUTH_FAILURE,
        source_ip: sourceIp,
        sourceIp,
        user: 'root',
        timestamp: new Date().toISOString(),
        details: { failureReason: 'INVALID_CREDENTIALS' },
      };
      const dets = detectionEngine.processEvent(event);
      if (dets.length > 0) triggered.push(...dets);
    }

    assert.ok(triggered.length > 0, 'Brute force rule must trigger on repeated auth failures');
    assert.ok(triggered.some(d => d.rule_id === 'RULE_AUTH_BRUTEFORCE_001' || (d.rule_name && d.rule_name.includes('Brute Force'))));
  });

  // 4. SQL Injection Success Detection
  test('Flags SQL Injection exploitation when payload returns HTTP 200 with data markers', () => {
    const sqliEvent = {
      event_id: `evt-sqli-${Date.now()}`,
      event_type: EventTypes.EXPLOIT_PROBE,
      source_ip: '203.0.113.88',
      sourceIp: '203.0.113.88',
      timestamp: new Date().toISOString(),
      details: {
        attackType: 'SQL Injection',
        payload: "' UNION SELECT username, password_hash FROM users--",
        statusCode: 200,
        responseSize: 18450,
      },
    };

    const dets = detectionEngine.processEvent(sqliEvent);
    assert.ok(dets.length > 0, 'SQLi rule must trigger on HTTP 200 exploit payload');
    assert.strictEqual(dets[0].severity, 'CRITICAL');
  });

  return { passed, failed };
}

if (require.main === module) {
  runDetectionRulesUnitTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runDetectionRulesUnitTests };
