/**
 * tests/unit/mitreMapping.test.js
 * Unit test suite for MITRE ATT&CK Framework Mapping and Technique Enrichment.
 */

const assert = require('assert');
const path = require('path');

const { ATTACK_TACTICS, mitreRegistry } = require(path.join(__dirname, '../../backend/src/services/detection/mitreRegistry'));

async function runMitreMappingUnitTests() {
  console.log('\n--- [Unit] MITRE ATT&CK Framework Mapping ---');
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

  // 1. MITRE Tactics Catalog
  test('Contains standard MITRE Enterprise ATT&CK tactics', () => {
    assert.ok(ATTACK_TACTICS.TA0001); // Initial Access
    assert.ok(ATTACK_TACTICS.TA0002); // Execution
    assert.ok(ATTACK_TACTICS.TA0003); // Persistence
    assert.ok(ATTACK_TACTICS.TA0004); // Privilege Escalation
    assert.ok(ATTACK_TACTICS.TA0006); // Credential Access
    assert.ok(ATTACK_TACTICS.TA0011); // Command and Control
    assert.ok(ATTACK_TACTICS.TA0010); // Exfiltration
  });

  // 2. Technique Resolution
  test('Resolves technique metadata by ID (T1110 - Brute Force)', () => {
    const tech = mitreRegistry.getTechnique('T1110');
    assert.ok(tech, 'Technique T1110 must be defined');
    assert.strictEqual(tech.id, 'T1110');
    assert.strictEqual(tech.technique_name, 'Brute Force');
    assert.strictEqual(tech.tactic_id, 'TA0006');
  });

  test('Resolves sub-technique metadata by ID (T1059.001 - PowerShell)', () => {
    const tech = mitreRegistry.getTechnique('T1059.001');
    assert.ok(tech, 'Technique T1059.001 must be defined');
    assert.strictEqual(tech.id, 'T1059.001');
    assert.strictEqual(tech.technique_id, 'T1059');
    assert.ok(tech.url.includes('T1059/001'));
  });

  // 3. Technique Resolution using resolveTechniques
  test('Resolves technique via resolveTechniques', () => {
    const resolved = mitreRegistry.resolveTechniques(['T1190']);
    assert.ok(Array.isArray(resolved));
    assert.strictEqual(resolved.length, 1);
    assert.strictEqual(resolved[0].id, 'T1190');
  });

  return { passed, failed };
}

if (require.main === module) {
  runMitreMappingUnitTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runMitreMappingUnitTests };
