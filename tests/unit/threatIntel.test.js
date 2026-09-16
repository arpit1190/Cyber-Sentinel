/**
 * tests/unit/threatIntel.test.js
 * Unit test suite for Threat Intelligence, IOC Indexing, and Threat Feed Integration.
 */

const assert = require('assert');
const path = require('path');

const { matchIoc, addIndicators } = require(path.join(__dirname, '../../backend/src/services/threatIntel/iocMatcher'));
const { getLiveCves, fallbackThreats } = require(path.join(__dirname, '../../backend/src/utils/liveThreatFetcher'));

async function runThreatIntelUnitTests() {
  console.log('\n--- [Unit] Threat Intelligence & IOC Indexing ---');
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

  // 1. Ingest & Match Malicious IPv4 IOC
  test('Matches indexed malicious IPv4 and returns threat metadata', () => {
    const maliciousIp = '185.220.101.5';
    addIndicators([{
      value: maliciousIp,
      malware: 'Cobalt Strike',
      confidence: 95,
      mitreTechnique: 'T1071.001',
    }]);

    const match = matchIoc(maliciousIp);
    assert.strictEqual(match.matched, true);
    assert.strictEqual(match.malware, 'Cobalt Strike');
    assert.strictEqual(match.confidence, 95);
  });

  // 2. Ingest & Match Malicious SHA-256 File Hash
  test('Matches indexed malicious SHA-256 hash', () => {
    const maliciousHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    addIndicators([{
      value: maliciousHash,
      malware: 'WannaCry',
      confidence: 99,
    }]);

    const match = matchIoc(maliciousHash);
    assert.strictEqual(match.matched, true);
    assert.strictEqual(match.malware, 'WannaCry');
  });

  // 3. Clean Indicator (No Match)
  test('Returns matched: false for benign indicator', () => {
    const benignIp = '8.8.8.8';
    const match = matchIoc(benignIp);
    assert.strictEqual(match.matched, false);
  });

  // 4. Threat Intelligence Pool & CVE Catalog
  test('Retrieves authentic threats and CVE catalog', () => {
    const cves = getLiveCves();
    assert.ok(Array.isArray(fallbackThreats));
    assert.ok(Array.isArray(cves));
    assert.ok(fallbackThreats.length > 0, 'Threat pool must contain active threat items');
    assert.ok(cves.length > 0, 'CVE pool must contain active vulnerabilities');
  });

  return { passed, failed };
}

if (require.main === module) {
  runThreatIntelUnitTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runThreatIntelUnitTests };
