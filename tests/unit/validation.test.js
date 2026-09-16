/**
 * tests/unit/validation.test.js
 * Unit test suite for Input Validation, Normalization, Prototype Pollution Defense, and Sanitization.
 */

const assert = require('assert');
const path = require('path');

const { normalizeEvent, EventTypes } = require(path.join(__dirname, '../../backend/src/services/normalizer/eventNormalizer'));
const { sanitizeFilename } = require(path.join(__dirname, '../../backend/src/services/upload/uploadSecurityService'));
const { detectFileType } = require(path.join(__dirname, '../../backend/src/services/malware/fileTypeDetector'));

async function runValidationUnitTests() {
  console.log('\n--- [Unit] Input Validation & Sanitization ---');
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

  // 1. Event Normalizer & Schema Standardizer
  test('Normalizes standard telemetry fields to canonical uppercase EventType', () => {
    const raw = {
      event_type: 'auth_failure',
      source_ip: '192.168.1.50',
      device_id: 'dev-001',
      user: 'admin',
    };
    const normalized = normalizeEvent(raw);
    assert.strictEqual(normalized.eventType, EventTypes.AUTH_FAILURE);
    assert.strictEqual(normalized.sourceIp, '192.168.1.50');
    assert.strictEqual(normalized.deviceId, 'dev-001');
    assert.strictEqual(normalized.user.name, 'admin');
    assert.ok(normalized.timestamp);
  });

  // 2. Prototype Pollution Defense
  test('Prevents prototype pollution via __proto__ and constructor payload injection', () => {
    const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}, "constructor": {"prototype": {"admin": true}}}');
    const clean = normalizeEvent(maliciousPayload);

    assert.strictEqual({}.polluted, undefined, 'Object prototype must not be polluted');
    assert.strictEqual({}.admin, undefined, 'Object prototype must not be polluted');
  });

  // 3. Filename Sanitization & Path Traversal Neutralization
  test('Sanitizes nested directory traversal sequences from filenames', () => {
    const res = sanitizeFilename('../../../../etc/passwd');
    assert.strictEqual(res.sanitized.includes('..'), false);
    assert.strictEqual(res.sanitized.includes('/'), false);
    assert.strictEqual(res.sanitized, 'passwd');
  });

  test('Strips null-byte filename injections', () => {
    const res = sanitizeFilename('malicious.pdf\x00.exe');
    assert.strictEqual(res.sanitized.includes('\x00'), false);
  });

  // 4. Double Extension Masquerading Detection
  test('Detects dangerous double extensions (e.g., .pdf.exe, .jpg.vbs)', () => {
    const result1 = sanitizeFilename('invoice.pdf.exe');
    assert.strictEqual(result1.isDoubleExtension, true);

    const result2 = sanitizeFilename('clean_document.pdf');
    assert.strictEqual(result2.isDoubleExtension, false);
  });

  // 5. Magic Byte Content Inspection
  test('Identifies Windows PE binary from magic bytes MZ (0x4D 0x5A)', () => {
    const peBuffer = Buffer.alloc(64);
    peBuffer[0] = 0x4D;
    peBuffer[1] = 0x5A;
    const detection = detectFileType(peBuffer);
    assert.strictEqual(detection.mime, 'application/x-dosexec');
    assert.strictEqual(detection.isExecutable, true);
  });

  test('Identifies Linux ELF executable from magic bytes 0x7F ELF', () => {
    const elfBuffer = Buffer.alloc(64);
    elfBuffer[0] = 0x7F;
    elfBuffer[1] = 0x45;
    elfBuffer[2] = 0x4C;
    elfBuffer[3] = 0x46;
    const detection = detectFileType(elfBuffer);
    assert.strictEqual(detection.mime, 'application/x-executable');
    assert.strictEqual(detection.isExecutable, true);
  });

  test('Identifies legitimate PDF document from %PDF header', () => {
    const pdfBuffer = Buffer.from('%PDF-1.7\n%some content');
    const detection = detectFileType(pdfBuffer);
    assert.strictEqual(detection.mime, 'application/pdf');
    assert.strictEqual(detection.isExecutable, false);
  });

  return { passed, failed };
}

if (require.main === module) {
  runValidationUnitTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runValidationUnitTests };
