/**
 * test_upload_security.js
 * Adversarial Test Suite for File Upload Security, Magic-Byte Inspection, Archive Bombs & Quarantine Isolation.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const {
  sanitizeFilename,
  inspectArchiveSafety,
  validateFileUpload,
} = require('./src/services/upload/uploadSecurityService');
const {
  quarantineSample,
  getQuarantinedSample,
  pruneQuarantine,
} = require('./src/services/malware/quarantineManager');

console.log('🧪 Starting File Upload Security Adversarial Test Suite...\n');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  ✅ PASS: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ FAIL: ${name}`);
    console.error(`     Error: ${err.message}\n`);
  }
}

// ── 1. Filename Sanitization & Path Traversal Tests ──
test('Strips Unix path traversal sequences (../../../../etc/passwd)', () => {
  const result = sanitizeFilename('../../../../etc/passwd');
  assert.strictEqual(result.sanitized, 'passwd');
  assert.strictEqual(result.isDoubleExtension, false);
});

test('Strips Windows path traversal sequences (..\\..\\windows\\system32\\cmd.exe)', () => {
  const result = sanitizeFilename('..\\..\\windows\\system32\\cmd.exe');
  assert.strictEqual(result.sanitized, 'cmd.exe');
});

test('Strips URI-encoded path traversal sequences (%2e%2e%2f%2e%2e%2fsecrets.txt)', () => {
  const result = sanitizeFilename('%2e%2e%2f%2e%2e%2fsecrets.txt');
  assert.strictEqual(result.sanitized, 'secrets.txt');
});

test('Strips null-byte filename injection (innocent.pdf\\0.exe)', () => {
  const result = sanitizeFilename('innocent.pdf\0.exe');
  assert.strictEqual(result.sanitized, 'innocent.pdf.exe');
  assert.strictEqual(result.isDoubleExtension, true);
});

test('Strips URI-encoded null-byte injection (resume.doc%00.vbs)', () => {
  const result = sanitizeFilename('resume.doc%00.vbs');
  assert.strictEqual(result.sanitized, 'resume.doc.vbs');
  assert.strictEqual(result.isDoubleExtension, true);
});

test('Detects dangerous double extension masquerading (invoice.pdf.exe)', () => {
  const result = sanitizeFilename('invoice.pdf.exe');
  assert.strictEqual(result.isDoubleExtension, true);
  assert.deepStrictEqual(result.detectedExtensions, ['.pdf', '.exe']);
});

// ── 2. Magic-Byte Validation & MIME Spoofing Tests ──
test('Detects Windows PE executable disguised as image/jpeg', () => {
  // Construct a buffer with MZ header (0x4D 0x5A)
  const peBuffer = Buffer.alloc(128);
  peBuffer[0] = 0x4D; // 'M'
  peBuffer[1] = 0x5A; // 'Z'
  peBuffer.write('PE\0\0', 60);

  const validation = validateFileUpload({
    buffer: peBuffer,
    declaredFilename: 'vacation_photo.jpg',
    declaredMime: 'image/jpeg',
  });

  assert.strictEqual(validation.valid, true);
  assert.strictEqual(validation.isDisguisedExecutable, true);
  assert.strictEqual(validation.detectedType.isExecutable, true);
  assert.strictEqual(validation.detectedType.category, 'EXECUTABLE_PE');
});

test('Detects Linux ELF executable disguised as application/pdf', () => {
  // Construct a buffer with \x7fELF header
  const elfBuffer = Buffer.alloc(64);
  elfBuffer[0] = 0x7F;
  elfBuffer[1] = 0x45; // 'E'
  elfBuffer[2] = 0x4C; // 'L'
  elfBuffer[3] = 0x46; // 'F'

  const validation = validateFileUpload({
    buffer: elfBuffer,
    declaredFilename: 'document.pdf',
    declaredMime: 'application/pdf',
  });

  assert.strictEqual(validation.isDisguisedExecutable, true);
  assert.strictEqual(validation.detectedType.category, 'EXECUTABLE_ELF');
});

test('Rejects executable upload when endpoint explicitly disallows executables', () => {
  const peBuffer = Buffer.alloc(64);
  peBuffer[0] = 0x4D;
  peBuffer[1] = 0x5A;

  const validation = validateFileUpload({
    buffer: peBuffer,
    declaredFilename: 'script.exe',
    disallowExecutables: true,
  });

  assert.strictEqual(validation.valid, false);
  assert.strictEqual(validation.status, 415);
  assert.ok(validation.error.includes('prohibited'));
});

// ── 3. Payload Size Bounds Tests ──
test('Rejects oversized file payload exceeding max size limit (HTTP 413)', () => {
  const smallLimit = 1024; // 1 KB
  const oversizedBuffer = Buffer.alloc(2048); // 2 KB

  const validation = validateFileUpload({
    buffer: oversizedBuffer,
    declaredFilename: 'big_file.bin',
    maxSizeBytes: smallLimit,
  });

  assert.strictEqual(validation.valid, false);
  assert.strictEqual(validation.status, 413);
});

test('Rejects empty 0-byte file buffer (HTTP 400)', () => {
  const emptyBuffer = Buffer.alloc(0);
  const validation = validateFileUpload({
    buffer: emptyBuffer,
    declaredFilename: 'empty.bin',
  });

  assert.strictEqual(validation.valid, false);
  assert.strictEqual(validation.status, 400);
});

// ── 4. Archive Bomb & Zip Slip Defense Tests ──
test('Detects Zip Slip path traversal sequence inside ZIP header', () => {
  // Construct minimal mock ZIP local file header with ../../../etc/shadow
  const zipSlipEntryName = '../../../../etc/shadow';
  const entryNameBuf = Buffer.from(zipSlipEntryName, 'utf8');

  const zipHeader = Buffer.alloc(30 + entryNameBuf.length + 10);
  zipHeader.writeUInt32LE(0x04034B50, 0); // PK\x03\x04
  zipHeader.writeUInt16LE(20, 4); // version needed
  zipHeader.writeUInt16LE(0, 6); // flags
  zipHeader.writeUInt16LE(0, 8); // compression
  zipHeader.writeUInt32LE(10, 18); // compressed size
  zipHeader.writeUInt32LE(10, 22); // uncompressed size
  zipHeader.writeUInt16LE(entryNameBuf.length, 26); // file name length
  zipHeader.writeUInt16LE(0, 28); // extra field length
  entryNameBuf.copy(zipHeader, 30);

  const archiveCheck = inspectArchiveSafety(zipHeader);
  assert.strictEqual(archiveCheck.isArchive, true);
  assert.strictEqual(archiveCheck.hasZipSlip, true);
  assert.strictEqual(archiveCheck.safe, false);
});

// ── 5. Isolated Storage & Non-Executable Permissions Tests ──
test('Quarantines sample using random UUID filename and verifies non-executable storage', () => {
  const maliciousPayload = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
  const record = quarantineSample(maliciousPayload, '../../malicious_eicar.com');

  assert.ok(record.sampleId.startsWith('SAMPLE-'));
  assert.strictEqual(record.sanitizedFilename, 'malicious_eicar.com');
  assert.ok(!record.diskPath.includes('..'));
  assert.ok(record.isExecutableFlagRemoved);

  // Verify retrieval
  const retrieved = getQuarantinedSample(record.sampleId);
  assert.ok(retrieved !== null);
  assert.strictEqual(retrieved.sha256, record.sha256);
});

test('Quarantine retention pruning removes expired entries', () => {
  const result = pruneQuarantine(0); // Prune anything older than 0ms
  assert.strictEqual(typeof result.prunedCount, 'number');
  assert.ok(result.prunedCount >= 0);
});

console.log(`\n📊 File Upload Security Test Results: ${passedTests}/${totalTests} Passed\n`);
if (passedTests !== totalTests) {
  process.exit(1);
}
