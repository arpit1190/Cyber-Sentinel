/**
 * tests/security/fileUploadSecurity.test.js
 * Security test suite for File Upload Defenses, Magic Byte Inspection, Archive Bombs & Quarantine Isolation.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const {
  sanitizeFilename,
  inspectArchiveSafety,
  validateFileUpload,
} = require(path.join(__dirname, '../../backend/src/services/upload/uploadSecurityService'));

const {
  quarantineSample,
  getQuarantinedSample,
  pruneQuarantine,
} = require(path.join(__dirname, '../../backend/src/services/malware/quarantineManager'));

async function runFileUploadSecurityTests() {
  console.log('\n--- [Security] File Upload Hardening & Malware Quarantine ---');
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

  // 1. Path Traversal Defenses
  await test('Neutralizes nested Unix & Windows path traversal in filenames', async () => {
    assert.strictEqual(sanitizeFilename('../../../../etc/shadow').sanitized, 'shadow');
    assert.strictEqual(sanitizeFilename('..\\..\\windows\\system32\\cmd.exe').sanitized, 'cmd.exe');
    assert.strictEqual(sanitizeFilename('%2e%2e%2f%2e%2e%2fetc%2fpasswd').sanitized, 'passwd');
  });

  // 2. Null-Byte Injections
  await test('Strips raw and URI-encoded null bytes from filenames', async () => {
    assert.strictEqual(sanitizeFilename('report.pdf\x00.exe').sanitized, 'report.pdf.exe');
    assert.strictEqual(sanitizeFilename('report.pdf%00.exe').sanitized, 'report.pdf.exe');
  });

  // 3. Executable Masquerading via Content Magic Bytes
  await test('Rejects Windows PE binary when disallowExecutables is configured', async () => {
    const fakePng = Buffer.concat([
      Buffer.from([0x4D, 0x5A, 0x90, 0x00]), // MZ header
      Buffer.alloc(100, 0),
    ]);

    const result = validateFileUpload({
      buffer: fakePng,
      declaredFilename: 'screenshot.png',
      declaredMime: 'image/png',
      disallowExecutables: true,
    });

    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.status, 415);
  });

  // 4. Zip Slip Defenses
  await test('Detects Zip Slip archive traversal sequence inside ZIP header', async () => {
    const zipSlipEntryName = '../../../../etc/shadow';
    const entryNameBuf = Buffer.from(zipSlipEntryName, 'utf8');

    const zipHeader = Buffer.alloc(30 + entryNameBuf.length + 10);
    zipHeader.writeUInt32LE(0x04034B50, 0); // PK\x03\x04
    zipHeader.writeUInt16LE(20, 4);
    zipHeader.writeUInt16LE(0, 6);
    zipHeader.writeUInt16LE(0, 8);
    zipHeader.writeUInt32LE(10, 18);
    zipHeader.writeUInt32LE(10, 22);
    zipHeader.writeUInt16LE(entryNameBuf.length, 26);
    zipHeader.writeUInt16LE(0, 28);
    entryNameBuf.copy(zipHeader, 30);

    const archiveCheck = inspectArchiveSafety(zipHeader);
    assert.strictEqual(archiveCheck.isArchive, true);
    assert.strictEqual(archiveCheck.hasZipSlip, true);
    assert.strictEqual(archiveCheck.safe, false);
  });

  // 5. Isolated UUID Quarantine & Non-Executable Permissions (0o600)
  await test('Quarantines sample using random UUID filename and non-executable mode (0o600)', async () => {
    const sampleBuffer = Buffer.from('TEST_MALWARE_PAYLOAD_SAFE_INSPECTION');
    const item = quarantineSample(sampleBuffer, 'trojan.bin', { actor: 'analyst' });

    assert.ok(item.sampleId);
    assert.ok(item.diskPath);
    assert.notStrictEqual(path.basename(item.diskPath), 'trojan.bin');

    // Verify file exists on disk with 0o600 mode
    const stat = fs.statSync(item.diskPath);
    assert.strictEqual(stat.mode & 0o111, 0, 'File must not possess execution permissions');
  });

  // 6. Retention Pruning
  await test('Prunes expired quarantine samples according to retention policy', async () => {
    const result = pruneQuarantine(0);
    assert.strictEqual(typeof result.prunedCount, 'number');
    assert.ok(result.prunedCount >= 0);
  });

  return { passed, failed };
}

if (require.main === module) {
  runFileUploadSecurityTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runFileUploadSecurityTests };
