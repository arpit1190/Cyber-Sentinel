/**
 * test_disaster_recovery.js
 * Verification and Controlled Testing of Disaster Recovery, Backup Integrity, and Restoration.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  createSnapshot,
  verifySnapshot,
  restoreFromSnapshot,
  runDrillSimulation,
} = require('./src/utils/disasterRecovery');

async function runDisasterRecoveryTests() {
  console.log('\n--- [Disaster Recovery & Backup Restoration Suite] ---');
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

  const tempBackupDir = path.join(__dirname, '..', 'backups', `test-dr-${Date.now()}`);

  let createdSnapshotDir = null;

  await test('Creates a valid GZIP-compressed snapshot with SHA-256 manifest', async () => {
    const res = await createSnapshot({ backupDir: tempBackupDir, label: 'unit-test' });
    assert.ok(res.snapshotId, 'Must return a unique snapshot ID');
    assert.ok(fs.existsSync(res.snapshotDir), 'Snapshot directory must exist on disk');
    assert.ok(fs.existsSync(path.join(res.snapshotDir, 'manifest.json')), 'Manifest file must exist');

    const manifest = JSON.parse(fs.readFileSync(path.join(res.snapshotDir, 'manifest.json'), 'utf8'));
    assert.ok(manifest.manifest_sha256, 'Manifest must contain signature hash');
    assert.ok(manifest.total_records >= 0, 'Total records count must be recorded');
    createdSnapshotDir = res.snapshotDir;
  });

  await test('Verifies cryptographic integrity of all backup component files', async () => {
    assert.ok(createdSnapshotDir, 'Snapshot must be created first');
    const verifyRes = verifySnapshot(createdSnapshotDir);
    assert.strictEqual(verifyRes.valid, true, 'Snapshot verification must pass');
    assert.strictEqual(verifyRes.errors.length, 0, 'Must have zero verification errors');
    assert.ok(verifyRes.checkedComponents.length > 0, 'Must have verified at least one component');
  });

  await test('Detects tampering if a backup archive file is corrupted', async () => {
    const tamperedDir = path.join(tempBackupDir, `tampered-snap-${Date.now()}`);
    fs.mkdirSync(tamperedDir, { recursive: true });

    // Copy original manifest and create corrupted file
    const origManifest = JSON.parse(fs.readFileSync(path.join(createdSnapshotDir, 'manifest.json'), 'utf8'));
    const dummyCorrupt = Buffer.from('CORRUPTED_NON_GZIP_CONTENT', 'utf8');
    const compName = Object.keys(origManifest.components)[0];
    const compFile = origManifest.components[compName].file;

    fs.writeFileSync(path.join(tamperedDir, compFile), dummyCorrupt);
    fs.writeFileSync(path.join(tamperedDir, 'manifest.json'), JSON.stringify(origManifest, null, 2));

    const verifyRes = verifySnapshot(tamperedDir);
    assert.strictEqual(verifyRes.valid, false, 'Tampered snapshot must fail verification');
    assert.ok(verifyRes.errors.length > 0, 'Must report checksum mismatch errors');

    // Clean up tampered dir
    fs.rmSync(tamperedDir, { recursive: true, force: true });
  });

  await test('Executes restoration from snapshot successfully', async () => {
    const restoreRes = await restoreFromSnapshot(createdSnapshotDir);
    assert.strictEqual(restoreRes.status, 'SUCCESS', 'Restoration status must be SUCCESS');
    assert.ok(restoreRes.durationMs >= 0, 'Must record restoration duration');
  });

  await test('Executes end-to-end Disaster Recovery drill simulation with 100% data fidelity', async () => {
    const drillMetrics = await runDrillSimulation();
    assert.strictEqual(drillMetrics.success, true, 'DR drill simulation must succeed');
    assert.strictEqual(drillMetrics.dataFidelity, '100%', 'Data fidelity must be 100%');
    assert.ok(drillMetrics.rtoMeasuredMs < 5000, 'RTO for in-memory snapshot must be under 5s');
    console.log(`     ⚡ DR Drill Metrics: RTO = ${drillMetrics.rtoMeasuredMs.toFixed(2)}ms | Records = ${drillMetrics.totalRecords}`);
  });

  // Clean up test backup directory
  try {
    fs.rmSync(tempBackupDir, { recursive: true, force: true });
  } catch (_) {}

  return { passed, failed };
}

if (require.main === module) {
  runDisasterRecoveryTests();
}

module.exports = { runDisasterRecoveryTests };
