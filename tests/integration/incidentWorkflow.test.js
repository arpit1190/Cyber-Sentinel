/**
 * tests/integration/incidentWorkflow.test.js
 * Integration test suite for Incident Management Workflow, NIST/SANS State Transitions,
 * and Cryptographic Timeline Immutability.
 */

const assert = require('assert');
const path = require('path');

const incidentService = require(path.join(__dirname, '../../backend/src/services/incidentService'));
const { IncidentStatus, validateStateTransition } = require(path.join(__dirname, '../../backend/src/services/incidentStateMachine'));
const { verifyTimelineIntegrity } = require(path.join(__dirname, '../../backend/src/services/timelineService'));

async function runIncidentWorkflowIntegrationTests() {
  console.log('\n--- [Integration] Incident Lifecycle, State Machine & Timeline Hashing ---');
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

  let incident = null;

  // 1. Incident Creation
  await test('Creates a new security incident initialized to NEW status', async () => {
    incident = incidentService.createManualIncident({
      title: 'Credential Stuffing on Auth Gateway',
      description: 'Multiple failed logins detected from known TOR exit nodes.',
      severity: 'HIGH',
      assignee: 'analyst@sentinel.defense',
      user: { name: 'System Detector', email: 'system@sentinel.defense', role: 'admin' },
    });

    assert.ok(incident.id);
    assert.strictEqual(incident.status, IncidentStatus.NEW);
    assert.ok(Array.isArray(incident.timeline));
    assert.ok(incident.timeline.length > 0, 'Timeline must contain creation event');
  });

  // 2. Valid State Transitions (NIST SP 800-61r2)
  await test('Transitions status across valid NIST lifecycle: NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT', async () => {
    // NEW -> TRIAGED
    const t1 = incidentService.updateStatus(incident.id, {
      status: IncidentStatus.TRIAGED,
      user: { name: 'Analyst One', email: 'analyst1@sentinel.defense', role: 'analyst' },
      note: 'Initial triage confirmed active attack',
    });
    assert.strictEqual(t1.status, IncidentStatus.TRIAGED);

    // TRIAGED -> INVESTIGATING
    const t2 = incidentService.updateStatus(incident.id, {
      status: IncidentStatus.INVESTIGATING,
      user: { name: 'Analyst One', email: 'analyst1@sentinel.defense', role: 'analyst' },
      note: 'Assigned investigator and analyzing logs',
    });
    assert.strictEqual(t2.status, IncidentStatus.INVESTIGATING);

    // INVESTIGATING -> CONTAINMENT
    const t3 = incidentService.updateStatus(incident.id, {
      status: IncidentStatus.CONTAINMENT,
      user: { name: 'Analyst One', email: 'analyst1@sentinel.defense', role: 'analyst' },
      note: 'Source IPs blocked at perimeter firewall',
    });
    assert.strictEqual(t3.status, IncidentStatus.CONTAINMENT);
  });

  // 3. Invalid State Transition Rejection
  await test('Rejects invalid backward state transition (e.g., CLOSED -> NEW)', async () => {
    const valid = validateStateTransition(IncidentStatus.CLOSED, IncidentStatus.NEW);
    assert.strictEqual(valid.valid, false);
    
    assert.throws(() => {
      incidentService.updateStatus(incident.id, {
        status: IncidentStatus.NEW,
        user: { name: 'Analyst One', email: 'analyst1@sentinel.defense', role: 'analyst' },
        note: 'Attempting illegal reset',
      });
    });
  });

  // 4. Timeline Event Cryptographic Hashing & Chaining
  await test('Generates immutable SHA-256 hash chain across timeline events', async () => {
    const updated = incidentService.getIncident(incident.id);
    const timeline = updated.timeline;

    assert.ok(timeline.length >= 3);

    for (let i = 0; i < timeline.length; i++) {
      const event = timeline[i];
      assert.ok(event.hash, `Event ${i} must have a SHA-256 hash`);
      assert.strictEqual(event.hash.length, 64);
    }

    const integrityCheck = verifyTimelineIntegrity(timeline);
    assert.strictEqual(integrityCheck.valid, true);
  });

  // 5. Tamper Detection
  await test('Detects tampering if historical timeline event content is modified', async () => {
    const updated = incidentService.getIncident(incident.id);
    const tamperedTimeline = JSON.parse(JSON.stringify(updated.timeline));

    // Tamper with historical hash pointer
    tamperedTimeline[0].hash = 'a'.repeat(64);

    const integrityCheck = verifyTimelineIntegrity(tamperedTimeline);
    assert.strictEqual(integrityCheck.valid, false, 'Tampered event content must invalidate hash chain');
  });

  return { passed, failed };
}

if (require.main === module) {
  runIncidentWorkflowIntegrationTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runIncidentWorkflowIntegrationTests };
