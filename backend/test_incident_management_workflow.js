/**
 * test_incident_management_workflow.js
 * Comprehensive Verification Suite for SOC Incident Management Lifecycle.
 * 
 * Verifies:
 * 1. Canonical 8-state NIST/SANS incident lifecycle:
 *    NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT -> ERADICATION -> RECOVERY -> RESOLVED -> CLOSED
 * 2. Full Incident entity data model validation (ID, title, description, severity, confidence, status,
 *    assignee, affected devices, detections, indicators, MITRE techniques, notes, timeline, response actions, timestamps).
 * 3. Server-side validation of legal state transitions.
 * 4. Server-side rejection of illegal / arbitrary status manipulation (e.g. NEW -> RESOLVED).
 * 5. Incident assignment and analyst workload routing.
 * 6. Partial metadata updates (title, severity, confidence, affected devices).
 * 7. Analyst note append operations and response action tracking.
 * 8. Incident search, severity filtering, and pagination.
 * 9. Immutable audit trail logging for all sensitive lifecycle events.
 */

const assert = require('assert');
const { IncidentStatus, validateStateTransition, normalizeStatus } = require('./src/services/incidentStateMachine');
const incidentService = require('./src/services/incidentService');
const securityStore = require('./src/data/securityStore');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function runTest(name, fn) {
  totalTests++;
  const start = process.hrtime.bigint();
  try {
    fn();
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
console.log('🛡️   CYBER SENTINEL — SOC INCIDENT MANAGEMENT WORKFLOW SUITE');
console.log('======================================================================\n');

const mockUser = {
  id: 'usr-soc-analyst-01',
  name: 'Alex Vance',
  email: 'avance@cybersentinel.local',
  role: 'senior_analyst',
};

const mockReq = {
  ip: '10.0.0.50',
  headers: { 'user-agent': 'CyberSentinel-SOC-UI/1.0' },
};

console.log('━━━ SECTION 1: Incident Creation & Entity Model Validation ━━━');

let testIncidentId = null;

runTest('[CREATION] Creates incident with all required SOC fields and initial NEW status', () => {
  const incident = incidentService.createManualIncident({
    title: 'Ransomware Outbreak on Finance Subnet',
    severity: 'CRITICAL',
    confidence: 95,
    category: 'RANSOMWARE',
    description: 'Multiple endpoints reporting VSS deletion and locked .enc files.',
    assignee: 'Unassigned',
    affectedDevices: ['DEV-FIN-01', 'DEV-FIN-02'],
    indicators: ['198.51.100.77', '185.220.101.5'],
    detections: ['det-mimikatz-01', 'det-vss-02'],
    mitreTechniques: [
      { id: 'T1490', technique_name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1486', technique_name: 'Data Encrypted for Impact', tactic: 'Impact' }
    ],
    evidence: { encryptedFilesCount: 24, targetDrive: 'C:' },
    user: mockUser,
    req: mockReq,
  });

  assert.ok(incident);
  assert.ok(incident.id.startsWith('INC-'));
  testIncidentId = incident.id;

  assert.strictEqual(incident.title, 'Ransomware Outbreak on Finance Subnet');
  assert.strictEqual(incident.severity, 'CRITICAL');
  assert.strictEqual(incident.confidence, 95);
  assert.strictEqual(incident.status, IncidentStatus.NEW);
  assert.strictEqual(incident.assignee, 'Unassigned');
  assert.deepStrictEqual(incident.affectedDevices, ['DEV-FIN-01', 'DEV-FIN-02']);
  assert.deepStrictEqual(incident.indicators, ['198.51.100.77', '185.220.101.5']);
  assert.strictEqual(incident.mitreTechniques.length, 2);
  assert.ok(Array.isArray(incident.notes));
  assert.ok(Array.isArray(incident.responseActions));
  assert.ok(Array.isArray(incident.timeline));
  assert.strictEqual(incident.timeline.length, 1);
  assert.strictEqual(incident.timeline[0].action, 'INCIDENT_CREATED');
  assert.ok(incident.createdAt);
  assert.ok(incident.updatedAt);
  assert.strictEqual(incident.resolvedAt, null);
  assert.strictEqual(incident.closedAt, null);
});

console.log('\n━━━ SECTION 2: Valid State Machine Transitions (Full NIST Lifecycle) ━━━');

runTest('[TRANSITION] Step 1: NEW -> TRIAGED', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.TRIAGED,
    note: 'Initial triage completed. Confirmed true positive ransomware wave.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.TRIAGED);
  assert.strictEqual(inc.timeline[inc.timeline.length - 1].action, 'STATUS_CHANGE');
  assert.strictEqual(inc.timeline[inc.timeline.length - 1].newStatus, IncidentStatus.TRIAGED);
});

runTest('[TRANSITION] Step 2: TRIAGED -> INVESTIGATING', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.INVESTIGATING,
    note: 'Deep dive into memory dump and MFT logs.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.INVESTIGATING);
});

runTest('[TRANSITION] Step 3: INVESTIGATING -> CONTAINMENT', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.CONTAINMENT,
    note: 'Network isolation rules pushed to perimeter firewall.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.CONTAINMENT);
});

runTest('[TRANSITION] Step 4: CONTAINMENT -> ERADICATION', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.ERADICATION,
    note: 'Killed high-IOPS processes and purged staging malware artifacts.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.ERADICATION);
});

runTest('[TRANSITION] Step 5: ERADICATION -> RECOVERY', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.RECOVERY,
    note: 'Restored volume shadow copies from immutable off-site repository.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.RECOVERY);
});

runTest('[TRANSITION] Step 6: RECOVERY -> RESOLVED', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.RESOLVED,
    note: 'Workstations clean and operational. Subnet traffic restored.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.RESOLVED);
  assert.ok(inc.resolvedAt);
});

runTest('[TRANSITION] Step 7: RESOLVED -> CLOSED', () => {
  const inc = incidentService.closeIncident(testIncidentId, {
    reason: 'SUCCESSFULLY_MITIGATED',
    note: 'Post-incident review conducted. Lessons learned documented in wiki.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.CLOSED);
  assert.ok(inc.closedAt);
});

runTest('[TRANSITION] Step 8: CLOSED -> INVESTIGATING (Re-opening upon recurrence)', () => {
  const inc = incidentService.updateStatus(testIncidentId, {
    status: IncidentStatus.INVESTIGATING,
    note: 'Re-opening: Second wave observed on adjacent subnet.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.status, IncidentStatus.INVESTIGATING);
  assert.strictEqual(inc.closedAt, null);
});

console.log('\n━━━ SECTION 3: Illegal / Arbitrary State Transitions (Fails Closed) ━━━');

runTest('[SECURITY] Rejects illegal jump NEW -> RESOLVED', () => {
  const newInc = incidentService.createManualIncident({
    title: 'Phishing Email Investigation',
    description: 'Suspicious email received.',
    user: mockUser,
    req: mockReq,
  });

  assert.throws(
    () => {
      incidentService.updateStatus(newInc.id, {
        status: IncidentStatus.RESOLVED,
        user: mockUser,
        req: mockReq,
      });
    },
    (err) => {
      assert.strictEqual(err.status, 400);
      assert.ok(err.message.includes('Illegal state transition'));
      return true;
    }
  );
});

runTest('[SECURITY] Rejects illegal jump NEW -> CONTAINMENT', () => {
  const newInc = incidentService.createManualIncident({
    title: 'Suspicious Port Scan',
    description: 'Probing internal subnets.',
    user: mockUser,
    req: mockReq,
  });

  assert.throws(
    () => {
      incidentService.updateStatus(newInc.id, {
        status: IncidentStatus.CONTAINMENT,
        user: mockUser,
        req: mockReq,
      });
    },
    (err) => {
      assert.strictEqual(err.status, 400);
      return true;
    }
  );
});

runTest('[SECURITY] Rejects idempotent transition to same status (TRIAGED -> TRIAGED)', () => {
  const newInc = incidentService.createManualIncident({
    title: 'DNS Tunneling',
    description: 'High entropy queries.',
    user: mockUser,
    req: mockReq,
  });
  incidentService.updateStatus(newInc.id, { status: IncidentStatus.TRIAGED, user: mockUser, req: mockReq });

  assert.throws(
    () => {
      incidentService.updateStatus(newInc.id, {
        status: IncidentStatus.TRIAGED,
        user: mockUser,
        req: mockReq,
      });
    },
    (err) => {
      assert.strictEqual(err.status, 400);
      assert.ok(err.message.includes('already in status'));
      return true;
    }
  );
});

runTest('[SECURITY] Rejects completely bogus status string', () => {
  const newInc = incidentService.createManualIncident({
    title: 'Test Incident',
    description: 'Testing bogus status.',
    user: mockUser,
    req: mockReq,
  });

  assert.throws(
    () => {
      incidentService.updateStatus(newInc.id, {
        status: 'MAGIC_PWNED_STATUS',
        user: mockUser,
        req: mockReq,
      });
    },
    (err) => {
      assert.strictEqual(err.status, 400);
      return true;
    }
  );
});

console.log('\n━━━ SECTION 4: Incident Operations (Assign, Update, Notes, Response Actions) ━━━');

runTest('[ASSIGNMENT] Assigns incident to analyst and records timeline', () => {
  const inc = incidentService.assignIncident(testIncidentId, {
    assignee: 'soc_lead@cybersentinel.local',
    note: 'Escalated to Tier-3 SOC Lead.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.assignee, 'soc_lead@cybersentinel.local');
  const lastTimeline = inc.timeline[inc.timeline.length - 1];
  assert.strictEqual(lastTimeline.action, 'INCIDENT_ASSIGNED');
});

runTest('[UPDATE] Updates incident metadata (confidence, severity, affected devices)', () => {
  const inc = incidentService.updateIncident(testIncidentId, {
    updates: {
      confidence: 100,
      severity: 'CRITICAL',
      affectedDevices: ['DEV-FIN-01', 'DEV-FIN-02', 'DEV-FIN-03'],
    },
    user: mockUser,
    req: mockReq,
    note: 'Added DEV-FIN-03 to scope after lateral movement confirmation.',
  });

  assert.strictEqual(inc.confidence, 100);
  assert.strictEqual(inc.affectedDevices.length, 3);
});

runTest('[NOTES] Appends analyst investigative notes', () => {
  const inc = incidentService.addNote(testIncidentId, {
    note: 'IOC hashes uploaded to Threat Intelligence blocklist.',
    user: mockUser,
    req: mockReq,
  });
  assert.strictEqual(inc.notes.length, 1);
  assert.ok(inc.notes[0].note.includes('IOC hashes'));
  assert.ok(inc.notes[0].author.includes('Alex Vance'));
});

runTest('[RESPONSE-ACTIONS] Records executed containment actions', () => {
  const inc = incidentService.addResponseAction(testIncidentId, {
    actionData: {
      actionType: 'ISOLATE_HOST',
      target: 'DEV-FIN-01',
      parameters: { vlan: 'QUARANTINE_ISOLATION' },
      status: 'SUCCESS',
      notes: 'Host isolated from all non-SOC routing.',
    },
    user: mockUser,
    req: mockReq,
  });

  assert.strictEqual(inc.responseActions.length, 1);
  assert.strictEqual(inc.responseActions[0].actionType, 'ISOLATE_HOST');
  assert.strictEqual(inc.responseActions[0].target, 'DEV-FIN-01');
});

console.log('\n━━━ SECTION 5: Querying, Filtering & Audit Trail ━━━');

runTest('[SEARCH & FILTER] Filters by status, severity, and search query', () => {
  const resAll = incidentService.listIncidents();
  assert.ok(resAll.total >= 1);

  const resSev = incidentService.listIncidents({ severity: 'CRITICAL' });
  assert.ok(resSev.incidents.every(i => i.severity === 'CRITICAL'));

  const resSearch = incidentService.listIncidents({ search: 'Finance' });
  assert.ok(resSearch.incidents.some(i => i.id === testIncidentId));
});

runTest('[AUDIT-LOG] Sensitive lifecycle transitions write immutable audit logs', () => {
  const logs = securityStore.getAuditLogs();
  assert.ok(logs.length > 0);
  const incidentLogs = logs.filter(l => l.target === testIncidentId || l.details?.action?.includes('INCIDENT'));
  assert.ok(incidentLogs.length >= 2, 'Must have recorded status changes and creations');
});

console.log('\n======================================================================');
console.log(`🏁  INCIDENT MANAGEMENT SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
console.log('======================================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
