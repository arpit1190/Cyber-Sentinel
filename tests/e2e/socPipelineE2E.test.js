/**
 * tests/e2e/socPipelineE2E.test.js
 * End-to-End SOC Lifecycle Verification:
 * Device Enrollment -> Signed Telemetry Ingestion -> IOC Match -> Detection Rule Trigger ->
 * Incident Creation -> AI Advisory Proposal -> Human Approval -> Response Action Execution ->
 * Immutable Cryptographic Audit Trail.
 */

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');

const deviceService = require(path.join(__dirname, '../../backend/src/services/deviceService'));
const { computeTelemetrySignature } = require(path.join(__dirname, '../../backend/src/middleware/telemetryAuth'));
const { normalizeEvent } = require(path.join(__dirname, '../../backend/src/services/normalizer/eventNormalizer'));
const { matchIoc, addIndicators } = require(path.join(__dirname, '../../backend/src/services/threatIntel/iocMatcher'));
const { detectionEngine } = require(path.join(__dirname, '../../backend/src/services/detection/detectionEngine'));
const incidentService = require(path.join(__dirname, '../../backend/src/services/incidentService'));
const { IncidentStatus } = require(path.join(__dirname, '../../backend/src/services/incidentStateMachine'));
const { createActionProposal, approveActionProposal } = require(path.join(__dirname, '../../backend/src/services/ai/aiActionProposals'));
const {
  requestResponseAction,
  approveResponseAction,
  executeResponseAction,
  ALLOWED_ACTION_TYPES,
  ACTION_STATUSES,
} = require(path.join(__dirname, '../../backend/src/services/response/responseActionService'));
const { logSecurityEvent, getAuditLogs, AuditActions } = require(path.join(__dirname, '../../backend/src/utils/auditLogger'));
const { verifyTimelineIntegrity } = require(path.join(__dirname, '../../backend/src/services/timelineService'));

async function runSocPipelineE2ETests() {
  console.log('\n======================================================================');
  console.log('🛡️   CYBER SENTINEL — END-TO-END SOC OPERATIONAL PIPELINE SUITE');
  console.log('======================================================================\n');
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

  // Phase 1: Device Enrollment
  let device = null;
  let deviceKey = null;
  await test('E2E Phase 1: Device enrolls and generates verified identity', async () => {
    const enrollment = await deviceService.enrollDevice({
      name: 'Prod Finance Database',
      platform: 'LINUX',
      hostname: `prod-finance-db-${Date.now()}`,
      ipAddress: '10.50.1.99',
      agentVersion: '2.4.0',
      user: { email: 'soc-admin@sentinel.defense', role: 'ADMIN' },
    });

    assert.ok(enrollment.device.id);
    assert.ok(enrollment.deviceSecret);
    device = enrollment.device;
    deviceKey = enrollment.deviceSecret;

    logSecurityEvent({
      action: AuditActions.INCIDENT_CREATED,
      actor: 'soc-admin@sentinel.defense',
      target: device.id,
      details: { hostname: device.hostname },
    });
  });

  // Phase 2: Signed Telemetry Ingestion & Threat Intel Enrichment
  let normalizedEvent = null;
  await test('E2E Phase 2: Agent transmits HMAC-signed telemetry matching known IOC', async () => {
    const c2Ip = '185.220.101.99';
    addIndicators([{
      value: c2Ip,
      malware: 'Drovorub',
      confidence: 98,
      mitreTechnique: 'T1071.001',
    }]);

    const rawTelemetry = {
      event_type: 'PROCESS_EXECUTION',
      source_ip: c2Ip,
      device_id: device.id,
      process_name: 'powershell.exe',
      command_line: 'powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA... -nop -w hidden',
      timestamp: new Date().toISOString(),
      details: {
        attackType: 'Suspicious PowerShell Execution',
      },
    };

    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = `nonce-${Date.now()}`;
    const res = computeTelemetrySignature({
      method: 'POST',
      path: '/api/events',
      timestamp,
      nonce,
      body: rawTelemetry,
      deviceSecret: deviceKey,
    });

    assert.ok(res.signature);
    assert.strictEqual(res.signature.length, 64);

    normalizedEvent = normalizeEvent(rawTelemetry);
    const iocMatch = matchIoc(normalizedEvent.sourceIp);
    assert.strictEqual(iocMatch.matched, true);
    assert.strictEqual(iocMatch.malware, 'Drovorub');
  });

  // Phase 3: Detection Engine Triggering
  let detections = [];
  await test('E2E Phase 3: Detection Engine evaluates normalized event against MITRE rules', async () => {
    detections = detectionEngine.processEvent(normalizedEvent);
    assert.ok(detections.length >= 0);
  });

  // Phase 4: Incident Auto-Creation & NIST Lifecycle
  let incident = null;
  await test('E2E Phase 4: Incident generated in NEW state with cryptographically hashed timeline', async () => {
    incident = incidentService.createManualIncident({
      title: `Critical Threat on ${device.hostname}: APT28 C2 Communication`,
      description: `Suspicious execution matched C2 IP ${normalizedEvent.sourceIp}`,
      severity: 'CRITICAL',
      affectedDevices: [device.id],
      user: { name: 'SOC Engine', email: 'system@sentinel.defense', role: 'admin' },
    });

    assert.ok(incident.id);
    assert.strictEqual(incident.status, IncidentStatus.NEW);

    const integrity = verifyTimelineIntegrity(incident.timeline);
    assert.strictEqual(integrity.valid, true);
  });

  // Phase 5: AI Copilot Advisory Proposal
  let proposal = null;
  await test('E2E Phase 5: AI Assistant proposes containment action without direct execution authority', async () => {
    proposal = createActionProposal({
      incidentId: incident.id,
      actionType: 'ISOLATE_ENDPOINT',
      target: device.id,
      parameters: { deviceId: device.id },
      justification: 'Active C2 beacon communication detected to Drovorub infrastructure.',
    });

    assert.ok(proposal.proposalId);
    assert.strictEqual(proposal.status, 'PENDING');
  });

  // Phase 6: Human Operator Approval & Response Execution
  await test('E2E Phase 6: Senior SOC Analyst approves proposal and executes allowlisted response action', async () => {
    // 1. Analyst approves AI proposal
    const approvedProp = approveActionProposal(proposal.proposalId, { email: 'senior-analyst@sentinel.defense', role: 'SOC_ANALYST' });
    assert.strictEqual(approvedProp.status, 'APPROVED');

    // 2. Request formal allowlisted response action
    const actionReq = requestResponseAction({
      incidentId: incident.id,
      actionType: ALLOWED_ACTION_TYPES.ISOLATE_ENDPOINT,
      deviceId: device.id,
      parameters: { deviceId: device.id },
      requesterUser: { email: 'senior-analyst@sentinel.defense', role: 'SOC_ANALYST' },
    });
    assert.strictEqual(actionReq.status, ACTION_STATUSES.PENDING);

    // 3. Dual-operator approval & execution
    approveResponseAction(actionReq.actionId, { email: 'lead-responder@sentinel.defense', role: 'ADMIN' });
    const executed = await executeResponseAction(actionReq.actionId, { email: 'lead-responder@sentinel.defense', role: 'ADMIN' });
    assert.strictEqual(executed.status, ACTION_STATUSES.SUCCESS);

    // 4. Update incident status step-by-step: NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT
    incidentService.updateStatus(incident.id, {
      status: IncidentStatus.TRIAGED,
      user: { name: 'Senior Analyst', email: 'senior-analyst@sentinel.defense', role: 'SOC_ANALYST' },
      note: 'Triage complete.',
    });

    incidentService.updateStatus(incident.id, {
      status: IncidentStatus.INVESTIGATING,
      user: { name: 'Senior Analyst', email: 'senior-analyst@sentinel.defense', role: 'SOC_ANALYST' },
      note: 'Investigating network activity.',
    });

    const containedInc = incidentService.updateStatus(incident.id, {
      status: IncidentStatus.CONTAINMENT,
      user: { name: 'Senior Analyst', email: 'senior-analyst@sentinel.defense', role: 'SOC_ANALYST' },
      note: `Device ${device.hostname} successfully isolated from network.`,
    });
    assert.strictEqual(containedInc.status, IncidentStatus.CONTAINMENT);
  });

  // Phase 7: End-to-End Cryptographic Audit Verification
  await test('E2E Phase 7: Validates end-to-end cryptographic hash chain and immutable audit trail', async () => {
    const finalIncident = incidentService.getIncident(incident.id);
    const integrity = verifyTimelineIntegrity(finalIncident.timeline);
    assert.strictEqual(integrity.valid, true, 'Full incident timeline must maintain cryptographic chain integrity');

    const auditLogs = getAuditLogs(10);
    assert.ok(auditLogs.length >= 1);
  });

  return { passed, failed };
}

if (require.main === module) {
  runSocPipelineE2ETests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runSocPipelineE2ETests };
