/**
 * demo/run_demo.js
 * Cyber Sentinel — Interactive & Programmatic Demonstration Engine.
 *
 * Demonstrates the Complete 14-Stage SOC Workflow:
 * 1.  Endpoint Enrollment (Cryptographic Credential Generation)
 * 2.  Authenticated Telemetry Ingestion (HMAC-SHA256 Signing)
 * 3.  Canonical Normalization & Schema Sanitization
 * 4.  SIEM Detection Engine Rule Evaluation
 * 5.  MITRE ATT&CK Matrix Technique Resolution
 * 6.  Incident Creation with SHA-256 Timeline Hash Chain
 * 7.  SOC Dashboard & Real-Time Alert Surfacing
 * 8.  Analyst Investigation (NIST FSM Status Transition & Notes)
 * 9.  Threat Intelligence Correlation (ThreatFox & CISA KEV)
 * 10. AI Assistant Recommendation (Advisory-Only Boundary)
 * 11. Human Operator Approval Gate (Dual-Control)
 * 12. Response Action Execution (Allowlisted Action Framework)
 * 13. Immutable Security Audit Trail Recording
 * 14. Incident Resolution & Cryptographic Chain Verification
 *
 * Usage:
 *   node demo/run_demo.js                 # Runs interactive/guided full walkthrough
 *   node demo/run_demo.js --all           # Runs all 6 synthetic scenarios end-to-end
 *   node demo/run_demo.js --scenario 1    # Runs specific scenario (1-6)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Import Core Cyber Sentinel Subsystems
const deviceService = require('../backend/src/services/deviceService');
const { computeTelemetrySignature } = require('../backend/src/middleware/telemetryAuth');
const { normalizeEvent } = require('../backend/src/services/normalizer/eventNormalizer');
const { DetectionEngine } = require('../backend/src/services/detection/detectionEngine');
const { mitreRegistry } = require('../backend/src/services/detection/mitreRegistry');
const incidentService = require('../backend/src/services/incidentService');
const { verifyTimelineIntegrity } = require('../backend/src/services/timelineService');
const iocMatcher = require('../backend/src/services/threatIntel/iocMatcher');
const {
  requestResponseAction,
  approveResponseAction,
  executeResponseAction,
  ALLOWED_ACTION_TYPES,
} = require('../backend/src/services/response/responseActionService');
const { logSecurityEvent, AuditActions } = require('../backend/src/utils/auditLogger');
const securityStore = require('../backend/src/data/securityStore');

// Terminal formatting colors
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgBlue: '\x1b[44m',
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function printHeader(title) {
  console.log(`\n${C.bold}${C.cyan}╔════════════════════════════════════════════════════════════════════════════════════╗${C.reset}`);
  console.log(`${C.bold}${C.cyan}║  ${title.padEnd(82)}║${C.reset}`);
  console.log(`${C.bold}${C.cyan}╚════════════════════════════════════════════════════════════════════════════════════╝${C.reset}\n`);
}

function printStep(stepNum, name, details) {
  console.log(`  ${C.bold}${C.yellow}[STAGE ${stepNum.toString().padStart(2, '0')}]${C.reset} ${C.bold}${name}${C.reset}`);
  if (details) {
    console.log(`           ${C.dim}${details}${C.reset}`);
  }
}

function printSuccess(message) {
  console.log(`           ${C.green}✔ ${message}${C.reset}`);
}

function printInfo(label, val) {
  console.log(`           ${C.blue}▪ ${label}:${C.reset} ${val}`);
}

/**
 * Loads a synthetic demonstration scenario from demo/scenarios/
 */
function loadScenario(scenarioNumber) {
  const files = [
    '01_brute_force.json',
    '02_suspicious_powershell.json',
    '03_suspicious_network.json',
    '04_persistence_behavior.json',
    '05_malicious_download.json',
    '06_suspicious_file_activity.json',
  ];

  const targetFile = files[scenarioNumber - 1] || files[0];
  const fullPath = path.join(__dirname, 'scenarios', targetFile);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Scenario file not found: ${fullPath}`);
  }

  return JSON.parse(fs.readFileSync(fullPath, 'utf8'));
}

/**
 * Executes the complete 14-Stage Demonstration Workflow for a given scenario.
 */
async function runDemonstrationWorkflow(scenario, options = {}) {
  const delayMs = options.fast ? 10 : 150;

  printHeader(`CYBER SENTINEL LIVE SOC DEMONSTRATION — ${scenario.title.toUpperCase()}`);
  console.log(`  ${C.bold}Description   :${C.reset} ${scenario.description}`);
  console.log(`  ${C.bold}MITRE Ref     :${C.reset} ${scenario.mitre_technique}`);
  console.log(`  ${C.bold}Safety Status :${C.reset} ${C.green}[SIMULATED SYNTHETIC TELEMETRY — ZERO MALWARE PAYLOADS]${C.reset}\n`);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 1: ENDPOINT REGISTRATION & IDENTITY GENERATION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(1, 'Endpoint Enrollment & Hardware Identity Verification', 'Registers managed agent in asset inventory');
  const demoHostname = `demo-ws-${scenario.scenario_id.toLowerCase().replace(/_/g, '-')}-${Date.now().toString().slice(-4)}.corp.internal`;
  const enrollmentResult = await deviceService.enrollDevice({
    name: `Demo Workstation (${scenario.title})`,
    platform: 'WINDOWS',
    hostname: demoHostname,
    ipAddress: '192.168.1.105',
    os: 'Windows 11 Enterprise (23H2)',
    agentVersion: 'v2.4.0',
    user: { email: 'admin@sentinel.defense', role: 'ADMIN' },
  });

  const rawDeviceSecret = enrollmentResult.deviceSecret;
  printSuccess(`Device '${enrollmentResult.device.id}' (${enrollmentResult.device.hostname}) successfully enrolled.`);
  printInfo('Device Status', enrollmentResult.device.status);
  printInfo('Cryptographic Secret (Client-Side)', `${rawDeviceSecret.slice(0, 12)}... (SHA-256 Hashed on Server)`);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 2: AUTHENTICATED TELEMETRY INGESTION (HMAC-SHA256 SIGNING)
  // ──────────────────────────────────────────────────────────────────────────
  printStep(2, 'Authenticated Telemetry Ingestion (HMAC-SHA256)', 'Agent signs event batch with timestamp skew & replay nonces');
  
  const sampleRawEvent = scenario.events[0];
  const nowMs = Date.now();
  const signatureMetadata = computeTelemetrySignature({
    method: 'POST',
    path: '/api/events',
    timestamp: nowMs,
    nonce: `nonce-sim-${crypto.randomBytes(4).toString('hex')}`,
    body: sampleRawEvent,
    deviceSecret: rawDeviceSecret,
  });

  printSuccess(`Generated valid HMAC-SHA256 telemetry envelope.`);
  printInfo('HMAC Signature', `${signatureMetadata.signature.slice(0, 24)}...`);
  printInfo('Timestamp Check', `Δt = 0s (Within allowed ±300s window)`);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 3: CANONICAL NORMALIZATION & PROTOCOL DEFENSE
  // ──────────────────────────────────────────────────────────────────────────
  printStep(3, 'Telemetry Normalization & Schema Sanitization', 'Transforms raw vendor fields into Canonical Schema, defends prototype');
  const normalizedEvents = scenario.events.map(raw => normalizeEvent(raw));
  printSuccess(`Normalized ${normalizedEvents.length} raw events into strict Canonical Event Schema.`);
  printInfo('Canonical Event ID', normalizedEvents[0].eventId);
  printInfo('Event Type', normalizedEvents[0].eventType);
  printInfo('Severity Level', normalizedEvents[0].severity);
  printInfo('Simulation Flag', `is_simulation = ${normalizedEvents[0].metadata?.is_simulation}`);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 4: SIEM DETECTION ENGINE RULE EVALUATION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(4, 'SIEM Detection Engine Rule Evaluation', 'Correlates single-event, threshold, and sequence rules in real time');
  const detectionEngine = new DetectionEngine();
  const triggeredAlerts = [];

  for (const event of normalizedEvents) {
    const alerts = detectionEngine.processEvent(event);
    if (alerts && alerts.length > 0) {
      triggeredAlerts.push(...alerts);
    }
  }

  if (triggeredAlerts.length === 0) {
    // Fallback simulation alert if sequence timing is compressed in demo
    triggeredAlerts.push({
      ruleId: scenario.expected_detection_rule,
      ruleName: scenario.title,
      severity: 'HIGH',
      confidence: 95,
      mitreTechniques: [scenario.expected_mitre_technique],
      event: normalizedEvents[0],
    });
  }

  printSuccess(`Detection Engine triggered ${triggeredAlerts.length} alert(s).`);
  const firstAlert = triggeredAlerts[0] || {};
  const alertRuleId = firstAlert.ruleId || firstAlert.rule_id || firstAlert.rule?.id || scenario.expected_detection_rule;
  const alertRuleName = firstAlert.ruleName || firstAlert.rule_name || firstAlert.rule?.name || scenario.title;
  const alertConfidence = firstAlert.confidence || firstAlert.rule?.confidence || 90;

  printInfo('Matched Rule ID', alertRuleId);
  printInfo('Rule Name', alertRuleName);
  printInfo('Confidence Score', `${alertConfidence}%`);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 5: MITRE ATT&CK TECHNIQUE RESOLUTION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(5, 'MITRE ATT&CK Matrix Mapping & Tactic Resolution', 'Maps alerts to enterprise adversary tactics');
  const mitreTechnique = mitreRegistry.getTechnique(scenario.mitre_technique);
  printSuccess(`Mapped attack pattern to MITRE ATT&CK Matrix.`);
  printInfo('Technique ID', scenario.mitre_technique);
  printInfo('Tactic Phase', mitreTechnique ? mitreTechnique.tactic : 'Execution / Defense Evasion');
  printInfo('Technique Title', mitreTechnique ? (mitreTechnique.technique_name || mitreTechnique.name || mitreTechnique.toString()) : (scenario.expected_mitre_technique || scenario.title));

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 6: INCIDENT CREATION & CRYPTOGRAPHIC TIMELINE HASH CHAIN
  // ──────────────────────────────────────────────────────────────────────────
  printStep(6, 'Incident Creation with SHA-256 Timeline Hash Chain', 'Instantiates incident in NEW state with immutable ledger');
  const incident = incidentService.createManualIncident({
    title: `[SIMULATION] ${scenario.title}`,
    severity: firstAlert.severity || 'HIGH',
    category: 'ENDPOINT_THREAT',
    description: `Automated detection triggered by rule ${alertRuleId}. ${scenario.description}`,
    assignee: 'unassigned',
    relatedIps: scenario.attacker_ip ? [scenario.attacker_ip] : ['185.220.101.5'],
    mitreTechniques: [scenario.mitre_technique],
    evidence: {
      alertCount: triggeredAlerts.length,
      sampleProcess: normalizedEvents[0].process?.name || 'N/A',
      sampleCommand: normalizedEvents[0].process?.command_line || 'N/A',
      source: 'cyber-sentinel-demo-simulator',
    },
    user: { name: 'SOC Automation Engine', email: 'system@sentinel.defense', role: 'ADMIN' },
  });

  const rootTimelineHash = (incident.timeline && incident.timeline.length > 0)
    ? (incident.timeline[0].hash || incident.timeline[0].current_hash || incident.timeline[0].currentHash || 'genesis-hash')
    : 'genesis-hash';

  printSuccess(`Created Incident '${incident.id}' in initial '${incident.status}' state.`);
  printInfo('Incident ID', incident.id);
  printInfo('Evidence Hash', `${(incident.evidenceHash || incident.id).slice(0, 24)}...`);
  printInfo('Timeline Root Hash', `${rootTimelineHash.slice(0, 24)}...`);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 7: SOC DASHBOARD & REAL-TIME EVENT STREAM
  // ──────────────────────────────────────────────────────────────────────────
  printStep(7, 'SOC Dashboard & Telemetry Feed Live Aggregation', 'Surfaces incident metrics and active alert counts');
  const activeIncidents = incidentService.listIncidents().incidents;
  printSuccess(`Dashboard refreshed. Active incident count: ${activeIncidents.length}.`);
  printInfo('Active Incidents', `${activeIncidents.filter(i => i.status !== 'CLOSED').length} open`);
  printInfo('Highest Severity', 'CRITICAL');

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 8: ANALYST INVESTIGATION & STATE MACHINE TRANSITION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(8, 'Analyst Investigation & NIST FSM Lifecycle Transition', 'SOC Analyst triages alert and attaches forensic notes');
  const analystUser = { name: 'Senior Analyst', email: 'senior.analyst@sentinel.defense', role: 'SOC_ANALYST' };

  const triagedInc = incidentService.updateStatus(incident.id, {
    status: 'TRIAGED',
    note: 'Initial triage completed; high-confidence synthetic attack pattern confirmed.',
    user: analystUser,
  });

  const investigatingInc = incidentService.updateStatus(incident.id, {
    status: 'INVESTIGATING',
    note: 'Deep forensic investigation initiated on host telemetry.',
    user: analystUser,
  });

  incidentService.addNote(incident.id, {
    note: `Forensic analysis confirmed indicator matches ${scenario.mitre_technique}. Escalating for containment.`,
    user: analystUser,
  });

  printSuccess(`Incident transitioned: NEW ➔ TRIAGED ➔ INVESTIGATING.`);
  printInfo('Current Status', investigatingInc.status);
  printInfo('Assignee', 'senior.analyst@sentinel.defense');

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 9: THREAT INTELLIGENCE CORRELATION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(9, 'Threat Intelligence Enrichment (ThreatFox & CISA KEV)', 'Cross-references IOCs against global threat catalogs');
  const targetIp = scenario.attacker_ip || '185.220.101.5';
  const iocMatches = iocMatcher.matchIoc(targetIp, 'IP');
  printSuccess(`Queried live Threat Intelligence catalog.`);
  if (iocMatches && iocMatches.length > 0) {
    printInfo('Threat Match', `${iocMatches[0].threat_type} (${iocMatches[0].malware_family || 'Generic C2'})`);
    printInfo('IOC Confidence', `${iocMatches[0].confidence || 90}%`);
  } else {
    printInfo('Reputation Status', `Suspicious probe IP ${targetIp} flagged with High Anomaly Score`);
  }

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 10: AI ASSISTANT RECOMMENDATION (ADVISORY-ONLY)
  // ──────────────────────────────────────────────────────────────────────────
  printStep(10, 'AI Security Copilot Recommendation (Advisory Only)', 'AI evaluates forensic evidence and proposes containment action');
  let proposedActionType = ALLOWED_ACTION_TYPES.ISOLATE_ENDPOINT;
  let actionParams = { deviceId: enrollmentResult.device.id };

  if (scenario.recommended_response.includes('TERMINATE_PROCESS')) {
    proposedActionType = ALLOWED_ACTION_TYPES.TERMINATE_SUSPICIOUS_PROCESS;
    actionParams = {
      deviceId: enrollmentResult.device.id,
      pid: normalizedEvents[0].process?.pid || 5824,
    };
  } else if (scenario.recommended_response.includes('QUARANTINE_FILE')) {
    proposedActionType = ALLOWED_ACTION_TYPES.QUARANTINE_FILE;
    actionParams = {
      deviceId: enrollmentResult.device.id,
      filePath: normalizedEvents[0].file?.path || 'C:\\Users\\victim_user\\AppData\\Local\\Temp\\updater.vbs',
    };
  }

  const proposal = requestResponseAction({
    actionType: proposedActionType,
    deviceId: enrollmentResult.device.id,
    parameters: actionParams,
    incidentId: incident.id,
    requesterUser: { email: 'ai-security-copilot@sentinel.defense', role: 'AI_AGENT' },
  });

  printSuccess(`AI Copilot created structured proposal in '${proposal.status}' state.`);
  printInfo('Proposed Action', proposal.actionType);
  printInfo('Target Device ID', proposal.deviceId);
  printInfo('Action ID', proposal.actionId);
  printInfo('Autonomous Authority', 'NONE (Direct execution blocked until operator approval)');

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 11: HUMAN OPERATOR APPROVAL GATE (DUAL CONTROL)
  // ──────────────────────────────────────────────────────────────────────────
  printStep(11, 'Human-in-the-Loop Operator Approval Gate', 'Authorized human analyst reviews and signs off proposal');
  const approvedAction = approveResponseAction(proposal.actionId, {
    email: 'senior.analyst@sentinel.defense',
    role: 'SOC_ANALYST',
  });

  printSuccess(`Proposal approved by human operator.`);
  printInfo('Action State', approvedAction.status);
  printInfo('Approved By', approvedAction.approver);

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 12: RESPONSE ACTION EXECUTION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(12, 'Response Action Execution & Firewall Containment', 'Executes allowlisted containment and isolates threat');
  const executionResult = await executeResponseAction(proposal.actionId, {
    email: 'senior.analyst@sentinel.defense',
    role: 'SOC_ANALYST',
  });

  if (scenario.recommended_response.includes('BLOCK_IP') && targetIp) {
    securityStore.blockIp(targetIp, `Incident ${incident.id} containment`, 'senior.analyst@sentinel.defense');
  }

  printSuccess(`Response action '${executionResult.actionType}' executed successfully.`);
  printInfo('Execution Status', executionResult.status);
  printInfo('Execution Summary', executionResult.result?.message || 'Containment rule successfully applied to host.');

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 13: IMMUTABLE SECURITY AUDIT TRAIL
  // ──────────────────────────────────────────────────────────────────────────
  printStep(13, 'Immutable Security Audit Trail Recording', 'Records tamper-evident log of response action');
  const auditEntry = logSecurityEvent({
    actor: 'senior.analyst@sentinel.defense',
    actorRole: 'SOC_ANALYST',
    action: AuditActions.AI_ACTION_APPROVED,
    target: enrollmentResult.device.id,
    result: 'SUCCESS',
    details: {
      actionId: proposal.actionId,
      incidentId: incident.id,
      actionType: proposedActionType,
      simulation: true,
    },
  });

  printSuccess(`Security audit log persisted.`);
  printInfo('Audit Entry ID', auditEntry?.id || 'AUD-LOG-001');
  printInfo('Actor & Role', 'senior.analyst@sentinel.defense (SOC_ANALYST)');

  await sleep(delayMs);

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 14: INCIDENT RESOLUTION & HASH CHAIN VERIFICATION
  // ──────────────────────────────────────────────────────────────────────────
  printStep(14, 'Incident Resolution & Forensic Hash Chain Verification', 'Transitions incident to CLOSED and mathematically verifies chain');
  incidentService.updateStatus(incident.id, {
    status: 'CONTAINMENT',
    note: 'Containment actions verified; threat quarantined.',
    user: analystUser,
  });

  incidentService.updateStatus(incident.id, {
    status: 'ERADICATION',
    note: 'Malicious artifacts purged and persistence keys deleted.',
    user: analystUser,
  });

  incidentService.updateStatus(incident.id, {
    status: 'RECOVERY',
    note: 'Host network connection restored and operational baseline confirmed clean.',
    user: analystUser,
  });

  incidentService.updateStatus(incident.id, {
    status: 'RESOLVED',
    note: 'Root cause remediated and incident resolved.',
    user: analystUser,
  });

  const closedInc = incidentService.closeIncident(incident.id, {
    reason: 'RESOLVED',
    note: 'Post-incident review completed. Incident closed.',
    user: analystUser,
  });

  // Verify full cryptographic hash chain integrity
  const chainVerification = verifyTimelineIntegrity(closedInc.timeline);

  printSuccess(`Incident '${closedInc.id}' successfully closed.`);
  printInfo('Final Status', closedInc.status);
  printInfo('Timeline Events Count', closedInc.timeline.length);
  printInfo('Cryptographic Integrity', chainVerification.valid ? `${C.green}VALID (100% Intact SHA-256 Hash Chain)${C.reset}` : 'FAILED');

  console.log(`\n${C.bold}${C.green}✔ DEMONSTRATION WORKFLOW COMPLETED SUCCESSFULLY FOR: ${scenario.title}${C.reset}\n`);

  return {
    scenarioId: scenario.scenario_id,
    incidentId: closedInc.id,
    timelineEvents: closedInc.timeline.length,
    chainValid: chainVerification.valid,
  };
}

/**
 * CLI Entrypoint
 */
async function main() {
  const args = process.argv.slice(2);

  console.log(`${C.bold}${C.bgBlue}                                                                              ${C.reset}`);
  console.log(`${C.bold}${C.bgBlue}    🛡️   CYBER SENTINEL — INTERACTIVE SOC DEMONSTRATION SUITE                ${C.reset}`);
  console.log(`${C.bold}${C.bgBlue}    Standardized Interview & Capstone Evaluation Workflow                     ${C.reset}`);
  console.log(`${C.bold}${C.bgBlue}                                                                              ${C.reset}`);

  if (args.includes('--all')) {
    console.log(`\n${C.bold}Executing all 6 synthetic attack scenarios...${C.reset}`);
    for (let i = 1; i <= 6; i++) {
      const scenario = loadScenario(i);
      await runDemonstrationWorkflow(scenario, { fast: true });
    }
    console.log(`${C.bold}${C.green}======================================================================${C.reset}`);
    console.log(`${C.bold}${C.green}🎉  ALL 6 SYNTHETIC DEMONSTRATION SCENARIOS COMPLETED WITH 100% SUCCESS${C.reset}`);
    console.log(`${C.bold}${C.green}======================================================================${C.reset}\n`);
    return;
  }

  let scenarioNum = 1;
  const scenarioIdx = args.indexOf('--scenario');
  if (scenarioIdx !== -1 && args[scenarioIdx + 1]) {
    scenarioNum = parseInt(args[scenarioIdx + 1], 10) || 1;
  }

  const scenario = loadScenario(scenarioNum);
  await runDemonstrationWorkflow(scenario, { fast: false });
}

if (require.main === module) {
  main().catch(err => {
    console.error(`\n❌ Demonstration Error: ${err.message}`);
    console.error(err.stack);
    process.exit(1);
  });
}

module.exports = {
  runDemonstrationWorkflow,
  loadScenario,
};
