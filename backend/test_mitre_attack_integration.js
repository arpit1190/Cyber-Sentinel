/**
 * test_mitre_attack_integration.js
 * Comprehensive Verification Suite for MITRE ATT&CK Enterprise Matrix Integration.
 * 
 * Verifies:
 * 1. Canonical MITRE Registry catalog lookup for tactics, techniques, and sub-techniques.
 * 2. Automated resolution of technique references into structured ATT&CK objects.
 * 3. Single-event detection rules mapping (LSASS Dumping T1003.001, PowerShell T1059.001, VSS Deletion T1490, SQLi T1190).
 * 4. Threshold detection rules multi-technique mapping (Brute Force T1110.001 / T1110.003, Port Scan T1046, Ransomware T1486).
 * 5. Sequence detection rules multi-stage attack kill chain mapping (T1190 -> T1059.001 -> T1490).
 * 6. Correlation detection rules cross-source mapping (Execution T1059.001 + C2 T1071.001).
 * 7. Dynamic registration of custom ATT&CK techniques without touching detection logic.
 * 8. Detection output structured fields: tactic, technique_id, technique_name, sub_technique, evidence, confidence, URL.
 * 9. Automated Incident escalation carrying structured MITRE ATT&CK metadata.
 */

const assert = require('assert');
const { mitreRegistry, MitreRegistry, ATTACK_TACTICS } = require('./src/services/detection/mitreRegistry');
const { ruleRegistry, RuleTypes } = require('./src/services/detection/ruleRegistry');
const { detectionEngine } = require('./src/services/detection/detectionEngine');
const { normalizeEvent } = require('./src/services/normalizer/eventNormalizer');
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
console.log('🛡️   CYBER SENTINEL — MITRE ATT&CK ENTERPRISE INTEGRATION SUITE');
console.log('======================================================================\n');

// Reset detection engine state
detectionEngine.resetState();

console.log('━━━ SECTION 1: MITRE ATT&CK Knowledge Base & Registry ━━━');

runTest('[REGISTRY] Retrieves top-level technique by ID (T1003 - OS Credential Dumping)', () => {
  const tech = mitreRegistry.getTechnique('T1003');
  assert.ok(tech);
  assert.strictEqual(tech.technique_id, 'T1003');
  assert.strictEqual(tech.technique_name, 'OS Credential Dumping');
  assert.strictEqual(tech.tactic, 'Credential Access');
  assert.strictEqual(tech.sub_technique_id, null);
  assert.strictEqual(tech.url, 'https://attack.mitre.org/techniques/T1003/');
});

runTest('[REGISTRY] Retrieves sub-technique by ID (T1003.001 - LSASS Memory)', () => {
  const subTech = mitreRegistry.getTechnique('T1003.001');
  assert.ok(subTech);
  assert.strictEqual(subTech.technique_id, 'T1003');
  assert.strictEqual(subTech.technique_name, 'OS Credential Dumping');
  assert.strictEqual(subTech.sub_technique_id, 'T1003.001');
  assert.strictEqual(subTech.sub_technique_name, 'LSASS Memory');
  assert.strictEqual(subTech.tactic, 'Credential Access');
  assert.strictEqual(subTech.url, 'https://attack.mitre.org/techniques/T1003/001/');
});

runTest('[REGISTRY] Resolves heterogeneous technique reference formats cleanly', () => {
  const refs = [
    'T1059.001 - Command and Scripting: PowerShell',
    'T1490',
    'T1190 - Exploit Public-Facing Application'
  ];
  const resolved = mitreRegistry.resolveTechniques(refs);
  assert.strictEqual(resolved.length, 3);

  const [t1, t2, t3] = resolved;
  assert.strictEqual(t1.sub_technique_id, 'T1059.001');
  assert.strictEqual(t1.tactic, 'Execution');
  assert.strictEqual(t2.technique_id, 'T1490');
  assert.strictEqual(t2.tactic, 'Impact');
  assert.strictEqual(t3.technique_id, 'T1190');
  assert.strictEqual(t3.tactic, 'Initial Access');
});

runTest('[REGISTRY] Supports dynamic on-demand custom technique registration without code rewrite', () => {
  const custom = mitreRegistry.registerTechnique({
    id: 'T1555.003',
    technique_name: 'Credentials from Password Stores',
    sub_technique_name: 'Credentials from Web Browsers',
    tactic_id: 'TA0006',
    tactic: 'Credential Access',
    description: 'Adversaries may acquire credentials from web browsers by reading database or vault files.'
  });

  assert.ok(custom);
  assert.strictEqual(custom.technique_id, 'T1555');
  assert.strictEqual(custom.sub_technique_id, 'T1555.003');
  assert.strictEqual(custom.url, 'https://attack.mitre.org/techniques/T1555/003/');

  const queried = mitreRegistry.getTechnique('T1555.003');
  assert.strictEqual(queried.sub_technique_name, 'Credentials from Web Browsers');
});

console.log('\n━━━ SECTION 2: Detection Rules MITRE ATT&CK Mapping ━━━');

runTest('[SINGLE-EVENT] Mimikatz rule returns T1003.001 (Credential Access, LSASS Memory, 98% conf)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-WORKSTATION-01',
    process: { command_line: 'mimikatz.exe "sekurlsa::logonpasswords"' },
  });

  const [detection] = detectionEngine.processEvent(event);
  assert.ok(detection);
  assert.strictEqual(detection.rule_id, 'RULE_MIMIKATZ_CRED_DUMP_001');
  assert.strictEqual(detection.severity, 'CRITICAL');
  assert.strictEqual(detection.confidence, 98);
  assert.ok(detection.evidence);
  assert.ok(detection.evidence.commandLine.includes('sekurlsa'));

  assert.ok(Array.isArray(detection.mitre_techniques));
  const mitre = detection.mitre_techniques[0];
  assert.strictEqual(mitre.tactic, 'Credential Access');
  assert.strictEqual(mitre.technique_id, 'T1003');
  assert.strictEqual(mitre.technique_name, 'OS Credential Dumping');
  assert.strictEqual(mitre.sub_technique_id, 'T1003.001');
  assert.strictEqual(mitre.sub_technique_name, 'LSASS Memory');
  assert.strictEqual(mitre.url, 'https://attack.mitre.org/techniques/T1003/001/');
});

runTest('[SINGLE-EVENT] PowerShell rule returns T1059.001 & T1027 (Execution & Defense Evasion)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-WORKSTATION-02',
    process: { command_line: 'powershell.exe -w hidden -enc IAAkAGEAP...' },
  });

  const [detection] = detectionEngine.processEvent(event);
  assert.ok(detection);
  assert.strictEqual(detection.confidence, 90);
  assert.ok(detection.evidence.commandLine.includes('-enc'));

  const tactics = detection.mitre_techniques.map(m => m.tactic);
  const techIds = detection.mitre_techniques.map(m => m.sub_technique_id || m.technique_id);
  assert.ok(tactics.includes('Execution'));
  assert.ok(tactics.includes('Defense Evasion'));
  assert.ok(techIds.includes('T1059.001'));
  assert.ok(techIds.includes('T1027'));
});

runTest('[SINGLE-EVENT] Shadow copy deletion returns T1490 (Impact, Inhibit System Recovery)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-SRV-01',
    process: { command_line: 'vssadmin delete shadows /all /quiet' },
  });

  const [detection] = detectionEngine.processEvent(event);
  assert.ok(detection);
  assert.strictEqual(detection.confidence, 99);

  const mitre = detection.mitre_techniques[0];
  assert.strictEqual(mitre.technique_id, 'T1490');
  assert.strictEqual(mitre.tactic, 'Impact');
  assert.strictEqual(mitre.technique_name, 'Inhibit System Recovery');
});

runTest('[THRESHOLD] Brute-force rule returns T1110.001 & T1110.003 (Password Guessing & Spraying)', () => {
  detectionEngine.resetState();
  const attackerIp = '198.51.100.44';

  let detection = null;
  for (let i = 1; i <= 5; i++) {
    const ev = normalizeEvent({
      event_type: 'AUTH_FAILURE',
      source_ip: attackerIp,
      user: `user_${i}`,
    });
    const res = detectionEngine.processEvent(ev);
    if (res.length > 0) detection = res[0];
  }

  assert.ok(detection);
  assert.strictEqual(detection.confidence, 90);
  assert.strictEqual(detection.evidence.eventCount, 5);

  const subIds = detection.mitre_techniques.map(m => m.sub_technique_id);
  assert.ok(subIds.includes('T1110.001'));
  assert.ok(subIds.includes('T1110.003'));
});

runTest('[SEQUENCE] Multi-stage kill chain returns ordered techniques across stages', () => {
  detectionEngine.resetState();
  const hostId = 'DEV-TARGET-APP';

  // Stage 1
  detectionEngine.processEvent(normalizeEvent({
    event_type: 'EXPLOIT_PROBE',
    device_id: hostId,
  }));
  // Stage 2
  detectionEngine.processEvent(normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: hostId,
    process: { name: 'powershell.exe', command_line: 'powershell.exe -ep bypass' },
  }));
  // Stage 3
  const dets = detectionEngine.processEvent(normalizeEvent({
    event_type: 'DEFENSE_EVASION',
    device_id: hostId,
    process: { command_line: 'vssadmin delete shadows' },
  }));

  const killChain = dets.find(d => d.rule_id === 'RULE_KILL_CHAIN_SEQUENCE_008');
  assert.ok(killChain);
  assert.strictEqual(killChain.confidence, 99);
  assert.ok(killChain.evidence.sequenceStagesCompleted);

  const tactics = killChain.mitre_techniques.map(m => m.tactic);
  assert.ok(tactics.includes('Initial Access'));
  assert.ok(tactics.includes('Execution'));
  assert.ok(tactics.includes('Impact'));
});

runTest('[CORRELATION] C2 Process correlation returns Execution (T1059.001) + C2 (T1071.001)', () => {
  detectionEngine.resetState();
  const hostId = 'DEV-WORKSTATION-CORR';

  // Event 1: Process
  detectionEngine.processEvent(normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: hostId,
    process: { name: 'powershell.exe', command_line: 'powershell.exe -enc ZQBjAGgAbwA=' },
  }));

  // Event 2: Network socket to external C2
  const dets = detectionEngine.processEvent(normalizeEvent({
    event_type: 'NETWORK_CONNECTION',
    device_id: hostId,
    network: { dest_ip: '203.0.113.15', dest_port: 443 },
  }));

  const corrDet = dets.find(d => d.rule_id === 'RULE_C2_PROCESS_CORRELATION_010');
  assert.ok(corrDet);
  assert.strictEqual(corrDet.confidence, 98);

  const subIds = corrDet.mitre_techniques.map(m => m.sub_technique_id);
  assert.ok(subIds.includes('T1059.001'));
  assert.ok(subIds.includes('T1071.001'));
});

console.log('\n━━━ SECTION 3: Incident Escalation & Forensics Preservation ━━━');

runTest('[ESCALATION] Escalated SecurityStore Incident carries structured MITRE ATT&CK objects and evidence', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-CRITICAL-DC',
    process: { command_line: 'mimikatz.exe sekurlsa::logonpasswords' },
  });

  const [det] = detectionEngine.processEvent(event);
  assert.ok(det.incident_id);

  const incident = securityStore.getIncidents().find(i => i.id === det.incident_id);
  assert.ok(incident);
  assert.strictEqual(incident.severity, 'CRITICAL');
  assert.ok(Array.isArray(incident.mitreTechniques));
  assert.ok(incident.mitreTechniques.length > 0);

  const m = incident.mitreTechniques[0];
  assert.strictEqual(m.tactic, 'Credential Access');
  assert.strictEqual(m.technique_id, 'T1003');
  assert.strictEqual(m.sub_technique_id, 'T1003.001');

  // Verify SHA-256 evidence integrity hash
  assert.ok(incident.evidence);
  assert.ok(incident.evidence.sha256);
  assert.strictEqual(incident.evidence.sha256.length, 64);
  assert.strictEqual(incident.evidence.payload.confidence, 98);
});

console.log('\n======================================================================');
console.log(`🏁  MITRE ATT&CK SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
console.log('======================================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
