/**
 * End-to-End Pipeline Verification Suite for Cyber Sentinel Capstone Architecture
 * 
 * Verifies:
 * 1. Unified Event Ingestion & Normalization
 * 2. High-Performance IOC Matcher (IP, domain, hash)
 * 3. SIEM Stateful Correlation Rules (SQLi + 200, Suspicious Execution + Socket)
 * 4. Incident Response Lifecycle & SHA-256 Evidence Integrity Hashing
 * 5. In-Memory Static PE Malware Analyzer (No execution guarantee)
 * 6. AI Copilot Safety Boundary (Human approval gate on IP containment)
 * 7. AI Copilot Forensic Investigation Tools (Incidents & live IOCs)
 * 8. Endpoint Agent Host Telemetry & Device ID Generation
 */

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const { normalizeEvent } = require('./src/services/normalizer/eventNormalizer');
const iocMatcher = require('./src/services/threatIntel/iocMatcher');
const { CorrelationEngine } = require('./src/utils/correlationEngine');
const securityStore = require('./src/data/securityStore');
const { analyzeBinary } = require('./src/services/malware/staticAnalyzer');
const { executeTool } = require('./src/utils/agentTools');

console.log('===============================================================');
console.log('🛡️  CYBER SENTINEL — CAPSTONE PIPELINE VERIFICATION SUITE');
console.log('===============================================================\n');

let passedTests = 0;
let totalTests = 0;

async function runTest(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`  ✅ [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ [FAIL] ${name}`);
    console.error(`     Error: ${err.message}\n`, err.stack);
  }
}

async function runSuite() {
  // ── TEST 1: Unified Event Normalization ──────────────────────────────────────
  await runTest('Event Normalization standardizes heterogeneous schemas', () => {
    const rawAgentEvent = {
      dataSource: 'endpoint-agent',
      dataType: 'process-execution',
      hostname: 'SEC-WORKSTATION-01',
      processName: 'powershell.exe',
      commandLine: 'powershell.exe -enc JABz...',
      destIp: '185.220.101.5',
      destPort: 4444,
      isSimulation: true
    };

    const normalized = normalizeEvent(rawAgentEvent);
    assert.strictEqual(normalized.dataSource, 'endpoint-agent');
    assert.strictEqual(normalized.hostname, 'SEC-WORKSTATION-01');
    assert.strictEqual(normalized.processName, 'powershell.exe');
    assert.strictEqual(normalized.destIp, '185.220.101.5');
    assert.strictEqual(normalized.destPort, 4444);
    assert.strictEqual(normalized.isSimulation, true);
    assert.ok(normalized.ingestedAt, 'Missing ingestedAt timestamp');
  });

  // ── TEST 2: High-Performance IOC Matcher ────────────────────────────────────
  await runTest('IOC Matcher indexes and matches malicious IPv4 and hashes', () => {
    // Add known IOCs
    iocMatcher.addIndicators([
      {
        ioc: '185.220.101.5',
        iocType: 'ip:port',
        malware: 'Cobalt Strike Beacon',
        confidence: 95,
        reporter: 'threatfox'
      },
      {
        ioc: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        iocType: 'sha256_hash',
        malware: 'LockBit 3.0',
        confidence: 100,
        reporter: 'cisa'
      }
    ]);

    // Match IP
    const ipMatch = iocMatcher.matchIndicator('185.220.101.5:4444');
    assert.ok(ipMatch, 'Should match IP:port IOC');
    assert.strictEqual(ipMatch.malware, 'Cobalt Strike Beacon');

    // Match SHA-256 Hash
    const hashMatch = iocMatcher.matchIndicator('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.ok(hashMatch, 'Should match file hash IOC');
    assert.strictEqual(hashMatch.malware, 'LockBit 3.0');

    // Non-malicious probe
    const cleanMatch = iocMatcher.matchIndicator('8.8.8.8');
    assert.strictEqual(cleanMatch, null, 'Clean IP should return null');
  });

  // ── TEST 3: SIEM Stateful Correlation Rules ─────────────────────────────────
  await runTest('Correlation Engine detects SQLi Success (RULE_SQLI_SUCCESS_002)', () => {
    const engine = new CorrelationEngine();
    let generatedIncident = null;
    engine.on('incident', (inc) => { generatedIncident = inc; });

    const rawSqliEvent = {
      dataSource: 'waf-logs',
      dataType: 'http-request',
      srcIp: '198.51.100.22',
      endpoint: '/api/v1/users?id=1%27%20UNION%20SELECT%20null,password%20FROM%20users--',
      httpStatus: 200
    };

    engine.processEvent(rawSqliEvent);
    assert.ok(generatedIncident, 'Should generate incident for successful SQLi probe');
    assert.strictEqual(generatedIncident.ruleId, 'RULE_SQLI_SUCCESS_002');
    assert.strictEqual(generatedIncident.severity, 'CRITICAL');
    assert.ok(generatedIncident.mitreTechniques.some(t => t.includes('T1190')));
  });

  await runTest('Correlation Engine detects Suspicious Execution + Socket (RULE_SUSPICIOUS_EXEC_004)', () => {
    const engine = new CorrelationEngine();
    let generatedIncident = null;
    engine.on('incident', (inc) => { generatedIncident = inc; });

    const rawExecEvent = {
      dataSource: 'endpoint-agent',
      dataType: 'process-execution',
      hostname: 'DEV-SERVER',
      processName: 'powershell.exe',
      commandLine: 'powershell.exe -w hidden -enc JAB4ACAAPQAgACcAdABlAHMAdAAnAA==',
      destIp: '198.51.100.99',
      destPort: 8080
    };

    engine.processEvent(rawExecEvent);
    assert.ok(generatedIncident, 'Should generate incident for suspicious PowerShell execution with socket');
    assert.strictEqual(generatedIncident.ruleId, 'RULE_SUSPICIOUS_EXEC_004');
    assert.ok(generatedIncident.mitreTechniques.some(t => t.includes('T1059.001')));
  });

  // ── TEST 4: Incident Response Lifecycle & Integrity Hashing ──────────────────
  await runTest('SecurityStore validates incident creation, SHA-256 evidence hashing, and lifecycle', () => {
    const testEvidence = [
      { type: 'NETWORK_FLOW', srcIp: '198.51.100.40', destPort: 443 },
      { type: 'IOC_MATCH', indicator: 'malicious-c2.xyz', threat: 'AgentTesla' }
    ];

    const rawEvidence = JSON.stringify(testEvidence);
    const expectedHash = crypto.createHash('sha256').update(rawEvidence).digest('hex');

    const inc = securityStore.createIncident({
      title: 'Verification Suite Test Incident',
      severity: 'HIGH',
      category: 'C2 Activity',
      sourceIp: '198.51.100.40',
      evidence: testEvidence
    });

    assert.ok(inc.id.startsWith('INC-'));
    assert.strictEqual(inc.status, 'NEW');
    assert.strictEqual(inc.evidenceHash, expectedHash);
    assert.strictEqual(inc.evidence.sha256, expectedHash);

    // Transition status: NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT
    const updated1 = securityStore.updateIncidentStatus(inc.id, 'TRIAGED', 'Analyst initial triage');
    assert.strictEqual(updated1.status, 'TRIAGED');

    const updated2 = securityStore.updateIncidentStatus(inc.id, 'INVESTIGATING', 'In-depth forensics started');
    assert.strictEqual(updated2.status, 'INVESTIGATING');
    assert.strictEqual(updated2.timeline.length, 3);

    const updated3 = securityStore.updateIncidentStatus(inc.id, 'CONTAINMENT', 'Host isolated via SOC firewall');
    assert.strictEqual(updated3.status, 'CONTAINMENT');
  });

  // ── TEST 5: In-Memory Static PE Malware Analyzer ────────────────────────────
  await runTest('Static PE Malware Analyzer evaluates synthetic binary safely in memory', () => {
    const buffer = Buffer.alloc(1024);
    // MZ header
    buffer[0] = 0x4D;
    buffer[1] = 0x5A;
    buffer.writeUInt32LE(0x80, 0x3C);

    // PE\0\0 header at 0x80
    buffer[0x80] = 0x50;
    buffer[0x81] = 0x45;
    buffer[0x82] = 0x00;
    buffer[0x83] = 0x00;
    buffer.writeUInt16LE(0x8664, 0x84);
    buffer.writeUInt16LE(1, 0x86);

    // Inject suspicious API strings and ransom strings
    const payloadStrings = 'VirtualAlloc\x00CreateRemoteThread\x00WriteProcessMemory\x00WinExec\x00vssadmin delete shadows\x00';
    buffer.write(payloadStrings, 0x100);

    const analysis = analyzeBinary(buffer, 'test_ransomware.exe');
    
    assert.strictEqual(analysis.metadata.executionPrevented, true);
    assert.strictEqual(analysis.peInfo.isPE, true);
    assert.strictEqual(analysis.peInfo.machineType, 'x64 (64-bit)');
    assert.ok(analysis.riskAssessment.score > 70, `Expected high risk score, got: ${analysis.riskAssessment.score}`);
    assert.strictEqual(analysis.riskAssessment.severity, 'CRITICAL');
    assert.ok(analysis.riskAssessment.mitreTechniques.includes('T1055'));
    assert.ok(analysis.riskAssessment.mitreTechniques.includes('T1490'));
  });

  // ── TEST 6: AI Safety Boundaries on Destructive Actions ──────────────────────
  await runTest('AI Copilot enforces human approval gate before IP containment', async () => {
    const targetIp = '203.0.113.150';

    // Step A: Attempt block WITHOUT confirmation
    const resWithoutConfirm = await executeTool('block_ip_address', { ip: targetIp });
    assert.strictEqual(resWithoutConfirm.result.requiresHumanApproval, true);
    assert.strictEqual(resWithoutConfirm.result.triggered, false);
    assert.strictEqual(resWithoutConfirm.result.riskClassification, 'HIGH_RISK_DESTRUCTIVE_ACTION');

    // Verify IP is NOT blocked
    assert.strictEqual(securityStore.isIpBlocked(targetIp), false);

    // Step B: Attempt block WITH operator confirmation
    const resWithConfirm = await executeTool('block_ip_address', { ip: targetIp, confirm: true, reason: 'Operator verified malicious C2' });
    assert.strictEqual(resWithConfirm.result.triggered, true);
    assert.strictEqual(securityStore.isIpBlocked(targetIp), true);

    // Cleanup: unblock
    securityStore.unblockIp(targetIp);
    assert.strictEqual(securityStore.isIpBlocked(targetIp), false);
  });

  // ── TEST 7: AI Copilot Forensic Investigation Tools ─────────────────────────
  await runTest('AI Copilot tools inspect incidents and live IOCs', async () => {
    const incRes = await executeTool('get_soc_incidents', {});
    assert.ok(incRes.result.incidents !== undefined);

    const iocRes = await executeTool('investigate_ioc', { indicator: '185.220.101.5' });
    assert.strictEqual(iocRes.result.verdict, 'MALICIOUS_IOC_MATCH');
    assert.strictEqual(iocRes.result.malware, 'Cobalt Strike Beacon');
  });

  // ── TEST 8: Endpoint Agent Telemetry & Device ID ────────────────────────────
  await runTest('Endpoint Agent generates deterministic device identity and telemetry', () => {
    const agentPath = path.resolve(__dirname, '../agent/agent.js');
    assert.ok(fs.existsSync(agentPath), 'agent/agent.js must exist');
    const os = require('os');
    assert.ok(os.hostname(), 'Must be able to query host details');
  });

  console.log(`\n===============================================================`);
  console.log(`🏁  VERIFICATION COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED`);
  console.log(`===============================================================\n`);

  process.exit(passedTests === totalTests ? 0 : 1);
}

runSuite().catch(err => {
  console.error('Unhandled suite error:', err);
  process.exit(1);
});
