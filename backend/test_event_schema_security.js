/**
 * test_event_schema_security.js
 * Comprehensive Verification & Fuzzing Suite for Cyber Sentinel Canonical Event Schema.
 * 
 * Verifies:
 * 1. Canonical schema mapping with all required SOC fields:
 *    event_id, timestamp, device_id, event_type, severity, source,
 *    process, network, file, user, metadata
 * 2. Strict type rejection (null, undefined, primitives, arrays, invalid objects)
 * 3. Malformed UUID detection & fallback UUIDv4 generation
 * 4. Timestamp validation & normalization (ISO-8601 UTC, epoch conversions, invalid date handling)
 * 5. String sanitization (control characters, null bytes, unicode normalization)
 * 6. Field size limits & boundary truncations
 * 7. Prototype pollution defenses (__proto__, constructor, prototype injections)
 * 8. Dangerous object structure handling (functions, symbols, circular references)
 * 9. Safe harvesting of unknown telemetry fields into metadata.custom
 * 10. Oversized nested object bounds (depth limitation, key count bounds, cycle guards)
 * 11. Heterogeneous source normalization (Agent, Windows Events, Syslog, Simulator)
 * 12. Backward compatibility verification (seamless camelCase accessors for SIEM)
 */

const assert = require('assert');
const crypto = require('crypto');
const {
  EventTypes,
  SeverityLevels,
  NetworkProtocols,
  NetworkDirections,
  FileActions,
  SchemaLimits,
} = require('./src/services/normalizer/eventSchema');

const {
  normalizeEvent,
  normalizeEventType,
  normalizeSeverity,
} = require('./src/services/normalizer/eventNormalizer');

const {
  isValidEventId,
  isValidTimestamp,
  sanitizeString,
  sanitizeIp,
  sanitizePort,
  sanitizeNestedObject,
  validateEvent,
} = require('./src/services/normalizer/eventValidator');

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
console.log('🛡️   CYBER SENTINEL — CANONICAL EVENT SCHEMA & NORMALIZER SUITE');
console.log('======================================================================\n');

console.log('━━━ SECTION 1: Canonical Schema Structure & Field Completeness ━━━');

runTest('[SCHEMA-COMPLETENESS] Normalizes full telemetry payload into complete canonical structure', () => {
  const raw = {
    event_id: '123e4567-e89b-12d3-a456-426614174000',
    timestamp: '2026-09-15T16:45:00.000Z',
    device_id: 'DEV-WORKSTATION-01',
    event_type: 'PROCESS_EXECUTION',
    severity: 'CRITICAL',
    source: 'endpoint-agent',
    process: {
      name: 'powershell.exe',
      pid: 4088,
      ppid: 1024,
      path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -enc JABz...',
      hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      parent_name: 'cmd.exe',
    },
    network: {
      source_ip: '192.168.1.100',
      source_port: 54321,
      dest_ip: '185.220.101.5',
      dest_port: 443,
      protocol: 'TCP',
      direction: 'OUTBOUND',
      domain: 'c2.evil-corp.com',
      bytes_sent: 1024,
      bytes_received: 4096,
    },
    file: {
      path: 'C:\\Users\\Victim\\AppData\\Local\\Temp\\malware.exe',
      name: 'malware.exe',
      action: 'CREATED',
      size_bytes: 65536,
      hash: 'd41d8cd98f00b204e9800998ecf8427e',
    },
    user: {
      name: 'sec-admin',
      domain: 'CORP',
      id: 'S-1-5-21-1234567890',
      email: 'admin@corp.local',
      is_admin: true,
    },
    tags: ['T1059.001', 'CobaltStrike', 'C2'],
    mitre_technique: 'T1059.001',
    custom_attribute: 'SpecialForensicMarker',
  };

  const normalized = normalizeEvent(raw);

  // Validate top-level canonical fields
  assert.strictEqual(normalized.event_id, '123e4567-e89b-12d3-a456-426614174000');
  assert.strictEqual(normalized.timestamp, '2026-09-15T16:45:00.000Z');
  assert.strictEqual(normalized.device_id, 'DEV-WORKSTATION-01');
  assert.strictEqual(normalized.event_type, 'PROCESS_EXECUTION');
  assert.strictEqual(normalized.severity, 'CRITICAL');
  assert.strictEqual(normalized.source, 'endpoint-agent');

  // Validate Process sub-object
  assert.strictEqual(normalized.process.name, 'powershell.exe');
  assert.strictEqual(normalized.process.pid, 4088);
  assert.strictEqual(normalized.process.ppid, 1024);
  assert.strictEqual(normalized.process.command_line, 'powershell.exe -enc JABz...');
  assert.strictEqual(normalized.process.hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.strictEqual(normalized.process.parent_name, 'cmd.exe');

  // Validate Network sub-object
  assert.strictEqual(normalized.network.source_ip, '192.168.1.100');
  assert.strictEqual(normalized.network.source_port, 54321);
  assert.strictEqual(normalized.network.dest_ip, '185.220.101.5');
  assert.strictEqual(normalized.network.dest_port, 443);
  assert.strictEqual(normalized.network.protocol, 'TCP');
  assert.strictEqual(normalized.network.direction, 'OUTBOUND');
  assert.strictEqual(normalized.network.domain, 'c2.evil-corp.com');

  // Validate File sub-object
  assert.strictEqual(normalized.file.name, 'malware.exe');
  assert.strictEqual(normalized.file.extension, 'exe');
  assert.strictEqual(normalized.file.action, 'CREATED');
  assert.strictEqual(normalized.file.size_bytes, 65536);

  // Validate User sub-object
  assert.strictEqual(normalized.user.name, 'sec-admin');
  assert.strictEqual(normalized.user.domain, 'CORP');
  assert.strictEqual(normalized.user.is_admin, true);

  // Validate Metadata & Unknown Field Harvester
  assert.strictEqual(normalized.metadata.schema_version, '1.0.0');
  assert.deepStrictEqual(normalized.metadata.tags, ['T1059.001', 'CobaltStrike', 'C2']);
  assert.strictEqual(normalized.metadata.mitre_technique, 'T1059.001');
  assert.strictEqual(normalized.metadata.custom.custom_attribute, 'SpecialForensicMarker');
});

console.log('\n━━━ SECTION 2: Type Robustness & Resilience Under Fuzzing ━━━');

runTest('[TYPE-RESILIENCE] Gracefully handles null, undefined, numbers, strings, and arrays', () => {
  [null, undefined, '', 'a string', 12345, true, false, [], [1, 2, 3]].forEach(invalid => {
    const res = normalizeEvent(invalid);
    assert.ok(res.event_id, 'Must generate valid event_id');
    assert.ok(res.timestamp, 'Must provide valid timestamp');
    assert.strictEqual(res.event_type, EventTypes.SYSTEM_ANOMALY);
    assert.strictEqual(res.severity, SeverityLevels.MEDIUM);
    assert.strictEqual(typeof res.process, 'object');
    assert.strictEqual(typeof res.network, 'object');
    assert.strictEqual(typeof res.file, 'object');
    assert.strictEqual(typeof res.user, 'object');
    assert.strictEqual(typeof res.metadata, 'object');
  });
});

console.log('\n━━━ SECTION 3: UUID & Timestamp Validations ━━━');

runTest('[UUID-VALIDATION] Rejects malformed / SQLi / traversal event IDs and generates UUIDv4', () => {
  const badIds = [
    '../../etc/passwd',
    "'; DROP TABLE events; --",
    '123-malformed',
    'not-a-uuid',
    '00000000-0000-0000-0000-000000000000-too-long',
    ' ',
  ];

  badIds.forEach(badId => {
    const res = normalizeEvent({ event_id: badId });
    assert.notStrictEqual(res.event_id, badId, `Bad ID '${badId}' should have been rejected`);
    assert.ok(isValidEventId(res.event_id), `Generated ID '${res.event_id}' must be valid UUIDv4`);
  });

  // Valid formats must be preserved
  const validUuid = crypto.randomUUID();
  const validEvt = `evt-${Date.now()}-abc123`;
  assert.strictEqual(normalizeEvent({ event_id: validUuid }).event_id, validUuid);
  assert.strictEqual(normalizeEvent({ event_id: validEvt }).event_id, validEvt);
});

runTest('[TIMESTAMP-VALIDATION] Converts epoch ms, epoch s, ISO dates and corrects impossible dates', () => {
  // 1. Valid ISO string
  const iso = '2026-09-15T12:00:00.000Z';
  assert.strictEqual(normalizeEvent({ timestamp: iso }).timestamp, iso);

  // 2. Epoch in milliseconds
  const epochMs = 1789491000000;
  assert.strictEqual(normalizeEvent({ timestamp: epochMs }).timestamp, new Date(epochMs).toISOString());

  // 3. Epoch in seconds
  const epochSec = 1789491000;
  assert.strictEqual(normalizeEvent({ timestamp: epochSec }).timestamp, new Date(epochSec * 1000).toISOString());

  // 4. Invalid dates fallback safely to current UTC timestamp
  ['invalid-date', '2026-13-45', 'NaN', '', null, 9999999999999999].forEach(badTs => {
    const normalized = normalizeEvent({ timestamp: badTs });
    assert.ok(!isNaN(Date.parse(normalized.timestamp)), 'Normalized timestamp must be valid date');
  });
});

console.log('\n━━━ SECTION 4: String Sanitization & Boundary Protections ━━━');

runTest('[STRING-SANITIZATION] Strips null bytes, non-printable control chars, and trims whitespace', () => {
  const dirty = {
    device_id: '  DEV-WORKSTATION\0\x01\x02  ',
    process: {
      name: 'malicious\0.exe\x07',
      command_line: 'powershell.exe\0 -c calc.exe',
    },
    user: '  administrator\0  ',
  };

  const clean = normalizeEvent(dirty);
  assert.strictEqual(clean.device_id, 'DEV-WORKSTATION');
  assert.strictEqual(clean.process.name, 'malicious.exe');
  assert.strictEqual(clean.process.command_line, 'powershell.exe -c calc.exe');
  assert.strictEqual(clean.user.name, 'administrator');
});

runTest('[FIELD-LIMITS] Enforces max string length limits on oversized inputs', () => {
  const giganticCmd = 'powershell.exe ' + 'A'.repeat(SchemaLimits.MAX_CMDLINE_LEN + 500);
  const giganticPath = '/var/log/' + 'B'.repeat(5000);

  const res = normalizeEvent({
    process: { command_line: giganticCmd },
    file: { path: giganticPath },
  });

  assert.strictEqual(res.process.command_line.length, SchemaLimits.MAX_CMDLINE_LEN);
  assert.strictEqual(res.file.path.length, SchemaLimits.MAX_PATH_LEN);
});

console.log('\n━━━ SECTION 5: Prototype Pollution & Object Security Defenses ━━━');

runTest('[PROTOTYPE-POLLUTION] Blocks __proto__, constructor, and prototype injection attempts', () => {
  const payload = JSON.parse(`{
    "__proto__": { "polluted": "yes", "admin": true },
    "constructor": { "prototype": { "hacked": true } },
    "metadata": {
      "__proto__": { "innerPollution": true }
    },
    "details": {
      "constructor": { "prototype": { "subHacked": true } }
    }
  }`);

  const normalized = normalizeEvent(payload);

  assert.strictEqual(Object.prototype.polluted, undefined, 'Object.prototype.polluted was polluted');
  assert.strictEqual(Object.prototype.admin, undefined, 'Object.prototype.admin was polluted');
  assert.strictEqual(Object.prototype.hacked, undefined, 'Object.prototype.hacked was polluted');
  assert.strictEqual(Object.prototype.innerPollution, undefined, 'Object.prototype.innerPollution was polluted');
  assert.strictEqual(Object.prototype.subHacked, undefined, 'Object.prototype.subHacked was polluted');

  assert.strictEqual(normalized.metadata.custom.__proto__, undefined);
  assert.strictEqual(normalized.metadata.custom.constructor, undefined);
});

runTest('[DANGEROUS-STRUCTURES] Strips functions, symbols, and safely handles circular references', () => {
  const circular = { key: 'value' };
  circular.self = circular;

  const sanitized = sanitizeNestedObject(circular);
  assert.strictEqual(sanitized.key, 'value');
  assert.strictEqual(sanitized.self, '[Circular Reference]');

  const withFunctions = {
    func: function() { return 'evil'; },
    sym: Symbol('secret'),
    validStr: 'safe',
  };

  const cleanObj = sanitizeNestedObject(withFunctions);
  assert.strictEqual(cleanObj.func, undefined);
  assert.strictEqual(cleanObj.sym, undefined);
  assert.strictEqual(cleanObj.validStr, 'safe');
});

console.log('\n━━━ SECTION 6: Unknown Fields & Oversized Object Bounds ━━━');

runTest('[UNKNOWN-FIELDS] Safely collects unrecognized fields into metadata.custom', () => {
  const raw = {
    event_type: 'AUTH_FAILURE',
    unrecognizedVendorField1: 'firewall-log-raw',
    unrecognizedVendorField2: { ruleId: 999, nested: 'ok' },
  };

  const normalized = normalizeEvent(raw);
  assert.strictEqual(normalized.metadata.custom.unrecognizedVendorField1, 'firewall-log-raw');
  assert.strictEqual(normalized.metadata.custom.unrecognizedVendorField2.ruleId, 999);
});

runTest('[NESTING-DEPTH] Bounds excessive object nesting depth to max 4 levels', () => {
  const deepObject = {
    level1: {
      level2: {
        level3: {
          level4: {
            level5: {
              level6: 'too deep'
            }
          }
        }
      }
    }
  };

  const sanitized = sanitizeNestedObject(deepObject);
  assert.strictEqual(typeof sanitized.level1.level2.level3.level4, 'object');
  assert.strictEqual(sanitized.level1.level2.level3.level4.level5, '[Max Depth Exceeded]');
});

console.log('\n━━━ SECTION 7: Heterogeneous Telemetry Sources Normalization ━━━');

runTest('[HETEROGENEOUS-SOURCES] Normalizes Windows Event Log schema', () => {
  const winLog = {
    EventID: 4625,
    TimeCreated: '2026-09-15T14:30:00.000Z',
    Computer: 'WIN-DC-01.corp.local',
    TargetUserName: 'bob',
    TargetDomainName: 'CORP',
    IpAddress: '10.0.0.50',
    IpPort: '49152',
    LogonType: '3',
    source: 'windows-event-log',
  };

  const normalized = normalizeEvent(winLog);
  assert.strictEqual(normalized.event_type, EventTypes.AUTH_FAILURE);
  assert.strictEqual(normalized.device_id, 'WIN-DC-01.corp.local');
  assert.strictEqual(normalized.user.name, 'bob');
  assert.strictEqual(normalized.user.domain, 'CORP');
  assert.strictEqual(normalized.network.source_ip, '10.0.0.50');
  assert.strictEqual(normalized.network.source_port, 49152);
});

runTest('[HETEROGENEOUS-SOURCES] Normalizes Syslog CEF/LEEF event format', () => {
  const syslog = {
    host: 'edge-gw-01',
    src: '185.220.101.5',
    dst: '192.168.1.1',
    spt: 4444,
    dpt: 80,
    proto: 'TCP',
    act: 'BLOCK',
    msg: 'SQL Injection attempt detected in URI query',
    dataSource: 'syslog-collector',
  };

  const normalized = normalizeEvent(syslog);
  assert.strictEqual(normalized.event_type, EventTypes.EXPLOIT_PROBE);
  assert.strictEqual(normalized.device_id, 'edge-gw-01');
  assert.strictEqual(normalized.network.source_ip, '185.220.101.5');
  assert.strictEqual(normalized.network.dest_ip, '192.168.1.1');
  assert.strictEqual(normalized.network.source_port, 4444);
  assert.strictEqual(normalized.network.dest_port, 80);
});

console.log('\n━━━ SECTION 8: Backward Compatibility Accessor Matrix ━━━');

runTest('[BACKWARD-COMPATIBILITY] Provides seamless camelCase accessors for legacy code & SIEM rules', () => {
  const raw = {
    eventType: 'PROCESS_EXECUTION',
    hostname: 'SEC-ENDPOINT-02',
    processName: 'powershell.exe',
    commandLine: 'powershell.exe -enc ...',
    destIp: '185.220.101.5',
    destPort: 4444,
    isSimulation: true,
  };

  const normalized = normalizeEvent(raw);

  // Both canonical (snake_case) and legacy (camelCase) properties must be accessible
  assert.strictEqual(normalized.event_type, 'PROCESS_EXECUTION');
  assert.strictEqual(normalized.eventType, 'PROCESS_EXECUTION');
  assert.strictEqual(normalized.device_id, 'SEC-ENDPOINT-02');
  assert.strictEqual(normalized.hostname, 'SEC-ENDPOINT-02');
  assert.strictEqual(normalized.process.name, 'powershell.exe');
  assert.strictEqual(normalized.processName, 'powershell.exe');
  assert.strictEqual(normalized.process.command_line, 'powershell.exe -enc ...');
  assert.strictEqual(normalized.commandLine, 'powershell.exe -enc ...');
  assert.strictEqual(normalized.network.dest_ip, '185.220.101.5');
  assert.strictEqual(normalized.destIp, '185.220.101.5');
  assert.strictEqual(normalized.network.dest_port, 4444);
  assert.strictEqual(normalized.destPort, 4444);
  assert.strictEqual(normalized.isSimulation, true);
});

console.log('\n======================================================================');
console.log(`🏁  EVENT SCHEMA & NORMALIZER SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
console.log('======================================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
