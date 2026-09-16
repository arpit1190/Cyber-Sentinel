/**
 * test_data_privacy.js
 * Verification of Data Minimization, PII Scrubbing, and Privacy Utilities.
 */

const assert = require('assert');
const {
  redactSecretsAndTokens,
  maskIpAddress,
  pseudonymizeUser,
  sanitizeAuditDetails,
} = require('./src/utils/privacyMinimizer');

function runPrivacyTests() {
  console.log('\n--- [Privacy & Data Minimization] Credential Scrubbing & PII Redaction ---');
  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  test('Redacts passwords in command-line arguments', () => {
    const raw = 'curl -u admin:superSecret123 https://api.corp.internal/data --password P@ssw0rd99';
    const scrubbed = redactSecretsAndTokens(raw);
    assert(!scrubbed.includes('superSecret123'), 'URL password must be scrubbed');
    assert(!scrubbed.includes('P@ssw0rd99'), 'CLI password must be scrubbed');
    assert(scrubbed.includes('[REDACTED_SECRET]'), 'Must replace with redaction token');
  });

  test('Redacts Bearer and JWT tokens from strings', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature12345';
    const text = `Authorization: Bearer mySecretTokenValue12345, or JWT: ${jwt}`;
    const scrubbed = redactSecretsAndTokens(text);
    assert(!scrubbed.includes('mySecretTokenValue12345'), 'Bearer token must be scrubbed');
    assert(!scrubbed.includes('doNotLeakThisSignature12345'), 'JWT token signature must be scrubbed');
  });

  test('Redacts API keys for cloud providers', () => {
    const raw = 'export GEMINI_API_KEY=AIzaSyD-1234567890abcdefghijklmnopqrstuvw';
    const scrubbed = redactSecretsAndTokens(raw);
    assert(!scrubbed.includes('AIzaSyD-1234567890abcdefghijklmnopqrstuvw'), 'API key must be scrubbed');
    assert(scrubbed.includes('[REDACTED_API_KEY]'), 'Must contain redacted token placeholder');
  });

  test('Masks IPv4 to /24 subnet for privacy preservation', () => {
    const masked = maskIpAddress('192.168.1.144');
    assert.strictEqual(masked, '192.168.1.0/24');
  });

  test('Pseudonymizes employee username deterministically', () => {
    const p1 = pseudonymizeUser('john.doe@enterprise.com');
    const p2 = pseudonymizeUser('john.doe@enterprise.com');
    const p3 = pseudonymizeUser('alice.smith@enterprise.com');

    assert(p1.startsWith('user_'), 'Must generate user_ prefix');
    assert.strictEqual(p1, p2, 'Same user must produce identical pseudonym');
    assert.notStrictEqual(p1, p3, 'Different users must produce distinct pseudonyms');
  });

  test('Sanitizes sensitive authentication parameters in audit log details', () => {
    const details = {
      actionTarget: 'user_123',
      currentPassword: 'RawOldPassword123!',
      newPassword: 'RawNewPassword456!',
      token: 'secretSessionToken123456',
      metadata: {
        command: 'run --secret SuperSecretKey123',
      },
    };

    const cleaned = sanitizeAuditDetails(details);
    assert.strictEqual(cleaned.currentPassword, '[REDACTED_SECURITY_PARAM]');
    assert.strictEqual(cleaned.newPassword, '[REDACTED_SECURITY_PARAM]');
    assert.strictEqual(cleaned.token, '[REDACTED_SECURITY_PARAM]');
    assert(!cleaned.metadata.command.includes('SuperSecretKey123'));
  });

  return { passed, failed };
}

if (require.main === module) {
  runPrivacyTests();
}

module.exports = { runPrivacyTests };
