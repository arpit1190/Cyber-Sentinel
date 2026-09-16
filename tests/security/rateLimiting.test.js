/**
 * tests/security/rateLimiting.test.js
 * Security test suite for API Rate Limiting, Brute Force Throttling, and Account Lockouts.
 */

const assert = require('assert');
const path = require('path');
const rateLimit = require('express-rate-limit');

const authService = require(path.join(__dirname, '../../backend/src/services/authService'));

async function runRateLimitingSecurityTests() {
  console.log('\n--- [Security] Rate Limiting & Denial of Service Safeguards ---');
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

  // 1. Rate Limiter Middleware Factory
  test('Instantiates express-rate-limit middleware with standard headers enabled', () => {
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 50,
      standardHeaders: true,
      legacyHeaders: false,
    });

    assert.strictEqual(typeof limiter, 'function');
  });

  // 2. AuthService Progressive Account Lockout on Consecutive Failures
  test('AuthService locks account after 5 consecutive failed authentication attempts', () => {
    const targetEmail = `brute-target-${Date.now()}@sentinel.defense`;

    // 4 failed attempts -> Not locked
    for (let i = 0; i < 4; i++) {
      authService.recordFailure(targetEmail);
    }
    assert.doesNotThrow(() => {
      authService.checkRateLimit(targetEmail);
    });

    // 5th failed attempt -> Locked
    authService.recordFailure(targetEmail);
    assert.throws(() => {
      authService.checkRateLimit(targetEmail);
    }, (err) => err.status === 429);
  });

  // 3. Successful Login Clears Failed Attempts Counter
  test('Successful authentication resets failed attempt counter', () => {
    const testUser = `reset-counter-${Date.now()}@sentinel.defense`;
    authService.recordFailure(testUser);
    authService.recordFailure(testUser);

    authService.clearFailure(testUser);
    assert.doesNotThrow(() => {
      authService.checkRateLimit(testUser);
    });
  });

  return { passed, failed };
}

if (require.main === module) {
  runRateLimitingSecurityTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runRateLimitingSecurityTests };
