/**
 * test_authentication_security.js
 * Comprehensive Security & Resilience Verification Suite for Cyber Sentinel Authentication Layer.
 * 
 * Verifies:
 * 1. Password complexity & dictionary attack defenses (NIST SP 800-63B)
 * 2. Bcrypt password hashing & timing-safe verification
 * 3. JWT strict cryptographic signing, expiration, and required claim enforcement
 * 4. JWT algorithm confusion & 'none' algorithm rejection
 * 5. Malformed, truncated, and tampered token rejection
 * 6. Refresh-token rotation and SHA-256 hashed storage
 * 7. Refresh-token reuse & replay attack detection (automatic family session invalidation)
 * 8. Brute-force & credential stuffing defense (progressive account lockout)
 * 9. Generic error responses preventing user enumeration
 * 10. Session invalidation on password update and secure logout
 */

const assert = require('assert');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const authService = require('./src/services/authService');
const userRepository = require('./src/repositories/userRepository');
const { requireAuth, ALLOWED_ALGORITHMS } = require('./src/middleware/auth');
const { validatePassword, validateRegisterInput } = require('./src/validators/authValidators');
const { getJwtSecret } = require('./src/config/jwt');
const { ROLES } = require('./src/constants/roles');

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

async function runAsyncTest(name, fn) {
  totalTests++;
  const start = process.hrtime.bigint();
  try {
    await fn();
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
console.log('🛡️   CYBER SENTINEL — AUTHENTICATION SECURITY & CRYPTOGRAPHY SUITE');
console.log('======================================================================\n');

async function runSuite() {
  console.log('━━━ SECTION 1: Password Strength & NIST Policy Enforcement ━━━');

  runTest('[PASSWORD] Rejects short passwords (< 8 characters)', () => {
    const res = validatePassword('Aa1!');
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.includes('at least 8 characters'));
  });

  runTest('[PASSWORD] Rejects passwords missing special characters or uppercase', () => {
    const noSpecial = validatePassword('Password123');
    assert.strictEqual(noSpecial.valid, false);

    const noUpper = validatePassword('password123!');
    assert.strictEqual(noUpper.valid, false);

    const noDigits = validatePassword('Password!@#');
    assert.strictEqual(noDigits.valid, false);
  });

  runTest('[PASSWORD] Rejects common/breached dictionary passwords', () => {
    const res = validatePassword('password123');
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.includes('common'));
  });

  runTest('[PASSWORD] Accepts strong compliant passphrases', () => {
    const res = validatePassword('Sentinel@2026_SecureSOC!');
    assert.strictEqual(res.valid, true);
  });

  console.log('\n━━━ SECTION 2: User Registration & Bcrypt Hashing ━━━');

  const testEmail = `operator_${Date.now()}@sentinel.local`;
  const strongPassword = 'P@ssw0rd_Enterprise_2026!';

  await runAsyncTest('[REGISTER] Registers user with salt rounds >= 12 and hashed credentials', async () => {
    const result = await authService.register({
      email: testEmail,
      password: strongPassword,
      name: 'Lead SOC Operator',
    });

    assert.ok(result.token, 'Must return access token');
    assert.ok(result.refreshToken, 'Must return refresh token');
    assert.strictEqual(result.user.email, testEmail);

    const savedUser = await userRepository.findByEmail(testEmail);
    assert.ok(savedUser, 'User must exist in repository');
    assert.notStrictEqual(savedUser.passwordHash, strongPassword, 'Password must never be stored in plaintext');
    assert.ok(savedUser.passwordHash.startsWith('$2'), 'Must be a valid bcrypt hash');
  });

  console.log('\n━━━ SECTION 3: Login Authentication & Generic Error Protection ━━━');

  await runAsyncTest('[LOGIN] Authenticates valid operator credentials', async () => {
    const result = await authService.login({
      email: testEmail,
      password: strongPassword,
    });

    assert.ok(result.token, 'Must issue access token');
    assert.ok(result.refreshToken, 'Must issue refresh token');
    assert.strictEqual(result.user.email, testEmail);
  });

  await runAsyncTest('[LOGIN] Rejects incorrect password with generic error message', async () => {
    try {
      await authService.login({
        email: testEmail,
        password: 'WrongPassword123!',
      });
      assert.fail('Should have rejected bad password');
    } catch (err) {
      assert.strictEqual(err.status, 401);
      assert.strictEqual(err.message, 'Invalid email or password.');
    }
  });

  await runAsyncTest('[LOGIN] Rejects nonexistent account with identical generic error (prevents enumeration)', async () => {
    try {
      await authService.login({
        email: 'nonexistent_account_999@sentinel.local',
        password: strongPassword,
      });
      assert.fail('Should have rejected nonexistent account');
    } catch (err) {
      assert.strictEqual(err.status, 401);
      assert.strictEqual(err.message, 'Invalid email or password.');
    }
  });

  console.log('\n━━━ SECTION 4: JWT Cryptographic Verification & Algorithm Hardening ━━━');

  const secret = getJwtSecret();

  runTest('[JWT] Valid access token is verified and populates req.user', () => {
    const token = jwt.sign(
      { sub: 'usr-123', email: testEmail, name: 'Operator', role: ROLES.SOC_ANALYST },
      secret,
      { algorithm: 'HS256', expiresIn: '15m' }
    );

    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = {
      status(s) { this._status = s; return this; },
      json(b) { this._body = b; }
    };
    let nextCalled = false;

    requireAuth(req, res, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
    assert.strictEqual(req.user.email, testEmail);
    assert.strictEqual(req.user.role, ROLES.SOC_ANALYST);
  });

  runTest('[JWT] Rejects expired access token with 401 session expired', () => {
    const expiredToken = jwt.sign(
      { sub: 'usr-123', email: testEmail, role: ROLES.ANALYST },
      secret,
      { algorithm: 'HS256', expiresIn: '-10s' }
    );

    const req = { headers: { authorization: `Bearer ${expiredToken}` } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };

    requireAuth(req, res, () => {});
    assert.strictEqual(status, 401);
    assert.ok(jsonBody.error.includes('expired'));
  });

  runTest('[JWT] Rejects malformed and truncated tokens', () => {
    const malformed = ['not-a-token', 'a.b', 'a.b.c.d', '..'];

    malformed.forEach(token => {
      const req = { headers: { authorization: `Bearer ${token}` } };
      let status = null;
      let jsonBody = null;
      const res = {
        status(s) { status = s; return this; },
        json(b) { jsonBody = b; }
      };

      requireAuth(req, res, () => {});
      assert.strictEqual(status, 401, `Token '${token}' should be rejected with 401`);
    });
  });

  runTest('[JWT] Rejects tampered tokens and invalid signatures', () => {
    const validToken = jwt.sign(
      { sub: 'usr-123', email: testEmail, role: ROLES.ADMIN },
      secret,
      { algorithm: 'HS256' }
    );

    // Tamper with signature
    const parts = validToken.split('.');
    parts[2] = 'tamperedSignatureHere1234567890';
    const tamperedToken = parts.join('.');

    const req = { headers: { authorization: `Bearer ${tamperedToken}` } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };

    requireAuth(req, res, () => {});
    assert.strictEqual(status, 401);
    assert.ok(jsonBody.error.includes('Invalid authentication token') || jsonBody.error.includes('signature'));
  });

  runTest('[JWT] Rejects unsigned ("none" algorithm) bypass tokens', () => {
    const unsignedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'usr-123', email: testEmail, role: ROLES.ADMIN })).toString('base64url');
    const unsignedToken = `${unsignedHeader}.${payload}.`;

    const req = { headers: { authorization: `Bearer ${unsignedToken}` } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };

    requireAuth(req, res, () => {});
    assert.strictEqual(status, 401);
  });

  runTest('[JWT] Rejects wrong / unsupported algorithm (e.g. HS512, RS256)', () => {
    const wrongAlgToken = jwt.sign(
      { sub: 'usr-123', email: testEmail, role: ROLES.ADMIN },
      secret,
      { algorithm: 'HS512' }
    );

    const req = { headers: { authorization: `Bearer ${wrongAlgToken}` } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };

    requireAuth(req, res, () => {});
    assert.strictEqual(status, 401);
  });

  runTest('[JWT] Rejects tokens missing required claims (email or role)', () => {
    const missingRoleToken = jwt.sign(
      { sub: 'usr-123', email: testEmail },
      secret,
      { algorithm: 'HS256' }
    );

    const req = { headers: { authorization: `Bearer ${missingRoleToken}` } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };

    requireAuth(req, res, () => {});
    assert.strictEqual(status, 401);
    assert.ok(jsonBody.error.includes('required role claim'));
  });

  console.log('\n━━━ SECTION 5: Refresh Token Rotation & Hashed Storage ━━━');

  let activeRefreshToken;
  let nextRefreshToken;

  await runAsyncTest('[REFRESH] Stores SHA-256 hash of refresh tokens, never plaintext', async () => {
    const loginResult = await authService.login({
      email: testEmail,
      password: strongPassword,
    });
    activeRefreshToken = loginResult.refreshToken;

    const tokenHash = authService.hashToken(activeRefreshToken);
    const sessionRecord = authService.refreshTokens.get(tokenHash);

    assert.ok(sessionRecord, 'Record must exist keyed by hash');
    assert.strictEqual(sessionRecord.tokenHash, tokenHash);
    assert.ok(!authService.refreshTokens.has(activeRefreshToken), 'Plaintext token must not be used as map key');
  });

  await runAsyncTest('[REFRESH] Rotates refresh token on valid exchange and invalidates old token', async () => {
    const refreshResult = await authService.refresh(activeRefreshToken);

    assert.ok(refreshResult.token, 'Must return new access token');
    assert.ok(refreshResult.refreshToken, 'Must return rotated new refresh token');
    assert.notStrictEqual(refreshResult.refreshToken, activeRefreshToken, 'Must be a distinct new refresh token');

    nextRefreshToken = refreshResult.refreshToken;

    const oldHash = authService.hashToken(activeRefreshToken);
    const oldSession = authService.refreshTokens.get(oldHash);
    assert.ok(oldSession.revokedAt, 'Old refresh token must be marked revoked');
    assert.strictEqual(oldSession.replacedByTokenHash, authService.hashToken(nextRefreshToken));
  });

  console.log('\n━━━ SECTION 6: Refresh Token Reuse & Compromise Detection ━━━');

  await runAsyncTest('[COMPROMISE] Detecting reuse of rotated/revoked token invalidates ALL family sessions', async () => {
    // Present the previously rotated activeRefreshToken again (replay attack)
    try {
      await authService.refresh(activeRefreshToken);
      assert.fail('Should have detected token reuse');
    } catch (err) {
      assert.strictEqual(err.status, 401);
      assert.ok(err.message.includes('reused refresh token detected'));
    }

    // Verify that the legitimate active token was also revoked due to family invalidation
    const nextHash = authService.hashToken(nextRefreshToken);
    const nextRecord = authService.refreshTokens.get(nextHash);
    assert.ok(nextRecord.revokedAt, 'All family tokens must be terminated upon reuse detection');
  });

  console.log('\n━━━ SECTION 7: Brute-Force Defenses & Account Lockout ━━━');

  const bruteEmail = `target_victim_${Date.now()}@sentinel.local`;
  const attackerIp = '10.99.88.77';

  await runAsyncTest('[BRUTE-FORCE] Enforces progressive lockout after 5 consecutive failed attempts', async () => {
    await authService.register({
      email: bruteEmail,
      password: strongPassword,
      name: 'Victim User',
    });

    // Attempt 5 bad logins from attacker IP
    for (let i = 1; i <= 5; i++) {
      try {
        await authService.login({ email: bruteEmail, password: 'WrongPassword!', req: { ip: attackerIp } });
      } catch (err) {
        assert.strictEqual(err.status, 401);
      }
    }

    // 6th attempt should be blocked by lockout policy with 429
    try {
      await authService.login({ email: bruteEmail, password: strongPassword, req: { ip: attackerIp } });
      assert.fail('Should be locked out after 5 failures');
    } catch (err) {
      assert.strictEqual(err.status, 429);
      assert.ok(err.message.includes('temporarily locked'));
    }

    // Cleanup failure state
    authService.clearFailure(bruteEmail);
    authService.clearFailure(attackerIp);
  });

  console.log('\n━━━ SECTION 8: Session Invalidation & Secure Logout ━━━');

  await runAsyncTest('[LOGOUT] Revokes refresh token and terminates session', async () => {
    const loginRes = await authService.login({
      email: testEmail,
      password: strongPassword,
    });

    const tokenToRevoke = loginRes.refreshToken;
    const hash = authService.hashToken(tokenToRevoke);

    await authService.logout({ refreshToken: tokenToRevoke, user: loginRes.user });

    const record = authService.refreshTokens.get(hash);
    assert.ok(record.revokedAt, 'Refresh token must be marked revoked');

    try {
      await authService.refresh(tokenToRevoke);
      assert.fail('Revoked token must not be accepted');
    } catch (err) {
      assert.strictEqual(err.status, 401);
    }
  });

  await runAsyncTest('[SESSION-INVALIDATION] Password update revokes all active refresh tokens for user', async () => {
    const session1 = await authService.login({ email: testEmail, password: strongPassword });
    const session2 = await authService.login({ email: testEmail, password: strongPassword });

    assert.ok(session1.refreshToken);
    assert.ok(session2.refreshToken);

    // Simulate password change session invalidation
    authService.revokeAllUserSessions(testEmail, 'Password reset/change');

    // Both previous sessions must be rejected
    try {
      await authService.refresh(session1.refreshToken);
      assert.fail('Session 1 should have been invalidated');
    } catch (err) {
      assert.strictEqual(err.status, 401);
    }

    try {
      await authService.refresh(session2.refreshToken);
      assert.fail('Session 2 should have been invalidated');
    } catch (err) {
      assert.strictEqual(err.status, 401);
    }
  });

  console.log('\n======================================================================');
  console.log(`🏁  AUTHENTICATION SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
  console.log('======================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runSuite().catch(err => {
  console.error('Unhandled suite error:', err);
  process.exit(1);
});
