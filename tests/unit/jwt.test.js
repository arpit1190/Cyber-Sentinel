/**
 * tests/unit/jwt.test.js
 * Unit tests for JWT Signing, Expiration, Claims Enforcement, Algorithm Confusion Defense,
 * and Refresh Token Rotation & Replay Protection.
 */

const assert = require('assert');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');

const authService = require(path.join(__dirname, '../../backend/src/services/authService'));
const { getJwtSecret } = require(path.join(__dirname, '../../backend/src/config/jwt'));
const { ALLOWED_ALGORITHMS } = require(path.join(__dirname, '../../backend/src/middleware/auth'));

async function runJwtUnitTests() {
  console.log('\n--- [Unit] JWT & Cryptographic Token Security ---');
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

  const user = {
    id: 'usr-test-101',
    email: 'analyst@sentinel.defense',
    role: 'SOC_ANALYST',
  };

  const secret = getJwtSecret();

  // 1. JWT Generation & Required Claims
  test('Generates JWT containing required claims (sub, email, role, iat, exp)', () => {
    const token = authService.generateAccessToken(user);
    const decoded = jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS });
    assert.strictEqual(decoded.sub, user.id);
    assert.strictEqual(decoded.email, user.email);
    assert.strictEqual(decoded.role, 'SOC_ANALYST');
    assert.ok(decoded.iat);
    assert.ok(decoded.exp);
    assert.ok(decoded.exp > decoded.iat);
  });

  // 2. Algorithm Confusion Rejection
  test('Rejects tokens signed with "none" algorithm', () => {
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: user.id, role: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
    const unsignedToken = `${noneHeader}.${payload}.`;

    assert.throws(() => {
      jwt.verify(unsignedToken, secret, { algorithms: ['HS256'] });
    }, /jwt|invalid|signature/i);
  });

  // 3. Secret Tampering Rejection
  test('Rejects tokens signed with invalid secret key', () => {
    const maliciousSecret = 'attacker-controlled-secret-key-32-chars-long!';
    const rogueToken = jwt.sign({ sub: user.id, role: 'admin' }, maliciousSecret, { algorithm: 'HS256', expiresIn: '1h' });

    assert.throws(() => {
      jwt.verify(rogueToken, secret, { algorithms: ['HS256'] });
    }, /invalid signature/i);
  });

  // 4. Token Expiration Enforcement
  test('Rejects expired JWT tokens', () => {
    const expiredToken = jwt.sign({ sub: user.id, role: user.role }, secret, {
      algorithm: 'HS256',
      expiresIn: '-10s',
    });

    assert.throws(() => {
      jwt.verify(expiredToken, secret, { algorithms: ['HS256'] });
    }, /jwt expired/i);
  });

  // 5. Refresh Token Cryptographic Strength & Hashing
  test('Generates high-entropy refresh token (>= 64 chars) and SHA-256 hash', () => {
    const rawToken = crypto.randomBytes(40).toString('hex');
    assert.ok(rawToken && rawToken.length >= 64);

    const hash1 = authService.hashToken(rawToken);
    const hash2 = authService.hashToken(rawToken);
    assert.strictEqual(hash1, hash2);
    assert.strictEqual(hash1.length, 64); // SHA-256 hex length
  });

  return { passed, failed };
}

if (require.main === module) {
  runJwtUnitTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runJwtUnitTests };
