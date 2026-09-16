/**
 * tests/unit/auth.test.js
 * Unit test suite for Authentication, Password Security, TOTP, and Role Permissions.
 */

const assert = require('assert');
const bcrypt = require('bcryptjs');
const path = require('path');

const { validatePassword, validateRegisterInput } = require(path.join(__dirname, '../../backend/src/validators/authValidators'));
const { ROLES, PERMISSIONS, hasPermission } = require(path.join(__dirname, '../../backend/src/constants/roles'));
const totp = require(path.join(__dirname, '../../backend/src/utils/totp'));

async function runAuthUnitTests() {
  console.log('\n--- [Unit] Authentication & Authorization Utilities ---');
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

  async function asyncTest(name, fn) {
    try {
      await fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  // 1. Password Complexity Validator
  test('Rejects short passwords (< 8 chars)', () => {
    const res = validatePassword('Pass1!');
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.includes('8 characters'));
  });

  test('Rejects passwords missing uppercase or symbols', () => {
    const res = validatePassword('alllowercasenumber1234');
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.length > 0);
  });

  test('Accepts compliant complex NIST passwords', () => {
    const res = validatePassword('Cyb3r$entinel#2026!SecOps');
    assert.strictEqual(res.valid, true);
  });

  // 2. Registration Input Validation
  test('Validates email formatting and rejects malformed domains', () => {
    const res = validateRegisterInput({
      name: 'Analyst One',
      email: 'not-an-email',
      password: 'Cyb3r$entinel#2026!SecOps',
    });
    assert.strictEqual(res.valid, false);
    assert.ok(res.error.includes('email'));
  });

  // 3. Bcrypt Password Hashing
  await asyncTest('Bcrypt generates unique salt and verifies matching hashes', async () => {
    const password = 'Cyb3r$entinel#2026!SecOps';
    const salt1 = await bcrypt.genSalt(10);
    const hash1 = await bcrypt.hash(password, salt1);
    const salt2 = await bcrypt.genSalt(10);
    const hash2 = await bcrypt.hash(password, salt2);

    assert.notStrictEqual(hash1, hash2, 'Salt ensures hashes are distinct');
    assert.strictEqual(await bcrypt.compare(password, hash1), true);
    assert.strictEqual(await bcrypt.compare('WrongPassword!123', hash1), false);
  });

  // 4. Role-Based Access Control (RBAC) Permissions
  test('Admin role possesses ALL system permissions', () => {
    const allPerms = Object.values(PERMISSIONS);
    for (const perm of allPerms) {
      assert.strictEqual(
        hasPermission(ROLES.ADMIN, perm),
        true,
        `Admin must have permission: ${perm}`
      );
    }
  });

  test('Viewer role has read-only permissions and lacks write/delete permissions', () => {
    assert.strictEqual(hasPermission(ROLES.VIEWER, PERMISSIONS.INCIDENTS_READ), true);
    assert.strictEqual(hasPermission(ROLES.VIEWER, PERMISSIONS.INCIDENTS_WRITE), false);
    assert.strictEqual(hasPermission(ROLES.VIEWER, PERMISSIONS.RESPONSE_EXECUTE), false);
    assert.strictEqual(hasPermission(ROLES.VIEWER, PERMISSIONS.DEVICES_DELETE), false);
  });

  test('Analyst role can read & write incidents but cannot manage users', () => {
    assert.strictEqual(hasPermission(ROLES.SOC_ANALYST, PERMISSIONS.INCIDENTS_WRITE), true);
    assert.strictEqual(hasPermission(ROLES.SOC_ANALYST, PERMISSIONS.USERS_WRITE), false);
  });

  // 5. TOTP (RFC 6238) Verification
  test('Generates base32 secret and valid 6-digit TOTP tokens', () => {
    const secret = totp.generateSecret();
    assert.ok(secret && secret.length >= 16);
    const token = totp.generateTOTP(secret);
    assert.match(token, /^\d{6}$/);
    assert.strictEqual(totp.verifyTOTP(token, secret), true);
    assert.strictEqual(totp.verifyTOTP('000000', secret), false);
  });

  return { passed, failed };
}

if (require.main === module) {
  runAuthUnitTests().then(({ passed, failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

module.exports = { runAuthUnitTests };
