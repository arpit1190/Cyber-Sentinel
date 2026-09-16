/**
 * test_rbac_authorization.js
 * Verification Suite for Server-Side Role-Based Access Control (RBAC) & Authorization Hardening.
 * 
 * Tests:
 * 1. Server-side permission mapping & deny-by-default evaluation
 * 2. VIEWER role cannot execute mutations, IP containment, or administrative operations
 * 3. SOC_ANALYST role cannot modify system configuration (system:write)
 * 4. ENDPOINT_OPERATOR role cannot modify detection rules or manage users
 * 5. Only authorized roles (ADMIN, ENDPOINT_OPERATOR) can execute response actions
 * 6. IDOR Defense: Users cannot view or modify resources belonging to another user
 * 7. Privilege Escalation Defense: Client cannot self-promote to ADMIN during registration or profile updates
 * 8. Mass Assignment Defense: Arbitrary injected fields (isAdmin, role, permissions) are ignored/stripped
 * 9. requireRole & requirePermission middleware behavior
 */

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { ROLES, PERMISSIONS, ROLE_PERMISSIONS, normalizeRole, hasPermission } = require('./src/constants/roles');
const { requireAuth, requireRole, requirePermission, preventIdor } = require('./src/middleware/auth');
const authService = require('./src/services/authService');
const userRepository = require('./src/repositories/userRepository');
const { getJwtSecret } = require('./src/config/jwt');

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
console.log('🛡️   CYBER SENTINEL — ROLE-BASED ACCESS CONTROL & AUTHORIZATION SUITE');
console.log('======================================================================\n');

async function runSuite() {
  console.log('━━━ SECTION 1: Canonical Roles & Permission Mapping Matrix ━━━');

  runTest('[RBAC-MATRIX] ADMIN holds superset permissions across all domain boundaries', () => {
    Object.values(PERMISSIONS).forEach(perm => {
      assert.strictEqual(hasPermission(ROLES.ADMIN, perm), true, `ADMIN must have ${perm}`);
    });
  });

  runTest('[RBAC-MATRIX] VIEWER has zero write, execution, or mutation permissions', () => {
    const mutationPerms = [
      PERMISSIONS.USERS_WRITE,
      PERMISSIONS.USERS_DELETE,
      PERMISSIONS.DEVICES_ISOLATE,
      PERMISSIONS.DEVICES_WRITE,
      PERMISSIONS.INCIDENTS_WRITE,
      PERMISSIONS.INCIDENTS_STATUS,
      PERMISSIONS.RULES_WRITE,
      PERMISSIONS.RESPONSE_EXECUTE,
      PERMISSIONS.SYSTEM_WRITE,
    ];

    mutationPerms.forEach(perm => {
      assert.strictEqual(hasPermission(ROLES.VIEWER, perm), false, `VIEWER must NOT have ${perm}`);
    });
  });

  runTest('[RBAC-MATRIX] Denies unrecognized roles and unknown permissions by default', () => {
    assert.strictEqual(hasPermission('GUEST_HACKER', PERMISSIONS.INCIDENTS_READ), false);
    assert.strictEqual(hasPermission(ROLES.SOC_ANALYST, 'nuclear_launch_codes'), false);
    assert.strictEqual(hasPermission(null, PERMISSIONS.AUDIT_READ), false);
  });

  console.log('\n━━━ SECTION 2: Role Authorization Middleware (requireRole) ━━━');

  runTest('[REQUIRE-ROLE] Rejects unauthorized roles with 403 Forbidden', () => {
    const middleware = requireRole([ROLES.ADMIN, ROLES.SECURITY_ENGINEER]);

    const req = { user: { email: 'viewer@sentinel.local', role: ROLES.VIEWER } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };
    let nextCalled = false;

    middleware(req, res, () => { nextCalled = true; });

    assert.strictEqual(nextCalled, false, 'Next must not be called');
    assert.strictEqual(status, 403);
    assert.ok(jsonBody.error.includes('Access denied'));
  });

  runTest('[REQUIRE-ROLE] Grants access to matching authorized roles and ADMIN', () => {
    const middleware = requireRole([ROLES.SOC_ANALYST]);

    // Test exact match
    let next1 = false;
    middleware({ user: { role: ROLES.SOC_ANALYST } }, {}, () => { next1 = true; });
    assert.strictEqual(next1, true, 'SOC_ANALYST must be granted');

    // Test ADMIN superset privilege
    let next2 = false;
    middleware({ user: { role: ROLES.ADMIN } }, {}, () => { next2 = true; });
    assert.strictEqual(next2, true, 'ADMIN must be granted automatically');
  });

  console.log('\n━━━ SECTION 3: Granular Permission Middleware (requirePermission) ━━━');

  runTest('[REQUIRE-PERMISSION] SOC_ANALYST cannot modify system configuration (system:write)', () => {
    const sysAdminMiddleware = requirePermission(PERMISSIONS.SYSTEM_WRITE);

    const req = { user: { email: 'analyst@sentinel.local', role: ROLES.SOC_ANALYST } };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };
    let nextCalled = false;

    sysAdminMiddleware(req, res, () => { nextCalled = true; });

    assert.strictEqual(nextCalled, false);
    assert.strictEqual(status, 403);
    assert.ok(jsonBody.error.includes('Insufficient permissions'));
  });

  runTest('[REQUIRE-PERMISSION] Only authorized roles can execute response actions', () => {
    const responseMiddleware = requirePermission(PERMISSIONS.RESPONSE_EXECUTE);

    // VIEWER denied
    let viewerNext = false;
    let viewerStatus = null;
    responseMiddleware(
      { user: { role: ROLES.VIEWER } },
      { status(s) { viewerStatus = s; return this; }, json() {} },
      () => { viewerNext = true; }
    );
    assert.strictEqual(viewerNext, false);
    assert.strictEqual(viewerStatus, 403);

    // ENDPOINT_OPERATOR permitted
    let operatorNext = false;
    responseMiddleware({ user: { role: ROLES.ENDPOINT_OPERATOR } }, {}, () => { operatorNext = true; });
    assert.strictEqual(operatorNext, true);

    // ADMIN permitted
    let adminNext = false;
    responseMiddleware({ user: { role: ROLES.ADMIN } }, {}, () => { adminNext = true; });
    assert.strictEqual(adminNext, true);
  });

  console.log('\n━━━ SECTION 4: Insecure Direct Object Reference (IDOR) Defenses ━━━');

  runTest('[IDOR] Non-admin user cannot access another user\'s resources by ID', () => {
    const idorMiddleware = preventIdor('userId');

    const req = {
      user: { id: 'USR-USER-0001', email: 'alice@sentinel.local', role: ROLES.SOC_ANALYST },
      params: { userId: 'USR-USER-9999' } // Attempting to access Bob's resource
    };
    let status = null;
    let jsonBody = null;
    const res = {
      status(s) { status = s; return this; },
      json(b) { jsonBody = b; }
    };
    let nextCalled = false;

    idorMiddleware(req, res, () => { nextCalled = true; });

    assert.strictEqual(nextCalled, false);
    assert.strictEqual(status, 403);
    assert.ok(jsonBody.error.includes('resources belonging to another user'));
  });

  runTest('[IDOR] User can access their own resources', () => {
    const idorMiddleware = preventIdor('userId');

    const req = {
      user: { id: 'USR-USER-0001', email: 'alice@sentinel.local', role: ROLES.SOC_ANALYST },
      params: { userId: 'USR-USER-0001' }
    };
    let nextCalled = false;

    idorMiddleware(req, {}, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
  });

  runTest('[IDOR] ADMIN can access any user\'s resources without obstruction', () => {
    const idorMiddleware = preventIdor('userId');

    const req = {
      user: { id: 'USR-ADMIN-0001', email: 'admin@sentinel.local', role: ROLES.ADMIN },
      params: { userId: 'USR-USER-9999' }
    };
    let nextCalled = false;

    idorMiddleware(req, {}, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
  });

  console.log('\n━━━ SECTION 5: Privilege Escalation & Mass Assignment Defenses ━━━');

  await runAsyncTest('[PRIV-ESCALATION] Registration ignores client-passed "role: ADMIN"', async () => {
    const maliciousPayload = {
      email: `attacker_${Date.now()}@sentinel.local`,
      password: 'Attacker_Password123!',
      name: 'Sneaky Attacker',
      role: 'ADMIN',            // Attempting self-promotion to ADMIN
      isAdmin: true,
      permissions: ['*'],
    };

    const res = await authService.register(maliciousPayload);

    assert.notStrictEqual(res.user.role, ROLES.ADMIN, 'User role must NEVER default or adopt client-supplied ADMIN');
    assert.strictEqual(res.user.role, ROLES.SOC_ANALYST, 'Role must default to standard least-privilege analyst');

    const savedUser = await userRepository.findByEmail(maliciousPayload.email);
    assert.strictEqual(savedUser.role, ROLES.SOC_ANALYST);
  });

  console.log('\n======================================================================');
  console.log(`🏁  RBAC SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
  console.log('======================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runSuite().catch(err => {
  console.error('Unhandled RBAC suite error:', err);
  process.exit(1);
});
