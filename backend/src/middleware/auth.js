/**
 * auth.js
 * Production-grade JWT Authentication & Role-Based Access Control (RBAC) Middleware.
 * 
 * Enforces:
 * 1. Server-side zero-trust authorization (frontend checks never trusted).
 * 2. Explicit signature & algorithm verification (HS256 only).
 * 3. Granular permission checking (requirePermission).
 * 4. Role checking with inheritance (requireRole).
 * 5. Insecure Direct Object Reference (IDOR) defense.
 * 6. Privilege escalation and horizontal authorization defenses.
 * 7. Deny-by-default access policy.
 */

const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('../config/jwt');
const { ROLES, PERMISSIONS, normalizeRole, hasPermission } = require('../constants/roles');

const ALLOWED_ALGORITHMS = ['HS256'];

/**
 * Authentication middleware: verifies Bearer JWT token and extracts user identity.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  const token = header.slice(7).trim();
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Empty token supplied.' });
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return res.status(401).json({ error: 'Malformed authentication token structure.' });
  }

  try {
    const secret = getJwtSecret();
    if (!secret) {
      console.error('[AUTH] Critical: JWT secret is not configured.');
      return res.status(500).json({ error: 'Authentication service misconfigured.' });
    }

    const payload = jwt.verify(token, secret, {
      algorithms: ALLOWED_ALGORITHMS,
      ignoreExpiration: false,
    });

    if (!payload || typeof payload !== 'object') {
      return res.status(401).json({ error: 'Invalid token payload.' });
    }

    if (!payload.email || typeof payload.email !== 'string') {
      return res.status(401).json({ error: 'Token is missing required email claim.' });
    }

    if (!payload.role || typeof payload.role !== 'string') {
      return res.status(401).json({ error: 'Token is missing required role claim.' });
    }

    const normalizedRole = normalizeRole(payload.role);

    req.user = {
      id: payload.sub || payload.id || payload.email,
      email: payload.email.toLowerCase().trim(),
      name: payload.name ? String(payload.name).trim() : payload.email.split('@')[0],
      role: normalizedRole,
      iat: payload.iat,
      exp: payload.exp,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Authentication session expired. Please log in again.' });
    }
    if (err.name === 'JsonWebTokenError') {
      if (err.message.includes('invalid signature')) {
        return res.status(401).json({ error: 'Invalid authentication token signature.' });
      }
      if (err.message.includes('invalid algorithm') || err.message.includes('algorithm')) {
        return res.status(401).json({ error: 'Unsupported or forbidden token algorithm.' });
      }
      return res.status(401).json({ error: 'Invalid authentication token.' });
    }
    return res.status(401).json({ error: 'Authentication failed.' });
  }
}

/**
 * Server-side RBAC Role authorization middleware.
 * Denies access by default if user's role is not in allowedRoles.
 * ADMIN has superset privileges.
 */
function requireRole(allowedRoles = []) {
  const normalizedAllowed = (Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles])
    .map(r => normalizeRole(r));

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required before checking permissions.' });
    }

    const userRole = normalizeRole(req.user.role);

    // ADMIN always has full access
    if (userRole === ROLES.ADMIN || normalizedAllowed.includes(userRole)) {
      return next();
    }

    return res.status(403).json({
      error: `Access denied. Role '${userRole}' is not authorized for this operation. Required: [${normalizedAllowed.join(', ')}]`,
    });
  };
}

/**
 * Granular Permission authorization middleware.
 * Checks whether the user's role satisfies all required permissions.
 */
function requirePermission(requiredPermissions = []) {
  const perms = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required before evaluating permissions.' });
    }

    const userRole = normalizeRole(req.user.role);

    // Check all required permissions
    const missingPerms = perms.filter(perm => !hasPermission(userRole, perm));
    if (missingPerms.length === 0) {
      return next();
    }

    return res.status(403).json({
      error: `Access denied. Insufficient permissions. Required: [${missingPerms.join(', ')}]`,
    });
  };
}

/**
 * IDOR Defense Middleware:
 * Ensures the requesting user can only access/modify their own resource ID,
 * unless they hold administrative privileges.
 */
function preventIdor(resourceParam = 'id') {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    const targetId = req.params[resourceParam] || req.query[resourceParam] || req.body[resourceParam];
    if (!targetId) {
      return next();
    }

    const currentUserId = req.user.id;
    const currentUserEmail = req.user.email;
    const userRole = normalizeRole(req.user.role);

    // Admins can access all records
    if (userRole === ROLES.ADMIN) {
      return next();
    }

    // Check if target resource belongs to the current user
    if (targetId === currentUserId || targetId.toLowerCase() === currentUserEmail.toLowerCase()) {
      return next();
    }

    return res.status(403).json({
      error: 'Access denied. You do not have permission to access or modify resources belonging to another user.'
    });
  };
}

module.exports = {
  requireAuth,
  requireAuthentication: requireAuth,
  requireRole,
  requirePermission,
  preventIdor,
  verifyToken: requireAuth,
  ALLOWED_ALGORITHMS,
};
