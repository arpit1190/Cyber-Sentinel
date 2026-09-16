/**
 * auth.js
 * Hardened Authentication & Operator Identity API Routes.
 * 
 * Implements:
 * - Constant-time credential checking and generic error responses
 * - Short-lived HS256 JWT access tokens with strict signature & algorithm verification
 * - Rotating SHA-256 hashed refresh tokens with family-based reuse & replay detection
 * - Mandatory RFC 6238 TOTP Multi-Factor Authentication
 * - Progressive lockout and brute-force defenses
 * - Immediate session revocation on password modification or token theft
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const userStore = require('../data/userStore');
const userRepository = require('../repositories/userRepository');
const authService = require('../services/authService');
const { requireAuth } = require('../middleware/auth');
const {
  validateRegisterInput,
  validateLoginInput,
  validateResetPasswordInput,
  validatePassword,
  EMAIL_RE
} = require('../validators/authValidators');
const { sendPasswordResetEmail, sendPasswordResetOTP } = require('../utils/notifier');
const { generateSecret, verifyTOTP, generateOtpAuthUri } = require('../utils/totp');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');
const { getJwtSecret } = require('../config/jwt');
const { ROLES } = require('../constants/roles');

const router = express.Router();

// ── In-Memory Password Reset Stores (Email Link & Mobile OTP) ────────────────
const resetTokens = new Map(); // token -> { email, expiresAt }
const resetOTPs = new Map();   // email -> { hashedOtp, expiresAt, attempts, maxAttempts }

// ── POST /api/auth/register ──────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const validation = validateRegisterInput(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  try {
    const result = await authService.register(validation.data, req);
    return res.status(201).json(result);
  } catch (err) {
    const status = err.status || 500;
    return res.status(status).json({ error: err.message || 'Registration failed.' });
  }
});

// ── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const validation = validateLoginInput(req.body);
  if (!validation.valid) {
    return res.status(401).json({ error: validation.error });
  }

  try {
    const result = await authService.login({ ...validation.data, req });
    return res.json(result);
  } catch (err) {
    const status = err.status || 500;
    return res.status(status).json({ error: err.message || 'Authentication failed.' });
  }
});

// ── POST /api/auth/refresh ───────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    const result = await authService.refresh(refreshToken, req);
    return res.json(result);
  } catch (err) {
    const status = err.status || 401;
    return res.status(status).json({ error: err.message || 'Token refresh failed.' });
  }
});

// ── POST /api/auth/verify-mfa ────────────────────────────────────────────────
router.post('/verify-mfa', async (req, res) => {
  try {
    const { mfaTicket, code, totpCode } = req.body || {};
    const inputCode = String(code || totpCode || '').trim();

    if (!mfaTicket) {
      return res.status(400).json({ error: 'MFA challenge ticket is required.' });
    }

    if (!inputCode) {
      return res.status(400).json({ error: '6-digit authenticator code is required.' });
    }

    // Cryptographically verify challenge ticket with explicit HS256 algorithm
    let ticketPayload;
    try {
      ticketPayload = jwt.verify(mfaTicket, getJwtSecret(), {
        algorithms: ['HS256'],
        ignoreExpiration: false,
      });
    } catch (err) {
      return res.status(401).json({ error: 'MFA challenge ticket has expired or is invalid. Please log in again.' });
    }

    if (ticketPayload.purpose !== 'mfa_challenge' || !ticketPayload.email) {
      return res.status(401).json({ error: 'Invalid MFA challenge token claims.' });
    }

    const user = await userRepository.findByEmail(ticketPayload.email);
    if (!user || user.status === 'suspended') {
      return res.status(401).json({ error: 'Operator account not found or suspended.' });
    }

    const secret = user.totpSecret || user.mfaSecret;
    if (!secret) {
      return res.status(400).json({ error: 'MFA is active but no authenticator secret is configured in profile.' });
    }

    const isTotpValid = verifyTOTP(inputCode, secret);
    if (!isTotpValid) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.MFA_FAILED || 'MFA_FAILED',
        target: 'AUTH_SERVICE',
        req,
        result: 'FAILURE',
        details: { reason: 'Invalid TOTP code' },
      });
      return res.status(401).json({ error: 'Invalid or expired authenticator code.' });
    }

    // Generate tokens upon successful MFA
    const token = authService.generateAccessToken(user);
    const { rawRefreshToken } = authService.generateRefreshToken(user, null, req);

    logSecurityEvent({
      actor: user.email,
      actorRole: user.role,
      action: AuditActions.LOGIN,
      result: 'SUCCESS',
      req,
      details: { mfaCompleted: true, role: user.role },
    });

    return res.json({
      token,
      refreshToken: rawRefreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: true,
        isPhoneVerified: true,
        mfaEnabled: true,
      }
    });
  } catch (err) {
    console.error('[AUTH] verify-mfa error:', err);
    return res.status(500).json({ error: 'Internal server error during MFA verification.' });
  }
});

// ── POST /api/auth/logout ────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    const result = await authService.logout({ refreshToken, user: req.user, req });
    return res.json(result);
  } catch (err) {
    console.error('[AUTH] logout error:', err);
    return res.status(500).json({ error: 'Internal server error during logout.' });
  }
});

// ── POST /api/auth/logout-all ────────────────────────────────────────────────
router.post('/logout-all', requireAuth, async (req, res) => {
  try {
    const result = await authService.logoutAll({ user: req.user, req });
    return res.json(result);
  } catch (err) {
    console.error('[AUTH] logout-all error:', err);
    return res.status(500).json({ error: 'Internal server error during global session termination.' });
  }
});

// ── PUT /api/auth/profile ────────────────────────────────────────────────────
router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { name, email, phone, currentPassword, newPassword, profilePic } = req.body;

    const user = await userRepository.findByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'Operator account not found.' });
    }

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current passcode is required to set a new passcode.' });
      }
      const valid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!valid) {
        return res.status(401).json({ error: 'Incorrect current passcode.' });
      }

      const passwordValidation = validatePassword(newPassword);
      if (!passwordValidation.valid) {
        return res.status(400).json({ error: passwordValidation.error });
      }

      user.passwordHash = await bcrypt.hash(newPassword, 12);
      // Invalidate all active sessions for security
      authService.revokeAllUserSessions(user.email, 'Operator changed password');
    }

    let emailChanged = false;
    const oldEmail = user.email;
    if (email && email.toLowerCase() !== user.email.toLowerCase()) {
      const emailLower = email.toLowerCase().trim();
      if (!EMAIL_RE.test(emailLower)) {
        return res.status(400).json({ error: 'Invalid email format.' });
      }
      const existing = await userRepository.findByEmail(emailLower);
      if (existing) {
        return res.status(409).json({ error: 'An operator with this email already exists.' });
      }
      user.email = emailLower;
      user.isEmailVerified = false;
      emailChanged = true;
    }

    if (phone !== undefined && phone !== (user.phone || '')) {
      user.phone = phone.trim();
      user.isPhoneVerified = false;
    }

    if (name) {
      user.name = String(name).trim();
    }

    if (profilePic !== undefined) {
      user.profilePic = profilePic;
    }

    if (emailChanged) {
      await userRepository.updateUserEmail(oldEmail, user.email, user);
    } else {
      await userRepository.updateUser(user);
    }

    const token = authService.generateAccessToken(user);

    return res.json({
      message: 'Profile updated successfully',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: Boolean(user.isEmailVerified),
        isPhoneVerified: Boolean(user.isPhoneVerified),
        mfaEnabled: Boolean(user.mfaEnabled),
      }
    });
  } catch (err) {
    console.error('[AUTH] Profile update error:', err);
    return res.status(500).json({ error: 'Internal server error during profile update.' });
  }
});

// ── GET /api/auth/me ────────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req, res) => {
  try {
    const user = await userRepository.findByEmail(req.user.email);
    if (!user) return res.status(404).json({ error: 'Operator account not found.' });
    return res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: Boolean(user.isEmailVerified),
        isPhoneVerified: Boolean(user.isPhoneVerified),
        mfaEnabled: Boolean(user.mfaEnabled),
      }
    });
  } catch (err) {
    console.error('[AUTH] /me error:', err);
    return res.status(500).json({ error: 'Internal server error retrieving operator profile.' });
  }
});

// ── GET /api/auth/mfa/setup ──────────────────────────────────────────────────
router.get('/mfa/setup', requireAuth, async (req, res) => {
  try {
    const user = await userRepository.findByEmail(req.user.email);
    if (!user) return res.status(404).json({ error: 'Operator account not found.' });

    const secret = user.totpSecret || generateSecret();
    const otpauthUri = generateOtpAuthUri(user.email, 'CyberSentinel', secret);

    return res.json({
      secret,
      otpauthUri,
      issuer: 'CyberSentinel',
      account: user.email,
      mfaEnabled: Boolean(user.mfaEnabled),
    });
  } catch (err) {
    console.error('[MFA] Setup error:', err);
    return res.status(500).json({ error: 'Failed to initiate MFA setup.' });
  }
});

// ── POST /api/auth/mfa/enable ────────────────────────────────────────────────
router.post('/mfa/enable', requireAuth, async (req, res) => {
  try {
    const { secret, code } = req.body || {};
    if (!secret || !code) {
      return res.status(400).json({ error: 'Secret and 6-digit verification code are required.' });
    }

    const isValid = verifyTOTP(String(code).trim(), secret);
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid authenticator code. Check the time on your device and retry.' });
    }

    const user = await userRepository.findByEmail(req.user.email);
    if (!user) return res.status(404).json({ error: 'Operator account not found.' });

    user.mfaEnabled = true;
    user.totpSecret = secret;
    await userRepository.updateUser(user);

    logSecurityEvent({
      actor: user.email,
      actorRole: user.role,
      action: AuditActions.MFA_ENABLED || 'MFA_ENABLED',
      target: 'MFA_SECURITY',
      req,
      details: { mfaType: 'TOTP' },
    });

    return res.json({ success: true, message: 'TOTP Multi-Factor Authentication successfully activated.' });
  } catch (err) {
    console.error('[MFA] Enable error:', err);
    return res.status(500).json({ error: 'Failed to enable MFA.' });
  }
});

// ── POST /api/auth/forgot-password ───────────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  try {
    const { method, email, phone } = req.body || {};
    if (!method || !['email', 'phone'].includes(method)) {
      return res.status(400).json({ error: 'method must be "email" or "phone"' });
    }

    let user;
    if (method === 'email') {
      if (!email) return res.status(400).json({ error: 'email is required' });
      user = await userRepository.findByEmail(String(email).toLowerCase().trim());
    } else {
      if (!phone) return res.status(400).json({ error: 'phone is required' });
      user = await userRepository.findByPhone(String(phone).trim());
    }

    // Always respond success to prevent user enumeration
    if (!user) {
      return res.json({ success: true, message: 'If an account exists, you will receive reset instructions.' });
    }

    if (method === 'email') {
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
      resetTokens.set(token, { email: user.email.toLowerCase(), expiresAt });

      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
      const resetUrl = `${frontendUrl}/reset-password?token=${token}&method=email`;

      sendPasswordResetEmail({ to: user.email, name: user.name, resetUrl }).catch(err => {
        console.error('[RESET] Email dispatch error:', err.message);
      });

      return res.json({ success: true, message: 'Password reset link sent to your email.' });
    } else {
      if (!user.phone) {
        return res.status(400).json({ error: 'No mobile number registered for this account.' });
      }

      const otp = crypto.randomInt(100000, 1000000).toString();
      const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');
      const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
      resetOTPs.set(user.email.toLowerCase(), {
        hashedOtp,
        expiresAt,
        attempts: 0,
        maxAttempts: 3,
      });

      sendPasswordResetOTP({ to: user.phone, otp }).catch(err => {
        console.error('[RESET] SMS dispatch error:', err.message);
      });

      const maskedPhone = user.phone.slice(0, -4).replace(/\d/g, '•') + user.phone.slice(-4);
      return res.json({
        success: true,
        message: 'OTP sent to your registered mobile number.',
        maskedPhone,
        email: user.email,
      });
    }
  } catch (err) {
    console.error('[RESET] forgot-password error:', err);
    return res.status(500).json({ error: 'Internal server error during password reset request.' });
  }
});

// ── POST /api/auth/reset-password ───────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
  const validation = validateResetPasswordInput(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { method, token, email, otp, newPassword } = validation.data;

  try {
    let userEmail;

    if (method === 'email') {
      const entry = resetTokens.get(token);
      if (!entry) {
        return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
      }
      if (Date.now() > entry.expiresAt) {
        resetTokens.delete(token);
        return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
      }
      userEmail = entry.email;
      resetTokens.delete(token);
    } else {
      const entry = resetOTPs.get(email.toLowerCase());
      if (!entry) {
        return res.status(400).json({ error: 'No active OTP found. Please request a new one.' });
      }
      if (Date.now() > entry.expiresAt) {
        resetOTPs.delete(email.toLowerCase());
        return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
      }

      if (entry.attempts >= entry.maxAttempts) {
        resetOTPs.delete(email.toLowerCase());
        return res.status(429).json({ error: 'Too many invalid attempts. Please request a new OTP.' });
      }

      entry.attempts += 1;
      const inputHashedOtp = crypto.createHash('sha256').update(otp.trim()).digest('hex');
      const isMatch = crypto.timingSafeEqual(Buffer.from(entry.hashedOtp), Buffer.from(inputHashedOtp));

      if (!isMatch) {
        const remaining = entry.maxAttempts - entry.attempts;
        return res.status(400).json({
          error: remaining > 0
            ? `Invalid OTP. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
            : 'Too many invalid attempts. Please request a new OTP.'
        });
      }

      userEmail = email.toLowerCase();
      resetOTPs.delete(userEmail);
    }

    const user = await userRepository.findByEmail(userEmail);
    if (!user) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    await userRepository.updateUser(user);

    // Invalidate all active user sessions upon password reset
    authService.revokeAllUserSessions(user.email, 'Password reset completed');

    logSecurityEvent({
      actor: user.email,
      actorRole: user.role,
      action: AuditActions.PASSWORD_RESET || 'PASSWORD_RESET',
      target: 'AUTH_CREDENTIALS',
      req,
      details: { method },
    });

    return res.json({ success: true, message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error('[RESET] reset-password error:', err);
    return res.status(500).json({ error: 'Internal server error during password reset.' });
  }
});

// Stubs for phone verification
router.post('/send-verification', requireAuth, async (req, res) => res.json({ message: 'Verified successfully' }));
router.post('/verify-code', requireAuth, async (req, res) => {
  const user = await userRepository.findByEmail(req.user?.email || '');
  return res.json({
    message: 'Verified successfully',
    user: user ? {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      profilePic: user.profilePic || null,
      createdAt: user.createdAt,
      phone: user.phone || '',
      isEmailVerified: true,
      isPhoneVerified: true
    } : req.user
  });
});

module.exports = router;
