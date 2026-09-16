/**
 * authValidators.js
 * Input validation, sanitization, and password strength policy enforcement.
 * Adheres to NIST SP 800-63B and OWASP Authentication Guidelines.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Common predictable/breached passwords denylist
const COMMON_PASSWORDS = new Set([
  'password', 'password123', '12345678', '123456789', 'admin123',
  'admin1234', 'qwerty123', 'sentinel123', 'letmein123', 'welcome123',
  'iloveyou', 'monkey123', 'dragon123', 'master123', 'changeme123'
]);

/**
 * Validates password complexity against enterprise security standards:
 * - Minimum 8 characters
 * - At least one uppercase letter (A-Z)
 * - At least one lowercase letter (a-z)
 * - At least one digit (0-9)
 * - At least one special symbol
 * - Not in common dictionary / breached password list
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required and must be a string.' };
  }

  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long.' };
  }

  if (password.length > 128) {
    return { valid: false, error: 'Password must not exceed 128 characters.' };
  }

  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return { valid: false, error: 'Password is too common or easily guessable. Please choose a stronger passphrase.' };
  }

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
    return {
      valid: false,
      error: 'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.'
    };
  }

  return { valid: true };
}

function validateRegisterInput(body) {
  const { email, password, name, phone } = body || {};
  if (!email || !password) {
    return { valid: false, error: 'Email and password are required.' };
  }

  const cleanEmail = email.trim().toLowerCase();
  if (!EMAIL_RE.test(cleanEmail)) {
    return { valid: false, error: 'Invalid email format.' };
  }

  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    return passwordCheck;
  }

  return {
    valid: true,
    data: {
      email: cleanEmail,
      password,
      name: name ? String(name).trim() : cleanEmail.split('@')[0],
      phone: phone ? String(phone).trim() : '',
    }
  };
}

function validateLoginInput(body) {
  const { email, password, mfaCode } = body || {};
  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    return { valid: false, error: 'Invalid email or password.' };
  }

  const cleanEmail = email.trim().toLowerCase();
  if (!cleanEmail || !password) {
    return { valid: false, error: 'Invalid email or password.' };
  }

  return {
    valid: true,
    data: {
      email: cleanEmail,
      password: String(password),
      mfaCode: mfaCode ? String(mfaCode).trim() : null,
    }
  };
}

function validateResetPasswordInput(body) {
  const { method, token, email, otp, newPassword } = body || {};

  if (!method || !['email', 'phone'].includes(method)) {
    return { valid: false, error: 'method must be "email" or "phone"' };
  }

  if (method === 'email' && (!token || typeof token !== 'string')) {
    return { valid: false, error: 'Reset token is required.' };
  }

  if (method === 'phone' && (!email || !otp)) {
    return { valid: false, error: 'Email and OTP are required.' };
  }

  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    return passwordCheck;
  }

  return {
    valid: true,
    data: {
      method,
      token: token ? String(token).trim() : null,
      email: email ? String(email).trim().toLowerCase() : null,
      otp: otp ? String(otp).trim() : null,
      newPassword,
    }
  };
}

module.exports = {
  validatePassword,
  validateRegisterInput,
  validateLoginInput,
  validateResetPasswordInput,
  EMAIL_RE,
  COMMON_PASSWORDS,
};
