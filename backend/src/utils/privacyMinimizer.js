/**
 * privacyMinimizer.js
 * Data Privacy & Data Minimization Utility for Cyber Sentinel.
 *
 * Implements privacy-by-design and data-minimization techniques:
 * 1. CLI / URL Credential & Secret Scrubbing (command lines, URLs, headers)
 * 2. Token & API Key Redaction (JWTs, Bearer tokens, cloud provider keys)
 * 3. IP Masking / Pseudonymization (optional privacy mode)
 * 4. Audit Log Detail Sanitization (removes authentication secrets)
 */

'use strict';

const crypto = require('crypto');

// Regular expressions for sensitive credentials embedded in CLI or strings
const CLI_PASSWORD_REGEX = /((?:--password|-p|--pass|-P|--pwd|--secret|--token|--key|--api-key|--auth-token)\s+(?:=|\s*))([^\s"']+)/gi;
const CLI_QUOTED_PASSWORD_REGEX = /((?:--password|-p|--pass|-P|--pwd|--secret|--token|--key|--api-key|--auth-token)\s*(?:=|\s*))["']([^"']+)["']/gi;
const CLI_USER_PASS_REGEX = /((?:-u|--user)\s+[^:\s"']+):([^\s"']+)/gi;
const URL_CREDENTIAL_REGEX = /(https?:\/\/)([^:\s\/]+):([^@\s\/]+)@/gi;
const BEARER_TOKEN_REGEX = /Bearer\s+([a-zA-Z0-9_\-\.]{15,})/gi;
const JWT_TOKEN_REGEX = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;
const GENERIC_API_KEY_REGEX = /(AIza[0-9A-Za-z-_]{35}|ghp_[a-zA-Z0-9]{36}|xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}|AKIA[0-9A-Z]{16})/g;

/**
 * Scrubs embedded credentials, passwords, Bearer tokens, JWTs, and API keys from arbitrary text.
 * 
 * @param {string} text - Raw string (e.g. command line, URL, file path, or log message).
 * @returns {string} Sanitized string with sensitive secrets masked.
 */
function redactSecretsAndTokens(text) {
  if (typeof text !== 'string' || !text) return text;

  let sanitized = text;

  // 1. Redact curl / CLI user:password flags (e.g. -u user:pass)
  sanitized = sanitized.replace(CLI_USER_PASS_REGEX, '$1:[REDACTED_PASSWORD]');

  // 2. Redact quoted passwords/secrets in CLI arguments
  sanitized = sanitized.replace(CLI_QUOTED_PASSWORD_REGEX, '$1"[REDACTED_SECRET]"');

  // 3. Redact unquoted passwords/secrets in CLI arguments
  sanitized = sanitized.replace(CLI_PASSWORD_REGEX, '$1[REDACTED_SECRET]');

  // 4. Redact Basic Auth credentials in URLs (e.g. https://user:pass@host)
  sanitized = sanitized.replace(URL_CREDENTIAL_REGEX, '$1$2:[REDACTED_PASSWORD]@');

  // 4. Redact Bearer tokens
  sanitized = sanitized.replace(BEARER_TOKEN_REGEX, 'Bearer [REDACTED_TOKEN]');

  // 5. Redact raw JWT tokens
  sanitized = sanitized.replace(JWT_TOKEN_REGEX, '[REDACTED_JWT_TOKEN]');

  // 6. Redact known cloud/SaaS API key patterns
  sanitized = sanitized.replace(GENERIC_API_KEY_REGEX, '[REDACTED_API_KEY]');

  return sanitized;
}

/**
 * Masks an IPv4 address to its /24 subnet or IPv6 to /48 for privacy preservation.
 * 
 * @param {string} ip - IP address string.
 * @returns {string} Masked IP address.
 */
function maskIpAddress(ip) {
  if (typeof ip !== 'string' || !ip) return ip;
  const trimmed = ip.trim();

  // IPv4 /24 masking (192.168.1.105 -> 192.168.1.0/24)
  const ipv4Parts = trimmed.split('.');
  if (ipv4Parts.length === 4 && ipv4Parts.every(p => !isNaN(parseInt(p, 10)))) {
    return `${ipv4Parts[0]}.${ipv4Parts[1]}.${ipv4Parts[2]}.0/24`;
  }

  // IPv6 /48 masking
  if (trimmed.includes(':')) {
    const parts = trimmed.split(':').filter(Boolean);
    if (parts.length >= 3) {
      return `${parts.slice(0, 3).join(':')}::/48`;
    }
  }

  return trimmed;
}

/**
 * Pseudonymizes a username or email using a deterministic SHA-256 HMAC digest.
 * 
 * @param {string} identifier - Raw username or email.
 * @param {string} [salt='cyber-sentinel-privacy-salt'] - HMAC salt.
 * @returns {string} Pseudonymized identifier (e.g. 'user_a3f89e1b').
 */
function pseudonymizeUser(identifier, salt = 'cyber-sentinel-privacy-salt') {
  if (typeof identifier !== 'string' || !identifier) return 'system';
  if (identifier.toLowerCase() === 'system' || identifier.toLowerCase() === 'root') {
    return identifier.toLowerCase();
  }

  const hash = crypto.createHmac('sha256', salt).update(identifier.trim().toLowerCase()).digest('hex').slice(0, 8);
  return `user_${hash}`;
}

/**
 * Sanitizes audit log details object to prevent accidental persistence of passwords,
 * tokens, session IDs, or private keys.
 * 
 * @param {Object} details - Raw details object.
 * @returns {Object} Cleaned details object.
 */
function sanitizeAuditDetails(details) {
  if (!details || typeof details !== 'object' || Array.isArray(details)) {
    return details;
  }

  const SENSITIVE_KEYS = new Set([
    'password', 'password_hash', 'currentPassword', 'newPassword', 'token',
    'refreshToken', 'refresh_token', 'secret', 'mfaSecret', 'totpSecret',
    'apiKey', 'api_key', 'privateKey', 'private_key', 'authorization', 'cookie'
  ]);

  const sanitized = {};
  for (const [key, value] of Object.entries(details)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase()) || SENSITIVE_KEYS.has(key)) {
      sanitized[key] = '[REDACTED_SECURITY_PARAM]';
    } else if (typeof value === 'string') {
      sanitized[key] = redactSecretsAndTokens(value);
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      sanitized[key] = sanitizeAuditDetails(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

module.exports = {
  redactSecretsAndTokens,
  maskIpAddress,
  pseudonymizeUser,
  sanitizeAuditDetails,
};
