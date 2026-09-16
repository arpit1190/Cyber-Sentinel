/**
 * Centralized Configuration Management System for Cyber Sentinel
 * 
 * Enforces:
 * 1. Fail-closed security validation in production (NODE_ENV=production)
 * 2. Type validation (integers, booleans, URLs, emails, port ranges)
 * 3. Safe local-only development and testing defaults
 * 4. Zero secret leakage in logs or exception messages
 * 5. Immutable configuration exports
 */

const path = require('path');
const crypto = require('crypto');

// Load environment file (.env) from backend root if present
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

// Known insecure / predictable secrets that are strictly forbidden in production
const INSECURE_DEFAULT_SECRETS = [
  'cyber-sentinel-dev-only-secret-do-not-use-in-production',
  'cyber-sentinel-dev-super-secure-random-key-12345',
  'change_this_to_a_long_random_secret',
  'secret',
  'jwt_secret',
  '123456',
  'password',
  'sentinel-device-auth-key'
];

/**
 * Validates integer within a range
 */
function parseInteger(val, defaultVal, min = 1, max = 65535, name = 'Value') {
  if (val === undefined || val === null || val === '') return defaultVal;
  const num = parseInt(val, 10);
  if (isNaN(num) || num < min || num > max) {
    throw new Error(`[CONFIG ERROR] ${name} must be a valid integer between ${min} and ${max}. Got: '${val}'`);
  }
  return num;
}

/**
 * Validates URL string format
 */
function isValidUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

/**
 * Normalizes and validates CORS origin configuration
 */
function parseCorsOrigins(rawOrigins, isProd) {
  if (!rawOrigins || rawOrigins.trim() === '') {
    return isProd
      ? []
      : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173', 'http://localhost:10000'];
  }

  const origins = rawOrigins
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  for (const origin of origins) {
    if (origin === '*') {
      if (isProd) {
        throw new Error('[CONFIG ERROR] CORS_ORIGIN cannot be wildcard (*) in production when credentials are enabled.');
      }
      continue;
    }
    if (!isValidUrl(origin)) {
      throw new Error(`[CONFIG ERROR] Invalid CORS origin URL: '${origin}'. Must start with http:// or https://`);
    }
  }

  return origins;
}

/**
 * Validates email format
 */
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

/**
 * Helper to mask secret strings for safe logging
 */
function maskSecret(val, placeholder = '[CONFIGURED]') {
  if (!val || typeof val !== 'string' || val.trim() === '') return '[NOT SET]';
  return `${placeholder} (${val.length} chars)`;
}

// ── Environment Discovery ──────────────────────────────────────────────────
const rawEnv = (process.env.NODE_ENV || 'development').trim().toLowerCase();
const validEnvs = ['development', 'test', 'staging', 'production'];
const NODE_ENV = validEnvs.includes(rawEnv) ? rawEnv : 'development';

const isProduction = NODE_ENV === 'production';
const isStaging = NODE_ENV === 'staging';
const isTest = NODE_ENV === 'test';
const isDevelopment = NODE_ENV === 'development';
const isSecureEnv = isProduction || isStaging;

// Accumulator for startup validation errors
const validationErrors = [];

// ── 1. Server Configuration ────────────────────────────────────────────────
let port = 5000;
try {
  port = parseInteger(process.env.PORT, isProduction ? 10000 : 5000, 1, 65535, 'PORT');
} catch (e) {
  validationErrors.push(e.message);
}

const frontendUrl = process.env.FRONTEND_URL || (isProduction ? '' : 'http://localhost:5173');
if (process.env.FRONTEND_URL && !isValidUrl(process.env.FRONTEND_URL)) {
  validationErrors.push(`[CONFIG ERROR] FRONTEND_URL must be a valid URL. Got: '${process.env.FRONTEND_URL}'`);
}

// ── 2. CORS Configuration ──────────────────────────────────────────────────
let corsOrigins = [];
try {
  corsOrigins = parseCorsOrigins(process.env.CORS_ORIGINS || process.env.CORS_ORIGIN, isProduction);
  if (isProduction && corsOrigins.length === 0) {
    validationErrors.push('[CONFIG ERROR] CORS_ORIGINS must specify at least one authorized origin in production.');
  }
} catch (e) {
  validationErrors.push(e.message);
}

// ── 3. Cryptographic & Auth Secrets ────────────────────────────────────────
const rawJwtSecret = process.env.JWT_SECRET ? process.env.JWT_SECRET.trim() : '';
let jwtSecret = rawJwtSecret;

if (isSecureEnv) {
  if (!rawJwtSecret) {
    validationErrors.push(`[CONFIG ERROR] JWT_SECRET is required in ${NODE_ENV} environment.`);
  } else if (rawJwtSecret.length < 32) {
    validationErrors.push(`[CONFIG ERROR] JWT_SECRET must be at least 32 characters long in ${NODE_ENV} environment.`);
  } else if (INSECURE_DEFAULT_SECRETS.includes(rawJwtSecret)) {
    validationErrors.push(`[CONFIG ERROR] JWT_SECRET cannot use known default/predictable development secret strings in ${NODE_ENV}.`);
  }
} else {
  if (!rawJwtSecret) {
    jwtSecret = 'cyber-sentinel-dev-only-secret-do-not-use-in-production';
  }
}

const rawRefreshSecret = process.env.REFRESH_TOKEN_SECRET ? process.env.REFRESH_TOKEN_SECRET.trim() : '';
let refreshTokenSecret = rawRefreshSecret;

if (isSecureEnv) {
  if (rawRefreshSecret && rawRefreshSecret.length < 32) {
    validationErrors.push(`[CONFIG ERROR] REFRESH_TOKEN_SECRET must be at least 32 characters long in ${NODE_ENV} when configured.`);
  } else if (rawRefreshSecret && INSECURE_DEFAULT_SECRETS.includes(rawRefreshSecret)) {
    validationErrors.push(`[CONFIG ERROR] REFRESH_TOKEN_SECRET cannot use known default secrets in ${NODE_ENV}.`);
  }
  if (!rawRefreshSecret && jwtSecret) {
    // Derive a dedicated refresh secret deterministically if not explicitly provided
    refreshTokenSecret = crypto.createHmac('sha256', jwtSecret).update('sentinel_refresh_secret_seed').digest('hex');
  }
} else {
  refreshTokenSecret = rawRefreshSecret || 'cyber-sentinel-dev-refresh-token-secret-fallback-12345';
}

const jwtExpiresIn = process.env.JWT_EXPIRES_IN || (isProduction ? '1h' : '2h');
const refreshTokenExpiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

// ── 4. Endpoint Device Ingestion Authentication ────────────────────────────
const rawDeviceSecret = (process.env.DEVICE_SECRET || process.env.SENTINEL_DEVICE_TOKEN || process.env.SENTINEL_AGENT_KEY || '').trim();
let deviceSecret = rawDeviceSecret;

if (isSecureEnv) {
  if (rawDeviceSecret && rawDeviceSecret.length < 16) {
    validationErrors.push(`[CONFIG ERROR] DEVICE_SECRET must be at least 16 characters long in ${NODE_ENV}.`);
  } else if (rawDeviceSecret && INSECURE_DEFAULT_SECRETS.includes(rawDeviceSecret)) {
    validationErrors.push(`[CONFIG ERROR] DEVICE_SECRET cannot use predictable development strings in ${NODE_ENV}.`);
  }
} else {
  deviceSecret = rawDeviceSecret || 'sentinel-dev-device-token-1234567890';
}

// ── 5. Database Configuration ──────────────────────────────────────────────
const databaseUrl = process.env.DATABASE_URL ? process.env.DATABASE_URL.trim() : '';
if (databaseUrl) {
  if (!databaseUrl.startsWith('postgres://') && !databaseUrl.startsWith('postgresql://')) {
    validationErrors.push('[CONFIG ERROR] DATABASE_URL must start with postgres:// or postgresql://');
  }
}

// ── 6. Metrics Endpoint Protection ─────────────────────────────────────────
const metricsToken = process.env.METRICS_TOKEN ? process.env.METRICS_TOKEN.trim() : null;

// ── 7. AI & LLM Credentials ───────────────────────────────────────────────
const geminiApiKey = process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.trim() : null;
const geminiModel = process.env.GEMINI_MODEL ? process.env.GEMINI_MODEL.trim() : 'gemini-2.0-flash';

// ── 8. Initial Admin Provisioning ──────────────────────────────────────────
const initialAdminEmail = (process.env.INITIAL_ADMIN_EMAIL || 'admin@sentinel.local').trim().toLowerCase();
if (process.env.INITIAL_ADMIN_EMAIL && !isValidEmail(process.env.INITIAL_ADMIN_EMAIL)) {
  validationErrors.push(`[CONFIG ERROR] INITIAL_ADMIN_EMAIL is not a valid email address: '${process.env.INITIAL_ADMIN_EMAIL}'`);
}

const initialAdminPassword = process.env.INITIAL_ADMIN_PASSWORD ? process.env.INITIAL_ADMIN_PASSWORD.trim() : '';
if (isProduction && initialAdminPassword && initialAdminPassword.length < 12) {
  validationErrors.push('[CONFIG ERROR] INITIAL_ADMIN_PASSWORD must be at least 12 characters long in production.');
}

// ── 9. Notification Gateways (Optional) ────────────────────────────────────
const smtpPort = process.env.SMTP_PORT ? parseInteger(process.env.SMTP_PORT, 587, 1, 65535, 'SMTP_PORT') : 587;
const smtpConfig = {
  host: process.env.SMTP_HOST || null,
  port: smtpPort,
  user: process.env.SMTP_USER || null,
  pass: process.env.SMTP_PASS || null,
  from: process.env.SMTP_FROM || process.env.SMTP_USER || 'Cyber Sentinel <no-reply@sentinel.local>',
  enabled: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS)
};

const twilioConfig = {
  accountSid: process.env.TWILIO_ACCOUNT_SID || null,
  authToken: process.env.TWILIO_AUTH_TOKEN || null,
  fromPhone: process.env.TWILIO_PHONE_NUMBER || null,
  enabled: Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER)
};

const fast2smsConfig = {
  apiKey: process.env.FAST2SMS_API_KEY || null,
  enabled: Boolean(process.env.FAST2SMS_API_KEY)
};

// ── Fail-Closed Enforcement ────────────────────────────────────────────────
if (validationErrors.length > 0) {
  const errorMessage = [
    '',
    '═══════════════════════════════════════════════════════════════════',
    '🚨 FATAL CONFIGURATION INITIALIZATION ERROR',
    '═══════════════════════════════════════════════════════════════════',
    ...validationErrors.map(e => `  ❌ ${e}`),
    '═══════════════════════════════════════════════════════════════════',
    'Refusing to start server with invalid or insecure configuration.',
    ''
  ].join('\n');

  if (isProduction || validationErrors.some(e => e.includes('PORT') || e.includes('DATABASE_URL'))) {
    throw new Error(errorMessage);
  } else {
    console.warn(errorMessage);
  }
}

// ── Immutable Config Export ────────────────────────────────────────────────
const config = Object.freeze({
  env: NODE_ENV,
  isProduction,
  isTest,
  isDevelopment,
  server: Object.freeze({
    port,
    frontendUrl,
    corsOrigins: Object.freeze(corsOrigins),
  }),
  auth: Object.freeze({
    jwtSecret,
    jwtExpiresIn,
    refreshTokenSecret,
    refreshTokenExpiresIn,
    deviceSecret,
    initialAdminEmail,
    initialAdminPassword,
  }),
  database: Object.freeze({
    url: databaseUrl,
    hasPostgres: Boolean(databaseUrl),
    maxConnections: 15,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  }),
  ai: Object.freeze({
    apiKey: geminiApiKey,
    model: geminiModel,
    enabled: Boolean(geminiApiKey),
  }),
  telemetry: Object.freeze({
    metricsToken,
    hasMetricsAuth: Boolean(metricsToken),
  }),
  notifications: Object.freeze({
    smtp: Object.freeze(smtpConfig),
    twilio: Object.freeze(twilioConfig),
    fast2sms: Object.freeze(fast2smsConfig),
  }),
  getJwtSecret() {
    return jwtSecret;
  },
  getJwtExpiresIn() {
    return jwtExpiresIn;
  },
  getRefreshTokenSecret() {
    return refreshTokenSecret;
  },
  getDeviceSecret() {
    return deviceSecret;
  },
  /**
   * Generates a safe summary of active configuration for diagnostic logging
   * without leaking plaintext secrets.
   */
  getSafeSummary() {
    return {
      environment: NODE_ENV,
      port,
      frontendUrl,
      corsOrigins: corsOrigins.length > 0 ? corsOrigins : '[NONE]',
      database: databaseUrl ? 'PostgreSQL Configured' : 'Offline JSON Repository Mode',
      aiEngine: geminiApiKey ? `Enabled (${geminiModel})` : 'Offline Heuristic Mode',
      jwtSecretStatus: maskSecret(jwtSecret, '[ACTIVE KEY]'),
      refreshTokenSecretStatus: maskSecret(refreshTokenSecret, '[ACTIVE KEY]'),
      deviceSecretStatus: maskSecret(deviceSecret, '[ACTIVE KEY]'),
      metricsAuthProtected: Boolean(metricsToken),
      smtpConfigured: smtpConfig.enabled,
      smsConfigured: twilioConfig.enabled || fast2smsConfig.enabled,
    };
  }
});

module.exports = config;
