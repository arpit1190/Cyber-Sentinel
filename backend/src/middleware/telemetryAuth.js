/**
 * telemetryAuth.js
 * Cryptographic Authentication & Integrity Middleware for Endpoint Telemetry Ingestion.
 * 
 * Enforces:
 * 1. HMAC-SHA256 Request Signing with Device-Specific Secret
 * 2. Strict Timestamp Freshness (prevents delayed packet replay)
 * 3. Nonce Tracking Sliding Window (prevents exact replay attacks)
 * 4. Request Body SHA-256 Digest Integrity Verification
 * 5. Device Lifecycle Status & Authorization (rejects revoked / decommissioned endpoints)
 * 6. Constant-Time Timing-Safe Comparison (mitigates timing attacks)
 * 7. Zero Secret Logging
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('../config/jwt');
const deviceRepository = require('../repositories/deviceRepository');
const deviceService = require('../services/deviceService');
const config = require('../config');

// Maximum allowable clock drift (past and future): 5 minutes (300,000 ms)
const MAX_CLOCK_DRIFT_MS = 5 * 60 * 1000;

// In-memory sliding window for Nonce Replay Protection: Map<"deviceId:nonce", timestampMs>
const nonceStore = new Map();

// Periodic prune of nonces older than MAX_CLOCK_DRIFT_MS (every 60 seconds)
setInterval(() => {
  const threshold = Date.now() - MAX_CLOCK_DRIFT_MS;
  for (const [key, ts] of nonceStore.entries()) {
    if (ts < threshold) {
      nonceStore.delete(key);
    }
  }
}, 60 * 1000).unref();

/**
 * Computes the canonical message and HMAC-SHA256 signature for a telemetry request.
 * Canonical format:
 *   METHOD\n
 *   PATH\n
 *   TIMESTAMP\n
 *   NONCE\n
 *   BODY_HASH
 */
function computeTelemetrySignature({ method, path, timestamp, nonce, body, deviceSecret }) {
  const cleanMethod = (method || 'POST').toUpperCase();
  const cleanPath = path ? path.split('?')[0] : '/api/events';
  const cleanTs = String(timestamp);
  const cleanNonce = String(nonce);

  let rawBodyString = '';
  if (typeof body === 'string') {
    rawBodyString = body;
  } else if (body !== undefined && body !== null) {
    rawBodyString = JSON.stringify(body);
  }

  const bodyHash = crypto.createHash('sha256').update(rawBodyString).digest('hex');
  const canonical = `${cleanMethod}\n${cleanPath}\n${cleanTs}\n${cleanNonce}\n${bodyHash}`;
  const signature = crypto.createHmac('sha256', deviceSecret).update(canonical).digest('hex');

  return {
    canonical,
    bodyHash,
    signature,
  };
}

/**
 * Middleware: authenticateTelemetry
 */
async function authenticateTelemetry(req, res, next) {
  const deviceId = req.headers['x-device-id'];
  const timestamp = req.headers['x-timestamp'];
  const nonce = req.headers['x-nonce'];
  const signature = req.headers['x-signature'];
  const legacyToken = req.headers['x-device-token'];
  const authHeader = req.headers.authorization || '';

  // ── 1. Cryptographic HMAC-SHA256 Telemetry Authentication (Primary) ──
  if (deviceId && (signature || timestamp || nonce)) {
    if (!signature || !timestamp || !nonce) {
      return res.status(401).json({
        error: 'Unauthorized: Missing required telemetry authentication headers (X-Timestamp, X-Nonce, X-Signature).'
      });
    }

    // 1.1 Validate Device Existence
    const device = await deviceRepository.findById(deviceId);
    if (!device) {
      return res.status(401).json({
        error: 'Unauthorized: Unknown or unauthenticated device identifier.'
      });
    }

    // 1.2 Validate Device Lifecycle Status
    if (device.status === 'REVOKED' || device.status === 'DECOMMISSIONED') {
      return res.status(403).json({
        error: `Forbidden: Device is in '${device.status}' state. Telemetry ingestion rejected.`
      });
    }
    if (device.status === 'PENDING') {
      return res.status(403).json({
        error: 'Forbidden: Device enrollment is pending operator authorization.'
      });
    }

    // 1.3 Validate Timestamp Freshness
    let tsMs = Date.parse(timestamp);
    if (isNaN(tsMs) && /^\d+$/.test(String(timestamp).trim())) {
      const num = Number(timestamp);
      tsMs = num > 1e11 ? num : num * 1000;
    }

    if (isNaN(tsMs)) {
      return res.status(400).json({
        error: 'Bad Request: Invalid timestamp format in X-Timestamp.'
      });
    }

    const now = Date.now();
    if (tsMs < now - MAX_CLOCK_DRIFT_MS) {
      return res.status(401).json({
        error: 'Unauthorized: Expired telemetry timestamp (maximum allowed clock drift is 5 minutes).'
      });
    }
    if (tsMs > now + MAX_CLOCK_DRIFT_MS) {
      return res.status(401).json({
        error: 'Unauthorized: Future telemetry timestamp rejected.'
      });
    }

    // 1.4 Detect Nonce Replay
    const nonceKey = `${deviceId}:${nonce}`;
    if (nonceStore.has(nonceKey)) {
      return res.status(401).json({
        error: 'Unauthorized: Replay attack detected. Nonce has already been used.'
      });
    }

    // 1.5 Retrieve Device Secret
    const deviceSecret = await deviceService.getDeviceSecret(deviceId);
    if (!deviceSecret) {
      return res.status(401).json({
        error: 'Unauthorized: No active cryptographic credential found for device.'
      });
    }

    // 1.6 Verify Request Body Digest & HMAC-SHA256 Signature
    let rawBodyString = '';
    if (req.rawBody) {
      rawBodyString = typeof req.rawBody === 'string' ? req.rawBody : req.rawBody.toString('utf8');
    } else if (typeof req.body === 'string') {
      rawBodyString = req.body;
    } else if (req.body !== undefined && req.body !== null) {
      rawBodyString = JSON.stringify(req.body);
    }

    const bodyHash = crypto.createHash('sha256').update(rawBodyString).digest('hex');
    const reqPath = req.originalUrl ? req.originalUrl.split('?')[0] : (req.path || '/api/events');
    const canonical = `${req.method.toUpperCase()}\n${reqPath}\n${timestamp}\n${nonce}\n${bodyHash}`;
    const expectedSignature = crypto.createHmac('sha256', deviceSecret).update(canonical).digest('hex');

    let isValidSignature = false;
    try {
      const sigBuf = Buffer.from(String(signature).trim().toLowerCase(), 'hex');
      const expBuf = Buffer.from(expectedSignature.toLowerCase(), 'hex');
      if (sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf)) {
        isValidSignature = true;
      }
    } catch (_) {
      isValidSignature = false;
    }

    if (!isValidSignature) {
      return res.status(401).json({
        error: 'Unauthorized: Invalid HMAC-SHA256 telemetry signature.'
      });
    }

    // Consume nonce to prevent replay
    nonceStore.set(nonceKey, now);

    // Update last seen
    await deviceRepository.updateLastSeen(deviceId);

    req.device = device;
    req.agent = { deviceId, device, type: 'hmac-endpoint' };
    return next();
  }

  // ── 2. Operator Bearer JWT Authentication (SOC UI / Script Fallback) ──
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    try {
      const decoded = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] });
      req.user = decoded;
      return next();
    } catch (_) {}
  }

  // ── 3. Token-Based Authentication (Individual Device Token or Dev Fallback) ──
  if (deviceId && legacyToken) {
    const authResult = await deviceService.authenticateDevice(deviceId, legacyToken);
    if (authResult.authenticated) {
      req.agent = { deviceId, device: authResult.device, type: 'endpoint-agent' };
      return next();
    }

    // Static fallback key allowed ONLY in non-production simulation/development mode
    if (!config.isProduction) {
      const expectedAgentKey = config.auth?.deviceSecret || process.env.SENTINEL_AGENT_KEY || 'sentinel-device-auth-key';
      if (legacyToken === expectedAgentKey) {
        req.agent = { deviceId, type: 'endpoint-agent' };
        return next();
      }
    }

    return res.status(401).json({
      error: authResult.error || 'Invalid or revoked device credentials.'
    });
  }

  return res.status(401).json({
    error: 'Unauthorized: Telemetry ingestion requires HMAC-SHA256 signed headers (X-Device-ID, X-Timestamp, X-Nonce, X-Signature) or valid Bearer token.'
  });
}

/**
 * Resets the nonce store (useful for clean unit testing isolation).
 */
function resetNonceStore() {
  nonceStore.clear();
}

module.exports = {
  authenticateTelemetry,
  computeTelemetrySignature,
  resetNonceStore,
  MAX_CLOCK_DRIFT_MS,
};
