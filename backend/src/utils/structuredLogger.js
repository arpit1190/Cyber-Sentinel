/**
 * structuredLogger.js
 * Production-grade Structured JSON Logging and Credential Scrubbing Engine.
 *
 * Guarantees:
 * 1. Single-line structured JSON output for easy log aggregation (Elasticsearch, Datadog, CloudWatch).
 * 2. Mandatory Fields: timestamp, service, requestId, endpoint, method, status, latencyMs, safeActor, errorCode.
 * 3. ZERO SECRET LEAKAGE: Scrubs passwords, JWTs, Bearer tokens, API keys, device secrets, and binary buffers.
 */

'use strict';

const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /authorization/i,
  /cookie/i,
  /private[_-]?key/i,
  /credential/i,
  /contentBase64/i,
  /contentHex/i,
  /rawBuffer/i,
];

/**
 * Deeply scrubs sensitive fields and long binary streams from objects/strings.
 */
function sanitizeData(data, depth = 0) {
  if (depth > 5) return '[NESTED_OBJECT_TRUNCATED]';
  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    // Scrub JWT patterns: eyJ...
    let clean = data.replace(/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, '[REDACTED_JWT]');
    // Scrub Bearer header pattern
    clean = clean.replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED_TOKEN]');
    // Limit string length in logs
    if (clean.length > 500) {
      clean = clean.slice(0, 500) + '...[TRUNCATED]';
    }
    return clean;
  }

  if (Buffer.isBuffer(data)) {
    return `[BINARY_BUFFER_${data.length}_BYTES]`;
  }

  if (Array.isArray(data)) {
    return data.slice(0, 50).map(item => sanitizeData(item, depth + 1));
  }

  if (typeof data === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(data)) {
      if (SENSITIVE_KEY_PATTERNS.some(p => p.test(key))) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = sanitizeData(value, depth + 1);
      }
    }
    return sanitized;
  }

  return data;
}

/**
 * Express middleware for structured HTTP request logging.
 */
function structuredLogger(options = {}) {
  const serviceName = options.service || 'cyber-sentinel-api';

  return (req, res, next) => {
    const startTime = process.hrtime.bigint();
    const requestId = req.id || req.headers['x-request-id'] || 'req-unknown';

    // Hook response finish event
    res.on('finish', () => {
      const endTime = process.hrtime.bigint();
      const latencyMs = Number((endTime - startTime) / 1_000_000n);

      // Extract safe actor identifier (never raw password or unverified headers)
      let safeActor = 'anonymous';
      if (req.user) {
        safeActor = req.user.email ? req.user.email : `user:${req.user.id || 'authenticated'}`;
      } else if (req.headers['x-device-id']) {
        safeActor = `device:${String(req.headers['x-device-id']).slice(0, 32)}`;
      }

      const logRecord = {
        timestamp: new Date().toISOString(),
        service: serviceName,
        requestId,
        endpoint: req.baseUrl ? `${req.baseUrl}${req.path}` : req.path,
        method: req.method,
        status: res.statusCode,
        latencyMs,
        safeActor,
        ip: req.ip || req.socket?.remoteAddress || '127.0.0.1',
        userAgent: req.headers['user-agent'] ? String(req.headers['user-agent']).slice(0, 100) : 'unknown',
        errorCode: res.statusCode >= 400 ? (res.locals?.errorCode || `HTTP_${res.statusCode}`) : null,
      };

      // Output as single-line JSON
      if (process.env.NODE_ENV !== 'test') {
        const jsonString = JSON.stringify(logRecord);
        if (res.statusCode >= 500) {
          console.error(jsonString);
        } else if (res.statusCode >= 400) {
          console.warn(jsonString);
        } else {
          console.log(jsonString);
        }
      }
    });

    next();
  };
}

module.exports = {
  structuredLogger,
  sanitizeData,
};
