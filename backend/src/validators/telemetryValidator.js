/**
 * telemetryValidator.js
 * Schema, Size, and Rate-Limiting Validators for Telemetry Event Ingestion.
 */

const MAX_TELEMETRY_PAYLOAD_BYTES = 1024 * 1024; // 1 MB limit
const MAX_BATCH_EVENTS = 500;

// In-memory sliding rate limiter per device/IP
const telemetryRateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 120;

// Periodic cleanup of rate limit tracking
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS;
  for (const [key, record] of telemetryRateLimitMap.entries()) {
    if (record.resetTime < cutoff) {
      telemetryRateLimitMap.delete(key);
    }
  }
}, 60 * 1000).unref();

function validateTelemetryPayload(req, res, next) {
  // 1. Request Size Validation
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLength > MAX_TELEMETRY_PAYLOAD_BYTES) {
    return res.status(413).json({
      error: `Payload Too Large: Telemetry payload exceeds maximum limit of ${MAX_TELEMETRY_PAYLOAD_BYTES} bytes.`
    });
  }

  // If stringified body exceeds limit
  const rawBodyString = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});
  if (Buffer.byteLength(rawBodyString, 'utf8') > MAX_TELEMETRY_PAYLOAD_BYTES) {
    return res.status(413).json({
      error: `Payload Too Large: Telemetry payload exceeds maximum limit of ${MAX_TELEMETRY_PAYLOAD_BYTES} bytes.`
    });
  }

  // 2. Telemetry Rate Limiting
  const identifier = req.headers['x-device-id'] || req.ip || 'unknown-client';
  const now = Date.now();
  let rateRecord = telemetryRateLimitMap.get(identifier);

  if (!rateRecord || now > rateRecord.resetTime) {
    rateRecord = { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS };
    telemetryRateLimitMap.set(identifier, rateRecord);
  } else {
    rateRecord.count++;
    if (rateRecord.count > MAX_REQUESTS_PER_WINDOW) {
      const retryAfter = Math.ceil((rateRecord.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: `Too Many Requests: Telemetry ingestion rate limit exceeded (${MAX_REQUESTS_PER_WINDOW} req/min). Please back off.`
      });
    }
  }

  // 3. Schema & Structural Validation
  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({
      error: 'Bad Request: Malformed telemetry payload. Expected a JSON object or array of events.'
    });
  }

  const events = Array.isArray(body) ? body : [body];

  if (events.length === 0) {
    return res.status(400).json({
      error: 'Bad Request: Telemetry event batch cannot be empty.'
    });
  }

  if (events.length > MAX_BATCH_EVENTS) {
    return res.status(400).json({
      error: `Bad Request: Telemetry batch size exceeds maximum of ${MAX_BATCH_EVENTS} events.`
    });
  }

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    if (!ev || typeof ev !== 'object' || Array.isArray(ev)) {
      return res.status(400).json({
        error: `Bad Request: Malformed event at index ${i}. Each item must be a JSON object.`
      });
    }

    // Must have at least an eventType, type, or some descriptive event field
    const eventType = ev.eventType || ev.event_type || ev.type || ev.action;
    if (!eventType || typeof eventType !== 'string' || !eventType.trim()) {
      return res.status(400).json({
        error: `Bad Request: Missing or invalid eventType at index ${i}.`
      });
    }

    // Prevent Prototype Pollution
    if (ev.__proto__ && Object.keys(ev.__proto__).length > 0) {
      delete ev.__proto__;
    }
    if (ev.constructor && ev.constructor !== Object) {
      return res.status(400).json({
        error: `Bad Request: Malformed event structure at index ${i}.`
      });
    }
  }

  next();
}

function resetRateLimitStore() {
  telemetryRateLimitMap.clear();
}

module.exports = {
  validateTelemetryPayload,
  resetRateLimitStore,
  MAX_TELEMETRY_PAYLOAD_BYTES,
  MAX_BATCH_EVENTS,
  MAX_REQUESTS_PER_WINDOW,
};
