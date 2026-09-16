/**
 * eventValidator.js
 * Runtime Validation & Sanitization Engine for Cybersecurity Event Telemetry.
 * 
 * Provides:
 * - Strict type checking & structural assertions
 * - Malformed UUID & timestamp validation
 * - Prototype pollution defense
 * - Bounded depth & cycle prevention for nested objects
 * - Field length truncation & normalization
 */

const { SchemaLimits, EventTypes, SeverityLevels, NetworkProtocols, NetworkDirections, FileActions } = require('./eventSchema');

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CANONICAL_EVENT_ID_REGEX = /^(evt-[a-zA-Z0-9_-]{6,64}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

/**
 * Validates whether an event ID conforms to UUID or canonical prefixed format.
 */
function isValidEventId(id) {
  if (!id || typeof id !== 'string') return false;
  return CANONICAL_EVENT_ID_REGEX.test(id.trim());
}

/**
 * Validates timestamp format and date boundaries.
 */
function isValidTimestamp(ts) {
  if (ts === null || ts === undefined) return false;
  let parsed = NaN;

  if (typeof ts === 'number') {
    parsed = ts > 1e11 ? ts : ts * 1000;
  } else if (typeof ts === 'string') {
    const trimmed = ts.trim();
    if (!trimmed) return false;
    if (/^\d+$/.test(trimmed)) {
      const num = Number(trimmed);
      parsed = num > 1e11 ? num : num * 1000;
    } else {
      parsed = Date.parse(trimmed);
    }
  } else if (ts instanceof Date) {
    parsed = ts.getTime();
  }

  if (isNaN(parsed)) return false;

  // Year boundary guard (between 2000 and 2100)
  const year = new Date(parsed).getUTCFullYear();
  return year >= 2000 && year <= 2100;
}

/**
 * Sanitizes a string: strips null bytes, trims whitespace, limits length.
 */
function sanitizeString(val, maxLen = SchemaLimits.MAX_NAME_LEN) {
  if (val === null || val === undefined) return null;
  if (typeof val !== 'string') {
    val = String(val);
  }
  // Strip null bytes and non-printable control characters (except tab, LF, CR)
  const cleaned = val.replace(/\0/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
  if (cleaned.length === 0) return null;
  return cleaned.length > maxLen ? cleaned.substring(0, maxLen) : cleaned;
}

/**
 * Validates and normalizes IP addresses.
 */
function sanitizeIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  let clean = ip.trim().replace(/\0/g, '');

  // Strip IPv6 brackets [::1]
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // Handle embedded port in IPv4 (192.168.1.1:8080)
  if (clean.includes(':') && !clean.includes('::') && clean.split(':').length === 2) {
    const [addr] = clean.split(':');
    if (IPV4_REGEX.test(addr)) {
      clean = addr;
    }
  }

  if (IPV4_REGEX.test(clean) || IPV6_REGEX.test(clean) || clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') {
    return clean;
  }

  return null;
}

/**
 * Validates and bounds port numbers (1-65535).
 */
function sanitizePort(port) {
  if (port === null || port === undefined || port === '') return null;
  const num = Number(port);
  if (Number.isInteger(num) && num >= 1 && num <= 65535) {
    return num;
  }
  return null;
}

/**
 * Deeply sanitizes arbitrary nested objects (metadata / custom fields)
 * preventing prototype pollution, cycles, excessive depth, and oversized payloads.
 */
function sanitizeNestedObject(obj, currentDepth = 0, visited = new WeakSet()) {
  if (obj === null || obj === undefined) return null;
  if (currentDepth > SchemaLimits.MAX_NESTING_DEPTH) return '[Max Depth Exceeded]';

  // Handle primitives
  if (typeof obj === 'string') {
    return sanitizeString(obj, 1024);
  }
  if (typeof obj === 'number') {
    return Number.isFinite(obj) ? obj : null;
  }
  if (typeof obj === 'boolean') {
    return obj;
  }
  if (typeof obj === 'function' || typeof obj === 'symbol') {
    return undefined; // Discard functions & symbols
  }

  // Handle Arrays
  if (Array.isArray(obj)) {
    if (visited.has(obj)) return '[Circular Reference]';
    visited.add(obj);

    const result = [];
    const limit = Math.min(obj.length, 50);
    for (let i = 0; i < limit; i++) {
      const sanitizedItem = sanitizeNestedObject(obj[i], currentDepth + 1, visited);
      if (sanitizedItem !== undefined) {
        result.push(sanitizedItem);
      }
    }
    return result;
  }

  // Handle Objects
  if (typeof obj === 'object') {
    if (visited.has(obj)) return '[Circular Reference]';
    visited.add(obj);

    const sanitizedObj = Object.create(null);
    const entries = Object.entries(obj);
    let keyCount = 0;

    for (const [key, value] of entries) {
      if (keyCount >= SchemaLimits.MAX_CUSTOM_KEYS) break;

      // Defense against Prototype Pollution
      const cleanKey = String(key).replace(/\0/g, '').trim();
      if (
        cleanKey === '__proto__' ||
        cleanKey === 'constructor' ||
        cleanKey === 'prototype' ||
        !cleanKey
      ) {
        continue;
      }

      if (cleanKey.length > 64) {
        continue; // Skip oversized key names
      }

      const sanitizedVal = sanitizeNestedObject(value, currentDepth + 1, visited);
      if (sanitizedVal !== undefined) {
        sanitizedObj[cleanKey] = sanitizedVal;
        keyCount++;
      }
    }

    return sanitizedObj;
  }

  return null;
}

/**
 * Runtime validation of raw event payload.
 * Returns { valid: boolean, errors: string[] }
 */
function validateEvent(rawEvent, options = { strict: false }) {
  const errors = [];

  if (!rawEvent || typeof rawEvent !== 'object' || Array.isArray(rawEvent)) {
    return {
      valid: false,
      errors: ['Event payload must be a non-null JSON object.'],
    };
  }

  // 1. Prototype Pollution Check
  if (rawEvent.__proto__ && Object.keys(rawEvent.__proto__).length > 0) {
    errors.push('Prototype pollution detected in event payload.');
  }

  // 2. Event ID (if supplied)
  const eventId = rawEvent.event_id || rawEvent.eventId;
  if (eventId !== undefined && eventId !== null && !isValidEventId(eventId)) {
    if (options.strict) {
      errors.push(`Invalid event_id '${eventId}'. Must be a valid UUIDv4 or 'evt-...' identifier.`);
    }
  }

  // 3. Timestamp (if supplied)
  const ts = rawEvent.timestamp || rawEvent.observed_at || rawEvent.observedAt;
  if (ts !== undefined && ts !== null && !isValidTimestamp(ts)) {
    errors.push(`Invalid or unparseable timestamp '${ts}'.`);
  }

  // 4. Port validations
  const srcPort = rawEvent.network?.source_port || rawEvent.sourcePort;
  if (srcPort !== undefined && srcPort !== null && sanitizePort(srcPort) === null) {
    errors.push(`Invalid source_port '${srcPort}'. Must be an integer between 1 and 65535.`);
  }

  const destPort = rawEvent.network?.dest_port || rawEvent.destPort || rawEvent.port;
  if (destPort !== undefined && destPort !== null && sanitizePort(destPort) === null) {
    errors.push(`Invalid dest_port '${destPort}'. Must be an integer between 1 and 65535.`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

module.exports = {
  isValidEventId,
  isValidTimestamp,
  sanitizeString,
  sanitizeIp,
  sanitizePort,
  sanitizeNestedObject,
  validateEvent,
};
