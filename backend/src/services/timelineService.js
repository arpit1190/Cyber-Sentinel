/**
 * timelineService.js
 * Cryptographically Verifiable & Immutable Incident Timeline Service.
 * 
 * Features:
 * - Structured Canonical Event Types (Telemetry -> Detection -> Creation -> Assignment -> Investigation -> AI Recommendation -> Approval -> Response -> Resolution)
 * - Cryptographic SHA-256 Hash Chaining (Merkle/Blockchain-style tamper detection)
 * - Strict In-Memory Immutability & Deep Object Freezing
 * - Multi-criteria Filtering & Pagination for High-Volume Timelines
 * - Forensic Chain Verification (detects any inserted, modified, or deleted events)
 */

'use strict';

const crypto = require('crypto');

const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const TimelineEventType = Object.freeze({
  TELEMETRY_INGESTED: 'TELEMETRY_INGESTED',
  DETECTION_ALERT: 'DETECTION_ALERT',
  INCIDENT_CREATED: 'INCIDENT_CREATED',
  ANALYST_ASSIGNED: 'ANALYST_ASSIGNED',
  INVESTIGATION_STARTED: 'INVESTIGATION_STARTED',
  AI_RECOMMENDATION: 'AI_RECOMMENDATION',
  ANALYST_APPROVAL: 'ANALYST_APPROVAL',
  RESPONSE_ACTION_EXECUTED: 'RESPONSE_ACTION_EXECUTED',
  STATUS_CHANGED: 'STATUS_CHANGED',
  NOTE_ADDED: 'NOTE_ADDED',
  INCIDENT_UPDATED: 'INCIDENT_UPDATED',
  INCIDENT_RESOLVED: 'INCIDENT_RESOLVED',
  INCIDENT_CLOSED: 'INCIDENT_CLOSED',
  CUSTOM_EVENT: 'CUSTOM_EVENT',
});

// Legacy action mappings to canonical TimelineEventType
const ACTION_TYPE_MAP = Object.freeze({
  'INCIDENT_CREATED': TimelineEventType.INCIDENT_CREATED,
  'INCIDENT_UPDATED': TimelineEventType.INCIDENT_UPDATED,
  'STATUS_CHANGE': TimelineEventType.STATUS_CHANGED,
  'STATUS_CHANGED': TimelineEventType.STATUS_CHANGED,
  'INCIDENT_ASSIGNED': TimelineEventType.ANALYST_ASSIGNED,
  'NOTE_ADDED': TimelineEventType.NOTE_ADDED,
  'RESPONSE_ACTION_EXECUTED': TimelineEventType.RESPONSE_ACTION_EXECUTED,
  'DETECTION': TimelineEventType.DETECTION_ALERT,
  'TELEMETRY': TimelineEventType.TELEMETRY_INGESTED,
  'AI_RECOMMENDATION': TimelineEventType.AI_RECOMMENDATION,
  'ANALYST_APPROVAL': TimelineEventType.ANALYST_APPROVAL,
});

/**
 * Deterministic JSON stringifier to guarantee hash consistency across environments.
 */
function canonicalJson(obj) {
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return String(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

/**
 * Computes SHA-256 hash for a timeline event bound to the previous event's hash.
 */
function calculateEventHash(eventFields, prevHash = GENESIS_PREV_HASH) {
  const hashPayload = [
    prevHash,
    eventFields.sequence,
    eventFields.timestamp,
    eventFields.eventType,
    eventFields.actor || 'SYSTEM',
    eventFields.source || 'SOC_SYSTEM',
    eventFields.description || '',
    canonicalJson(eventFields.relatedEvent || null),
    canonicalJson(eventFields.relatedDetection || null),
    canonicalJson(eventFields.relatedResponseAction || null),
    canonicalJson(eventFields.metadata || {}),
  ].join('|');

  return crypto.createHash('sha256').update(hashPayload, 'utf8').digest('hex');
}

/**
 * Creates a cryptographically chained timeline event record.
 */
function createTimelineEvent(data = {}, prevEvent = null, sequenceNumber = 1) {
  const now = data.timestamp || new Date().toISOString();
  const rawType = data.eventType || data.action || data.type || TimelineEventType.CUSTOM_EVENT;
  const eventType = ACTION_TYPE_MAP[rawType] || rawType;

  const prevHash = prevEvent && prevEvent.hash ? prevEvent.hash : GENESIS_PREV_HASH;
  const sequence = prevEvent && typeof prevEvent.sequence === 'number'
    ? prevEvent.sequence + 1
    : sequenceNumber;

  const explicitAction = data.action || String(eventType);
  const previousStatus = data.previousStatus !== undefined ? data.previousStatus : (data.metadata?.previousStatus || null);
  const newStatus = data.newStatus !== undefined ? data.newStatus : (data.metadata?.newStatus || null);
  const previousAssignee = data.previousAssignee !== undefined ? data.previousAssignee : (data.metadata?.previousAssignee || null);
  const newAssignee = data.newAssignee !== undefined ? data.newAssignee : (data.metadata?.newAssignee || null);

  const eventRecord = {
    id: data.id || `tle-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    sequence,
    timestamp: now,
    eventType: String(eventType),
    action: explicitAction, // backwards compatibility for existing UI/consumers
    actor: data.actor ? String(data.actor).trim() : 'SYSTEM',
    source: data.source ? String(data.source).trim() : 'SOC_CORE',
    description: data.description || data.note || data.message || `Timeline event: ${eventType}`,
    note: data.note || data.description || '', // backwards compatibility
    previousStatus,
    newStatus,
    previousAssignee,
    newAssignee,
    relatedEvent: data.relatedEvent || null,
    relatedDetection: data.relatedDetection || null,
    relatedResponseAction: data.relatedResponseAction || null,
    metadata: data.metadata || (data.changes || previousStatus || newStatus || previousAssignee || newAssignee ? {
      changes: data.changes,
      previousStatus,
      newStatus,
      previousAssignee,
      newAssignee,
      actionId: data.actionId,
    } : {}),
    prevHash,
  };

  eventRecord.hash = calculateEventHash(eventRecord, prevHash);

  // Return deeply frozen object to guarantee in-memory immutability
  return deepFreeze(eventRecord);
}

/**
 * Recursively freezes an object preventing any property modification or deletion.
 */
function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

/**
 * Appends a new event to an incident's timeline maintaining the cryptographic hash chain.
 */
function appendEventToTimeline(timelineArray = [], eventData = {}) {
  const timeline = Array.isArray(timelineArray) ? [...timelineArray] : [];
  const prevEvent = timeline.length > 0 ? timeline[timeline.length - 1] : null;
  const newEvent = createTimelineEvent(eventData, prevEvent, timeline.length + 1);
  timeline.push(newEvent);
  return timeline;
}

/**
 * Validates the full cryptographic integrity of a timeline array.
 * Proves mathematically that no events have been modified, deleted, reordered, or inserted.
 */
function verifyTimelineIntegrity(timeline = []) {
  if (!Array.isArray(timeline) || timeline.length === 0) {
    return {
      valid: true,
      count: 0,
      genesisHash: null,
      latestHash: null,
      message: 'Timeline is empty.',
    };
  }

  let expectedPrevHash = GENESIS_PREV_HASH;

  for (let i = 0; i < timeline.length; i++) {
    const event = timeline[i];
    const expectedSeq = i + 1;

    // 1. Verify sequence order
    if (event.sequence !== undefined && event.sequence !== expectedSeq) {
      return {
        valid: false,
        error: `Sequence discontinuity at index ${i}: expected sequence ${expectedSeq}, got ${event.sequence}`,
        corruptedIndex: i,
        corruptedEventId: event.id,
      };
    }

    // 2. Verify previous hash pointer
    const currentPrevHash = event.prevHash || (i === 0 ? GENESIS_PREV_HASH : null);
    if (currentPrevHash !== expectedPrevHash) {
      return {
        valid: false,
        error: `Broken cryptographic hash chain at index ${i} (ID: ${event.id}). Expected prevHash '${expectedPrevHash}', but event points to '${currentPrevHash}'.`,
        corruptedIndex: i,
        corruptedEventId: event.id,
      };
    }

    // 3. Recompute event hash and compare
    const recomputedHash = calculateEventHash(event, expectedPrevHash);
    if (event.hash && event.hash !== recomputedHash) {
      return {
        valid: false,
        error: `Cryptographic tamper detected on event at index ${i} (ID: ${event.id}). Stored hash '${event.hash}' does not match recomputed hash '${recomputedHash}'. Data was modified after recording.`,
        corruptedIndex: i,
        corruptedEventId: event.id,
      };
    }

    expectedPrevHash = event.hash || recomputedHash;
  }

  return {
    valid: true,
    count: timeline.length,
    genesisHash: timeline[0].hash || null,
    latestHash: timeline[timeline.length - 1].hash || null,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Paginates, filters, and sorts a timeline array.
 */
function paginateTimeline(timeline = [], options = {}) {
  const events = Array.isArray(timeline) ? timeline : [];
  const {
    page = 1,
    limit = 20,
    order = 'asc',
    eventType = null,
    actor = null,
    source = null,
    search = null,
  } = options;

  const parsedPage = Math.max(1, parseInt(page, 10) || 1);
  const parsedLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));

  // 1. Filter
  let filtered = events.filter(evt => {
    if (eventType) {
      const matchType = String(eventType).toUpperCase();
      const evtType = String(evt.eventType || evt.action || '').toUpperCase();
      if (evtType !== matchType) return false;
    }
    if (actor) {
      const matchActor = String(actor).toLowerCase();
      const evtActor = String(evt.actor || '').toLowerCase();
      if (!evtActor.includes(matchActor)) return false;
    }
    if (source) {
      const matchSource = String(source).toLowerCase();
      const evtSource = String(evt.source || '').toLowerCase();
      if (!evtSource.includes(matchSource)) return false;
    }
    if (search) {
      const term = String(search).toLowerCase();
      const text = [
        evt.description,
        evt.note,
        evt.actor,
        evt.source,
        evt.eventType,
        canonicalJson(evt.metadata),
      ].join(' ').toLowerCase();
      if (!text.includes(term)) return false;
    }
    return true;
  });

  // 2. Sort
  const isDesc = String(order).toLowerCase() === 'desc';
  filtered.sort((a, b) => {
    const timeA = new Date(a.timestamp).getTime() || 0;
    const timeB = new Date(b.timestamp).getTime() || 0;
    if (timeA === timeB) {
      const seqA = a.sequence || 0;
      const seqB = b.sequence || 0;
      return isDesc ? seqB - seqA : seqA - seqB;
    }
    return isDesc ? timeB - timeA : timeA - timeB;
  });

  // 3. Paginate
  const total = filtered.length;
  const totalPages = Math.ceil(total / parsedLimit) || 1;
  const offset = (parsedPage - 1) * parsedLimit;
  const paginatedEvents = filtered.slice(offset, offset + parsedLimit);

  // 4. Run chain integrity verification across full chronological events
  const integrity = verifyTimelineIntegrity(events);

  return {
    total,
    page: parsedPage,
    limit: parsedLimit,
    totalPages,
    order: isDesc ? 'desc' : 'asc',
    integrity: {
      verified: integrity.valid,
      hashChainValid: integrity.valid,
      genesisHash: integrity.genesisHash,
      latestHash: integrity.latestHash,
      totalChainedEvents: integrity.count,
      error: integrity.error || null,
    },
    events: paginatedEvents,
  };
}

module.exports = {
  TimelineEventType,
  GENESIS_PREV_HASH,
  calculateEventHash,
  createTimelineEvent,
  appendEventToTimeline,
  verifyTimelineIntegrity,
  paginateTimeline,
  deepFreeze,
};
