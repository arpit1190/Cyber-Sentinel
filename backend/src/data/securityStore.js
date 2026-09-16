/**
 * securityStore.js
 * Centralized, thread-safe repository supporting PostgreSQL with local file persistence.
 * 
 * Manages:
 * - Active firewall containment rules (IP blocklist)
 * - Incident lifecycle and forensic evidence with SHA-256 integrity hashing
 * - Immutable security audit trail
 * - In-memory malware scan histories and real-time state
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { isPostgresConnected, query } = require('./db');
const { validateStateTransition, IncidentStatus, normalizeStatus } = require('../services/incidentStateMachine');
const {
  TimelineEventType,
  appendEventToTimeline,
  verifyTimelineIntegrity,
  paginateTimeline,
} = require('../services/timelineService');

const DATA_FILE = path.join(__dirname, 'security_state.json');

// In-memory state cache
let state = {
  blockedIps: {},      // ip -> { ip, reason, blockedAt, blockedBy, active: true }
  incidents: [],       // list of incident objects
  auditLogs: [],       // append-only log trail
  scans: [],           // malware analysis reports
  lastScanResult: null,
  lastLogAnalysis: null,
  lastProtectionScan: null,
  lastSandboxResult: null,
  lastSystemMetrics: null,
};

async function syncFromPostgres() {
  try {
    if (!isPostgresConnected()) return;

    // 1. Sync Incidents
    const incRes = await query('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 500');
    state.incidents = incRes.rows.map(r => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      category: r.category,
      status: r.status,
      description: r.description,
      assignee: r.assignee,
      relatedIps: r.related_ips || [],
      relatedAlerts: r.related_alerts || [],
      mitreTechniques: r.mitre_techniques || [],
      evidence: r.evidence || {},
      evidenceHash: r.evidence_hash,
      timeline: r.timeline || [],
      createdAt: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString(),
      updatedAt: r.updated_at ? new Date(r.updated_at).toISOString() : new Date().toISOString(),
    }));

    // 2. Sync Firewall Rules
    const fwRes = await query('SELECT * FROM firewall_rules WHERE active = true');
    const fwMap = {};
    fwRes.rows.forEach(r => {
      fwMap[r.ip] = {
        ip: r.ip,
        reason: r.reason,
        blockedAt: r.blocked_at ? new Date(r.blocked_at).toISOString() : new Date().toISOString(),
        blockedBy: r.blocked_by,
        active: r.active,
      };
    });
    state.blockedIps = fwMap;

    // 3. Sync Audit Logs
    const auditRes = await query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 500');
    state.auditLogs = auditRes.rows.map(r => ({
      id: r.id,
      actor: r.actor,
      actorRole: r.actor_role,
      action: r.action,
      target: r.target,
      result: r.result,
      sourceIp: r.source_ip,
      details: r.details || {},
      timestamp: r.timestamp ? new Date(r.timestamp).toISOString() : new Date().toISOString(),
    }));

    console.log(`[DB] Synchronized security state from PostgreSQL (${state.incidents.length} incidents, ${fwRes.rows.length} blocked IPs).`);
  } catch (err) {
    console.error('[DB] Error syncing security state from PostgreSQL:', err.message);
  }
}

// Load initial state from disk if exists
function loadState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      state = { ...state, ...parsed };
      if (Array.isArray(state.blockedIps)) {
        const map = {};
        state.blockedIps.forEach(ip => {
          map[ip] = { ip, reason: 'Manual containment', blockedAt: new Date().toISOString(), blockedBy: 'system', active: true };
        });
        state.blockedIps = map;
      }
      if (!Array.isArray(state.scans)) state.scans = [];
    }
  } catch (err) {
    console.warn('[SecurityStore] Error reading state file; initializing fresh store:', err.message);
  }
}

// Persist state atomically and asynchronously with debouncing to prevent event-loop freezing
let persistTimeout = null;

function persistState(immediate = false) {
  if (immediate) {
    if (persistTimeout) {
      clearTimeout(persistTimeout);
      persistTimeout = null;
    }
    try {
      fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2), 'utf8');
    } catch (err) {
      console.error('[SecurityStore] Failed to write security state:', err.message);
    }
    return;
  }

  if (persistTimeout) return;
  persistTimeout = setTimeout(() => {
    persistTimeout = null;
    try {
      const data = JSON.stringify(state, null, 2);
      fs.writeFile(DATA_FILE, data, 'utf8', (err) => {
        if (err) console.error('[SecurityStore] Failed to async write security state:', err.message);
      });
    } catch (err) {
      console.error('[SecurityStore] Failed to serialize security state:', err.message);
    }
  }, 25);
}

function flushState() {
  persistState(true);
}

// Initial load on import
loadState();

// ── IP Containment Operations ──────────────────────────────────────────────
function blockIp(ip, reason = 'Automated threat containment', blockedBy = 'system') {
  const cleanIp = (typeof ip === 'string' ? ip : '').trim();
  if (!cleanIp) return null;

  const record = {
    ip: cleanIp,
    reason,
    blockedAt: new Date().toISOString(),
    blockedBy,
    active: true,
  };

  state.blockedIps[cleanIp] = record;
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO firewall_rules (ip, reason, blocked_at, blocked_by, active)
       VALUES ($1, $2, $3, $4, true)
       ON CONFLICT (ip) DO UPDATE SET
         reason = EXCLUDED.reason,
         blocked_at = EXCLUDED.blocked_at,
         blocked_by = EXCLUDED.blocked_by,
         active = true,
         unblocked_at = NULL`,
      [cleanIp, reason, record.blockedAt, blockedBy]
    ).catch(e => console.error('[DB] Error blocking IP in PostgreSQL:', e.message));
  }

  return record;
}

function unblockIp(ip) {
  const cleanIp = (typeof ip === 'string' ? ip : '').trim();
  if (state.blockedIps[cleanIp]) {
    state.blockedIps[cleanIp].active = false;
    state.blockedIps[cleanIp].unblockedAt = new Date().toISOString();
    delete state.blockedIps[cleanIp];
    persistState();

    if (isPostgresConnected()) {
      query(
        `UPDATE firewall_rules SET active = false, unblocked_at = NOW() WHERE ip = $1`,
        [cleanIp]
      ).catch(e => console.error('[DB] Error unblocking IP in PostgreSQL:', e.message));
    }
    return true;
  }
  return false;
}

function isIpBlocked(ip) {
  const cleanIp = (typeof ip === 'string' ? ip : '').trim();
  const entry = state.blockedIps[cleanIp];
  return Boolean(entry && entry.active);
}

function getBlockedIps() {
  return Object.values(state.blockedIps)
    .filter(item => item.active)
    .map(item => item.ip);
}

function getBlockedRecords() {
  return Object.values(state.blockedIps).filter(item => item.active);
}

// ── Immutable Audit Log Operations ─────────────────────────────────────────
function addAuditLog({ actor, actorRole, action, target, result = 'SUCCESS', sourceIp, details = {} }) {
  const entry = {
    id: `AUDIT-${Date.now().toString().slice(-6)}-${crypto.randomInt(10, 99)}`,
    actor: actor || 'anonymous',
    actorRole: actorRole || 'unauthenticated',
    action,
    target: String(target || 'SYSTEM'),
    result,
    sourceIp: sourceIp || '127.0.0.1',
    details,
    timestamp: new Date().toISOString(),
  };

  state.auditLogs.unshift(entry);
  if (state.auditLogs.length > 1000) {
    state.auditLogs = state.auditLogs.slice(0, 1000);
  }
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO audit_logs (id, actor, actor_role, action, target, result, source_ip, details, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [entry.id, entry.actor, entry.actorRole, entry.action, entry.target, entry.result, entry.sourceIp, JSON.stringify(entry.details), entry.timestamp]
    ).catch(e => console.error('[DB] Error inserting audit log into PostgreSQL:', e.message));
  }

  return entry;
}

function getAuditLogs(limit = 100) {
  return state.auditLogs.slice(0, limit);
}

// ── Incident Management Operations ─────────────────────────────────────────

function createIncident(params = {}) {
  const p = (params && typeof params === 'object') ? params : {};
  const {
    title = 'Untitled Incident',
    severity = 'HIGH',
    confidence = 80,
    category = 'THREAT_DETECTION',
    description = '',
    assignee = 'Unassigned',
    affectedDevices = [],
    affected_devices = [],
    detections = [],
    indicators = [],
    relatedIps = [],
    related_ips = [],
    relatedAlerts = [],
    mitreTechniques = [],
    mitre_techniques = [],
    evidence = null,
    createdBy = 'correlation-engine'
  } = p;

  const incId = `INC-${Date.now().toString().slice(-5)}${crypto.randomInt(10, 99)}`;
  
  let evidenceHash = null;
  let storedEvidence = evidence;
  if (evidence) {
    try {
      const rawEvidence = typeof evidence === 'string' ? evidence : JSON.stringify(evidence);
      evidenceHash = crypto.createHash('sha256').update(rawEvidence || '').digest('hex');
    } catch (_) {
      evidenceHash = crypto.createHash('sha256').update(String(evidence)).digest('hex');
      storedEvidence = '[Non-serializable or Complex Evidence Payload]';
    }
  }

  const rawIps = indicators.length > 0 ? indicators : (relatedIps.length > 0 ? relatedIps : related_ips);
  const rawDevs = affectedDevices.length > 0 ? affectedDevices : affected_devices;
  const rawMitre = mitreTechniques.length > 0 ? mitreTechniques : mitre_techniques;

  const now = new Date().toISOString();

  const incident = {
    id: incId,
    title: String(title).trim(),
    severity: (severity || 'HIGH').toUpperCase(),
    confidence: typeof confidence === 'number' ? Math.min(Math.max(confidence, 0), 100) : 80,
    category: category || 'THREAT_DETECTION',
    status: IncidentStatus.NEW,
    description: description || '',
    assignee: assignee || 'Unassigned',
    affectedDevices: Array.isArray(rawDevs) ? rawDevs : (rawDevs ? [rawDevs] : []),
    detections: Array.isArray(detections) ? detections : (detections ? [detections] : []),
    indicators: Array.isArray(rawIps) ? rawIps : (rawIps ? [rawIps] : []),
    relatedIps: Array.isArray(rawIps) ? rawIps : (rawIps ? [rawIps] : []),
    relatedAlerts: Array.isArray(relatedAlerts) ? relatedAlerts : [relatedAlerts],
    mitreTechniques: Array.isArray(rawMitre) ? rawMitre : [rawMitre],
    notes: [],
    responseActions: [],
    evidence: {
      payload: storedEvidence,
      sha256: evidenceHash,
      preservedAt: now,
    },
    evidenceHash: evidenceHash,
    timeline: [],
    createdAt: now,
    updatedAt: now,
    resolvedAt: null,
    closedAt: null,
  };

  // Seed genesis timeline events: Telemetry -> Detection -> Incident Creation
  if (p.relatedEvent) {
    incident.timeline = appendEventToTimeline(incident.timeline, {
      eventType: TimelineEventType.TELEMETRY_INGESTED,
      action: 'TELEMETRY_INGESTED',
      actor: 'ENDPOINT_AGENT',
      source: 'ENDPOINT_AGENT',
      description: `Raw telemetry event ingested from endpoint`,
      relatedEvent: p.relatedEvent,
    });
  }

  if (p.relatedDetection) {
    incident.timeline = appendEventToTimeline(incident.timeline, {
      eventType: TimelineEventType.DETECTION_ALERT,
      action: 'DETECTION_ALERT',
      actor: 'DETECTION_ENGINE',
      source: 'DETECTION_ENGINE',
      description: `Detection rule triggered: ${incident.category || title}`,
      relatedDetection: p.relatedDetection,
    });
  }

  // Genesis INCIDENT_CREATED event
  incident.timeline = appendEventToTimeline(incident.timeline, {
    eventType: TimelineEventType.INCIDENT_CREATED,
    action: 'INCIDENT_CREATED',
    actor: createdBy,
    source: 'SOC_CORRELATION_ENGINE',
    description: `Incident automatically flagged and correlated: ${title}`,
    relatedDetection: p.relatedDetection || null,
    metadata: {
      initialStatus: IncidentStatus.NEW,
      severity: incident.severity,
      confidence: incident.confidence,
    }
  });

  state.incidents.unshift(incident);
  if (state.incidents.length > 500) {
    state.incidents = state.incidents.slice(0, 500);
  }
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO incidents (id, title, severity, category, status, description, assignee, related_ips, related_alerts, mitre_techniques, evidence, evidence_hash, timeline, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        incident.id,
        incident.title,
        incident.severity,
        incident.category,
        incident.status,
        incident.description,
        incident.assignee,
        JSON.stringify(incident.relatedIps),
        JSON.stringify(incident.relatedAlerts),
        JSON.stringify(incident.mitreTechniques),
        JSON.stringify(incident.evidence),
        incident.evidenceHash,
        JSON.stringify(incident.timeline),
        incident.createdAt,
        incident.updatedAt
      ]
    ).catch(e => console.error('[DB] Error inserting incident into PostgreSQL:', e.message));
  }

  return incident;
}

function getIncidents(status = null) {
  if (status && status !== 'ALL') {
    const normalized = normalizeStatus(status);
    return state.incidents.filter(i => i.status === normalized || i.status === status.toUpperCase());
  }
  return state.incidents;
}

function getIncidentById(id) {
  return state.incidents.find(i => i.id === id) || null;
}

function updateIncident(id, updates = {}, actor = 'analyst', note = '') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const now = new Date().toISOString();
  if (updates.title !== undefined) incident.title = updates.title;
  if (updates.description !== undefined) incident.description = updates.description;
  if (updates.severity !== undefined) incident.severity = updates.severity;
  if (updates.confidence !== undefined) incident.confidence = updates.confidence;
  if (updates.affectedDevices !== undefined) incident.affectedDevices = updates.affectedDevices;
  if (updates.indicators !== undefined) {
    incident.indicators = updates.indicators;
    incident.relatedIps = updates.indicators;
  }
  if (updates.assignee !== undefined) incident.assignee = updates.assignee;

  incident.updatedAt = now;
  incident.timeline = appendEventToTimeline(incident.timeline || [], {
    eventType: TimelineEventType.INCIDENT_UPDATED,
    action: 'INCIDENT_UPDATED',
    actor,
    source: 'SOC_PORTAL',
    description: note || `Incident fields updated by ${actor}`,
    metadata: { changes: updates },
  });

  persistState();
  return incident;
}

function updateIncidentStatus(id, newStatus, actor = 'analyst', note = '') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const transitionCheck = validateStateTransition(incident.status, newStatus);
  if (!transitionCheck.valid) {
    const err = new Error(transitionCheck.error);
    err.status = 400;
    throw err;
  }

  const oldStatus = incident.status;
  const canonicalNext = transitionCheck.to;
  const now = new Date().toISOString();

  incident.status = canonicalNext;
  incident.updatedAt = now;

  let eventType = TimelineEventType.STATUS_CHANGED;
  if (canonicalNext === IncidentStatus.RESOLVED) {
    incident.resolvedAt = now;
    eventType = TimelineEventType.INCIDENT_RESOLVED;
  } else if (canonicalNext === IncidentStatus.CLOSED) {
    incident.closedAt = now;
    if (!incident.resolvedAt) incident.resolvedAt = now;
    eventType = TimelineEventType.INCIDENT_CLOSED;
  } else if (canonicalNext === IncidentStatus.INVESTIGATING) {
    eventType = TimelineEventType.INVESTIGATION_STARTED;
    if (oldStatus === IncidentStatus.CLOSED) {
      // Re-opened
      incident.closedAt = null;
      incident.resolvedAt = null;
    }
  }

  incident.timeline = appendEventToTimeline(incident.timeline || [], {
    eventType,
    action: 'STATUS_CHANGE',
    actor,
    source: 'SOC_PORTAL',
    description: note || `Status transitioned from ${oldStatus} to ${canonicalNext}`,
    previousStatus: oldStatus,
    newStatus: canonicalNext,
    metadata: {
      previousStatus: oldStatus,
      newStatus: canonicalNext,
    },
  });

  persistState();

  if (isPostgresConnected()) {
    query(
      `UPDATE incidents SET status = $1, timeline = $2, updated_at = NOW() WHERE id = $3`,
      [incident.status, JSON.stringify(incident.timeline), id]
    ).catch(e => console.error('[DB] Error updating incident status in PostgreSQL:', e.message));
  }

  return incident;
}

function assignIncident(id, assignee, actor = 'analyst', note = '') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const oldAssignee = incident.assignee || 'Unassigned';
  const newAssignee = String(assignee).trim();
  const now = new Date().toISOString();

  incident.assignee = newAssignee;
  incident.updatedAt = now;

  incident.timeline = appendEventToTimeline(incident.timeline || [], {
    eventType: TimelineEventType.ANALYST_ASSIGNED,
    action: 'INCIDENT_ASSIGNED',
    actor,
    source: 'SOC_PORTAL',
    description: note || `Incident reassigned from ${oldAssignee} to ${newAssignee}`,
    previousAssignee: oldAssignee,
    newAssignee: newAssignee,
    metadata: {
      previousAssignee: oldAssignee,
      newAssignee: newAssignee,
    },
  });

  persistState();
  return incident;
}

function closeIncident(id, resolutionReason = 'RESOLVED', actor = 'analyst', note = '') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  return updateIncidentStatus(
    id,
    IncidentStatus.CLOSED,
    actor,
    note || `Incident closed with reason: ${resolutionReason}`
  );
}

function addIncidentNote(id, actor = 'analyst', note = '') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const now = new Date().toISOString();
  const noteEntry = {
    id: `note-${Date.now()}-${crypto.randomInt(10, 99)}`,
    author: actor,
    note: String(note).trim(),
    createdAt: now,
  };

  incident.notes = incident.notes || [];
  incident.notes.push(noteEntry);

  incident.timeline = appendEventToTimeline(incident.timeline || [], {
    eventType: TimelineEventType.NOTE_ADDED,
    actor,
    source: 'SOC_ANALYST',
    description: String(note).trim(),
  });
  incident.updatedAt = now;
  persistState();

  if (isPostgresConnected()) {
    query(
      `UPDATE incidents SET timeline = $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(incident.timeline), id]
    ).catch(e => console.error('[DB] Error adding incident note in PostgreSQL:', e.message));
  }

  return incident;
}

function addResponseAction(id, actionData = {}, actor = 'analyst') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const now = new Date().toISOString();
  const actionEntry = {
    id: `act-${Date.now()}-${crypto.randomInt(10, 99)}`,
    actionType: actionData.actionType || 'CONTAINMENT_ACTION',
    target: actionData.target,
    parameters: actionData.parameters || {},
    status: actionData.status || 'EXECUTED',
    executedBy: actor,
    timestamp: now,
    notes: actionData.notes || '',
  };

  incident.responseActions = incident.responseActions || [];
  incident.responseActions.push(actionEntry);

  incident.timeline = appendEventToTimeline(incident.timeline || [], {
    eventType: TimelineEventType.RESPONSE_ACTION_EXECUTED,
    actor,
    source: 'SOAR_ENGINE',
    description: `Executed response action: ${actionEntry.actionType} targeting ${actionEntry.target}`,
    relatedResponseAction: actionEntry,
    metadata: {
      actionId: actionEntry.id,
      target: actionEntry.target,
      actionType: actionEntry.actionType,
    },
  });

  incident.updatedAt = now;
  persistState();
  return incident;
}

function appendTimelineEvent(id, eventData = {}, actor = null, source = null) {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const resolvedActor = eventData.actor || actor || 'SYSTEM';
  const resolvedSource = eventData.source || source || 'SOC_ANALYST';

  const now = new Date().toISOString();
  incident.timeline = appendEventToTimeline(incident.timeline || [], {
    ...eventData,
    actor: resolvedActor,
    source: resolvedSource,
  });

  incident.updatedAt = now;
  persistState();

  if (isPostgresConnected()) {
    query(
      `UPDATE incidents SET timeline = $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(incident.timeline), id]
    ).catch(e => console.error('[DB] Error appending timeline event in PostgreSQL:', e.message));
  }

  return incident.timeline[incident.timeline.length - 1];
}

function getIncidentTimeline(id, options = {}) {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;
  return paginateTimeline(incident.timeline || [], options);
}

function verifyIncidentTimelineIntegrity(id) {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;
  return verifyTimelineIntegrity(incident.timeline || []);
}

// ── Malware Scan Reports ───────────────────────────────────────────────────
function addScan(scan) {
  if (!state.scans) state.scans = [];
  state.scans.unshift(scan);
  if (state.scans.length > 200) {
    state.scans = state.scans.slice(0, 200);
  }
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO malware_scans (id, filename, sha256, score, severity, details, analyzed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (id) DO NOTHING`,
      [scan.id, scan.filename, scan.sha256, scan.score, scan.severity, JSON.stringify(scan.details || {}), scan.analyzedAt || new Date().toISOString()]
    ).catch(e => console.error('[DB] Error inserting malware scan into PostgreSQL:', e.message));
  }

  return scan;
}

function getScans() {
  return state.scans || [];
}

// ── Volatile Module Snapshots ───────────────────────────────────────────────
function setLastScanResult(data)       { state.lastScanResult = data; }
function getLastScanResult()           { return state.lastScanResult; }
function setLastLogAnalysis(data)      { state.lastLogAnalysis = data; }
function getLastLogAnalysis()          { return state.lastLogAnalysis; }
function setLastProtectionScan(data)   { state.lastProtectionScan = data; }
function getLastProtectionScan()       { return state.lastProtectionScan; }
function setLastSandboxResult(data)    { state.lastSandboxResult = data; }
function getLastSandboxResult()        { return state.lastSandboxResult; }
function setLastSystemMetrics(data)    { state.lastSystemMetrics = data; }
function getLastSystemMetrics()        { return state.lastSystemMetrics; }

module.exports = {
  syncFromPostgres,
  blockIp,
  unblockIp,
  isIpBlocked,
  getBlockedIps,
  getBlockedRecords,
  addAuditLog,
  getAuditLogs,
  createIncident,
  getIncidents,
  getIncidentById,
  updateIncident,
  updateIncidentStatus,
  assignIncident,
  closeIncident,
  addIncidentNote,
  addResponseAction,
  appendTimelineEvent,
  getIncidentTimeline,
  verifyIncidentTimelineIntegrity,
  TimelineEventType,
  IncidentStatus,
  flushState,
  addScan,
  getScans,
  setLastScanResult,
  getLastScanResult,
  setLastLogAnalysis,
  getLastLogAnalysis,
  setLastProtectionScan,
  getLastProtectionScan,
  setLastSandboxResult,
  getLastSandboxResult,
  setLastSystemMetrics,
  getLastSystemMetrics,
};
