/**
 * incidentValidators.js
 * Input validation for SOC incident management and lifecycle operations.
 */

const { IncidentStatus, normalizeStatus } = require('../services/incidentStateMachine');

const VALID_STATUSES = Object.values(IncidentStatus);
const VALID_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function validateCreateIncident(body) {
  const {
    title,
    severity,
    confidence,
    category,
    description,
    assignee,
    affectedDevices,
    affected_devices,
    detections,
    indicators,
    relatedIps,
    related_ips,
    mitreTechniques,
    mitre_techniques,
    evidence,
  } = body || {};

  if (!title || typeof title !== 'string' || !title.trim()) {
    return { valid: false, error: 'Title is required and must be a non-empty string.' };
  }
  if (!description || typeof description !== 'string' || !description.trim()) {
    return { valid: false, error: 'Description is required and must be a non-empty string.' };
  }

  const cleanSeverity = severity ? String(severity).toUpperCase() : 'MEDIUM';
  if (!VALID_SEVERITIES.includes(cleanSeverity)) {
    return { valid: false, error: `Invalid severity '${severity}'. Must be one of: ${VALID_SEVERITIES.join(', ')}` };
  }

  let cleanConfidence = 80;
  if (confidence !== undefined && confidence !== null) {
    const num = Number(confidence);
    if (isNaN(num) || num < 0 || num > 100) {
      return { valid: false, error: 'Confidence must be an integer between 0 and 100.' };
    }
    cleanConfidence = Math.round(num);
  }

  const rawDevices = affectedDevices || affected_devices || [];
  const rawIps = indicators || relatedIps || related_ips || [];
  const rawDetections = detections || [];
  const rawMitre = mitreTechniques || mitre_techniques || [];

  return {
    valid: true,
    data: {
      title: title.trim(),
      severity: cleanSeverity,
      confidence: cleanConfidence,
      category: category ? String(category).trim() : 'MANUAL_REPORT',
      description: description.trim(),
      assignee: assignee ? String(assignee).trim() : 'Unassigned',
      affectedDevices: Array.isArray(rawDevices) ? rawDevices : [rawDevices],
      indicators: Array.isArray(rawIps) ? rawIps : [rawIps],
      relatedIps: Array.isArray(rawIps) ? rawIps : [rawIps],
      detections: Array.isArray(rawDetections) ? rawDetections : [rawDetections],
      mitreTechniques: Array.isArray(rawMitre) ? rawMitre : [rawMitre],
      evidence: evidence || null,
    }
  };
}

function validateUpdateIncident(body) {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Update payload must be an object.' };
  }

  const updates = {};
  if (body.title !== undefined) {
    if (typeof body.title !== 'string' || !body.title.trim()) {
      return { valid: false, error: 'Title cannot be empty.' };
    }
    updates.title = body.title.trim();
  }

  if (body.description !== undefined) {
    if (typeof body.description !== 'string' || !body.description.trim()) {
      return { valid: false, error: 'Description cannot be empty.' };
    }
    updates.description = body.description.trim();
  }

  if (body.severity !== undefined) {
    const cleanSev = String(body.severity).toUpperCase();
    if (!VALID_SEVERITIES.includes(cleanSev)) {
      return { valid: false, error: `Invalid severity '${body.severity}'. Must be one of: ${VALID_SEVERITIES.join(', ')}` };
    }
    updates.severity = cleanSev;
  }

  if (body.confidence !== undefined) {
    const num = Number(body.confidence);
    if (isNaN(num) || num < 0 || num > 100) {
      return { valid: false, error: 'Confidence must be between 0 and 100.' };
    }
    updates.confidence = Math.round(num);
  }

  if (body.affectedDevices !== undefined || body.affected_devices !== undefined) {
    const devs = body.affectedDevices || body.affected_devices;
    updates.affectedDevices = Array.isArray(devs) ? devs : [devs];
  }

  if (body.indicators !== undefined || body.relatedIps !== undefined || body.related_ips !== undefined) {
    const iocs = body.indicators || body.relatedIps || body.related_ips;
    updates.indicators = Array.isArray(iocs) ? iocs : [iocs];
    updates.relatedIps = updates.indicators;
  }

  if (body.assignee !== undefined) {
    updates.assignee = String(body.assignee).trim() || 'Unassigned';
  }

  if (Object.keys(updates).length === 0) {
    return { valid: false, error: 'No valid update fields provided.' };
  }

  return { valid: true, data: updates };
}

function validateStatusUpdate(body) {
  const { status, note } = body || {};
  if (!status || typeof status !== 'string') {
    return { valid: false, error: 'New status is required.' };
  }
  const cleanStatus = normalizeStatus(status);
  if (!cleanStatus) {
    return { valid: false, error: `Invalid status '${status}'. Must be one of: ${VALID_STATUSES.join(', ')}` };
  }
  return {
    valid: true,
    data: {
      status: cleanStatus,
      note: note ? String(note).trim() : '',
    }
  };
}

function validateAssignIncident(body) {
  const { assignee, note } = body || {};
  if (!assignee || typeof assignee !== 'string' || !assignee.trim()) {
    return { valid: false, error: 'Assignee name or email is required.' };
  }
  return {
    valid: true,
    data: {
      assignee: assignee.trim(),
      note: note ? String(note).trim() : '',
    }
  };
}

function validateCloseIncident(body) {
  const { reason, note } = body || {};
  return {
    valid: true,
    data: {
      reason: reason ? String(reason).trim() : 'RESOLVED',
      note: note ? String(note).trim() : 'Incident successfully mitigated and closed by SOC operator.',
    }
  };
}

function validateResponseAction(body) {
  const { actionType, action_type, target, parameters, notes } = body || {};
  const type = actionType || action_type;
  if (!type || typeof type !== 'string') {
    return { valid: false, error: 'Response actionType is required (e.g. ISOLATE_HOST, BLOCK_IP, KILL_PROCESS).' };
  }
  if (!target || typeof target !== 'string') {
    return { valid: false, error: 'Response action target is required.' };
  }
  return {
    valid: true,
    data: {
      actionType: String(type).trim().toUpperCase(),
      target: String(target).trim(),
      parameters: parameters || {},
      notes: notes ? String(notes).trim() : '',
    }
  };
}

function validateTimelineQuery(query = {}) {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20));
  const order = String(query.order || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';
  const eventType = query.eventType || query.type || null;
  const actor = query.actor || null;
  const source = query.source || null;
  const search = query.search || query.q || null;

  return {
    page,
    limit,
    order,
    eventType: eventType ? String(eventType).trim().toUpperCase() : null,
    actor: actor ? String(actor).trim() : null,
    source: source ? String(source).trim() : null,
    search: search ? String(search).trim() : null,
  };
}

function validateAppendTimelineEvent(body = {}) {
  const {
    eventType,
    action,
    type,
    description,
    note,
    message,
    source,
    relatedEvent,
    relatedDetection,
    relatedResponseAction,
    metadata,
  } = body;

  const rawType = eventType || action || type;
  if (!rawType || typeof rawType !== 'string' || !rawType.trim()) {
    return { valid: false, error: 'eventType (or action) is required.' };
  }

  const desc = description || note || message;
  if (!desc || typeof desc !== 'string' || !desc.trim()) {
    return { valid: false, error: 'Event description (or note) is required.' };
  }

  return {
    valid: true,
    data: {
      eventType: String(rawType).trim().toUpperCase(),
      description: String(desc).trim(),
      source: source ? String(source).trim() : 'SOC_ANALYST',
      relatedEvent: relatedEvent && typeof relatedEvent === 'object' ? relatedEvent : null,
      relatedDetection: relatedDetection && typeof relatedDetection === 'object' ? relatedDetection : null,
      relatedResponseAction: relatedResponseAction && typeof relatedResponseAction === 'object' ? relatedResponseAction : null,
      metadata: metadata && typeof metadata === 'object' ? metadata : {},
    }
  };
}

module.exports = {
  validateCreateIncident,
  validateUpdateIncident,
  validateStatusUpdate,
  validateAssignIncident,
  validateCloseIncident,
  validateResponseAction,
  validateTimelineQuery,
  validateAppendTimelineEvent,
  VALID_STATUSES,
  VALID_SEVERITIES,
};
