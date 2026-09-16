/**
 * incidentService.js
 * Business logic for SOC Incident Management, NIST/SANS State Transitions, and Audit Logging.
 */

const securityRepository = require('../repositories/securityRepository');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');
const { IncidentStatus, validateStateTransition, normalizeStatus } = require('./incidentStateMachine');

class IncidentService {
  listIncidents({ status, severity, assignee, search, limit = 100, offset = 0 } = {}) {
    let incidents = securityRepository.getIncidents(status);

    if (severity && severity !== 'ALL') {
      incidents = incidents.filter(i => (i.severity || '').toUpperCase() === severity.toUpperCase());
    }

    if (assignee && assignee !== 'ALL') {
      const cleanAssignee = assignee.toLowerCase();
      incidents = incidents.filter(i => (i.assignee || '').toLowerCase().includes(cleanAssignee));
    }

    if (search) {
      const q = search.toLowerCase();
      incidents = incidents.filter(i =>
        (i.title || '').toLowerCase().includes(q) ||
        (i.id || '').toLowerCase().includes(q) ||
        (i.description || '').toLowerCase().includes(q) ||
        (i.assignee || '').toLowerCase().includes(q) ||
        (Array.isArray(i.affectedDevices) && i.affectedDevices.some(d => String(d).toLowerCase().includes(q))) ||
        (Array.isArray(i.indicators) && i.indicators.some(ip => String(ip).toLowerCase().includes(q))) ||
        (Array.isArray(i.relatedIps) && i.relatedIps.some(ip => String(ip).toLowerCase().includes(q)))
      );
    }

    const total = incidents.length;
    const paginated = incidents.slice(Number(offset), Number(offset) + Number(limit));

    return {
      total,
      limit: Number(limit),
      offset: Number(offset),
      incidents: paginated,
    };
  }

  getIncident(id) {
    const incident = securityRepository.getIncidentById(id);
    if (!incident) {
      const err = new Error('Incident not found');
      err.status = 404;
      throw err;
    }
    return incident;
  }

  createManualIncident({
    title,
    severity = 'MEDIUM',
    confidence = 80,
    category = 'MANUAL_REPORT',
    description,
    assignee = 'Unassigned',
    affectedDevices = [],
    indicators = [],
    relatedIps = [],
    detections = [],
    mitreTechniques = [],
    evidence = null,
    user,
    req
  }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';

    const incident = securityRepository.createIncident({
      title,
      severity,
      confidence,
      category,
      description,
      assignee,
      affectedDevices,
      indicators: indicators.length > 0 ? indicators : relatedIps,
      relatedIps: indicators.length > 0 ? indicators : relatedIps,
      detections,
      mitreTechniques,
      evidence,
      createdBy: actor,
    });

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.INCIDENT_CREATED,
        target: incident.id,
        req,
        details: { title, severity, confidence, status: incident.status },
      });
    }

    return incident;
  }

  updateIncident(id, { updates, user, req, note }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';
    const incident = securityRepository.updateIncident(id, updates, actor, note);
    if (!incident) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.INCIDENT_STATUS_CHANGE,
        target: incident.id,
        req,
        details: { action: 'INCIDENT_FIELDS_UPDATED', changedFields: Object.keys(updates) },
      });
    }

    return incident;
  }

  updateStatus(id, { status, note, user, req }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';
    
    // Check if incident exists before running validation
    const existing = securityRepository.getIncidentById(id);
    if (!existing) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    const transitionCheck = validateStateTransition(existing.status, status);
    if (!transitionCheck.valid) {
      const err = new Error(transitionCheck.error);
      err.status = 400;
      throw err;
    }

    const incident = securityRepository.updateIncidentStatus(id, status, actor, note);

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.INCIDENT_STATUS_CHANGE,
        target: incident.id,
        req,
        details: { from: transitionCheck.from, to: transitionCheck.to, note },
      });
    }

    return incident;
  }

  assignIncident(id, { assignee, note, user, req }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';
    const existing = securityRepository.getIncidentById(id);
    if (!existing) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    const previousAssignee = existing.assignee;
    const incident = securityRepository.assignIncident(id, assignee, actor, note);

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.INCIDENT_STATUS_CHANGE,
        target: incident.id,
        req,
        details: { action: 'INCIDENT_ASSIGNED', previousAssignee, newAssignee: assignee, note },
      });
    }

    return incident;
  }

  closeIncident(id, { reason = 'RESOLVED', note, user, req }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';
    const existing = securityRepository.getIncidentById(id);
    if (!existing) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    const transitionCheck = validateStateTransition(existing.status, IncidentStatus.CLOSED);
    if (!transitionCheck.valid) {
      const err = new Error(transitionCheck.error);
      err.status = 400;
      throw err;
    }

    const incident = securityRepository.closeIncident(id, reason, actor, note);

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.INCIDENT_STATUS_CHANGE,
        target: incident.id,
        req,
        details: { action: 'INCIDENT_CLOSED', reason, note },
      });
    }

    return incident;
  }

  addNote(id, { note, user, req }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';
    const incident = securityRepository.addIncidentNote(id, actor, note);
    if (!incident) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.ANALYST_NOTE_ADDED,
        target: incident.id,
        req,
        details: { noteSnippet: note.slice(0, 100) },
      });
    }

    return incident;
  }

  addResponseAction(id, { actionData, user, req }) {
    const actor = user ? `${user.name || user.email} (${user.role})` : 'system';
    const incident = securityRepository.addResponseAction(id, actionData, actor);
    if (!incident) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.CONTAINMENT_IP_BLOCKED,
        target: incident.id,
        req,
        details: { actionType: actionData.actionType, target: actionData.target },
      });
    }

    return incident;
  }

  getTimeline(id, options = {}) {
    const existing = securityRepository.getIncidentById(id);
    if (!existing) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }
    const timelineData = securityRepository.getIncidentTimeline(id, options);
    return {
      incidentId: id,
      ...timelineData,
    };
  }

  appendTimelineEvent(id, { eventData, user, req }) {
    const existing = securityRepository.getIncidentById(id);
    if (!existing) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    const actor = user ? `${user.name || user.email} (${user.role})` : (eventData.actor || 'SYSTEM');
    const source = eventData.source || 'SOC_ANALYST';

    const newEvent = securityRepository.appendTimelineEvent(id, eventData, actor, source);

    if (user && req) {
      logSecurityEvent({
        actor: user.email,
        actorRole: user.role,
        action: AuditActions.INCIDENT_STATUS_CHANGE,
        target: id,
        req,
        details: { action: 'TIMELINE_EVENT_APPENDED', eventType: newEvent.eventType, eventId: newEvent.id },
      });
    }

    return newEvent;
  }

  verifyTimelineIntegrity(id) {
    const existing = securityRepository.getIncidentById(id);
    if (!existing) {
      const err = new Error('Incident not found.');
      err.status = 404;
      throw err;
    }

    return {
      incidentId: id,
      ...securityRepository.verifyIncidentTimelineIntegrity(id),
    };
  }
}

module.exports = new IncidentService();
