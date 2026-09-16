/**
 * incidentController.js
 * Request handlers for SOC security incident lifecycle operations.
 */

const incidentService = require('../services/incidentService');
const {
  validateCreateIncident,
  validateUpdateIncident,
  validateStatusUpdate,
  validateAssignIncident,
  validateCloseIncident,
  validateResponseAction,
  validateTimelineQuery,
  validateAppendTimelineEvent,
} = require('../validators/incidentValidators');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');

class IncidentController {
  list(req, res) {
    try {
      const { status, severity, assignee, search, limit, offset } = req.query;
      const result = incidentService.listIncidents({ status, severity, assignee, search, limit, offset });
      return res.json({
        success: true,
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        incidents: result.incidents,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  getById(req, res) {
    try {
      const incident = incidentService.getIncident(req.params.id);
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  create(req, res) {
    const validation = validateCreateIncident(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const incident = incidentService.createManualIncident({
        ...validation.data,
        user: req.user,
        req,
      });
      return res.status(201).json({ success: true, incident });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  update(req, res) {
    const validation = validateUpdateIncident(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const incident = incidentService.updateIncident(req.params.id, {
        updates: validation.data,
        user: req.user,
        req,
      });
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 400;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  updateStatus(req, res) {
    const validation = validateStatusUpdate(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const incident = incidentService.updateStatus(req.params.id, {
        status: validation.data.status,
        note: validation.data.note,
        user: req.user,
        req,
      });
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 400;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  assign(req, res) {
    const validation = validateAssignIncident(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const incident = incidentService.assignIncident(req.params.id, {
        assignee: validation.data.assignee,
        note: validation.data.note,
        user: req.user,
        req,
      });
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 400;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  close(req, res) {
    const validation = validateCloseIncident(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const incident = incidentService.closeIncident(req.params.id, {
        reason: validation.data.reason,
        note: validation.data.note,
        user: req.user,
        req,
      });
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 400;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  addNote(req, res) {
    const { note } = req.body || {};
    if (!note || typeof note !== 'string' || !note.trim()) {
      return res.status(400).json({ success: false, error: 'Note text cannot be empty.' });
    }

    try {
      const incident = incidentService.addNote(req.params.id, {
        note: note.trim(),
        user: req.user,
        req,
      });
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  addResponseAction(req, res) {
    const validation = validateResponseAction(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const incident = incidentService.addResponseAction(req.params.id, {
        actionData: validation.data,
        user: req.user,
        req,
      });
      return res.json({ success: true, incident });
    } catch (err) {
      const status = err.status || 400;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  getTimeline(req, res) {
    try {
      const options = validateTimelineQuery(req.query);
      const timelineData = incidentService.getTimeline(req.params.id, options);
      return res.json({ success: true, ...timelineData });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  appendTimelineEvent(req, res) {
    const validation = validateAppendTimelineEvent(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const event = incidentService.appendTimelineEvent(req.params.id, {
        eventData: validation.data,
        user: req.user,
        req,
      });
      return res.status(201).json({ success: true, event });
    } catch (err) {
      const status = err.status || 400;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  verifyTimelineIntegrity(req, res) {
    try {
      const verification = incidentService.verifyTimelineIntegrity(req.params.id);
      return res.json({ success: true, ...verification });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  rejectTimelineMutation(req, res) {
    if (req.user) {
      logSecurityEvent({
        actor: req.user.email,
        actorRole: req.user.role,
        action: AuditActions.TAMPER_ATTEMPT_DETECTED,
        target: req.params.id || 'INCIDENT_TIMELINE',
        req,
        details: {
          method: req.method,
          path: req.originalUrl,
          message: 'Attempted modification or deletion of immutable timeline record blocked.',
        },
      });
    }

    return res.status(405).json({
      success: false,
      error: 'Timeline events are immutable audit records and cannot be modified or deleted.',
      code: 'IMMUTABLE_RECORD_RESTRICTION',
    });
  }
}

module.exports = new IncidentController();
