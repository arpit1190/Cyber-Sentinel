/**
 * incidents.js
 * Comprehensive SOC incident response management API routes.
 * 
 * Enforces:
 * - Server-side NIST/SANS 8-state transition validation
 * - RBAC permission checks
 * - Immutable timeline auditing
 * - Cryptographic SHA-256 evidence integrity
 */
const express = require('express');
const router = express.Router();
const { requireAuth, requireRole, requirePermission } = require('../middleware/auth');
const incidentController = require('../controllers/incidentController');

// ── 1. List Incidents (Filter by status, severity, assignee, search query) ──
router.get('/', requireAuth, (req, res) => incidentController.list(req, res));

// ── 2. Get Incident by ID ──
router.get('/:id', requireAuth, (req, res) => incidentController.getById(req, res));

// ── 3. Create Manual Incident ──
router.post('/', requireAuth, (req, res) => incidentController.create(req, res));

// ── 4. Update Incident Fields (Metadata, devices, indicators, confidence) ──
router.patch('/:id', requireAuth, (req, res) => incidentController.update(req, res));
router.put('/:id', requireAuth, (req, res) => incidentController.update(req, res));

// ── 5. Change Incident Status (Validated against NIST lifecycle state machine) ──
router.patch('/:id/status', requireAuth, (req, res) => incidentController.updateStatus(req, res));
router.post('/:id/status', requireAuth, (req, res) => incidentController.updateStatus(req, res));

// ── 6. Assign Incident to SOC Analyst ──
router.post('/:id/assign', requireAuth, (req, res) => incidentController.assign(req, res));
router.patch('/:id/assign', requireAuth, (req, res) => incidentController.assign(req, res));

// ── 7. Close Incident with Resolution Directive ──
router.post('/:id/close', requireAuth, (req, res) => incidentController.close(req, res));

// ── 8. Add Analyst Note ──
router.post('/:id/notes', requireAuth, (req, res) => incidentController.addNote(req, res));

// ── 9. Execute / Record Incident Response Action (Containment / Eradication) ──
router.post('/:id/response-actions', requireAuth, (req, res) => incidentController.addResponseAction(req, res));

// ── 10. Immutable Incident Timeline & Cryptographic Integrity ──
// Paginated timeline retrieval
router.get('/:id/timeline', requireAuth, (req, res) => incidentController.getTimeline(req, res));

// Append event to timeline
router.post('/:id/timeline', requireAuth, (req, res) => incidentController.appendTimelineEvent(req, res));

// Cryptographic hash chain verification
router.get('/:id/timeline/verify', requireAuth, (req, res) => incidentController.verifyTimelineIntegrity(req, res));

// Reject any deletion or modification of historical timeline audit records (Fail Closed / 405 Method Not Allowed)
router.put('/:id/timeline/:eventId', requireAuth, (req, res) => incidentController.rejectTimelineMutation(req, res));
router.patch('/:id/timeline/:eventId', requireAuth, (req, res) => incidentController.rejectTimelineMutation(req, res));
router.delete('/:id/timeline/:eventId', requireAuth, (req, res) => incidentController.rejectTimelineMutation(req, res));
router.delete('/:id/timeline', requireAuth, (req, res) => incidentController.rejectTimelineMutation(req, res));

module.exports = router;
