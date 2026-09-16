/**
 * responseActions.js
 * SOC Response Actions Router with RBAC Authorization, Human Approval & Idempotency.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth, requireRole, requirePermission } = require('../middleware/auth');
const {
  requestResponseAction,
  approveResponseAction,
  rejectResponseAction,
  executeResponseAction,
  listResponseActions,
  getResponseAction,
} = require('../services/response/responseActionService');

router.use(requireAuth);

/**
 * POST /api/response-actions/request
 * Request a new response action.
 */
router.post('/request', (req, res) => {
  try {
    const { incidentId, deviceId, actionType, parameters, idempotencyKey } = req.body || {};

    if (!actionType) {
      return res.status(400).json({ success: false, error: 'actionType is required.' });
    }

    const action = requestResponseAction({
      incidentId,
      deviceId,
      actionType,
      parameters: parameters || {},
      requesterUser: req.user,
      idempotencyKey: idempotencyKey || req.headers['x-idempotency-key'] || null,
    });

    return res.status(201).json({ success: true, action });
  } catch (err) {
    const status = err.status || 400;
    return res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/response-actions/:id/approve
 * Human operator approves an action.
 */
router.post('/:id/approve', requirePermission('incident:update'), (req, res) => {
  try {
    const action = approveResponseAction(req.params.id, req.user);
    return res.json({ success: true, action });
  } catch (err) {
    const status = err.status || 400;
    return res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/response-actions/:id/reject
 * Human operator rejects an action.
 */
router.post('/:id/reject', requirePermission('incident:update'), (req, res) => {
  try {
    const { reason } = req.body || {};
    const action = rejectResponseAction(req.params.id, req.user, reason);
    return res.json({ success: true, action });
  } catch (err) {
    const status = err.status || 400;
    return res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/response-actions/:id/execute
 * Executes an approved response action.
 */
router.post('/:id/execute', requirePermission('incident:update'), async (req, res) => {
  try {
    const action = await executeResponseAction(req.params.id, req.user);
    return res.json({ success: true, action });
  } catch (err) {
    const status = err.status || 400;
    return res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/response-actions
 * Lists all response actions.
 */
router.get('/', (req, res) => {
  try {
    const { status, incidentId, deviceId } = req.query;
    const actions = listResponseActions({ status, incidentId, deviceId });
    return res.json({ success: true, count: actions.length, actions });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/response-actions/:id
 * Retrieves a response action by ID.
 */
router.get('/:id', (req, res) => {
  try {
    const action = getResponseAction(req.params.id);
    if (!action) {
      return res.status(404).json({ success: false, error: 'Response action not found.' });
    }
    return res.json({ success: true, action });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
