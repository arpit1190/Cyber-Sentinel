/**
 * devices.js
 * Secure Endpoint & Device Enrollment API Routes.
 * 
 * Endpoints:
 * - POST /api/devices/enroll             -> Enroll new device & issue unique credential
 * - GET  /api/devices                    -> List enrolled devices
 * - GET  /api/devices/:id                -> Get device details
 * - POST /api/devices/:id/revoke         -> Revoke device & invalidate credentials
 * - POST /api/devices/:id/rotate-credential -> Rotate secret & invalidate old token
 */

const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { requireAuth, requirePermission } = require('../middleware/auth');
const { PERMISSIONS } = require('../constants/roles');

router.use(requireAuth);

// POST /api/devices/enroll - Register new endpoint
router.post('/enroll', requirePermission(PERMISSIONS.DEVICES_WRITE), (req, res) => {
  return deviceController.enroll(req, res);
});

// GET /api/devices - List all registered devices
router.get('/', requirePermission(PERMISSIONS.DEVICES_READ), (req, res) => {
  return deviceController.list(req, res);
});

// GET /api/devices/:id - Get device details
router.get('/:id', requirePermission(PERMISSIONS.DEVICES_READ), (req, res) => {
  return deviceController.getById(req, res);
});

// POST /api/devices/:id/revoke - Revoke endpoint
router.post('/:id/revoke', requirePermission(PERMISSIONS.DEVICES_DELETE), (req, res) => {
  return deviceController.revoke(req, res);
});

// POST /api/devices/:id/rotate-credential - Rotate endpoint secret
router.post('/:id/rotate-credential', requirePermission(PERMISSIONS.DEVICES_WRITE), (req, res) => {
  return deviceController.rotateCredential(req, res);
});

module.exports = router;
