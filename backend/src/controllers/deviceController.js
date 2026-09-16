/**
 * deviceController.js
 * Request handlers for endpoint device enrollment and fleet management.
 */

const deviceService = require('../services/deviceService');
const { validateEnrollDeviceInput, validateDeviceStatusUpdate } = require('../validators/deviceValidators');

class DeviceController {
  async enroll(req, res) {
    const validation = validateEnrollDeviceInput(req.body);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    try {
      const result = await deviceService.enrollDevice({
        ...validation.data,
        user: req.user,
        req,
      });
      return res.status(201).json({ success: true, ...result });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message || 'Device enrollment failed.' });
    }
  }

  async list(req, res) {
    try {
      const { status, search } = req.query;
      const devices = await deviceService.listDevices({ status, search });
      return res.json({
        success: true,
        total: devices.length,
        devices,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  async getById(req, res) {
    try {
      const device = await deviceService.getDeviceById(req.params.id);
      return res.json({ success: true, device });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  async revoke(req, res) {
    try {
      const { reason } = req.body || {};
      const result = await deviceService.revokeDevice(req.params.id, {
        reason,
        user: req.user,
        req,
      });
      return res.json(result);
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }

  async rotateCredential(req, res) {
    try {
      const result = await deviceService.rotateCredential(req.params.id, {
        user: req.user,
        req,
      });
      return res.json(result);
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ success: false, error: err.message });
    }
  }
}

module.exports = new DeviceController();
