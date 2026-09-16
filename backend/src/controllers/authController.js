/**
 * authController.js
 * Request handlers for authentication and user sessions.
 */

const authService = require('../services/authService');
const { validateRegisterInput, validateLoginInput } = require('../validators/authValidators');

class AuthController {
  async register(req, res) {
    const validation = validateRegisterInput(req.body);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    try {
      const result = await authService.register(validation.data);
      return res.status(201).json(result);
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ error: err.message || 'Internal server error during registration.' });
    }
  }

  async login(req, res) {
    const validation = validateLoginInput(req.body);
    if (!validation.valid) {
      return res.status(401).json({ error: validation.error });
    }

    try {
      const result = await authService.login({ ...validation.data, req });
      return res.json(result);
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ error: err.message || 'Internal server error during login.' });
    }
  }

  async refresh(req, res) {
    const { refreshToken } = req.body || {};
    try {
      const result = await authService.refresh(refreshToken);
      return res.json(result);
    } catch (err) {
      const status = err.status || 401;
      return res.status(status).json({ error: err.message || 'Token refresh failed.' });
    }
  }
}

module.exports = new AuthController();
