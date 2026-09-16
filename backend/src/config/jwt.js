/**
 * Centralized JWT Configuration & Secrets Management (Compatibility Wrapper)
 * Delegates directly to centralized config engine.
 */

const config = require('./index');

module.exports = {
  getJwtSecret: config.getJwtSecret,
  getJwtExpiresIn: config.getJwtExpiresIn,
  getRefreshTokenSecret: config.getRefreshTokenSecret,
  getDeviceSecret: config.getDeviceSecret,
  config
};
