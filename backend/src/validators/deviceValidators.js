/**
 * deviceValidators.js
 * Input validation and sanitization for Device Enrollment and Management.
 */

const VALID_PLATFORMS = ['WINDOWS', 'LINUX', 'DARWIN', 'MACOS', 'ANDROID', 'IOS', 'UNKNOWN'];
const VALID_LIFECYCLE_STATUSES = ['PENDING', 'ACTIVE', 'QUARANTINED', 'REVOKED', 'DECOMMISSIONED'];

function validateEnrollDeviceInput(body) {
  const { name, platform, hostname, agentVersion, ipAddress } = body || {};

  if (!hostname || typeof hostname !== 'string' || !hostname.trim()) {
    return { valid: false, error: 'Hostname is required for device enrollment.' };
  }

  const cleanPlatform = (platform ? String(platform).trim().toUpperCase() : 'UNKNOWN');
  const cleanHostname = hostname.trim();
  const cleanName = name ? String(name).trim() : cleanHostname;

  return {
    valid: true,
    data: {
      name: cleanName,
      platform: cleanPlatform,
      hostname: cleanHostname,
      agentVersion: agentVersion ? String(agentVersion).trim() : '1.0.0',
      ipAddress: ipAddress ? String(ipAddress).trim() : '127.0.0.1',
    }
  };
}

function validateDeviceStatusUpdate(body) {
  const { status, reason } = body || {};
  if (!status || typeof status !== 'string') {
    return { valid: false, error: 'Device lifecycle status is required.' };
  }

  const cleanStatus = status.trim().toUpperCase();
  if (!VALID_LIFECYCLE_STATUSES.includes(cleanStatus)) {
    return {
      valid: false,
      error: `Invalid status '${status}'. Allowed values: ${VALID_LIFECYCLE_STATUSES.join(', ')}`
    };
  }

  return {
    valid: true,
    data: {
      status: cleanStatus,
      reason: reason ? String(reason).trim() : 'Operator lifecycle update',
    }
  };
}

module.exports = {
  validateEnrollDeviceInput,
  validateDeviceStatusUpdate,
  VALID_LIFECYCLE_STATUSES,
  VALID_PLATFORMS,
};
