/**
 * deviceService.js
 * Comprehensive Endpoint Device Lifecycle & Credential Management Service.
 * 
 * Manages:
 * - Device Enrollment & Unique Cryptographic Secret Provisioning
 * - Credential Rotation & Old Secret Invalidation
 * - Lifecycle Transitions: PENDING -> ACTIVE -> QUARANTINED -> REVOKED -> DECOMMISSIONED
 * - Telemetry Ingestion Authentication against SHA-256 Hashes
 * - Immutable Audit Logging
 */

const crypto = require('crypto');
const deviceRepository = require('../repositories/deviceRepository');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');

class DeviceService {
  hashToken(token) {
    return crypto.createHash('sha256').update(String(token)).digest('hex');
  }

  generateDeviceSecret() {
    return `sec_${crypto.randomBytes(36).toString('hex')}`;
  }

  async enrollDevice({ name, platform, hostname, agentVersion, ipAddress, user, req }) {
    const cleanHostname = hostname.trim();

    // Check for duplicate active device on the same hostname
    const existing = await deviceRepository.findByHostname(cleanHostname);
    if (existing && existing.status === 'ACTIVE') {
      throw {
        status: 409,
        message: `An active endpoint with hostname '${cleanHostname}' is already enrolled (ID: ${existing.id}). Please rotate credentials or decommission the existing device first.`
      };
    }

    const deviceId = `DEV-${crypto.createHash('sha256').update(`${cleanHostname}-${Date.now()}`).digest('hex').substring(0, 16).toUpperCase()}`;

    const device = await deviceRepository.createDevice({
      id: deviceId,
      name: name || cleanHostname,
      platform: platform || 'UNKNOWN',
      hostname: cleanHostname,
      status: 'ACTIVE',
      agentVersion: agentVersion || '1.0.0',
      enrolledBy: user?.email || 'operator',
      ipAddress: ipAddress || req?.ip || '127.0.0.1',
    });

    // Generate unique random device credential
    const rawSecret = this.generateDeviceSecret();
    const tokenHash = this.hashToken(rawSecret);
    const keyIdentifier = `KEY-${Date.now().toString().slice(-6)}-${crypto.randomInt(10, 99)}`;

    await deviceRepository.addCredential({
      deviceId: device.id,
      tokenHash,
      keyIdentifier,
      secret: rawSecret,
    });

    logSecurityEvent({
      actor: user?.email || 'operator',
      actorRole: user?.role || 'ENDPOINT_OPERATOR',
      action: AuditActions.DEVICE_ENROLLED || 'DEVICE_ENROLLED',
      target: device.id,
      req,
      details: { hostname: cleanHostname, platform: device.platform, keyIdentifier },
    });

    return {
      device: {
        id: device.id,
        name: device.name,
        platform: device.platform,
        hostname: device.hostname,
        status: device.status,
        agentVersion: device.agentVersion,
        createdAt: device.createdAt,
        enrolledBy: device.enrolledBy,
      },
      deviceSecret: rawSecret,
      keyIdentifier,
      message: 'Endpoint successfully enrolled. Save the device secret securely; it will not be displayed again.',
    };
  }

  async listDevices({ status, search }) {
    let devices = await deviceRepository.getAllDevices(status);

    if (search) {
      const q = search.toLowerCase();
      devices = devices.filter(d =>
        d.id.toLowerCase().includes(q) ||
        d.hostname.toLowerCase().includes(q) ||
        d.name.toLowerCase().includes(q)
      );
    }

    return devices;
  }

  async getDeviceById(id) {
    const device = await deviceRepository.findById(id);
    if (!device) {
      throw { status: 404, message: 'Endpoint device not found.' };
    }
    return device;
  }

  async revokeDevice(id, { reason, user, req }) {
    const device = await deviceRepository.findById(id);
    if (!device) {
      throw { status: 404, message: 'Endpoint device not found.' };
    }

    if (device.status === 'REVOKED') {
      return { success: true, message: 'Device is already revoked.', device };
    }

    await deviceRepository.updateStatus(id, 'REVOKED');
    await deviceRepository.revokeCredentialsForDevice(id);

    logSecurityEvent({
      actor: user?.email || 'operator',
      actorRole: user?.role || 'ENDPOINT_OPERATOR',
      action: AuditActions.DEVICE_REVOKED || 'DEVICE_REVOKED',
      target: device.id,
      req,
      details: { reason: reason || 'Operator containment revocation', previousStatus: device.status },
    });

    return {
      success: true,
      message: `Endpoint ${device.id} (${device.hostname}) revoked and all credentials permanently invalidated.`,
      device: { ...device, status: 'REVOKED' },
    };
  }

  async rotateCredential(id, { user, req }) {
    const device = await deviceRepository.findById(id);
    if (!device) {
      throw { status: 404, message: 'Endpoint device not found.' };
    }

    if (device.status === 'REVOKED' || device.status === 'DECOMMISSIONED') {
      throw {
        status: 400,
        message: `Cannot rotate credentials for a device in '${device.status}' state.`
      };
    }

    // 1. Invalidate previous credentials
    await deviceRepository.revokeCredentialsForDevice(id);

    // 2. Generate new secret
    const newSecret = this.generateDeviceSecret();
    const tokenHash = this.hashToken(newSecret);
    const keyIdentifier = `KEY-${Date.now().toString().slice(-6)}-${crypto.randomInt(10, 99)}`;

    await deviceRepository.addCredential({
      deviceId: device.id,
      tokenHash,
      keyIdentifier,
      secret: newSecret,
    });

    logSecurityEvent({
      actor: user?.email || 'operator',
      actorRole: user?.role || 'ENDPOINT_OPERATOR',
      action: AuditActions.DEVICE_CREDENTIAL_ROTATED || 'DEVICE_CREDENTIAL_ROTATED',
      target: device.id,
      req,
      details: { keyIdentifier },
    });

    return {
      success: true,
      deviceId: device.id,
      newDeviceSecret: newSecret,
      keyIdentifier,
      message: 'New device credential generated. Old credentials have been invalidated.',
    };
  }

  async getDeviceSecret(deviceId) {
    if (!deviceId) return null;
    const device = await deviceRepository.findById(deviceId);
    if (!device || device.status === 'REVOKED' || device.status === 'DECOMMISSIONED') {
      return null;
    }
    return await deviceRepository.getActiveSecretForDevice(deviceId);
  }

  async authenticateDevice(deviceId, rawSecret) {
    if (!deviceId || !rawSecret) {
      return { authenticated: false, error: 'Missing device credentials.' };
    }

    const tokenHash = this.hashToken(rawSecret);
    const cred = await deviceRepository.findCredentialByHash(tokenHash);

    if (!cred || !cred.isActive || cred.deviceId !== deviceId) {
      return { authenticated: false, error: 'Invalid or revoked device credential.' };
    }

    const device = await deviceRepository.findById(deviceId);
    if (!device) {
      return { authenticated: false, error: 'Device record not found.' };
    }

    if (device.status === 'REVOKED' || device.status === 'DECOMMISSIONED') {
      return { authenticated: false, error: `Device access denied. Endpoint is in '${device.status}' state.` };
    }

    // Update last seen
    await deviceRepository.updateLastSeen(deviceId);

    return {
      authenticated: true,
      device,
      cred,
    };
  }
}

module.exports = new DeviceService();
