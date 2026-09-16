/**
 * deviceRepository.js
 * Data Access Layer for Endpoint Devices and Device Credentials.
 * Supports PostgreSQL with in-memory zero-latency cache fallback.
 */

const crypto = require('crypto');
const { query, isPostgresConnected } = require('../data/db');

class DeviceRepository {
  constructor() {
    // In-memory caches:
    // deviceId -> { id, name, platform, hostname, status, agentVersion, enrolledBy, lastSeen, createdAt, updatedAt }
    this.devices = new Map();
    // tokenHash -> { id, deviceId, tokenHash, keyIdentifier, isActive, revokedAt, createdAt }
    this.credentials = new Map();
  }

  // ── Device Lifecycle Queries ───────────────────────────────────────────────
  async createDevice(deviceData) {
    const device = {
      id: deviceData.id || `DEV-${crypto.randomBytes(8).toString('hex').toUpperCase()}`,
      name: deviceData.name || 'Unnamed Endpoint',
      platform: deviceData.platform || 'Unknown',
      hostname: deviceData.hostname || 'Unknown-Host',
      status: deviceData.status || 'ACTIVE',
      agentVersion: deviceData.agentVersion || '1.0.0',
      enrolledBy: deviceData.enrolledBy || 'system',
      ipAddress: deviceData.ipAddress || '127.0.0.1',
      lastSeen: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this.devices.set(device.id, device);

    if (isPostgresConnected()) {
      try {
        await query(
          `INSERT INTO devices (id, name, platform, hostname, status, agent_version, last_seen, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name,
             platform = EXCLUDED.platform,
             hostname = EXCLUDED.hostname,
             status = EXCLUDED.status,
             agent_version = EXCLUDED.agent_version,
             last_seen = EXCLUDED.last_seen,
             updated_at = NOW()`,
          [device.id, device.name, device.platform, device.hostname, device.status, device.agentVersion, device.lastSeen, device.createdAt, device.updatedAt]
        );
      } catch (err) {
        console.error('[DeviceRepository] Error inserting device into PostgreSQL:', err.message);
      }
    }

    return device;
  }

  async findById(id) {
    if (!id) return null;
    if (this.devices.has(id)) {
      return this.devices.get(id);
    }

    if (isPostgresConnected()) {
      try {
        const res = await query('SELECT * FROM devices WHERE id = $1', [id]);
        if (res.rows.length > 0) {
          const r = res.rows[0];
          const device = {
            id: r.id,
            name: r.name,
            platform: r.platform,
            hostname: r.hostname,
            status: r.status,
            agentVersion: r.agent_version,
            lastSeen: r.last_seen ? new Date(r.last_seen).toISOString() : null,
            createdAt: r.created_at ? new Date(r.created_at).toISOString() : null,
            updatedAt: r.updated_at ? new Date(r.updated_at).toISOString() : null,
          };
          this.devices.set(device.id, device);
          return device;
        }
      } catch (err) {
        console.error('[DeviceRepository] Error querying device by ID:', err.message);
      }
    }

    return null;
  }

  async findByHostname(hostname) {
    if (!hostname) return null;
    const clean = hostname.trim().toLowerCase();
    for (const d of this.devices.values()) {
      if (d.hostname && d.hostname.toLowerCase() === clean) {
        return d;
      }
    }
    return null;
  }

  async getAllDevices(status = null) {
    let list = Array.from(this.devices.values());
    if (status && status !== 'ALL') {
      list = list.filter(d => (d.status || '').toUpperCase() === status.toUpperCase());
    }
    return list;
  }

  async updateStatus(id, newStatus) {
    const device = await this.findById(id);
    if (!device) return null;

    device.status = newStatus.toUpperCase();
    device.updatedAt = new Date().toISOString();
    this.devices.set(device.id, device);

    if (isPostgresConnected()) {
      try {
        await query(
          `UPDATE devices SET status = $1, updated_at = NOW() WHERE id = $2`,
          [device.status, device.id]
        );
      } catch (err) {
        console.error('[DeviceRepository] Error updating device status:', err.message);
      }
    }

    return device;
  }

  async updateLastSeen(id) {
    const device = await this.findById(id);
    if (device) {
      device.lastSeen = new Date().toISOString();
      if (isPostgresConnected()) {
        query('UPDATE devices SET last_seen = NOW() WHERE id = $1', [id])
          .catch(e => console.error('[DeviceRepository] Error updating last_seen:', e.message));
      }
    }
  }

  // ── Device Credentials Queries ────────────────────────────────────────────
  async addCredential({ deviceId, tokenHash, keyIdentifier, secret }) {
    const cred = {
      id: crypto.randomUUID(),
      deviceId,
      tokenHash,
      keyIdentifier: keyIdentifier || `KEY-${Date.now().toString().slice(-6)}`,
      secret: secret || null,
      isActive: true,
      revokedAt: null,
      createdAt: new Date().toISOString(),
    };

    this.credentials.set(tokenHash, cred);

    if (isPostgresConnected()) {
      try {
        await query(
          `INSERT INTO device_credentials (id, device_id, token_hash, key_identifier, is_active, created_at)
           VALUES ($1, $2, $3, $4, true, $5)`,
          [cred.id, cred.deviceId, cred.tokenHash, cred.keyIdentifier, cred.createdAt]
        );
      } catch (err) {
        console.error('[DeviceRepository] Error saving device credential:', err.message);
      }
    }

    return cred;
  }

  async findCredentialByHash(tokenHash) {
    if (!tokenHash) return null;
    if (this.credentials.has(tokenHash)) {
      return this.credentials.get(tokenHash);
    }

    if (isPostgresConnected()) {
      try {
        const res = await query(
          `SELECT * FROM device_credentials WHERE token_hash = $1`,
          [tokenHash]
        );
        if (res.rows.length > 0) {
          const r = res.rows[0];
          const cred = {
            id: r.id,
            deviceId: r.device_id,
            tokenHash: r.token_hash,
            keyIdentifier: r.key_identifier,
            isActive: r.is_active,
            revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null,
            createdAt: r.created_at ? new Date(r.created_at).toISOString() : null,
          };
          this.credentials.set(cred.tokenHash, cred);
          return cred;
        }
      } catch (err) {
        console.error('[DeviceRepository] Error querying device credential:', err.message);
      }
    }

    return null;
  }

  async getActiveCredentialByDeviceId(deviceId) {
    if (!deviceId) return null;
    for (const cred of this.credentials.values()) {
      if (cred.deviceId === deviceId && cred.isActive) {
        return cred;
      }
    }
    return null;
  }

  async getActiveSecretForDevice(deviceId) {
    if (!deviceId) return null;
    const cred = await this.getActiveCredentialByDeviceId(deviceId);
    return cred && cred.isActive ? cred.secret : null;
  }

  async revokeCredentialsForDevice(deviceId) {
    for (const [hash, cred] of this.credentials) {
      if (cred.deviceId === deviceId) {
        cred.isActive = false;
        cred.revokedAt = new Date().toISOString();
      }
    }

    if (isPostgresConnected()) {
      try {
        await query(
          `UPDATE device_credentials SET is_active = false, revoked_at = NOW() WHERE device_id = $1`,
          [deviceId]
        );
      } catch (err) {
        console.error('[DeviceRepository] Error revoking device credentials in DB:', err.message);
      }
    }
  }
}

module.exports = new DeviceRepository();
