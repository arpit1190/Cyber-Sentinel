/**
 * userRepository.js
 * Data Access Layer for User identity, credentials, and profile management.
 * Provides unified queries against PostgreSQL with in-memory & file fallback.
 */

const userStore = require('../data/userStore');
const { query, isPostgresConnected } = require('../data/db');
const { ROLES, normalizeRole } = require('../constants/roles');

class UserRepository {
  async findByEmail(email) {
    if (!email) return null;
    return userStore.findByEmail(email);
  }

  async findById(id) {
    if (!id) return null;
    if (isPostgresConnected()) {
      try {
        const res = await query('SELECT * FROM users WHERE id = $1', [id]);
        if (res.rows.length > 0) {
          const row = res.rows[0];
          return {
            id: row.id,
            email: row.email,
            name: row.name,
            passwordHash: row.password_hash,
            role: normalizeRole(row.role),
            status: row.status,
            mfaEnabled: row.mfa_enabled,
            totpSecret: row.totp_secret,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
          };
        }
      } catch (err) {
        console.error('[UserRepository] Error querying user by ID:', err.message);
      }
    }
    const all = userStore.getAllUsers();
    return all.find(u => u.id === id) || null;
  }

  async findByPhone(phone) {
    return userStore.findByPhone(phone);
  }

  async createUser(userData) {
    return userStore.createUser(userData);
  }

  async updateUser(userData) {
    return userStore.updateUser(userData);
  }

  async updateUserEmail(oldEmail, newEmail, userData) {
    return userStore.updateUserEmail(oldEmail, newEmail, userData);
  }

  async getAllUsers() {
    return userStore.getAllUsers();
  }

  async sync() {
    return userStore.syncFromPostgres();
  }
}

module.exports = new UserRepository();
