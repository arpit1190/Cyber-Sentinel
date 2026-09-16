/**
 * db.js — Production Database Layer for PostgreSQL
 * 
 * Provides:
 * - Connection pooling with configurable limits & keep-alive
 * - Transaction isolation helper: withTransaction(async (client) => { ... })
 * - Parameterized query executor
 * - Automated versioned migration on startup via migrator.js
 * - Dual-mode detection (PostgreSQL vs. local offline repository fallback)
 * - Safe error handling and graceful shutdown
 */

const { Pool } = require('pg');
const config = require('../config');

let pool = null;
let isConnected = false;

/**
 * Retrieves or initializes the PostgreSQL Connection Pool
 */
function getPool() {
  if (!pool && config.database.url) {
    const connectionString = config.database.url;
    const isProduction = config.isProduction;

    pool = new Pool({
      connectionString,
      ssl: isProduction && !connectionString.includes('localhost') 
        ? { rejectUnauthorized: false } 
        : false,
      max: config.database.maxConnections || 15,
      idleTimeoutMillis: config.database.idleTimeoutMillis || 30000,
      connectionTimeoutMillis: config.database.connectionTimeoutMillis || 5000,
    });

    pool.on('error', (err) => {
      console.error('[DB] Unexpected idle PostgreSQL client error:', err.message);
    });
  }
  return pool;
}

/**
 * Initializes the database connection and runs pending migrations
 */
async function initDb() {
  if (!config.database.url) {
    console.log('[DB] No DATABASE_URL configured. Active mode: Offline Persistent Repositories.');
    isConnected = false;
    return false;
  }

  try {
    const activePool = getPool();
    if (!activePool) return false;

    // Test connection
    const client = await activePool.connect();
    console.log('[DB] Successfully established connection to PostgreSQL database.');
    client.release();

    // Execute versioned schema migrations
    const { runMigrations } = require('./migrator');
    await runMigrations(activePool);

    isConnected = true;
    return true;
  } catch (err) {
    console.error('[DB] Failed to connect or migrate PostgreSQL:', err.message);
    console.warn('[DB] Operating in local persistent repository fallback mode.');
    isConnected = false;
    return false;
  }
}

/**
 * Executes a parameterized SQL query against the connection pool
 */
async function query(text, params) {
  const activePool = getPool();
  if (!activePool) {
    throw new Error('Database pool not available (DATABASE_URL not configured).');
  }
  return activePool.query(text, params);
}

/**
 * Executes a callback within a managed transaction block.
 * Automatically handles BEGIN, COMMIT, and ROLLBACK on failure.
 * 
 * @param {Function} callback - Async function receiving the checked-out pg client
 * @returns {Promise<any>} Result of callback
 */
async function withTransaction(callback) {
  const activePool = getPool();
  if (!activePool) {
    throw new Error('Database pool not available for transaction.');
  }

  const client = await activePool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

function isPostgresConnected() {
  return isConnected && pool !== null;
}

/**
 * Gracefully terminates the PostgreSQL connection pool
 */
async function closeDb() {
  if (pool) {
    await pool.end();
    pool = null;
    isConnected = false;
    console.log('[DB] PostgreSQL connection pool gracefully closed.');
  }
}

module.exports = {
  getPool,
  initDb,
  query,
  withTransaction,
  isPostgresConnected,
  closeDb,
};
