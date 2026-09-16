/**
 * Production Database Migration Engine for Cyber Sentinel
 * 
 * Features:
 * - Versioned, ordered SQL migrations execution
 * - Transaction-safe execution per migration (Atomic BEGIN/COMMIT/ROLLBACK)
 * - SHA-256 migration checksum verification against tampering
 * - schema_migrations tracking table
 * - Dual CLI and programmatic invocation
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getPool, closeDb } = require('./db');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

/**
 * Computes SHA-256 checksum of SQL migration content
 */
function getChecksum(content) {
  return crypto.createHash('sha256').update(content.trim()).digest('hex');
}

/**
 * Initializes the schema_migrations tracking table
 */
async function ensureMigrationTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      checksum VARCHAR(64) NOT NULL,
      applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

/**
 * Runs all pending migrations against the provided PostgreSQL pool or active pool
 */
async function runMigrations(customPool = null) {
  const pool = customPool || getPool();
  if (!pool) {
    console.log('[DB-Migrator] No PostgreSQL connection configured. Skipping relational migrations.');
    return { applied: 0, total: 0, status: 'offline_mode' };
  }

  const client = await pool.connect();
  try {
    console.log('[DB-Migrator] Initializing database migration runner...');
    await ensureMigrationTable(client);

    // Retrieve list of already applied migrations
    const res = await client.query('SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC');
    const appliedMap = new Map();
    res.rows.forEach(r => appliedMap.set(r.version, r));

    // Discover migration files
    if (!fs.existsSync(MIGRATIONS_DIR)) {
      console.warn(`[DB-Migrator] Migrations directory not found at: ${MIGRATIONS_DIR}`);
      return { applied: 0, total: 0, status: 'empty' };
    }

    const files = fs.readdirSync(MIGRATIONS_DIR)
      .filter(f => f.endsWith('.sql'))
      .sort((a, b) => a.localeCompare(b));

    let appliedCount = 0;

    for (const file of files) {
      const match = file.match(/^(\d+)_([\w-]+)\.sql$/);
      if (!match) {
        console.warn(`[DB-Migrator] Skipping invalid migration filename: ${file}`);
        continue;
      }

      const version = parseInt(match[1], 10);
      const name = match[2];
      const filePath = path.join(MIGRATIONS_DIR, file);
      const content = fs.readFileSync(filePath, 'utf8');
      const checksum = getChecksum(content);

      if (appliedMap.has(version)) {
        const applied = appliedMap.get(version);
        if (applied.checksum !== checksum) {
          console.warn(
            `[DB-Migrator] WARNING: Migration ${version} (${name}) checksum mismatch! ` +
            `Recorded: ${applied.checksum.slice(0, 8)}..., File: ${checksum.slice(0, 8)}...`
          );
        }
        continue; // Already applied
      }

      // Execute migration in an isolated transaction
      console.log(`[DB-Migrator] Applying migration ${version.toString().padStart(3, '0')}: ${name}...`);
      await client.query('BEGIN');
      try {
        await client.query(content);
        await client.query(
          'INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)',
          [version, name, checksum]
        );
        await client.query('COMMIT');
        console.log(`  ✅ [APPLIED] Migration ${version.toString().padStart(3, '0')}: ${name}`);
        appliedCount++;
      } catch (migrationErr) {
        await client.query('ROLLBACK');
        console.error(`  ❌ [FAILED] Migration ${version} (${name}): ${migrationErr.message}`);
        throw new Error(`Migration ${file} failed: ${migrationErr.message}`);
      }
    }

    if (appliedCount === 0) {
      console.log('[DB-Migrator] Database schema is up to date (0 pending migrations).');
    } else {
      console.log(`[DB-Migrator] Successfully applied ${appliedCount} database migration(s).`);
    }

    return { applied: appliedCount, total: files.length, status: 'success' };
  } finally {
    client.release();
  }
}

// CLI Execution Handler
if (require.main === module) {
  runMigrations()
    .then((result) => {
      console.log('[DB-Migrator] Migration process completed successfully:', result);
      return closeDb();
    })
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[DB-Migrator] Fatal migration error:', err);
      process.exit(1);
    });
}

module.exports = {
  runMigrations,
  getChecksum,
};
