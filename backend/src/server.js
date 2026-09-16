require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const authRoutes = require('./routes/auth');
const threatRoutes = require('./routes/threats');
const logRoutes = require('./routes/logs');
const vulnRoutes = require('./routes/vuln');
const chatbotRoutes = require('./routes/chatbot');
const systemRoutes = require('./routes/system');
const sandboxRoutes = require('./routes/sandbox');
const protectionRoutes = require('./routes/protection');
const incidentRoutes = require('./routes/incidents');
const auditRoutes = require('./routes/audit');
const eventRoutes = require('./routes/events');
const malwareRoutes = require('./routes/malware');
const deviceRoutes = require('./routes/devices');
const responseActionRoutes = require('./routes/responseActions');
const { startRealtimeEngine } = require('./utils/realtimeEngine');
const { structuredLogger } = require('./utils/structuredLogger');
const metricsCollector = require('./utils/metricsCollector');

const config = require('./config');

const app = express();

const isAllowedOrigin = (origin) => {
  if (!origin) return true; // Allow non-browser agents, CLI tools, server-to-server
  if (config.server.corsOrigins.includes(origin) || config.server.corsOrigins.includes('*')) return true;
  if (!config.isProduction && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
    return true;
  }
  return false;
};

const corsOptions = {
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy violation: Origin '${origin}' is not authorized`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-Device-Id', 'X-Device-Token', 'X-Timestamp', 'X-Nonce', 'X-Signature', 'X-Body-Hash', 'X-Request-ID', 'X-Idempotency-Key'],
};

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('./config/jwt');

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// Assign unique X-Request-ID header to every inbound request
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || `req-${crypto.randomUUID()}`;
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Metrics & Structured JSON Logger hooks
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    metricsCollector.recordRequest(req.method, req.path, res.statusCode, duration);
  });
  next();
});

app.use(structuredLogger({ service: 'cyber-sentinel-api' }));

// Strict JSON parse error handler
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError || err.type === 'entity.parse.failed' || err.status === 400 || err.statusCode === 400) {
    return res.status(400).json({ error: 'Invalid request body: must be a valid JSON object.' });
  }
  next(err);
});

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development') ? 1000 : 50,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'Too many authentication attempts. Please try again later.' }),
});
app.use('/api/auth', authLimiter, authRoutes);

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development') ? 10000 : 120,
  message: { error: 'Too many requests. Please try again in a minute.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/threats', apiLimiter, threatRoutes);
app.use('/api/logs', apiLimiter, logRoutes);
app.use('/api/vuln', apiLimiter, vulnRoutes);
app.use('/api/chatbot', apiLimiter, chatbotRoutes);
app.use('/api/system', apiLimiter, systemRoutes);
app.use('/api/sandbox', apiLimiter, sandboxRoutes);
app.use('/api/protection', apiLimiter, protectionRoutes);
app.use('/api/incidents', apiLimiter, incidentRoutes);
app.use('/api/audit-logs', apiLimiter, auditRoutes);
app.use('/api/events', apiLimiter, eventRoutes);
app.use('/api/malware', apiLimiter, malwareRoutes);
app.use('/api/devices', apiLimiter, deviceRoutes);
app.use('/api/response-actions', apiLimiter, responseActionRoutes);

// Observability: Health Check (Liveness)
const healthHandler = (req, res) => {
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https' ? 'https' : 'http';
  const websocketUrl = process.env.RENDER_EXTERNAL_URL || `${protocol}://${host}`;
  const { isPostgresConnected } = require('./data/db');
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'cyber-sentinel-api',
    uptime: Number(process.uptime().toFixed(2)),
    websocket: 'enabled',
    websocketUrl,
    components: {
      database: isPostgresConnected() ? 'connected' : 'offline_file_mode',
      aiCopilot: process.env.GEMINI_API_KEY ? 'agentic' : 'rule_based_offline',
      threatIntel: 'live',
      correlationEngine: 'active',
      realtimeEngine: 'active',
    },
  });
};

app.get('/health', healthHandler);
app.get('/api/health', healthHandler);
app.get('/api/health/live', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// Observability: Ready Check (Readiness)
const readyHandler = async (req, res) => {
  try {
    const { isPostgresConnected, getPool } = require('./data/db');
    let dbStatus = 'offline_file_mode';
    const dbPool = getPool();
    if (dbPool && isPostgresConnected()) {
      await dbPool.query('SELECT 1');
      dbStatus = 'connected';
    }
    return res.json({
      status: 'ready',
      database: dbStatus,
      uptime: Number(process.uptime().toFixed(2)),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    metricsCollector.incDatabaseError();
    return res.status(503).json({
      status: 'degraded',
      error: 'Database connection failed',
      timestamp: new Date().toISOString(),
    });
  }
};

app.get('/ready', readyHandler);
app.get('/api/ready', readyHandler);
app.get('/api/health/ready', readyHandler);

// Observability: Protected Prometheus & JSON Metrics Endpoint
const metricsHandler = (req, res) => {
  // Authorization check: Require METRICS_TOKEN or Bearer auth token with permissions
  const metricsToken = process.env.METRICS_TOKEN || config.telemetry?.metricsToken;
  if (metricsToken) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (token !== metricsToken) {
      // Check if valid JWT with metrics read role
      try {
        const decoded = jwt.verify(token, getJwtSecret());
        if (decoded.role !== 'ADMIN' && decoded.role !== 'AUDITOR' && decoded.role !== 'SUPERADMIN') {
          return res.status(403).json({ error: 'Forbidden: Insufficient privileges to view telemetry metrics.' });
        }
      } catch (_) {
        return res.status(401).json({ error: 'Unauthorized: Valid METRICS_TOKEN or Admin Bearer token required.' });
      }
    }
  }

  // Support format=json query
  if (req.query.format === 'json') {
    return res.json(metricsCollector.getJsonSnapshot());
  }

  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  res.send(metricsCollector.getPrometheusFormat());
};

app.get('/metrics', metricsHandler);
app.get('/api/metrics', metricsHandler);

// Serve static frontend if available
const candidateDistPaths = [
  path.resolve(__dirname, '../../frontend/dist'),
  path.resolve(__dirname, '../../dist'),
  path.resolve(__dirname, '../dist'),
  path.resolve(process.cwd(), 'frontend/dist'),
  path.resolve(process.cwd(), 'dist'),
];
const frontendDistPath = candidateDistPaths.find(p => fs.existsSync(p)) || candidateDistPaths[0];
if (fs.existsSync(frontendDistPath)) {
  app.use(express.static(frontendDistPath));
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ error: 'API endpoint not found.' });
    }
    res.sendFile(path.join(frontendDistPath, 'index.html'));
  });
} else {
  app.use((req, res) => res.status(404).json({ error: 'Resource not found.' }));
}

// Global safe error handling: NEVER leak stack traces or internal DB details
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  const requestId = req.id || 'unknown';

  // Log internal error safely on server side
  console.error(`[UnhandledError][${requestId}]`, err.message);

  // Return clean, non-leaking error response to clients
  res.status(status).json({
    error: status >= 500 ? 'Internal server error. The incident has been recorded.' : err.message,
    requestId,
  });
});

// Socket.IO HTTP server setup
const server = http.createServer(app);
const io = new Server(server, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
});
app.set('io', io);

// Socket.IO JWT authentication
io.use((socket, next) => {
  const rawToken = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!rawToken) {
    return next(new Error('WS_AUTH_REQUIRED: Authentication token is required to connect'));
  }
  const cleanToken = rawToken.replace(/^Bearer\s+/i, '').trim();
  try {
    const decoded = jwt.verify(cleanToken, getJwtSecret());
    socket.user = decoded;
    const userRole = (decoded.role || 'ANALYST').toUpperCase();
    socket.join(`role:${userRole}`);
    socket.join('authenticated');
    return next();
  } catch (err) {
    return next(new Error(`WS_AUTH_INVALID: ${err.message}`));
  }
});

const startServer = () => {
  const PORT = process.env.PORT || 5000;
  return server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🛡  Cyber Sentinel API running on port ${PORT}`);
    console.log(`⚡  WebSocket real-time engine: ACTIVE`);
    console.log(`📡  Endpoints: /health · /ready · /metrics · /api/incidents · /api/response-actions\n`);
  });
};

const gracefulShutdown = (signal) => {
  console.log(`\n[Server] Received ${signal}. Shutting down gracefully...`);
  server.close(() => {
    const { getPool, closeDb } = require('./data/db');
    const dbPool = getPool();
    if (dbPool) {
      closeDb().then(() => {
        process.exit(0);
      }).catch(() => process.exit(0));
    } else {
      process.exit(0);
    }
  });
  setTimeout(() => {
    process.exit(1);
  }, 5000).unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

if (require.main === module) {
  startRealtimeEngine(io);
  chatbotRoutes.setIO(io);
  startServer();
}

module.exports = app;
