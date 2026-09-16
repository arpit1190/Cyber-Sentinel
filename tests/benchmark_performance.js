/**
 * tests/benchmark_performance.js
 * Comprehensive Empirical Performance & Benchmark Suite for Cyber Sentinel.
 * 
 * Measures actual wall-clock timings, latency percentiles (p50, p95, p99),
 * throughput (ops/sec / events/sec), and memory consumption across core system components:
 * 1. End-to-End HTTP API Latency (Health, Auth, Events, Incidents, Dashboard, Threats)
 * 2. Authentication & Cryptographic Latency (Bcrypt cost=10, JWT HS256, HMAC-SHA256)
 * 3. Telemetry Ingestion & Canonical Normalization (1,000, 10,000, 50,000 events)
 * 4. SIEM Detection Processing & Rule Evaluation (Modular engine, Correlation, IOC Matching)
 * 5. Incident Retrieval, Filtered Queries & Cryptographic Timeline Verification
 * 6. SOC Dashboard API Response & Aggregation Performance
 * 7. Database Query Performance & Indexing Analysis
 * 8. Memory Footprint & Heap Allocation Under Heavy Load
 */

process.env.NODE_ENV = 'test';
process.env.CYBER_SENTINEL_BENCHMARK = 'true';

const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// System modules under test
const app = require('../backend/src/server');
const { normalizeEvent, EventTypes } = require('../backend/src/services/normalizer/eventNormalizer');
const { computeTelemetrySignature } = require('../backend/src/middleware/telemetryAuth');
const { CorrelationEngine } = require('../backend/src/utils/correlationEngine');
const { detectionEngine } = require('../backend/src/services/detection/detectionEngine');
const incidentService = require('../backend/src/services/incidentService');
const { verifyTimelineIntegrity } = require('../backend/src/services/timelineService');
const iocMatcher = require('../backend/src/services/threatIntel/iocMatcher');
const { analyzeBinary } = require('../backend/src/services/malware/staticAnalyzer');
const userRepository = require('../backend/src/repositories/userRepository');
const deviceRepository = require('../backend/src/repositories/deviceRepository');
const securityRepository = require('../backend/src/repositories/securityRepository');
const securityStore = require('../backend/src/data/securityStore');
const userStore = require('../backend/src/data/userStore');
const authService = require('../backend/src/services/authService');
const { getJwtSecret } = require('../backend/src/config/jwt');
const { ROLES } = require('../backend/src/constants/roles');

// Statistical calculation helper
function calculateStats(latenciesMs) {
  if (!latenciesMs || latenciesMs.length === 0) {
    return { mean: 0, p50: 0, p95: 0, p99: 0, min: 0, max: 0, totalCount: 0 };
  }
  const sorted = [...latenciesMs].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, val) => acc + val, 0);
  const mean = sum / sorted.length;
  const p50 = sorted[Math.floor(sorted.length * 0.50)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  const p99 = sorted[Math.floor(sorted.length * 0.99)];
  const min = sorted[0];
  const max = sorted[sorted.length - 1];

  return { mean, p50, p95, p99, min, max, totalCount: sorted.length };
}

// HTTP helper for live server requests
function makeRequest(baseUrl, options, postData) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.path || '/', baseUrl);
    const reqOptions = {
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: 10000,
    };

    const t0 = process.hrtime.bigint();
    const req = http.request(url, reqOptions, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        const latencyMs = Number(process.hrtime.bigint() - t0) / 1e6;
        let parsed = null;
        try { parsed = JSON.parse(body); } catch (_) { parsed = body; }
        resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed, latencyMs });
      });
    });

    req.on('error', (err) => {
      const latencyMs = Number(process.hrtime.bigint() - t0) / 1e6;
      reject(Object.assign(err, { latencyMs }));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    if (postData) {
      if (typeof postData === 'string' || Buffer.isBuffer(postData)) {
        req.write(postData);
      } else {
        req.write(JSON.stringify(postData));
      }
    }
    req.end();
  });
}

async function runBenchmark() {
  console.log('======================================================================');
  console.log('⚡  CYBER SENTINEL — EMPIRICAL PERFORMANCE BENCHMARK SUITE');
  console.log('======================================================================\n');

  const report = {
    testEnvironment: {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      cpuCount: require('os').cpus().length,
      cpuModel: require('os').cpus()[0]?.model || 'Unknown',
      totalMemoryMB: Math.round(require('os').totalmem() / (1024 * 1024)),
      freeMemoryMB: Math.round(require('os').freemem() / (1024 * 1024)),
      timestamp: new Date().toISOString(),
    },
    benchmarks: {},
  };

  console.log(`💻 Environment: Node.js ${report.testEnvironment.nodeVersion} on ${report.testEnvironment.platform} (${report.testEnvironment.cpuModel})`);
  console.log(`🧠 Available Memory: ${report.testEnvironment.freeMemoryMB}MB / ${report.testEnvironment.totalMemoryMB}MB | CPU Cores: ${report.testEnvironment.cpuCount}\n`);

  // Start in-process HTTP server on ephemeral port for live HTTP measurements
  const testServer = http.createServer(app);
  await new Promise((resolve) => testServer.listen(0, '127.0.0.1', resolve));
  const port = testServer.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`🌐 Live Benchmark HTTP Server active on ${baseUrl}\n`);

  // Setup test authentication tokens
  const adminUser = { id: 'usr-bench-admin', email: 'admin.bench@sentinel.defense', role: 'ADMIN' };
  const analystUser = { id: 'usr-bench-analyst', email: 'analyst.bench@sentinel.defense', role: 'SOC_ANALYST' };
  const adminToken = authService.generateAccessToken(adminUser);
  const analystToken = authService.generateAccessToken(analystUser);
  const deviceSecret = 'sentinel-bench-device-secret-key-1234567890';

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 1: AUTHENTICATION & CRYPTOGRAPHIC LATENCY
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 1. Authentication & Cryptographic Latency ━━━');
  {
    const password = 'Cyb3r$entinel#2026!SecOpsBenchmark';
    
    // 1.1 Bcrypt Password Hash (Cost factor 10)
    const bcryptHashTimes = [];
    for (let i = 0; i < 10; i++) {
      const t0 = process.hrtime.bigint();
      const salt = await bcrypt.genSalt(10);
      await bcrypt.hash(password, salt);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      bcryptHashTimes.push(ms);
    }
    const hashStats = calculateStats(bcryptHashTimes);

    // 1.2 Bcrypt Password Verify
    const testHash = await bcrypt.hash(password, await bcrypt.genSalt(10));
    const bcryptVerifyTimes = [];
    for (let i = 0; i < 20; i++) {
      const t0 = process.hrtime.bigint();
      await bcrypt.compare(password, testHash);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      bcryptVerifyTimes.push(ms);
    }
    const verifyStats = calculateStats(bcryptVerifyTimes);

    // 1.3 JWT Signing & Verification (1,000 iterations)
    const secret = getJwtSecret();
    const jwtSignTimes = [];
    const jwtVerifyTimes = [];
    const jwtTokens = [];

    for (let i = 0; i < 1000; i++) {
      const t0 = process.hrtime.bigint();
      const token = authService.generateAccessToken(analystUser);
      jwtSignTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
      jwtTokens.push(token);
    }

    for (let i = 0; i < 1000; i++) {
      const t0 = process.hrtime.bigint();
      jwt.verify(jwtTokens[i], secret, { algorithms: ['HS256'] });
      jwtVerifyTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }

    const jwtSignStats = calculateStats(jwtSignTimes);
    const jwtVerifyStats = calculateStats(jwtVerifyTimes);

    // 1.4 HMAC-SHA256 Telemetry Request Signing (5,000 iterations)
    const hmacTimes = [];
    const samplePayload = { deviceId: 'dev-bench', event: 'network_connection', ip: '192.168.1.1' };
    for (let i = 0; i < 5000; i++) {
      const t0 = process.hrtime.bigint();
      computeTelemetrySignature({
        method: 'POST',
        path: '/api/events',
        timestamp: Date.now(),
        nonce: `nonce-${i}`,
        body: samplePayload,
        deviceSecret,
      });
      hmacTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const hmacStats = calculateStats(hmacTimes);

    report.benchmarks.authCrypto = {
      bcryptHash: hashStats,
      bcryptVerify: verifyStats,
      jwtSign: jwtSignStats,
      jwtVerify: jwtVerifyStats,
      hmacSign: hmacStats,
    };

    console.log(`  • Bcrypt Hash (cost=10) : Mean: ${hashStats.mean.toFixed(2)}ms | p50: ${hashStats.p50.toFixed(2)}ms | p95: ${hashStats.p95.toFixed(2)}ms | p99: ${hashStats.p99.toFixed(2)}ms`);
    console.log(`  • Bcrypt Verify         : Mean: ${verifyStats.mean.toFixed(2)}ms | p50: ${verifyStats.p50.toFixed(2)}ms | p95: ${verifyStats.p95.toFixed(2)}ms | p99: ${verifyStats.p99.toFixed(2)}ms`);
    console.log(`  • JWT Sign (HS256)      : Mean: ${(jwtSignStats.mean * 1000).toFixed(2)}µs | p95: ${(jwtSignStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / jwtSignStats.mean)} ops/sec`);
    console.log(`  • JWT Verify (HS256)    : Mean: ${(jwtVerifyStats.mean * 1000).toFixed(2)}µs | p95: ${(jwtVerifyStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / jwtVerifyStats.mean)} ops/sec`);
    console.log(`  • HMAC-SHA256 Signing   : Mean: ${(hmacStats.mean * 1000).toFixed(2)}µs | p95: ${(hmacStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / hmacStats.mean)} ops/sec\n`);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 2: END-TO-END HTTP API LATENCY & ROUTE PROFILING
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 2. End-to-End HTTP API Latency & Endpoint Response Times ━━━');
  {
    const apiEndpoints = [
      { name: 'GET /api/health (Liveness)', path: '/api/health', method: 'GET', iterations: 200, headers: {} },
      { name: 'GET /api/ready (Readiness)', path: '/api/ready', method: 'GET', iterations: 200, headers: {} },
      { name: 'GET /api/auth/me (Protected User Identity)', path: '/api/auth/me', method: 'GET', iterations: 200, headers: { Authorization: `Bearer ${analystToken}` } },
      { name: 'GET /api/threats/dashboard (SOC Overview)', path: '/api/threats/dashboard', method: 'GET', iterations: 100, headers: { Authorization: `Bearer ${analystToken}` } },
      { name: 'GET /api/threats/blocked (Containment Rules)', path: '/api/threats/blocked', method: 'GET', iterations: 200, headers: { Authorization: `Bearer ${analystToken}` } },
      { name: 'GET /api/threats/cves (CVE Threat Intel Feed)', path: '/api/threats/cves', method: 'GET', iterations: 200, headers: { Authorization: `Bearer ${analystToken}` } },
      { name: 'GET /api/incidents (Filtered Incident Query)', path: '/api/incidents?severity=HIGH&limit=25', method: 'GET', iterations: 200, headers: { Authorization: `Bearer ${analystToken}` } },
      { name: 'GET /api/devices (Enrolled Device Catalog)', path: '/api/devices', method: 'GET', iterations: 200, headers: { Authorization: `Bearer ${analystToken}` } },
      { name: 'GET /api/audit-logs (Audit Trail)', path: '/api/audit-logs?limit=50', method: 'GET', iterations: 200, headers: { Authorization: `Bearer ${adminToken}` } },
    ];

    const apiResults = {};
    for (const ep of apiEndpoints) {
      const latencies = [];
      for (let i = 0; i < ep.iterations; i++) {
        const res = await makeRequest(baseUrl, { path: ep.path, method: ep.method, headers: ep.headers });
        latencies.push(res.latencyMs);
      }
      const stats = calculateStats(latencies);
      apiResults[ep.name] = stats;
      const throughput = Math.round(1000 / (stats.mean || 1));
      console.log(`  • ${ep.name.padEnd(46)} : Mean: ${stats.mean.toFixed(2)}ms | p50: ${stats.p50.toFixed(2)}ms | p95: ${stats.p95.toFixed(2)}ms | p99: ${stats.p99.toFixed(2)}ms | ~${throughput} req/s`);
    }
    report.benchmarks.apiLatency = apiResults;
    console.log('');
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 3: TELEMETRY INGESTION & CANONICAL NORMALIZATION
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 3. Telemetry Normalization & Ingestion Throughput ━━━');
  {
    // 3.1 Normalization Throughput (In-Memory Processing)
    const eventCounts = [1000, 10000, 50000];
    const normalizerResults = {};

    for (const count of eventCounts) {
      const latencies = [];
      const tStart = process.hrtime.bigint();

      for (let i = 0; i < count; i++) {
        const raw = {
          event_type: i % 3 === 0 ? 'auth_failure' : (i % 3 === 1 ? 'process_spawn' : 'network_connection'),
          source_ip: `10.0.${(i >> 8) & 255}.${i & 255}`,
          dest_ip: '8.8.8.8',
          dest_port: 443,
          device_id: `dev-${i % 50}`,
          user: `analyst_${i % 100}`,
          pid: 1000 + (i % 8000),
          command_line: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Process`,
          details: { query: 'SELECT * FROM users', severity: 'HIGH' },
        };

        const t0 = process.hrtime.bigint();
        normalizeEvent(raw);
        latencies.push(Number(process.hrtime.bigint() - t0) / 1e6);
      }

      const totalDurationMs = Number(process.hrtime.bigint() - tStart) / 1e6;
      const throughput = Math.round((count / totalDurationMs) * 1000);
      const stats = calculateStats(latencies);

      normalizerResults[`events_${count}`] = {
        count,
        totalDurationMs,
        throughputEventsPerSec: throughput,
        stats,
      };

      console.log(`  • Normalization ${count.toLocaleString().padStart(6)} Events : Total: ${totalDurationMs.toFixed(1)}ms | Throughput: ${throughput.toLocaleString()} events/sec | Mean: ${(stats.mean * 1000).toFixed(1)}µs | p95: ${(stats.p95 * 1000).toFixed(1)}µs`);
    }

    // 3.2 End-to-End HTTP Telemetry Ingestion API (POST /api/events with HMAC auth)
    const httpIngestLatencies = [];
    for (let i = 0; i < 200; i++) {
      const payload = {
        event_type: 'network_connection',
        source_ip: `198.51.100.${(i % 250) + 1}`,
        dest_ip: '10.0.0.1',
        dest_port: 443,
        device_id: 'dev-bench-ingest-01',
        user: 'system',
      };
      const ts = Date.now();
      const nonce = `bench-nonce-${i}-${Date.now()}`;
      const sig = computeTelemetrySignature({
        method: 'POST',
        path: '/api/events',
        timestamp: ts,
        nonce,
        body: payload,
        deviceSecret,
      });

      const res = await makeRequest(baseUrl, {
        path: '/api/events',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Id': 'dev-bench-ingest-01',
          'X-Timestamp': String(ts),
          'X-Nonce': nonce,
          'X-Signature': sig,
        },
      }, payload);

      httpIngestLatencies.push(res.latencyMs);
    }
    const httpIngestStats = calculateStats(httpIngestLatencies);
    normalizerResults.httpIngestionApi = httpIngestStats;

    console.log(`  • HTTP POST /api/events (200 reqs): Mean: ${httpIngestStats.mean.toFixed(2)}ms | p50: ${httpIngestStats.p50.toFixed(2)}ms | p95: ${httpIngestStats.p95.toFixed(2)}ms | p99: ${httpIngestStats.p99.toFixed(2)}ms`);

    report.benchmarks.telemetryNormalization = normalizerResults;
    console.log('');
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 4: SIEM DETECTION ENGINE, CORRELATION & THREAT INTEL
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 4. SIEM Detection Processing & Threat Intel Matching ━━━');
  {
    // 4.1 Modular Detection Engine (Rule Evaluation)
    const ruleEvaluationTimes = [];
    const eventCount = 5000;
    const tStartDet = process.hrtime.bigint();

    for (let i = 0; i < eventCount; i++) {
      const event = normalizeEvent({
        event_type: i % 4 === 0 ? 'auth_failure' : (i % 4 === 1 ? 'exploit_probe' : (i % 4 === 2 ? 'process_execution' : 'network_connection')),
        source_ip: `192.168.1.${(i % 20) + 1}`,
        dest_ip: '10.0.0.5',
        device_id: `dev-${i % 10}`,
        user: `analyst_${i % 10}`,
        process_name: i % 4 === 2 ? 'powershell.exe' : 'nginx',
        command_line: i % 4 === 2 ? 'powershell.exe -enc JABjAGwAaQBlAG4AdAA=' : '',
      });

      const t0 = process.hrtime.bigint();
      detectionEngine.processEvent(event);
      ruleEvaluationTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const totalDurationDetMs = Number(process.hrtime.bigint() - tStartDet) / 1e6;
    const detStats = calculateStats(ruleEvaluationTimes);
    const detThroughput = Math.round((eventCount / totalDurationDetMs) * 1000);

    // 4.2 State Correlation Engine
    const corrEngine = new CorrelationEngine();
    const corrTimes = [];
    for (let i = 0; i < eventCount; i++) {
      const event = {
        eventId: `evt-corr-${i}`,
        eventType: i % 5 === 0 ? EventTypes.AUTH_FAILURE : EventTypes.PROCESS_EXECUTION,
        sourceIp: `192.168.1.${(i % 10) + 1}`,
        deviceId: `dev-corr-${i % 5}`,
        user: { name: `user_${i % 5}` },
        process: { name: 'powershell.exe', command_line: 'powershell.exe -enc evil' },
        timestamp: new Date().toISOString(),
      };
      const t0 = process.hrtime.bigint();
      corrEngine.processEvent(event);
      corrTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const corrStats = calculateStats(corrTimes);

    // 4.3 Threat Intel IOC High-Speed Lookups (20,000 lookups)
    const indicators = [];
    for (let i = 0; i < 1000; i++) {
      indicators.push({
        value: `198.51.100.${i % 250}`,
        malware: `ThreatGroup-${i % 10}`,
        confidence: 90,
        mitreTechnique: 'T1071.001',
      });
    }
    iocMatcher.addIndicators(indicators);

    const lookupTimes = [];
    const lookupCount = 20000;
    const tStartIoc = process.hrtime.bigint();

    for (let i = 0; i < lookupCount; i++) {
      const queryIp = `198.51.100.${i % 300}`;
      const t0 = process.hrtime.bigint();
      iocMatcher.matchIoc(queryIp);
      lookupTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }

    const totalDurationIocMs = Number(process.hrtime.bigint() - tStartIoc) / 1e6;
    const iocStats = calculateStats(lookupTimes);
    const iocThroughput = Math.round((lookupCount / totalDurationIocMs) * 1000);

    report.benchmarks.detectionEngine = {
      modularEngine: { eventCount, throughputEventsPerSec: detThroughput, stats: detStats },
      correlationEngine: { eventCount, stats: corrStats },
      threatIntel: { lookupCount, throughputLookupsPerSec: iocThroughput, stats: iocStats },
    };

    console.log(`  • Modular Detection Engine (${eventCount.toLocaleString()} evts) : Mean: ${(detStats.mean * 1000).toFixed(1)}µs | p95: ${(detStats.p95 * 1000).toFixed(1)}µs | Throughput: ${detThroughput.toLocaleString()} evts/sec`);
    console.log(`  • Correlation Engine (${eventCount.toLocaleString()} evts)       : Mean: ${(corrStats.mean * 1000).toFixed(1)}µs | p95: ${(corrStats.p95 * 1000).toFixed(1)}µs | Throughput: ${Math.round(1000 / corrStats.mean).toLocaleString()} evts/sec`);
    console.log(`  • Threat Intel IOC Matcher (${lookupCount.toLocaleString()} lookups): Mean: ${(iocStats.mean * 1000).toFixed(2)}µs | p99: ${(iocStats.p99 * 1000).toFixed(2)}µs | Throughput: ${iocThroughput.toLocaleString()} lookups/sec\n`);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 5: INCIDENT RETRIEVAL, PAGINATION & TIMELINE HASH INTEGRITY
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 5. Incident Lifecycle & Cryptographic Timeline Verification ━━━');
  {
    // 5.1 Incident Creation & Timeline SHA-256 Hashing (500 incidents)
    const createdIncidents = [];
    const creationTimes = [];

    for (let i = 0; i < 500; i++) {
      const t0 = process.hrtime.bigint();
      const inc = incidentService.createManualIncident({
        title: `Benchmark Incident #${i}`,
        severity: i % 4 === 0 ? 'CRITICAL' : (i % 3 === 0 ? 'HIGH' : 'MEDIUM'),
        assignedTo: 'analyst@sentinel.defense',
        summary: `Automated benchmark load test incident #${i}`,
        user: { id: 'usr-bench', email: 'analyst@sentinel.defense', role: 'SOC_ANALYST' },
      });
      creationTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
      createdIncidents.push(inc);
    }
    const createStats = calculateStats(creationTimes);

    // 5.2 Add Timeline Notes & State Transitions
    const noteTimes = [];
    for (let i = 0; i < 500; i++) {
      const t0 = process.hrtime.bigint();
      incidentService.addNote(createdIncidents[i].id, {
        note: `Forensic timeline addition for incident ${i}`,
        user: { name: 'SOC Lead', email: 'lead@sentinel.defense', role: 'SOC_ANALYST' },
      });
      noteTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const noteStats = calculateStats(noteTimes);

    // 5.3 Filtered Retrieval & Search Query Performance (1,000 queries)
    const queryTimes = [];
    for (let i = 0; i < 1000; i++) {
      const t0 = process.hrtime.bigint();
      incidentService.listIncidents({
        severity: i % 2 === 0 ? 'CRITICAL' : 'HIGH',
        limit: 50,
        offset: (i % 5) * 50,
        search: 'Benchmark',
      });
      queryTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const queryStats = calculateStats(queryTimes);

    // 5.4 Full Cryptographic Timeline Hash Chain Verification (500 timelines)
    const verifyTimes = [];
    for (let i = 0; i < 500; i++) {
      const inc = incidentService.getIncident(createdIncidents[i].id);
      const t0 = process.hrtime.bigint();
      verifyTimelineIntegrity(inc.timeline);
      verifyTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const verifyStats = calculateStats(verifyTimes);

    report.benchmarks.incidentManagement = {
      creation: createStats,
      timelineNoteAppend: noteStats,
      filteredSearchQuery: queryStats,
      timelineIntegrityVerify: verifyStats,
    };

    console.log(`  • Incident Creation & SHA-256 Hashing : Mean: ${(createStats.mean * 1000).toFixed(1)}µs | p95: ${(createStats.p95 * 1000).toFixed(1)}µs | Throughput: ${Math.round(1000 / createStats.mean).toLocaleString()} ops/sec`);
    console.log(`  • Timeline Note Cryptographic Append : Mean: ${(noteStats.mean * 1000).toFixed(1)}µs | p95: ${(noteStats.p95 * 1000).toFixed(1)}µs | Throughput: ${Math.round(1000 / noteStats.mean).toLocaleString()} ops/sec`);
    console.log(`  • Filtered List & Search Queries     : Mean: ${(queryStats.mean * 1000).toFixed(1)}µs | p95: ${(queryStats.p95 * 1000).toFixed(1)}µs | Throughput: ${Math.round(1000 / queryStats.mean).toLocaleString()} queries/sec`);
    console.log(`  • Full Timeline SHA-256 Chain Verify : Mean: ${(verifyStats.mean * 1000).toFixed(1)}µs | p95: ${(verifyStats.p95 * 1000).toFixed(1)}µs | Throughput: ${Math.round(1000 / verifyStats.mean).toLocaleString()} verifies/sec\n`);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 6: MALWARE STATIC ANALYSIS & ENTROPY COMPUTATION
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 6. Malware PE Static Analyzer & Entropy Calculation ━━━');
  {
    const sizes = [
      { name: 'Small Binary (64 KB)', size: 64 * 1024 },
      { name: 'Medium Binary (1 MB)', size: 1024 * 1024 },
      { name: 'Large Binary (8 MB)', size: 8 * 1024 * 1024 },
    ];

    const malwareResults = {};
    for (const item of sizes) {
      const buf = crypto.randomBytes(item.size);
      const latencies = [];
      const iterations = item.size > 2 * 1024 * 1024 ? 10 : 50;

      for (let i = 0; i < iterations; i++) {
        const t0 = process.hrtime.bigint();
        analyzeBinary(buf, 'sample.exe');
        latencies.push(Number(process.hrtime.bigint() - t0) / 1e6);
      }

      const stats = calculateStats(latencies);
      malwareResults[item.name] = stats;
      console.log(`  • ${item.name.padEnd(24)} (${iterations} iters) : Mean: ${stats.mean.toFixed(2)}ms | p50: ${stats.p50.toFixed(2)}ms | p95: ${stats.p95.toFixed(2)}ms | Max: ${stats.max.toFixed(2)}ms`);
    }

    report.benchmarks.malwareAnalysis = malwareResults;
    console.log('');
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 7: DATABASE & REPOSITORY QUERY PERFORMANCE
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 7. Database & Repository Layer Query Performance ━━━');
  {
    const dbBenchmarks = {};

    // 7.1 User Lookups (findByEmail, findById, getAllUsers)
    const userLookupTimes = [];
    for (let i = 0; i < 1000; i++) {
      const email = `analyst_${i % 100}@sentinel.defense`;
      const t0 = process.hrtime.bigint();
      userStore.findByEmail(email);
      userLookupTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const userStats = calculateStats(userLookupTimes);
    dbBenchmarks.userLookupByEmail = userStats;

    // 7.2 Device Queries (findById, findByHostname, getAllDevices)
    for (let i = 0; i < 200; i++) {
      await deviceRepository.createDevice({
        id: `dev-bench-query-${i}`,
        hostname: `workstation-${i}.corp.sentinel`,
        platform: 'Windows 11',
        agentVersion: '2.0.0',
      });
    }

    const deviceQueryTimes = [];
    for (let i = 0; i < 1000; i++) {
      const t0 = process.hrtime.bigint();
      await deviceRepository.findById(`dev-bench-query-${i % 200}`);
      deviceQueryTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const deviceStats = calculateStats(deviceQueryTimes);
    dbBenchmarks.deviceLookupById = deviceStats;

    // 7.3 Firewall Rules Query (isIpBlocked, getBlockedIps)
    for (let i = 0; i < 100; i++) {
      securityStore.blockIp(`198.51.100.${i}`, `Benchmark block ${i}`, 'bench-admin');
    }

    const fwQueryTimes = [];
    for (let i = 0; i < 1000; i++) {
      const t0 = process.hrtime.bigint();
      securityStore.isIpBlocked(`198.51.100.${i % 150}`);
      fwQueryTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const fwStats = calculateStats(fwQueryTimes);
    dbBenchmarks.firewallLookup = fwStats;

    // 7.4 Security Repository Incident & Audit Trail Aggregations
    const aggTimes = [];
    for (let i = 0; i < 1000; i++) {
      const t0 = process.hrtime.bigint();
      securityRepository.getIncidents();
      securityRepository.getAuditLogs(50);
      securityRepository.getBlockedIps();
      securityRepository.getScans();
      aggTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const aggStats = calculateStats(aggTimes);
    dbBenchmarks.dashboardAggregation = aggStats;

    report.benchmarks.databaseQueries = dbBenchmarks;

    console.log(`  • User Lookup by Indexed Email (1,000 queries) : Mean: ${(userStats.mean * 1000).toFixed(2)}µs | p95: ${(userStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / userStats.mean).toLocaleString()} lookups/sec`);
    console.log(`  • Device Lookup by Primary Key (1,000 queries) : Mean: ${(deviceStats.mean * 1000).toFixed(2)}µs | p95: ${(deviceStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / deviceStats.mean).toLocaleString()} queries/sec`);
    console.log(`  • Firewall Blocklist Check     (1,000 queries) : Mean: ${(fwStats.mean * 1000).toFixed(2)}µs | p95: ${(fwStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / fwStats.mean).toLocaleString()} checks/sec`);
    console.log(`  • Dashboard Multi-Table Aggregation           : Mean: ${(aggStats.mean * 1000).toFixed(2)}µs | p95: ${(aggStats.p95 * 1000).toFixed(2)}µs | Throughput: ${Math.round(1000 / aggStats.mean).toLocaleString()} aggregations/sec\n`);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // BENCHMARK 8: MEMORY FOOTPRINT & HEAP PROFILING UNDER SUSTAINED LOAD
  // ──────────────────────────────────────────────────────────────────────────
  console.log('━━━ 8. Memory Footprint & Heap Profiling Under Sustained Load ━━━');
  {
    if (global.gc) { global.gc(); }
    const initialMem = process.memoryUsage();

    // Ingest 50,000 events to observe heap delta
    for (let i = 0; i < 50000; i++) {
      normalizeEvent({
        event_type: 'process_execution',
        source_ip: '10.2.1.5',
        device_id: `dev-${i % 100}`,
        process: { name: 'curl.exe', command_line: 'curl -s https://test.com' },
      });
    }

    const peakMem = process.memoryUsage();
    if (global.gc) { global.gc(); }
    const postGcMem = process.memoryUsage();

    const heapDeltaMB = ((peakMem.heapUsed - initialMem.heapUsed) / (1024 * 1024)).toFixed(2);
    const postGcDeltaMB = ((postGcMem.heapUsed - initialMem.heapUsed) / (1024 * 1024)).toFixed(2);

    report.benchmarks.memoryProfiling = {
      initialHeapUsedMB: (initialMem.heapUsed / (1024 * 1024)).toFixed(2),
      peakHeapUsedMB: (peakMem.heapUsed / (1024 * 1024)).toFixed(2),
      postGcHeapUsedMB: (postGcMem.heapUsed / (1024 * 1024)).toFixed(2),
      heapDeltaMB,
      postGcDeltaMB,
      rssMB: (peakMem.rss / (1024 * 1024)).toFixed(2),
    };

    console.log(`  • Initial Heap Used : ${report.benchmarks.memoryProfiling.initialHeapUsedMB} MB`);
    console.log(`  • Peak Heap Used    : ${report.benchmarks.memoryProfiling.peakHeapUsedMB} MB (+${heapDeltaMB} MB for 50,000 events)`);
    console.log(`  • Post-GC Heap Used : ${report.benchmarks.memoryProfiling.postGcHeapUsedMB} MB (retained delta: ${postGcDeltaMB} MB)`);
    console.log(`  • Resident Set (RSS): ${report.benchmarks.memoryProfiling.rssMB} MB\n`);
  }

  // Gracefully close live HTTP benchmark server
  await new Promise((resolve) => testServer.close(resolve));

  console.log('======================================================================');
  console.log('🏁  BENCHMARK EXECUTION COMPLETED SUCCESSFULLY');
  console.log('======================================================================');

  return report;
}

if (require.main === module) {
  runBenchmark().then((report) => {
    // Write machine-readable benchmark results
    const outPath = path.join(__dirname, '../backend/benchmark_results.json');
    try {
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2), 'utf8');
      console.log(`\n📄 Benchmark results saved to ${outPath}`);
    } catch (_) {}
    process.exit(0);
  }).catch((err) => {
    console.error('Benchmark error:', err);
    process.exit(1);
  });
}

module.exports = { runBenchmark };
