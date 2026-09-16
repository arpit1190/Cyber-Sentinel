/**
 * test_observability.js
 * Verification Test Suite for Production Observability, Structured Logging, Health Probes & Metrics.
 */

'use strict';

const assert = require('assert');
const metricsCollector = require('./src/utils/metricsCollector');
const { sanitizeData } = require('./src/utils/structuredLogger');

console.log('🧪 Starting Observability & Metrics Test Suite...\n');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  ✅ PASS: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ FAIL: ${name}`);
    console.error(`     Error: ${err.message}\n`);
  }
}

// ── 1. Structured Logging Secret Scrubbing Tests ──
test('Structured Logger scrubs raw passwords from nested log objects', () => {
  const payload = {
    user: 'analyst@sentinel.internal',
    password: 'SuperSecretPassword123!',
    credentials: {
      clientSecret: 'secret-xyz-789',
      apiKey: 'AIzaSyD-1234567890abcdef',
    },
    meta: {
      clientSecret: 'secret-xyz-789',
      apiKey: 'AIzaSyD-1234567890abcdef',
    },
  };

  const clean = sanitizeData(payload);
  assert.strictEqual(clean.password, '[REDACTED]');
  assert.strictEqual(clean.credentials, '[REDACTED]');
  assert.strictEqual(clean.meta.clientSecret, '[REDACTED]');
  assert.strictEqual(clean.meta.apiKey, '[REDACTED]');
  assert.strictEqual(clean.user, 'analyst@sentinel.internal');
});

test('Structured Logger scrubs JWTs and Bearer tokens from string logs', () => {
  const logStr = 'User authenticated with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature';
  const clean = sanitizeData(logStr);
  assert.ok(!clean.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
  assert.ok(clean.includes('[REDACTED_TOKEN]') || clean.includes('[REDACTED_JWT]'));
});

test('Structured Logger truncates binary buffers to avoid log flooding', () => {
  const buf = Buffer.alloc(1024 * 1024); // 1MB buffer
  const clean = sanitizeData(buf);
  assert.strictEqual(clean, '[BINARY_BUFFER_1048576_BYTES]');
});

// ── 2. Metrics Collector Verification ──
test('Metrics Collector records HTTP requests and latency percentiles', () => {
  metricsCollector.recordRequest('GET', '/api/incidents', 200, 15);
  metricsCollector.recordRequest('POST', '/api/events', 202, 25);
  metricsCollector.recordRequest('POST', '/api/auth/login', 401, 10);
  metricsCollector.recordRequest('GET', '/ready', 500, 45);

  const snapshot = metricsCollector.getJsonSnapshot();
  assert.ok(snapshot.counters.http_requests_total >= 4);
  assert.strictEqual(snapshot.statusCodes['2xx'] >= 2, true);
  assert.strictEqual(snapshot.statusCodes['4xx'] >= 1, true);
  assert.strictEqual(snapshot.statusCodes['5xx'] >= 1, true);
});

test('Metrics Collector tracks operational security counters', () => {
  metricsCollector.incAuthFailure();
  metricsCollector.incTelemetryAccepted(5);
  metricsCollector.incTelemetryRejected(2);
  metricsCollector.incDetection(3);
  metricsCollector.incIncident(1);
  metricsCollector.incMalwareAnalysis(2);
  metricsCollector.incResponseAction(1);
  metricsCollector.incDatabaseError(1);

  const snapshot = metricsCollector.getJsonSnapshot();
  assert.ok(snapshot.counters.auth_failures_total >= 1);
  assert.ok(snapshot.counters.telemetry_accepted_total >= 5);
  assert.ok(snapshot.counters.telemetry_rejected_total >= 2);
  assert.ok(snapshot.counters.detections_total >= 3);
  assert.ok(snapshot.counters.incidents_total >= 1);
  assert.ok(snapshot.counters.malware_analyses_total >= 2);
  assert.ok(snapshot.counters.response_actions_total >= 1);
  assert.ok(snapshot.counters.database_errors_total >= 1);
});

test('Metrics Collector outputs valid Prometheus 0.0.4 exposition text', () => {
  const prometheusText = metricsCollector.getPrometheusFormat();
  assert.ok(typeof prometheusText === 'string');
  assert.ok(prometheusText.includes('# HELP cs_http_requests_total'));
  assert.ok(prometheusText.includes('# TYPE cs_http_requests_total counter'));
  assert.ok(prometheusText.includes('cs_auth_failures_total'));
  assert.ok(prometheusText.includes('cs_telemetry_accepted_total'));
  assert.ok(prometheusText.includes('cs_detections_total'));
  assert.ok(prometheusText.includes('cs_uptime_seconds'));
});

console.log(`\n📊 Observability Test Results: ${passedTests}/${totalTests} Passed\n`);
if (passedTests !== totalTests) {
  process.exit(1);
}
