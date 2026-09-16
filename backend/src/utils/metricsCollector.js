/**
 * metricsCollector.js
 * Production Metrics Registry for Prometheus Exposition and SOC Telemetry.
 */

'use strict';

class MetricsCollector {
  constructor() {
    this.counters = {
      http_requests_total: 0,
      auth_failures_total: 0,
      telemetry_accepted_total: 0,
      telemetry_rejected_total: 0,
      detections_total: 0,
      incidents_total: 0,
      malware_analyses_total: 0,
      response_actions_total: 0,
      database_errors_total: 0,
    };

    this.requestsByStatus = {
      '2xx': 0,
      '3xx': 0,
      '4xx': 0,
      '5xx': 0,
    };

    this.latencyBuckets = {
      p50: 0,
      p95: 0,
      p99: 0,
      totalLatencyMs: 0,
      samples: [],
    };
  }

  recordRequest(method, path, status, latencyMs) {
    this.counters.http_requests_total++;

    const statusGroup = `${Math.floor(status / 100)}xx`;
    if (this.requestsByStatus[statusGroup] !== undefined) {
      this.requestsByStatus[statusGroup]++;
    }

    this.latencyBuckets.totalLatencyMs += latencyMs;
    this.latencyBuckets.samples.push(latencyMs);

    // Keep rolling window of last 1000 samples for percentile calculations
    if (this.latencyBuckets.samples.length > 1000) {
      this.latencyBuckets.samples.shift();
    }
  }

  incAuthFailure() {
    this.counters.auth_failures_total++;
  }

  incTelemetryAccepted(count = 1) {
    this.counters.telemetry_accepted_total += count;
  }

  incTelemetryRejected(count = 1) {
    this.counters.telemetry_rejected_total += count;
  }

  incDetection(count = 1) {
    this.counters.detections_total += count;
  }

  incIncident(count = 1) {
    this.counters.incidents_total += count;
  }

  incMalwareAnalysis(count = 1) {
    this.counters.malware_analyses_total += count;
  }

  incResponseAction(count = 1) {
    this.counters.response_actions_total += count;
  }

  incDatabaseError(count = 1) {
    this.counters.database_errors_total += count;
  }

  getCalculatedLatencies() {
    if (this.latencyBuckets.samples.length === 0) {
      return { avgMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0 };
    }

    const sorted = [...this.latencyBuckets.samples].sort((a, b) => a - b);
    const count = sorted.length;
    const avg = this.latencyBuckets.totalLatencyMs / (this.counters.http_requests_total || 1);

    const p50 = sorted[Math.floor(count * 0.50)] || 0;
    const p95 = sorted[Math.floor(count * 0.95)] || 0;
    const p99 = sorted[Math.floor(count * 0.99)] || 0;

    return {
      avgMs: Number(avg.toFixed(2)),
      p50Ms: p50,
      p95Ms: p95,
      p99Ms: p99,
    };
  }

  getPrometheusFormat() {
    const mem = process.memoryUsage();
    const latencies = this.getCalculatedLatencies();

    return [
      '# HELP cs_uptime_seconds Total process uptime in seconds',
      '# TYPE cs_uptime_seconds gauge',
      `cs_uptime_seconds ${process.uptime().toFixed(2)}`,

      '# HELP cs_http_requests_total Total number of HTTP requests processed',
      '# TYPE cs_http_requests_total counter',
      `cs_http_requests_total ${this.counters.http_requests_total}`,

      '# HELP cs_http_requests_status_total HTTP requests partitioned by status code class',
      '# TYPE cs_http_requests_status_total counter',
      `cs_http_requests_status_total{status="2xx"} ${this.requestsByStatus['2xx']}`,
      `cs_http_requests_status_total{status="3xx"} ${this.requestsByStatus['3xx']}`,
      `cs_http_requests_status_total{status="4xx"} ${this.requestsByStatus['4xx']}`,
      `cs_http_requests_status_total{status="5xx"} ${this.requestsByStatus['5xx']}`,

      '# HELP cs_http_latency_ms HTTP request latency metrics',
      '# TYPE cs_http_latency_ms gauge',
      `cs_http_latency_ms{percentile="p50"} ${latencies.p50Ms}`,
      `cs_http_latency_ms{percentile="p95"} ${latencies.p95Ms}`,
      `cs_http_latency_ms{percentile="p99"} ${latencies.p99Ms}`,

      '# HELP cs_auth_failures_total Total failed authentication attempts',
      '# TYPE cs_auth_failures_total counter',
      `cs_auth_failures_total ${this.counters.auth_failures_total}`,

      '# HELP cs_telemetry_accepted_total Total ingested normalized endpoint telemetry events',
      '# TYPE cs_telemetry_accepted_total counter',
      `cs_telemetry_accepted_total ${this.counters.telemetry_accepted_total}`,

      '# HELP cs_telemetry_rejected_total Total rejected or malformed telemetry events',
      '# TYPE cs_telemetry_rejected_total counter',
      `cs_telemetry_rejected_total ${this.counters.telemetry_rejected_total}`,

      '# HELP cs_detections_total Total detections triggered by detection engine',
      '# TYPE cs_detections_total counter',
      `cs_detections_total ${this.counters.detections_total}`,

      '# HELP cs_incidents_total Total security incidents generated',
      '# TYPE cs_incidents_total counter',
      `cs_incidents_total ${this.counters.incidents_total}`,

      '# HELP cs_malware_analyses_total Total static malware analysis jobs executed',
      '# TYPE cs_malware_analyses_total counter',
      `cs_malware_analyses_total ${this.counters.malware_analyses_total}`,

      '# HELP cs_response_actions_total Total response actions triggered',
      '# TYPE cs_response_actions_total counter',
      `cs_response_actions_total ${this.counters.response_actions_total}`,

      '# HELP cs_database_errors_total Total database query or connection errors',
      '# TYPE cs_database_errors_total counter',
      `cs_database_errors_total ${this.counters.database_errors_total}`,

      '# HELP cs_memory_heap_used_bytes V8 heap memory used in bytes',
      '# TYPE cs_memory_heap_used_bytes gauge',
      `cs_memory_heap_used_bytes ${mem.heapUsed}`,
    ].join('\n');
  }

  getJsonSnapshot() {
    return {
      timestamp: new Date().toISOString(),
      uptimeSeconds: Number(process.uptime().toFixed(2)),
      counters: this.counters,
      statusCodes: this.requestsByStatus,
      latency: this.getCalculatedLatencies(),
      memory: process.memoryUsage(),
    };
  }
}

const metricsCollector = new MetricsCollector();

module.exports = metricsCollector;
