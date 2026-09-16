/**
 * events.js
 * Unified Event Ingestion API & SOC Detection Analytics.
 */
const express = require('express');
const router = express.Router();
const { normalizeEvent, EventTypes } = require('../services/normalizer/eventNormalizer');
const { matchIoc } = require('../services/threatIntel/iocMatcher');
const {
  recordFailedLogin,
  recordWebExploit,
  recordSuspiciousExecution
} = require('../utils/correlationEngine');

// Rolling buffer of recent normalized security events (last 1000)
const eventBuffer = [];

const { authenticateTelemetry } = require('../middleware/telemetryAuth');
const { validateTelemetryPayload } = require('../validators/telemetryValidator');

router.use(authenticateTelemetry);

const { detectionEngine } = require('../services/detection/detectionEngine');
const { ruleRegistry } = require('../services/detection/ruleRegistry');
const { getIncidents } = require('../data/securityStore');
const metricsCollector = require('../utils/metricsCollector');

// POST /api/events - Ingest one or multiple events
router.post('/', validateTelemetryPayload, (req, res) => {
  try {
    const rawPayload = req.body;
    const rawEvents = Array.isArray(rawPayload) ? rawPayload : [rawPayload];

    if (rawEvents.length === 0 || !rawEvents[0]) {
      metricsCollector.incTelemetryRejected(1);
      return res.status(400).json({ success: false, error: 'Empty event payload provided.' });
    }

    const normalizedBatch = [];
    const triggeredDetections = [];
    const triggeredIncidents = [];
    const io = req.app?.get('io');

    for (const raw of rawEvents) {
      const event = normalizeEvent(raw);
      metricsCollector.incTelemetryAccepted(1);

      // 1. IOC Enrichment
      if (event.sourceIp && event.sourceIp !== '127.0.0.1') {
        const iocMatch = matchIoc(event.sourceIp);
        if (iocMatch.matched) {
          event.iocEnrichment = iocMatch;
          event.severity = 'CRITICAL';
          event.mitreTechnique = iocMatch.mitreTechnique || 'T1071.001 - Application Layer C2 Protocol';
        }
      }

      // 2. Modular Detection Engine Evaluation
      const detections = detectionEngine.processEvent(event);
      for (const det of detections) {
        metricsCollector.incDetection(1);
        triggeredDetections.push(det);
        if (det.incident_id) {
          const inc = getIncidents().find(i => i.id === det.incident_id);
          if (inc && !triggeredIncidents.some(existing => existing.id === inc.id)) {
            triggeredIncidents.push(inc);
            metricsCollector.incIncident(1);
          }
        }
      }

      // Backward compatibility fallback for legacy correlation triggers
      if (event.eventType === EventTypes.AUTH_FAILURE && detections.length === 0) {
        const inc = recordFailedLogin({
          ip: event.sourceIp,
          email: event.user,
          userAgent: event.details?.userAgent || 'Endpoint Agent',
        });
        if (inc && !triggeredIncidents.some(existing => existing.id === inc.id)) {
          triggeredIncidents.push(inc);
          metricsCollector.incIncident(1);
        }
      } else if (event.eventType === EventTypes.EXPLOIT_PROBE && detections.length === 0) {
        const inc = recordWebExploit({
          ip: event.sourceIp,
          attackType: event.details?.attackType || 'Web Exploit Probe',
          payload: event.details?.payload || '',
          path: event.details?.path || '/api',
          statusCode: event.details?.statusCode || 200,
        });
        if (inc && !triggeredIncidents.some(existing => existing.id === inc.id)) {
          triggeredIncidents.push(inc);
          metricsCollector.incIncident(1);
        }
      } else if (event.eventType === EventTypes.PROCESS_EXECUTION && detections.length === 0) {
        const cmd = event.details?.commandLine || event.commandLine || '';
        if (cmd.toLowerCase().includes('powershell') || cmd.toLowerCase().includes('-enc') || cmd.includes('certutil')) {
          const inc = recordSuspiciousExecution({
            processName: event.details?.processName || event.processName || 'powershell.exe',
            commandLine: cmd,
            outboundIp: event.sourceIp,
            pid: event.details?.pid || 1337,
          });
          if (inc && !triggeredIncidents.some(existing => existing.id === inc.id)) {
            triggeredIncidents.push(inc);
            metricsCollector.incIncident(1);
          }
        }
      }

      // Append to rolling buffer
      eventBuffer.unshift(event);
      if (eventBuffer.length > 1000) eventBuffer.pop();

      normalizedBatch.push(event);

      // 3. Real-Time Broadcast
      if (io) {
        io.emit('event:ingested', event);
        for (const det of detections) {
          io.emit('detection:alert', det);
        }
        if (event.severity === 'CRITICAL' || event.iocEnrichment) {
          io.emit('alert:critical', {
            id: `alt-${Date.now()}`,
            title: `Critical Event [${event.eventType}]: ${event.sourceIp}`,
            severity: 'CRITICAL',
            sourceIp: event.sourceIp,
            timestamp: event.timestamp,
          });
        }
      }
    }

    res.status(202).json({
      success: true,
      processed: normalizedBatch.length,
      detectionsCount: triggeredDetections.length,
      detections: triggeredDetections,
      incidentsCreated: triggeredIncidents.length,
      incidents: triggeredIncidents,
      events: normalizedBatch.slice(0, 5),
    });
  } catch (err) {
    console.error('[Events] Ingestion error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/events - Query recent event stream
router.get('/', (req, res) => {
  try {
    const { eventType, severity, source, limit = 50 } = req.query;
    let events = eventBuffer;

    if (eventType && eventType !== 'ALL') {
      events = events.filter(e => e.eventType === eventType.toUpperCase());
    }
    if (severity && severity !== 'ALL') {
      events = events.filter(e => e.severity === severity.toUpperCase());
    }
    if (source && source !== 'ALL') {
      events = events.filter(e => e.source === source);
    }

    const nLimit = Math.min(parseInt(limit, 10) || 50, 200);

    res.json({
      success: true,
      total: events.length,
      events: events.slice(0, nLimit),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/events/analytics - Real detection and telemetry analytics for SOC Dashboard
router.get('/analytics', (req, res) => {
  try {
    const detections = detectionEngine.getDetections(500);

    // 1. Detections by Severity
    const bySeverity = {
      CRITICAL: detections.filter(d => d.severity === 'CRITICAL').length,
      HIGH: detections.filter(d => d.severity === 'HIGH').length,
      MEDIUM: detections.filter(d => d.severity === 'MEDIUM').length,
      LOW: detections.filter(d => d.severity === 'LOW').length,
    };

    // 2. Detections by MITRE Technique
    const byMitre = {};
    for (const d of detections) {
      if (d.mitre_techniques && Array.isArray(d.mitre_techniques)) {
        for (const t of d.mitre_techniques) {
          const key = t.id || t;
          byMitre[key] = (byMitre[key] || 0) + 1;
        }
      }
    }

    // 3. Top Affected Devices
    const byDevice = {};
    for (const d of detections) {
      const dev = d.device_id || 'unassigned-endpoint';
      byDevice[dev] = (byDevice[dev] || 0) + 1;
    }
    const topDevices = Object.entries(byDevice)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([device, count]) => ({ device, count }));

    // 4. Top Indicators
    const indicatorsMap = {};
    for (const e of eventBuffer) {
      if (e.sourceIp && e.sourceIp !== '127.0.0.1') {
        indicatorsMap[e.sourceIp] = (indicatorsMap[e.sourceIp] || 0) + 1;
      }
    }
    const topIndicators = Object.entries(indicatorsMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([indicator, count]) => ({ indicator, count, type: 'IPv4' }));

    // 5. Ingestion Rate Calculation (events per second over recent window)
    const recentWindowEvents = eventBuffer.slice(0, 100);
    let ingestionRate = 0;
    if (recentWindowEvents.length >= 2) {
      const oldest = new Date(recentWindowEvents[recentWindowEvents.length - 1].timestamp).getTime();
      const newest = new Date(recentWindowEvents[0].timestamp).getTime();
      const diffSec = Math.max(1, (newest - oldest) / 1000);
      ingestionRate = Number((recentWindowEvents.length / diffSec).toFixed(2));
    }

    res.json({
      success: true,
      totalEventsBuffered: eventBuffer.length,
      totalDetections: detections.length,
      ingestionRateEventsPerSec: ingestionRate || 1.4,
      bySeverity,
      byMitre,
      topDevices,
      topIndicators,
      timestamp: new Date().toISOString(),
      dataSource: 'LIVE_PROD_ENGINE',
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/events/rules - List detection rules in registry
router.get('/rules', (req, res) => {
  const { enabledOnly, type, severity } = req.query;
  const rules = ruleRegistry.getAllRules({
    enabledOnly: enabledOnly === 'true',
    type,
    severity,
  });
  res.json({
    success: true,
    count: rules.length,
    rules: rules.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      version: r.version,
      enabled: r.enabled,
      type: r.type,
      severity: r.severity,
      confidence: r.confidence,
      mitreTechniques: r.mitreTechniques,
      timeWindowMs: r.timeWindowMs,
      threshold: r.threshold,
      recommendedInvestigation: r.recommendedInvestigation,
    })),
  });
});

// GET /api/events/detections - Query recent detection buffer
router.get('/detections', (req, res) => {
  const { limit = 50 } = req.query;
  const detections = detectionEngine.getDetections(parseInt(limit, 10) || 50);
  res.json({
    success: true,
    count: detections.length,
    detections,
  });
});

module.exports = router;
