/**
 * detectionEngine.js
 * Modular Cybersecurity Detection & SIEM Event Correlation Engine.
 * 
 * Pipeline Architecture:
 * 1. Raw Telemetry Parsing (eventNormalizer)
 * 2. Canonical Normalization (eventSchema)
 * 3. Rule Evaluation & State Correlation (ruleRegistry & detectionEngine)
 * 4. Standardized Detection Generation (with Evidence & MITRE Mapping)
 * 5. Incident Escalation & Automated Alert Dispatch (securityStore & Socket.IO)
 */

const crypto = require('crypto');
const EventEmitter = require('events');
const { ruleRegistry, RuleTypes } = require('./ruleRegistry');
const { createIncident, getIncidents } = require('../../data/securityStore');

class DetectionEngine extends EventEmitter {
  constructor() {
    super();
    // Sliding window states:
    // thresholdState: Map<"ruleId:groupKey", [{ timestamp, event }]>
    this.thresholdState = new Map();
    // sequenceState: Map<"ruleId:groupKey", { currentStage: number, events: [{ stage, timestamp, event }], startedAt: number }>
    this.sequenceState = new Map();
    // correlationState: Map<"ruleId:groupKey", { state: Object, events: [{ timestamp, event }], startedAt: number }>
    this.correlationState = new Map();

    // Detections buffer (last 500)
    this.detectionsBuffer = [];
  }

  /**
   * Helper: Extracts grouping key from an event based on rule groupBy fields.
   */
  _extractGroupKey(event, groupByFields) {
    if (!groupByFields || groupByFields.length === 0) {
      return event.device_id || event.deviceId || 'global';
    }

    const keyParts = [];
    for (const field of groupByFields) {
      if (field === 'network.source_ip') {
        keyParts.push(event.network?.source_ip || event.sourceIp || '127.0.0.1');
      } else if (field === 'device_id') {
        keyParts.push(event.device_id || event.deviceId || 'unknown-device');
      } else if (field === 'user.name') {
        keyParts.push(event.user?.name || event.user || event.username || 'unknown-user');
      } else if (field.includes('.')) {
        const parts = field.split('.');
        let val = event;
        for (const p of parts) {
          val = val ? val[p] : undefined;
        }
        keyParts.push(val !== undefined ? String(val) : 'null');
      } else {
        keyParts.push(event[field] !== undefined ? String(event[field]) : 'null');
      }
    }

    return keyParts.join(':');
  }

  /**
   * Main Pipeline Ingestion & Evaluation Method.
   * Processes a normalized canonical event through all active detection rules.
   * 
   * @param {Object} event - Canonical normalized event.
   * @returns {Array<Object>} List of triggered detections for this event.
   */
  processEvent(event) {
    if (!event || typeof event !== 'object') return [];

    const now = Date.now();
    const triggeredDetections = [];
    const activeRules = ruleRegistry.getAllRules({ enabledOnly: true });

    for (const rule of activeRules) {
      try {
        let detection = null;

        // ── 1. SINGLE-EVENT RULES ──────────────────────────────────────────
        if (rule.type === RuleTypes.SINGLE_EVENT) {
          if (rule.match(event)) {
            detection = this._createDetectionObject({
              rule,
              primaryEvent: event,
              relatedEvents: [event],
              evidence: {
                triggeringEventId: event.event_id || event.eventId,
                eventType: event.event_type || event.eventType,
                deviceId: event.device_id || event.deviceId,
                sourceIp: event.network?.source_ip || event.sourceIp,
                processName: event.process?.name || event.processName,
                commandLine: event.process?.command_line || event.commandLine,
                user: event.user?.name || event.user,
                matchedAt: new Date(now).toISOString(),
              },
            });
          }
        }

        // ── 2. THRESHOLD RULES (COUNT OVER SLIDING TIME WINDOW) ───────────
        else if (rule.type === RuleTypes.THRESHOLD) {
          if (rule.match(event)) {
            const groupKey = this._extractGroupKey(event, rule.groupBy);
            const stateKey = `${rule.id}:${groupKey}`;

            let history = this.thresholdState.get(stateKey) || [];
            // Prune expired events outside rule time window
            history = history.filter(item => (now - item.timestamp) <= rule.timeWindowMs);
            history.push({ timestamp: now, event });
            this.thresholdState.set(stateKey, history);

            if (history.length >= rule.threshold) {
              const matchedEvents = history.map(h => h.event);
              detection = this._createDetectionObject({
                rule,
                primaryEvent: event,
                relatedEvents: matchedEvents,
                evidence: {
                  groupKey,
                  eventCount: history.length,
                  threshold: rule.threshold,
                  timeWindowSeconds: Math.round(rule.timeWindowMs / 1000),
                  firstSeen: new Date(history[0].timestamp).toISOString(),
                  lastSeen: new Date(now).toISOString(),
                  sourceIp: event.network?.source_ip || event.sourceIp,
                  targetUser: event.user?.name || event.user,
                },
              });

              // Reset threshold window after detection firing
              this.thresholdState.delete(stateKey);
            }
          }
        }

        // ── 3. SEQUENCE RULES (ORDERED ATTACK CHAIN STATE MACHINE) ────────
        else if (rule.type === RuleTypes.SEQUENCE) {
          if (Array.isArray(rule.sequence) && rule.sequence.length > 0) {
            const groupKey = this._extractGroupKey(event, rule.groupBy);
            const stateKey = `${rule.id}:${groupKey}`;

            let seqState = this.sequenceState.get(stateKey);
            // Prune expired sequence
            if (seqState && (now - seqState.startedAt) > rule.timeWindowMs) {
              this.sequenceState.delete(stateKey);
              seqState = null;
            }

            const currentStageIndex = seqState ? seqState.currentStage : 0;
            const targetStage = rule.sequence[currentStageIndex];

            if (targetStage && targetStage.match(event)) {
              if (!seqState) {
                seqState = {
                  currentStage: 1,
                  events: [{ stage: targetStage.name || `Stage 1`, timestamp: now, event }],
                  startedAt: now,
                };
                this.sequenceState.set(stateKey, seqState);
              } else {
                seqState.currentStage++;
                seqState.events.push({
                  stage: targetStage.name || `Stage ${seqState.currentStage}`,
                  timestamp: now,
                  event,
                });
              }

              // Check if entire sequence completed
              if (seqState.currentStage >= rule.sequence.length) {
                const matchedEvents = seqState.events.map(s => s.event);
                detection = this._createDetectionObject({
                  rule,
                  primaryEvent: event,
                  relatedEvents: matchedEvents,
                  evidence: {
                    groupKey,
                    sequenceStagesCompleted: seqState.events.map(s => ({
                      stage: s.stage,
                      timestamp: new Date(s.timestamp).toISOString(),
                      eventType: s.event.event_type || s.event.eventType,
                    })),
                    totalDurationSeconds: Math.round((now - seqState.startedAt) / 1000),
                  },
                });

                // Reset sequence after completion
                this.sequenceState.delete(stateKey);
              }
            }
          }
        }

        // ── 4. CORRELATION RULES (CROSS-SOURCE / MULTI-ENTITY MATCH) ──────
        else if (rule.type === RuleTypes.CORRELATION) {
          const groupKey = this._extractGroupKey(event, rule.groupBy);
          const stateKey = `${rule.id}:${groupKey}`;

          let corrState = this.correlationState.get(stateKey);
          if (corrState && (now - corrState.startedAt) > rule.timeWindowMs) {
            this.correlationState.delete(stateKey);
            corrState = null;
          }

          if (!corrState) {
            corrState = { state: {}, events: [], startedAt: now };
          }

          corrState.events.push({ timestamp: now, event });

          const isMatch = rule.match(event, corrState.state);
          if (isMatch) {
            const matchedEvents = corrState.events.map(e => e.event);
            detection = this._createDetectionObject({
              rule,
              primaryEvent: event,
              relatedEvents: matchedEvents,
              evidence: {
                groupKey,
                correlatedState: corrState.state,
                correlatedEventsCount: matchedEvents.length,
                timeWindowSeconds: Math.round(rule.timeWindowMs / 1000),
              },
            });

            this.correlationState.delete(stateKey);
          } else {
            this.correlationState.set(stateKey, corrState);
          }
        }

        // ── Escalate Detection to Incident & Emit ──────────────────────────
        if (detection) {
          this._escalateDetection(detection);
          triggeredDetections.push(detection);
          this.detectionsBuffer.unshift(detection);
          if (this.detectionsBuffer.length > 500) this.detectionsBuffer.pop();
          this.emit('detection', detection);
        }
      } catch (err) {
        console.error(`[DetectionEngine] Error evaluating rule '${rule.id}':`, err.message);
      }
    }

    return triggeredDetections;
  }

  /**
   * Constructs a standardized Detection output object.
   */
  _createDetectionObject({ rule, primaryEvent, relatedEvents, evidence }) {
    const detectionId = `det-${crypto.randomUUID()}`;
    const deviceId = primaryEvent.device_id || primaryEvent.deviceId || 'DEV-LOCAL-NODE';
    const sourceIp = primaryEvent.network?.source_ip || primaryEvent.sourceIp || '127.0.0.1';

    return {
      detection_id: detectionId,
      rule_id: rule.id,
      rule_name: rule.name,
      rule_version: rule.version,
      severity: rule.severity,
      confidence: rule.confidence,
      event_type: primaryEvent.event_type || primaryEvent.eventType,
      device_id: deviceId,
      source_ip: sourceIp,
      mitre_techniques: rule.mitreTechniques,
      detected_at: new Date().toISOString(),
      evidence,
      related_events: relatedEvents.map(e => ({
        event_id: e.event_id || e.eventId,
        timestamp: e.timestamp || e.observedAt,
        event_type: e.event_type || e.eventType,
        summary: e.process?.command_line || e.commandLine || `${e.event_type || e.eventType} on ${e.device_id || e.deviceId}`,
      })),
      recommended_investigation: rule.recommendedInvestigation,
      incident_id: null, // Populated on escalation
    };
  }

  /**
   * Escalates high-confidence / high-severity detections to SecurityStore Incidents.
   */
  _escalateDetection(detection) {
    try {
      const existing = getIncidents().find(
        i => i.ruleId === detection.rule_id &&
             i.relatedIps.includes(detection.source_ip) &&
             !['CLOSED', 'FALSE_POSITIVE'].includes(i.status)
      );

      if (existing) {
        detection.incident_id = existing.id;
        return;
      }

      const incident = createIncident({
        title: `${detection.rule_name} [${detection.device_id}]`,
        severity: detection.severity,
        category: detection.event_type || 'SECURITY_DETECTION',
        description: `Triggered by detection rule '${detection.rule_id}' (v${detection.rule_version}) with ${detection.confidence}% confidence.`,
        relatedIps: detection.source_ip !== '127.0.0.1' ? [detection.source_ip] : [],
        relatedAlerts: [`Detection ${detection.detection_id}: ${detection.rule_name}`],
        mitreTechniques: detection.mitre_techniques,
        evidence: {
          detectionId: detection.detection_id,
          ruleId: detection.rule_id,
          confidence: detection.confidence,
          ...detection.evidence,
          recommendedInvestigation: detection.recommended_investigation,
        },
        createdBy: `Detection Engine [${detection.rule_id}]`,
      });

      if (incident) {
        incident.ruleId = detection.rule_id;
        detection.incident_id = incident.id;
        this.emit('incident', incident);
      }
    } catch (err) {
      console.error('[DetectionEngine] Incident escalation error:', err.message);
    }
  }

  /**
   * Returns list of recent detections.
   */
  getDetections(limit = 50) {
    return this.detectionsBuffer.slice(0, limit);
  }

  /**
   * Resets all sliding correlation windows (useful for unit testing isolation).
   */
  resetState() {
    this.thresholdState.clear();
    this.sequenceState.clear();
    this.correlationState.clear();
    this.detectionsBuffer = [];
  }
}

const detectionEngine = new DetectionEngine();

module.exports = {
  detectionEngine,
  DetectionEngine,
};
