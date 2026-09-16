/**
 * test_immutable_timeline.js
 * Comprehensive Verification Suite for Cyber Sentinel Immutable Incident Timeline.
 * 
 * Verifies:
 * 1. End-to-end event capturing across the complete SOC lifecycle:
 *    Telemetry -> Detection -> Creation -> Assignment -> Investigation -> AI Recommendation -> Analyst Approval -> Response -> Resolution
 * 2. Mandatory field validation (timestamp, eventType, actor, source, description, relatedEvent, relatedDetection, relatedResponseAction, hash chain)
 * 3. Cryptographic SHA-256 Hash Chaining & Genesis hash pointers
 * 4. Forensic Tamper Detection (detects any modified, inserted, or deleted historical events)
 * 5. In-Memory Deep Freezing & Immutability guarantees
 * 6. Multi-criteria Pagination, Filtering, and Sorting on High-Volume Timelines
 * 7. Server-side Protection against Mutation / Deletion (rejection with 405 Method Not Allowed)
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const express = require('express');

const securityStore = require('./src/data/securityStore');
const securityRepository = require('./src/repositories/securityRepository');
const incidentService = require('./src/services/incidentService');
const incidentController = require('./src/controllers/incidentController');
const {
  TimelineEventType,
  createTimelineEvent,
  appendEventToTimeline,
  verifyTimelineIntegrity,
  paginateTimeline,
  calculateEventHash,
  GENESIS_PREV_HASH,
  deepFreeze,
} = require('./src/services/timelineService');

let totalTests = 0;
let passedTests = 0;

async function runTest(name, fn) {
  totalTests++;
  const t0 = process.hrtime.bigint();
  try {
    await fn();
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
    console.log(`  ✅ [PASS] (${elapsedMs.toFixed(2)}ms) ${name}`);
    passedTests++;
  } catch (err) {
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
    console.error(`  ❌ [FAIL] (${elapsedMs.toFixed(2)}ms) ${name}`);
    console.error(`     Error: ${err.message}`);
    if (err.stack) {
      console.error(err.stack.split('\n').slice(1, 4).join('\n'));
    }
  }
}

async function runSuite() {
  console.log('\n======================================================================');
  console.log('🛡️   CYBER SENTINEL — IMMUTABLE INCIDENT TIMELINE VERIFICATION SUITE');
  console.log('======================================================================\n');

  // Reset store to pristine state
  securityStore.flushState();

  // ── SECTION 1: Full SOC Lifecycle Timeline Capturing ────────────────────────
  console.log('━━━ SECTION 1: Full SOC Lifecycle Event Capturing ━━━');

  let incident = null;

  await runTest('[LIFECYCLE] Telemetry -> Detection -> Incident Creation (Genesis Chain)', () => {
    const rawTelemetry = {
      eventId: 'evt-endpoint-8821',
      deviceId: 'host-win11-corp-04',
      eventType: 'PROCESS_SPAWN',
      process: { name: 'powershell.exe', parent: 'winword.exe', pid: 4912 },
      timestamp: new Date().toISOString(),
    };

    const detectionData = {
      detectionId: 'det-macro-powershell-001',
      ruleId: 'RULE_OFFICE_SPAWNS_SHELL',
      severity: 'HIGH',
      mitreTechniques: ['T1059.001'],
    };

    incident = securityStore.createIncident({
      title: 'Macro Spawning PowerShell Process',
      severity: 'HIGH',
      category: 'EXECUTION',
      description: 'Word document spawned hidden powershell process with base64 payload.',
      relatedEvent: rawTelemetry,
      relatedDetection: detectionData,
      detections: [detectionData.ruleId],
      indicators: ['198.51.100.22'],
      affectedDevices: [rawTelemetry.deviceId],
      createdBy: 'DETECTION_ENGINE',
    });

    assert.ok(incident.id.startsWith('INC-'));
    assert.strictEqual(incident.timeline.length, 3);

    // Event 1: TELEMETRY_INGESTED
    const e1 = incident.timeline[0];
    assert.strictEqual(e1.sequence, 1);
    assert.strictEqual(e1.eventType, TimelineEventType.TELEMETRY_INGESTED);
    assert.strictEqual(e1.prevHash, GENESIS_PREV_HASH);
    assert.ok(e1.hash && e1.hash.length === 64);
    assert.deepStrictEqual(e1.relatedEvent, rawTelemetry);

    // Event 2: DETECTION_ALERT
    const e2 = incident.timeline[1];
    assert.strictEqual(e2.sequence, 2);
    assert.strictEqual(e2.eventType, TimelineEventType.DETECTION_ALERT);
    assert.strictEqual(e2.prevHash, e1.hash);
    assert.ok(e2.hash && e2.hash.length === 64);

    // Event 3: INCIDENT_CREATED
    const e3 = incident.timeline[2];
    assert.strictEqual(e3.sequence, 3);
    assert.strictEqual(e3.eventType, TimelineEventType.INCIDENT_CREATED);
    assert.strictEqual(e3.prevHash, e2.hash);
    assert.ok(e3.hash && e3.hash.length === 64);
  });

  await runTest('[LIFECYCLE] Analyst Assignment Event', () => {
    incident = securityStore.assignIncident(incident.id, 'analyst.chen@cyber-sentinel.local', 'lead.operator', 'Assigned for priority triage');
    const lastEvent = incident.timeline[incident.timeline.length - 1];
    assert.strictEqual(lastEvent.sequence, 4);
    assert.strictEqual(lastEvent.eventType, TimelineEventType.ANALYST_ASSIGNED);
    assert.strictEqual(lastEvent.prevHash, incident.timeline[2].hash);
    assert.strictEqual(lastEvent.metadata.newAssignee, 'analyst.chen@cyber-sentinel.local');
  });

  await runTest('[LIFECYCLE] Status Transition to INVESTIGATING (Investigation Started)', () => {
    // NEW -> TRIAGED -> INVESTIGATING
    incident = securityStore.updateIncidentStatus(incident.id, 'TRIAGED', 'analyst.chen');
    incident = securityStore.updateIncidentStatus(incident.id, 'INVESTIGATING', 'analyst.chen', 'Forensics underway');

    const invEvent = incident.timeline[incident.timeline.length - 1];
    assert.strictEqual(invEvent.sequence, 6);
    assert.strictEqual(invEvent.eventType, TimelineEventType.INVESTIGATION_STARTED);
    assert.strictEqual(invEvent.metadata.newStatus, 'INVESTIGATING');
  });

  await runTest('[LIFECYCLE] AI Recommendation & Analyst Approval Events', () => {
    // Append AI Recommendation
    const aiEvent = securityStore.appendTimelineEvent(incident.id, {
      eventType: TimelineEventType.AI_RECOMMENDATION,
      actor: 'AI_COPILOT',
      source: 'AI_AGENT_ENGINE',
      description: 'AI recommendation: Isolate device host-win11-corp-04 and block C2 IP 198.51.100.22',
      metadata: { recommendedActions: ['ISOLATE_HOST', 'BLOCK_IP'], confidence: 0.96 },
    });

    assert.strictEqual(aiEvent.sequence, 7);
    assert.strictEqual(aiEvent.eventType, TimelineEventType.AI_RECOMMENDATION);
    assert.strictEqual(aiEvent.actor, 'AI_COPILOT');

    // Append Analyst Approval
    const approvalEvent = securityStore.appendTimelineEvent(incident.id, {
      eventType: TimelineEventType.ANALYST_APPROVAL,
      actor: 'analyst.chen',
      source: 'SOC_PORTAL',
      description: 'Analyst approved host isolation action for host-win11-corp-04',
      metadata: { approvedAction: 'ISOLATE_HOST', target: 'host-win11-corp-04' },
    });

    assert.strictEqual(approvalEvent.sequence, 8);
    assert.strictEqual(approvalEvent.eventType, TimelineEventType.ANALYST_APPROVAL);
  });

  await runTest('[LIFECYCLE] Response Action Execution & Containment', () => {
    incident = securityStore.addResponseAction(incident.id, {
      actionType: 'ISOLATE_HOST',
      target: 'host-win11-corp-04',
      parameters: { mode: 'FULL_NETWORK_ISOLATION' },
      status: 'SUCCESS',
    }, 'analyst.chen');

    // Status to CONTAINMENT
    incident = securityStore.updateIncidentStatus(incident.id, 'CONTAINMENT', 'analyst.chen', 'Endpoint quarantined');

    const lastEvent = incident.timeline[incident.timeline.length - 1];
    assert.strictEqual(lastEvent.metadata.newStatus, 'CONTAINMENT');
  });

  await runTest('[LIFECYCLE] Eradication -> Recovery -> Resolution Chain', () => {
    incident = securityStore.updateIncidentStatus(incident.id, 'ERADICATION', 'analyst.chen', 'Malicious macro and scheduled task removed');
    incident = securityStore.updateIncidentStatus(incident.id, 'RECOVERY', 'analyst.chen', 'Endpoint verified clean, network unblocked');
    incident = securityStore.updateIncidentStatus(incident.id, 'RESOLVED', 'analyst.chen', 'Incident successfully resolved');

    const resolvedEvent = incident.timeline[incident.timeline.length - 1];
    assert.strictEqual(resolvedEvent.eventType, TimelineEventType.INCIDENT_RESOLVED);
    assert.strictEqual(incident.status, 'RESOLVED');
  });

  // ── SECTION 2: Cryptographic Hash Chaining & Integrity Verification ─────────
  console.log('\n━━━ SECTION 2: Cryptographic Hash Chaining & Tamper Detection ━━━');

  await runTest('[INTEGRITY] Untampered timeline validates 100% cryptographically sound', () => {
    const integrity = verifyTimelineIntegrity(incident.timeline);
    assert.strictEqual(integrity.valid, true);
    assert.strictEqual(integrity.count, incident.timeline.length);
    assert.ok(integrity.genesisHash);
    assert.ok(integrity.latestHash);
  });

  await runTest('[TAMPER-DETECT] Detects modification of historical event description', () => {
    // Clone mutable copy of timeline and tamper with event 2
    const tamperedTimeline = JSON.parse(JSON.stringify(incident.timeline));
    tamperedTimeline[1].description = 'Tampered description: no threat detected';

    const result = verifyTimelineIntegrity(tamperedTimeline);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.corruptedIndex, 1);
    assert.ok(result.error.includes('Cryptographic tamper detected'));
  });

  await runTest('[TAMPER-DETECT] Detects modification of historical actor/source', () => {
    const tamperedTimeline = JSON.parse(JSON.stringify(incident.timeline));
    tamperedTimeline[3].actor = 'malicious_impostor';

    const result = verifyTimelineIntegrity(tamperedTimeline);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.corruptedIndex, 3);
  });

  await runTest('[TAMPER-DETECT] Detects deletion of intermediate event in hash chain', () => {
    const tamperedTimeline = JSON.parse(JSON.stringify(incident.timeline));
    // Splice out event at index 2
    tamperedTimeline.splice(2, 1);

    const result = verifyTimelineIntegrity(tamperedTimeline);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error.includes('Broken cryptographic hash chain') || result.error.includes('Sequence discontinuity'));
  });

  await runTest('[TAMPER-DETECT] Detects insertion of unauthorized rogue event', () => {
    const tamperedTimeline = JSON.parse(JSON.stringify(incident.timeline));
    tamperedTimeline.splice(3, 0, {
      id: 'tle-rogue-999',
      sequence: 99,
      timestamp: new Date().toISOString(),
      eventType: 'ROGUE_BYPASS',
      actor: 'attacker',
      source: 'UNAUTHORIZED',
      description: 'Falsified timeline event',
      prevHash: 'fakehash',
      hash: 'fakehash2',
    });

    const result = verifyTimelineIntegrity(tamperedTimeline);
    assert.strictEqual(result.valid, false);
  });

  // ── SECTION 3: In-Memory Deep Immutability & Object Freezing ────────────────
  console.log('\n━━━ SECTION 3: Deep Object Immutability & Protection ━━━');

  await runTest('[IMMUTABILITY] Timeline event objects are deeply frozen against in-memory modification', () => {
    const event = incident.timeline[0];
    assert.ok(Object.isFrozen(event));

    // Modifying frozen object in strict mode throws TypeError
    assert.throws(() => {
      event.description = 'Hacked in memory';
    }, /Cannot assign to read only property|is not extensible/);

    assert.throws(() => {
      event.newField = 'injection';
    }, /Cannot add property|is not extensible/);
  });

  // ── SECTION 4: Pagination, Filtering & Sorting for High-Volume Timelines ───
  console.log('\n━━━ SECTION 4: Pagination, Filtering & Search ━━━');

  await runTest('[PAGINATION] Correctly paginates a 50+ event timeline', () => {
    // Generate incident with 60 distinct timeline events
    let bigTimeline = [];
    for (let i = 0; i < 60; i++) {
      bigTimeline = appendEventToTimeline(bigTimeline, {
        eventType: i % 2 === 0 ? TimelineEventType.TELEMETRY_INGESTED : TimelineEventType.STATUS_CHANGED,
        actor: i % 3 === 0 ? 'analyst.alpha' : 'system.daemon',
        source: 'SOC_ENGINE',
        description: `Synthetic bulk timeline event #${i + 1}`,
      });
    }

    assert.strictEqual(bigTimeline.length, 60);

    // Page 1 (limit 20)
    const p1 = paginateTimeline(bigTimeline, { page: 1, limit: 20, order: 'asc' });
    assert.strictEqual(p1.total, 60);
    assert.strictEqual(p1.totalPages, 3);
    assert.strictEqual(p1.events.length, 20);
    assert.strictEqual(p1.events[0].sequence, 1);
    assert.strictEqual(p1.events[19].sequence, 20);
    assert.strictEqual(p1.integrity.hashChainValid, true);

    // Page 3 (limit 20)
    const p3 = paginateTimeline(bigTimeline, { page: 3, limit: 20, order: 'asc' });
    assert.strictEqual(p3.events.length, 20);
    assert.strictEqual(p3.events[0].sequence, 41);
    assert.strictEqual(p3.events[19].sequence, 60);

    // Descending Order
    const pDesc = paginateTimeline(bigTimeline, { page: 1, limit: 10, order: 'desc' });
    assert.strictEqual(pDesc.events[0].sequence, 60);
    assert.strictEqual(pDesc.events[9].sequence, 51);

    // Filtering by Event Type
    const pFiltered = paginateTimeline(bigTimeline, { eventType: TimelineEventType.TELEMETRY_INGESTED, limit: 100 });
    assert.strictEqual(pFiltered.total, 30);
    assert.ok(pFiltered.events.every(e => e.eventType === TimelineEventType.TELEMETRY_INGESTED));

    // Filtering by Actor
    const pActor = paginateTimeline(bigTimeline, { actor: 'analyst.alpha', limit: 100 });
    assert.strictEqual(pActor.total, 20);

    // Text Search
    const pSearch = paginateTimeline(bigTimeline, { search: 'event #42' });
    assert.strictEqual(pSearch.total, 1);
    assert.strictEqual(pSearch.events[0].description, 'Synthetic bulk timeline event #42');
  });

  // ── SECTION 5: HTTP API Protection & Mutation Rejection ─────────────────────
  console.log('\n━━━ SECTION 5: HTTP API Verification & Tamper Rejection ━━━');

  await runTest('[API-SECURITY] Rejects PUT/PATCH/DELETE on timeline records with 405 Method Not Allowed', async () => {
    const authService = require('./src/services/authService');
    const token = authService.generateAccessToken({
      id: 'usr-analyst-1',
      email: 'analyst@sentinel.local',
      name: 'Analyst Sarah',
      role: 'SOC_ANALYST',
    });

    const app = express();
    app.use(express.json());

    const incidentRoutes = require('./src/routes/incidents');
    app.use('/api/incidents', incidentRoutes);

    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    async function makeRequest(method, path, body = null) {
      return new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port,
          path,
          method,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          }
        }, res => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode, body: JSON.parse(data) });
            } catch (e) {
              resolve({ status: res.statusCode, raw: data });
            }
          });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
      });
    }

    try {
      // 1. GET /api/incidents/:id/timeline (Paginated)
      const resGet = await makeRequest('GET', `/api/incidents/${incident.id}/timeline?limit=10`);
      assert.strictEqual(resGet.status, 200);
      assert.strictEqual(resGet.body.success, true);
      assert.strictEqual(resGet.body.incidentId, incident.id);
      assert.strictEqual(resGet.body.integrity.hashChainValid, true);

      // 2. GET /api/incidents/:id/timeline/verify
      const resVerify = await makeRequest('GET', `/api/incidents/${incident.id}/timeline/verify`);
      assert.strictEqual(resVerify.status, 200);
      assert.strictEqual(resVerify.body.valid, true);
      assert.ok(resVerify.body.latestHash);

      // 3. POST /api/incidents/:id/timeline (Valid append)
      const resAppend = await makeRequest('POST', `/api/incidents/${incident.id}/timeline`, {
        eventType: 'CUSTOM_EVENT',
        description: 'Post-incident review conducted with CISO',
        source: 'PIR_MEETING',
      });
      assert.strictEqual(resAppend.status, 201);
      assert.strictEqual(resAppend.body.event.eventType, 'CUSTOM_EVENT');
      assert.ok(resAppend.body.event.hash);

      // 4. PUT /api/incidents/:id/timeline/:eventId (Should fail 405)
      const resPut = await makeRequest('PUT', `/api/incidents/${incident.id}/timeline/tle-123`, { description: 'tampered' });
      assert.strictEqual(resPut.status, 405);
      assert.strictEqual(resPut.body.code, 'IMMUTABLE_RECORD_RESTRICTION');

      // 5. PATCH /api/incidents/:id/timeline/:eventId (Should fail 405)
      const resPatch = await makeRequest('PATCH', `/api/incidents/${incident.id}/timeline/tle-123`, { description: 'tampered' });
      assert.strictEqual(resPatch.status, 405);
      assert.strictEqual(resPatch.body.code, 'IMMUTABLE_RECORD_RESTRICTION');

      // 6. DELETE /api/incidents/:id/timeline/:eventId (Should fail 405)
      const resDel = await makeRequest('DELETE', `/api/incidents/${incident.id}/timeline/tle-123`);
      assert.strictEqual(resDel.status, 405);
      assert.strictEqual(resDel.body.code, 'IMMUTABLE_RECORD_RESTRICTION');

      // 7. DELETE /api/incidents/:id/timeline (Whole timeline purge attempt should fail 405)
      const resDelAll = await makeRequest('DELETE', `/api/incidents/${incident.id}/timeline`);
      assert.strictEqual(resDelAll.status, 405);
      assert.strictEqual(resDelAll.body.code, 'IMMUTABLE_RECORD_RESTRICTION');

    } finally {
      server.close();
    }
  });

  // ── SUMMARY REPORT ──────────────────────────────────────────────────────────
  console.log('\n======================================================================');
  console.log(`🏁  IMMUTABLE TIMELINE SUITE COMPLETE: ${passedTests} / ${totalTests} TESTS PASSED (${totalTests - passedTests} FAILED)`);
  console.log('======================================================================\n');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runSuite().catch(err => {
  console.error('Fatal error in timeline test suite:', err);
  process.exit(1);
});
