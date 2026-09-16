const express = require('express');
const { requireAuth, requirePermission } = require('../middleware/auth');
const { respond, clearSession, getSessionStats } = require('../utils/chatbot');
const {
  inspectPromptInjection,
  scrubOutboundSecretLeakage,
} = require('../services/ai/aiSecurityGuard');
const {
  listActionProposals,
  getActionProposal,
  approveActionProposal,
  rejectActionProposal,
} = require('../services/ai/aiActionProposals');

const router = express.Router();
router.use(requireAuth);

// Shared io instance — set by server.js after Socket.IO initializes
let _io = null;
function setIO(io) { _io = io; }

/**
 * POST /api/chatbot/message
 * Body: { message: string, sessionId?: string }
 * Returns: { reply, steps, toolsUsed, sessionId, mode }
 */
router.post('/message', async (req, res) => {
  const { message, sessionId: clientSessionId } = req.body || {};

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message (string) is required' });
  }

  // Input length guard
  if (message.length > 5000) {
    return res.status(413).json({ error: 'Message payload too large (max 5000 characters).' });
  }

  // Inspect direct prompt injection
  const injectionCheck = inspectPromptInjection(message);
  if (injectionCheck.isInjection) {
    return res.json({
      reply: `🛡️ **Sentinel AI Security Notice**:\n\nYour message contained prompt injection patterns or system instruction override tokens (\`${injectionCheck.matchedPattern}\`). In accordance with SOC Security Directives, this instruction was disarmed. I remain ready to assist with authorized cybersecurity operations, telemetry review, and incident analysis.`,
      steps: [],
      toolsUsed: [],
      sessionId: clientSessionId || 'default',
      mode: 'guarded',
      securityNotice: 'PROMPT_INJECTION_DEFENSE_TRIGGERED',
    });
  }

  // Use provided session ID scoped strictly to the authenticated user
  const userKey = req.user?.email || req.user?.id || 'anonymous';
  const sessionId = clientSessionId ? `${userKey}:${clientSessionId}` : `user-${userKey}`;

  try {
    const emitStep = _io
      ? (step) => {
          _io.emit(`agent:step:${sessionId}`, step);
          _io.emit('agent:step', { sessionId, ...step });
        }
      : null;

    const { reply, steps, toolsUsed } = await respond(message, sessionId, emitStep);

    // Scrub outbound reply for secrets/keys
    const safeReply = scrubOutboundSecretLeakage(reply);

    const mode = process.env.GEMINI_API_KEY ? 'agentic' : 'offline';

    res.json({
      reply: safeReply,
      steps,
      toolsUsed,
      sessionId,
      mode,
    });
  } catch (error) {
    console.error('[Chatbot Route] Error:', error);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

/**
 * POST /api/chatbot/recommend
 * Generates structured AI recommendations for an incident or finding.
 */
router.post('/recommend', (req, res) => {
  try {
    const { incidentId, topic, context } = req.body || {};
    const securityStore = require('../data/securityStore');

    let targetIncident = null;
    if (incidentId) {
      targetIncident = securityStore.getIncidentById(incidentId);
    }

    const recommendation = {
      timestamp: new Date().toISOString(),
      incidentId: incidentId || 'GENERAL',
      severityRecommendation: targetIncident?.severity || 'HIGH',
      suggestedMitreTechniques: targetIncident?.mitreTechniques || ['T1059', 'T1071'],
      investigationSteps: [
        '1. Verify SHA-256 evidence integrity in the immutable incident timeline.',
        '2. Review local network connections for active C2 beaconing.',
        '3. Cross-reference source IP against active ThreatFox IOC catalog.',
        '4. Propose containment action (ISOLATE_ENDPOINT or BLOCK_IP) for human analyst approval.',
      ],
      recommendedResponseAction: {
        actionType: 'ISOLATE_ENDPOINT',
        target: targetIncident?.sourceIp || 'Target Host',
        justification: 'Contain host to prevent lateral movement',
        requiresHumanApproval: true,
      },
    };

    return res.json({ success: true, recommendation });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/chatbot/proposals
 * Lists all active AI advisory action proposals requiring human review.
 */
router.get('/proposals', (req, res) => {
  try {
    const { status, incidentId } = req.query;
    const proposals = listActionProposals({ status, incidentId });
    return res.json({ success: true, count: proposals.length, proposals });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/chatbot/proposals/:id/approve
 * Human operator approves an AI advisory proposal.
 */
router.post('/proposals/:id/approve', requirePermission('incident:update'), (req, res) => {
  try {
    const proposal = approveActionProposal(req.params.id, req.user);
    return res.json({ success: true, proposal });
  } catch (err) {
    const status = err.status || 400;
    return res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/chatbot/proposals/:id/reject
 * Human operator rejects an AI advisory proposal.
 */
router.post('/proposals/:id/reject', requirePermission('incident:update'), (req, res) => {
  try {
    const { reason } = req.body || {};
    const proposal = rejectActionProposal(req.params.id, req.user, reason);
    return res.json({ success: true, proposal });
  } catch (err) {
    const status = err.status || 400;
    return res.status(status).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/chatbot/session/:sessionId
 * Clears the conversation history for a session.
 */
router.delete('/session/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const userKey = req.user?.email || req.user?.id || 'anonymous';

  if (sessionId.startsWith(`${userKey}:`) || sessionId === `user-${userKey}`) {
    clearSession(sessionId);
    return res.json({ success: true, message: `Session ${sessionId} cleared.` });
  }
  return res.status(403).json({ error: 'Access denied: Cannot clear sessions belonging to other operators.' });
});

/**
 * GET /api/chatbot/stats
 * Returns session stats for debugging.
 */
router.get('/stats', (req, res) => {
  res.json(getSessionStats());
});

module.exports = router;
module.exports.setIO = setIO;
