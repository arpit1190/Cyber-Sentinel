/**
 * aiActionProposals.js
 * Human-in-the-Loop AI Advisory Action Proposals Registry.
 *
 * Guardrail:
 * AI recommendations NEVER have authority to directly execute destructive actions.
 * Destructive operations must enter PENDING state as a Proposal, requiring explicit
 * human operator review, authorization, and approval.
 */

'use strict';

const crypto = require('crypto');
const { logSecurityEvent, AuditActions } = require('../../utils/auditLogger');

const PROPOSAL_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory proposal registry
const proposalsStore = new Map();

/**
 * Creates a structured action proposal from an AI recommendation.
 */
function createActionProposal({
  actionType,
  target,
  parameters = {},
  justification = 'AI recommendation based on forensic analysis',
  requester = 'AI_COPILOT',
  incidentId = null,
  deviceId = null,
}) {
  const proposalId = `PROP-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + PROPOSAL_TTL_MS);

  const proposal = {
    proposalId,
    actionType,
    target,
    parameters,
    justification,
    requester,
    incidentId,
    deviceId,
    status: 'PENDING',
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    isExpired: false,
    approver: null,
    approvedAt: null,
    rejectedAt: null,
    rejectionReason: null,
  };

  proposalsStore.set(proposalId, proposal);

  logSecurityEvent({
    actor: requester,
    actorRole: 'AI_ASSISTANT',
    action: AuditActions.AI_PROPOSAL_CREATED || 'AI_PROPOSAL_CREATED',
    target: `${actionType}:${target}`,
    details: { proposalId, actionType, justification, incidentId },
  });

  return proposal;
}

/**
 * Retrieves a proposal by ID and updates expiration status.
 */
function getActionProposal(proposalId) {
  const proposal = proposalsStore.get(proposalId);
  if (!proposal) return null;

  const now = Date.now();
  const expTime = new Date(proposal.expiresAt).getTime();
  if (proposal.status === 'PENDING' && now > expTime) {
    proposal.status = 'EXPIRED';
    proposal.isExpired = true;
  }

  return proposal;
}

/**
 * Lists all action proposals.
 */
function listActionProposals(filter = {}) {
  const now = Date.now();
  const results = [];

  for (const proposal of proposalsStore.values()) {
    const expTime = new Date(proposal.expiresAt).getTime();
    if (proposal.status === 'PENDING' && now > expTime) {
      proposal.status = 'EXPIRED';
      proposal.isExpired = true;
    }

    if (filter.status && proposal.status.toUpperCase() !== filter.status.toUpperCase()) {
      continue;
    }
    if (filter.incidentId && proposal.incidentId !== filter.incidentId) {
      continue;
    }

    results.push(proposal);
  }

  return results.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

/**
 * Approves a proposal by an authorized human operator.
 */
function approveActionProposal(proposalId, approverUser) {
  const proposal = getActionProposal(proposalId);
  if (!proposal) {
    throw new Error('Action proposal not found.');
  }

  if (proposal.status === 'EXPIRED') {
    throw new Error('Cannot approve expired proposal. Request a fresh recommendation.');
  }

  if (proposal.status !== 'PENDING') {
    throw new Error(`Cannot approve proposal in '${proposal.status}' state.`);
  }

  proposal.status = 'APPROVED';
  proposal.approver = approverUser?.email || approverUser?.id || 'operator';
  proposal.approvedAt = new Date().toISOString();

  logSecurityEvent({
    actor: proposal.approver,
    actorRole: approverUser?.role || 'SOC_ANALYST',
    action: AuditActions.AI_ACTION_APPROVED,
    target: `${proposal.actionType}:${proposal.target}`,
    details: { proposalId, actionType: proposal.actionType },
  });

  return proposal;
}

/**
 * Rejects a proposal.
 */
function rejectActionProposal(proposalId, rejectorUser, reason = 'Operator rejected proposed action') {
  const proposal = getActionProposal(proposalId);
  if (!proposal) {
    throw new Error('Action proposal not found.');
  }

  if (proposal.status !== 'PENDING') {
    throw new Error(`Cannot reject proposal in '${proposal.status}' state.`);
  }

  proposal.status = 'REJECTED';
  proposal.rejector = rejectorUser?.email || rejectorUser?.id || 'operator';
  proposal.rejectedAt = new Date().toISOString();
  proposal.rejectionReason = reason;

  logSecurityEvent({
    actor: proposal.rejector,
    actorRole: rejectorUser?.role || 'SOC_ANALYST',
    action: AuditActions.AI_ACTION_REJECTED || 'AI_ACTION_REJECTED',
    target: `${proposal.actionType}:${proposal.target}`,
    details: { proposalId, reason },
  });

  return proposal;
}

module.exports = {
  createActionProposal,
  getActionProposal,
  listActionProposals,
  approveActionProposal,
  rejectActionProposal,
};
