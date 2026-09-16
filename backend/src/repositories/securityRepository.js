/**
 * securityRepository.js
 * Data Access Layer for Security Incidents, Containment/Firewall, Audit Logs, and Scans.
 */

const securityStore = require('../data/securityStore');
const { query, isPostgresConnected } = require('../data/db');

class SecurityRepository {
  // ── Firewall / Blocklist ──
  blockIp(ip, reason, blockedBy) {
    return securityStore.blockIp(ip, reason, blockedBy);
  }

  unblockIp(ip) {
    return securityStore.unblockIp(ip);
  }

  isIpBlocked(ip) {
    return securityStore.isIpBlocked(ip);
  }

  getBlockedIps() {
    return securityStore.getBlockedIps();
  }

  getBlockedRecords() {
    return securityStore.getBlockedRecords();
  }

  // ── Incidents ──
  createIncident(params) {
    return securityStore.createIncident(params);
  }

  getIncidents(status) {
    return securityStore.getIncidents(status);
  }

  getIncidentById(id) {
    return securityStore.getIncidentById(id);
  }

  updateIncident(id, updates, actor, note) {
    return securityStore.updateIncident(id, updates, actor, note);
  }

  updateIncidentStatus(id, newStatus, actor, note) {
    return securityStore.updateIncidentStatus(id, newStatus, actor, note);
  }

  assignIncident(id, assignee, actor, note) {
    return securityStore.assignIncident(id, assignee, actor, note);
  }

  closeIncident(id, resolutionReason, actor, note) {
    return securityStore.closeIncident(id, resolutionReason, actor, note);
  }

  addIncidentNote(id, actor, note) {
    return securityStore.addIncidentNote(id, actor, note);
  }

  addResponseAction(id, actionData, actor) {
    return securityStore.addResponseAction(id, actionData, actor);
  }

  appendTimelineEvent(id, eventData, actor, source) {
    return securityStore.appendTimelineEvent(id, eventData, actor, source);
  }

  getIncidentTimeline(id, options) {
    return securityStore.getIncidentTimeline(id, options);
  }

  verifyIncidentTimelineIntegrity(id) {
    return securityStore.verifyIncidentTimelineIntegrity(id);
  }

  // ── Audit Logs ──
  addAuditLog(entry) {
    return securityStore.addAuditLog(entry);
  }

  getAuditLogs(limit) {
    return securityStore.getAuditLogs(limit);
  }

  // ── Scans & Module Cache ──
  addScan(scan) {
    return securityStore.addScan(scan);
  }

  getScans() {
    return securityStore.getScans();
  }

  setLastScanResult(data)     { securityStore.setLastScanResult(data); }
  getLastScanResult()         { return securityStore.getLastScanResult(); }
  setLastLogAnalysis(data)    { securityStore.setLastLogAnalysis(data); }
  getLastLogAnalysis()        { return securityStore.getLastLogAnalysis(); }
  setLastProtectionScan(data) { securityStore.setLastProtectionScan(data); }
  getLastProtectionScan()     { return securityStore.getLastProtectionScan(); }
  setLastSandboxResult(data)  { securityStore.setLastSandboxResult(data); }
  getLastSandboxResult()      { return securityStore.getLastSandboxResult(); }
  setLastSystemMetrics(data)  { securityStore.setLastSystemMetrics(data); }
  getLastSystemMetrics()      { return securityStore.getLastSystemMetrics(); }

  flush() {
    securityStore.flushState();
  }
}

module.exports = new SecurityRepository();
