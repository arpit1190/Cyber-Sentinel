const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const { generateRealLiveAttacks, getLiveCves } = require('../utils/liveThreatFetcher');
const { scanConfig } = require('../utils/scanner');
const { collectSystemMetrics } = require('../utils/systemMetrics');
const {
  blockIp,
  unblockIp,
  getBlockedIps,
  setLastSystemMetrics,
  getLastScanResult,
} = require('../data/securityStore');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');

const router = express.Router();

router.use(requireAuth);

let cachedSysMetrics = null;
let lastMetricsCollection = 0;

router.get('/dashboard', async (req, res) => {
  const liveAttacks = generateRealLiveAttacks(15);
  const blockedCount = liveAttacks.filter((a) => a.blocked).length;
  const criticalCount = liveAttacks.filter((a) => a.severity === 'CRITICAL').length;

  const timeline = Array.from({ length: 12 }, (_, i) => ({
    hour: `${i * 2}:00`,
    attacks: 0,
    blocked: 0,
  }));

  let threatScore = 0;
  let systemFindings = [];
  let sysMetrics = null;

  try {
    const now = Date.now();
    if (cachedSysMetrics && (now - lastMetricsCollection < 2000)) {
      sysMetrics = cachedSysMetrics;
    } else {
      sysMetrics = await collectSystemMetrics();
      cachedSysMetrics = sysMetrics;
      lastMetricsCollection = now;
      setLastSystemMetrics(sysMetrics);
    }
    threatScore = sysMetrics?.threatScore ?? 0;
    systemFindings = sysMetrics?.findings ?? [];
  } catch (e) {
    const lastScan = getLastScanResult();
    if (lastScan) {
      threatScore = lastScan.summary?.riskScore || 0;
      systemFindings = lastScan.findings || [];
    } else {
      const defaultScan = scanConfig({
        usesHttps: false,
        hasHsts: false,
        passwordMinLength: 6,
        mfaEnabled: false,
        openPorts: [22, 80, 3306],
        hasWaf: false,
        exposesAdminPanel: true,
        usesDefaultCredentials: true,
      });
      threatScore = defaultScan.summary.riskScore;
      systemFindings = defaultScan.findings;
    }
  }

  const linkedDevices = (sysMetrics && Array.isArray(sysMetrics.linkedDevices)) ? sysMetrics.linkedDevices : [];
  const externalDevices = linkedDevices.filter(d => !d?.internal);
  const activeBlocked = getBlockedIps();

  res.json({
    stats: {
      threatScore,
      liveAttacks: liveAttacks.length,
      activeDevices: externalDevices.length || 1,
      networkHealth: (sysMetrics?.cpu?.usagePercent != null && sysMetrics?.memory?.usagePercent != null)
        ? Math.max(0, Math.min(100, 100 - (sysMetrics.cpu.usagePercent || 0) * 0.4 - (sysMetrics.memory.usagePercent || 0) * 0.3))
        : 90,
      blockedToday: activeBlocked.length,
      criticalAlerts: criticalCount,
      cpuUsage: sysMetrics?.cpu?.usagePercent ?? null,
      memoryUsage: sysMetrics?.memory?.usagePercent ?? null,
      hostname: sysMetrics?.hostname ?? null,
      platform: sysMetrics?.platform ?? null,
      uptimeDays: sysMetrics?.uptimeDays ?? null,
      riskLevel: sysMetrics?.riskLevel ?? null,
    },
    liveAttacks,
    timeline,
    systemFindings,
    linkedDevices,
  });
});

router.get('/cves', (req, res) => {
  const cves = getLiveCves();
  res.json({ cves });
});

// GET /api/threats/blocked - List actively contained IPs
router.get('/blocked', (req, res) => {
  const blocked = getBlockedIps();
  res.json({ success: true, count: blocked.length, blocked });
});

// POST /api/threats/block-ip - Contain malicious IP (RBAC: Admin & Senior Analyst)
router.post('/block-ip', requireRole(['admin', 'senior_analyst']), (req, res) => {
  const { ip, reason } = req.body;
  if (!ip || typeof ip !== 'string') {
    return res.status(400).json({ success: false, error: 'Valid IP address required.' });
  }

  const record = blockIp(ip, reason || 'Manual analyst containment', req.user.email);

  logSecurityEvent({
    actor: req.user.email,
    actorRole: req.user.role,
    action: AuditActions.IP_BLOCKED,
    target: ip,
    req,
    details: { reason },
  });

  res.json({ success: true, message: `IP ${ip} contained successfully.`, record });
});

// POST /api/threats/unblock-ip - Revoke containment (RBAC: Admin & Senior Analyst)
router.post('/unblock-ip', requireRole(['admin', 'senior_analyst']), (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'Valid IP address required.' });
  }

  const success = unblockIp(ip);
  if (!success) {
    return res.status(404).json({ success: false, error: 'IP not found in active containment list.' });
  }

  logSecurityEvent({
    actor: req.user.email,
    actorRole: req.user.role,
    action: AuditActions.IP_UNBLOCKED,
    target: ip,
    req,
  });

  res.json({ success: true, message: `Containment revoked for ${ip}.` });
});

module.exports = router;
