const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { setLastScanResult } = require('../data/securityStore');
const { scanConfig } = require('../utils/scanner');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');

const router = express.Router();
router.use(requireAuth);

router.post('/scan', (req, res) => {
  const config = req.body || {};
  const result = scanConfig(config);
  setLastScanResult(result);

  logSecurityEvent({
    actor: req.user?.email,
    actorRole: req.user?.role,
    action: AuditActions.SCAN_COMPLETED,
    target: 'HOST_CONFIGURATION',
    req,
    details: { riskScore: result.summary?.riskScore, findingsCount: result.findings?.length },
  });

  res.json(result);
});

module.exports = router;
