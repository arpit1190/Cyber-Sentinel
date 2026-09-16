const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { analyzeEmail, analyzeLink, analyzeFile } = require('../utils/protectionEngine');
const { sanitizeFilename, validateFileUpload } = require('../services/upload/uploadSecurityService');
const { setLastProtectionScan } = require('../data/securityStore');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');

const router = express.Router();
router.use(requireAuth);

/**
 * POST /api/protection/scan-email
 * Scan email subject, sender, and text body.
 */
router.post('/scan-email', (req, res) => {
  const { emailText, emailSubject, emailSender } = req.body || {};
  if (typeof emailText !== 'string') {
    return res.status(400).json({ error: 'emailText (string) is required' });
  }

  if (emailText.length > 500_000) {
    return res.status(413).json({ error: 'Email content exceeds maximum allowed size of 500KB.' });
  }

  const result = analyzeEmail(emailText, emailSubject || '', emailSender || '');
  setLastProtectionScan({ scanType: 'email', ...result });

  logSecurityEvent({
    actor: req.user?.email,
    actorRole: req.user?.role,
    action: AuditActions.SCAN_COMPLETED,
    target: 'EMAIL_PROTECTION',
    req,
    details: { score: result.score, verdict: result.verdict },
  });

  res.json(result);
});

/**
 * POST /api/protection/scan-link
 * Scan URL.
 */
router.post('/scan-link', (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url (string) is required' });
  }

  if (url.length > 2048) {
    return res.status(400).json({ error: 'URL exceeds maximum length limit of 2048 characters.' });
  }

  const result = analyzeLink(url);
  setLastProtectionScan({ scanType: 'link', ...result });

  logSecurityEvent({
    actor: req.user?.email,
    actorRole: req.user?.role,
    action: AuditActions.SCAN_COMPLETED,
    target: 'URL_PROTECTION',
    req,
    details: { score: result.score, verdict: result.verdict },
  });

  res.json(result);
});

/**
 * POST /api/protection/scan-file
 * Scan file properties/signature with filename sanitization and magic-byte checks.
 */
router.post('/scan-file', (req, res) => {
  const { fileName, fileSize, fileHash, rawContent, contentBase64 } = req.body || {};
  if (!fileName || typeof fileName !== 'string') {
    return res.status(400).json({ error: 'fileName (string) is required' });
  }

  const { sanitized: safeFileName, isDoubleExtension } = sanitizeFilename(fileName);

  let buffer = null;
  if (contentBase64 && typeof contentBase64 === 'string') {
    try {
      buffer = Buffer.from(contentBase64, 'base64');
    } catch (_) {}
  } else if (rawContent && typeof rawContent === 'string') {
    buffer = Buffer.from(rawContent, 'utf8');
  }

  if (buffer && buffer.length > 10 * 1024 * 1024) {
    return res.status(413).json({ error: 'File content exceeds maximum allowed size of 10MB.' });
  }

  const size = buffer ? buffer.length : (typeof fileSize === 'number' ? fileSize : 0);
  const result = analyzeFile(safeFileName, size, fileHash || '', rawContent || '');
  result.isDoubleExtension = isDoubleExtension;
  result.sanitizedFileName = safeFileName;

  setLastProtectionScan({ scanType: 'file', ...result });

  logSecurityEvent({
    actor: req.user?.email,
    actorRole: req.user?.role,
    action: AuditActions.SCAN_COMPLETED,
    target: 'FILE_PROTECTION',
    req,
    details: { fileName: safeFileName, score: result.score, verdict: result.verdict, isDoubleExtension },
  });

  res.json(result);
});

/**
 * POST /api/protection/explain
 */
router.post('/explain', async (req, res) => {
  const { scanType, scanResult } = req.body || {};
  const apiKey = process.env.GEMINI_API_KEY;

  if (!scanType || !scanResult || typeof scanResult !== 'object') {
    return res.status(400).json({ error: 'scanType (string) and scanResult (object) are required' });
  }

  const fallbacks = {
    email: `### Email Security Mitigation Report (Local Signatures Mode)\n- **Status**: ${scanResult.summary?.status}\n- **Threat Index**: ${scanResult.summary?.threatScore}/100\n- **Identified Indicators**: ${scanResult.tags?.join(', ') || 'None'}`,
    link: `### Link Protection Mitigation Report (Local Signatures Mode)\n- **URL**: \`${scanResult.url}\`\n- **Status**: ${scanResult.summary?.status}\n- **Threat Index**: ${scanResult.summary?.threatScore}/100`,
    file: `### File Protection & Threat Mitigation Report (Local Signatures Mode)\n- **File**: \`${scanResult.fileName}\` (${scanResult.fileSize} bytes)\n- **Status**: ${scanResult.summary?.status}\n- **Malware Signature**: ${scanResult.detectedMalwareName || 'None Detected'}`
  };

  const fallbackReport = fallbacks[scanType] || `### Malware & Protection Scan Report\n- **Status**: ${scanResult.summary?.status || 'Unknown'}`;

  if (!apiKey) {
    return res.json({ explanation: fallbackReport });
  }

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            role: 'user',
            parts: [{ text: `Analyze protection scan result:\n${JSON.stringify(scanResult, null, 2)}` }]
          }]
        })
      }
    );

    if (response.ok) {
      const data = await response.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) return res.json({ explanation: text });
    }
    return res.json({ explanation: fallbackReport });
  } catch (_) {
    return res.json({ explanation: fallbackReport });
  }
});

module.exports = router;
