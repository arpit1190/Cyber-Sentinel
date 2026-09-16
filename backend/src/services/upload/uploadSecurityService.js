/**
 * uploadSecurityService.js
 * Comprehensive File Upload Security, Magic-Byte Inspection, Archive Bomb Defense & Lifecycle Management.
 *
 * Guardrails:
 * 1. ZERO BLIND TRUST: Never trusts user-supplied Content-Type or file extensions alone.
 * 2. PATH TRAVERSAL & NULL-BYTE DEFENSE: Sanitizes filenames and neutralizes double extensions.
 * 3. DISGUISED EXECUTABLE DETECTION: Detects executables pretending to be images, PDFs, or documents.
 * 4. ARCHIVE BOMB & ZIP SLIP DEFENSE: Inspects archive headers to block decompression bombs and Zip Slip attacks.
 * 5. RETENTION LIFECYCLE: Automatically prunes expired quarantined samples.
 */

'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { detectFileType } = require('../malware/fileTypeDetector');

const DEFAULT_MAX_BINARY_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_ARCHIVE_EXPANSION_RATIO = 100; // 100:1 ratio limit
const MAX_UNCOMPRESSED_ARCHIVE_SIZE = 50 * 1024 * 1024; // 50 MB max uncompressed
const DEFAULT_RETENTION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Dangerous execution extensions to flag in double-extension attacks
const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe',
  '.js', '.jse', '.wsf', '.wsh', '.hta', '.jar', '.sh', '.bash', '.pif', '.com'
]);

/**
 * Sanitizes a client-provided filename, stripping path traversal, null bytes,
 * control characters, and detecting dangerous double extensions.
 */
function sanitizeFilename(originalFilename = 'sample.bin') {
  if (typeof originalFilename !== 'string' || !originalFilename.trim()) {
    return {
      sanitized: 'sample.bin',
      isDoubleExtension: false,
      detectedExtensions: ['.bin'],
    };
  }

  let clean = originalFilename;

  // 1. URI decode (%2e%2e%2f, %00, etc.)
  try {
    clean = decodeURIComponent(clean);
  } catch (_) {
    // Continue if malformed
  }

  // 2. Strip null-bytes and non-printable control characters
  clean = clean.replace(/[\x00-\x1F\x7F]/g, '');

  // 3. Normalize path separators to forward slash and extract pure basename
  clean = clean.replace(/\\/g, '/');
  clean = path.posix.basename(clean);

  // 4. Remove traversal artifacts
  clean = clean.replace(/\.\./g, '_');
  clean = clean.replace(/^[\s._]+/, '');

  // 5. Detect double extensions (e.g. invoice.pdf.exe)
  const parts = clean.split('.');
  let isDoubleExtension = false;
  const detectedExtensions = [];

  if (parts.length > 2) {
    const trailingExt = '.' + parts[parts.length - 1].toLowerCase();
    const precedingExt = '.' + parts[parts.length - 2].toLowerCase();

    detectedExtensions.push(precedingExt, trailingExt);

    if (EXECUTABLE_EXTENSIONS.has(trailingExt)) {
      isDoubleExtension = true;
    }
  } else if (parts.length === 2) {
    detectedExtensions.push('.' + parts[1].toLowerCase());
  }

  // 6. Enforce safe length
  if (clean.length > 200) {
    const ext = path.extname(clean);
    clean = clean.slice(0, 190) + ext;
  }

  return {
    sanitized: clean || 'sample.bin',
    isDoubleExtension,
    detectedExtensions,
  };
}

/**
 * Inspects ZIP archive headers for Zip Slip path traversal and decompression bomb ratios.
 */
function inspectArchiveSafety(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) {
    return { isArchive: false, safe: true };
  }

  // Check for PK.. ZIP header
  const isZip = buffer[0] === 0x50 && buffer[1] === 0x4B;
  if (!isZip) {
    return { isArchive: false, safe: true };
  }

  let offset = 0;
  let totalUncompressedSize = 0;
  let entryCount = 0;
  let hasZipSlip = false;
  const flaggedEntries = [];

  try {
    while (offset < buffer.length - 30) {
      // Look for Local File Header Signature: 0x04034B50 (Little-Endian)
      if (buffer.readUInt32LE(offset) === 0x04034B50) {
        entryCount++;
        const compressedSize = buffer.readUInt32LE(offset + 18);
        const uncompressedSize = buffer.readUInt32LE(offset + 22);
        const fileNameLength = buffer.readUInt16LE(offset + 26);
        const extraFieldLength = buffer.readUInt16LE(offset + 28);

        totalUncompressedSize += uncompressedSize;

        const nameStart = offset + 30;
        const nameEnd = nameStart + fileNameLength;

        if (nameEnd <= buffer.length) {
          const entryName = buffer.subarray(nameStart, nameEnd).toString('utf8');

          // Check for Zip Slip path traversal
          if (entryName.includes('../') || entryName.includes('..\\') || path.isAbsolute(entryName)) {
            hasZipSlip = true;
            flaggedEntries.push(entryName);
          }
        }

        offset = nameEnd + extraFieldLength + compressedSize;
      } else {
        offset++;
      }
    }
  } catch (_) {
    // If parsing encounters malformed chunks, continue to validation assessment
  }

  const expansionRatio = buffer.length > 0 ? (totalUncompressedSize / buffer.length) : 0;
  const isDecompressionBomb = expansionRatio > MAX_ARCHIVE_EXPANSION_RATIO || totalUncompressedSize > MAX_UNCOMPRESSED_ARCHIVE_SIZE;

  return {
    isArchive: true,
    safe: !hasZipSlip && !isDecompressionBomb,
    entryCount,
    totalUncompressedBytes: totalUncompressedSize,
    compressedBytes: buffer.length,
    expansionRatio: Number(expansionRatio.toFixed(2)),
    hasZipSlip,
    isDecompressionBomb,
    flaggedEntries,
  };
}

/**
 * Validates a file upload payload against strict security rules.
 */
function validateFileUpload({
  buffer,
  declaredFilename = 'sample.bin',
  declaredMime = 'application/octet-stream',
  maxSizeBytes = DEFAULT_MAX_BINARY_SIZE,
  disallowExecutables = false,
}) {
  if (!Buffer.isBuffer(buffer)) {
    return { valid: false, status: 400, error: 'Payload must be a valid binary Buffer.' };
  }

  if (buffer.length === 0) {
    return { valid: false, status: 400, error: 'Uploaded file payload is empty (0 bytes).' };
  }

  if (buffer.length > maxSizeBytes) {
    return {
      valid: false,
      status: 413,
      error: `Uploaded file size (${(buffer.length / (1024 * 1024)).toFixed(2)}MB) exceeds maximum limit of ${(maxSizeBytes / (1024 * 1024)).toFixed(2)}MB.`,
    };
  }

  // 1. Sanitize filename & check double extension
  const { sanitized: safeFilename, isDoubleExtension, detectedExtensions } = sanitizeFilename(declaredFilename);

  // 2. Magic-byte detection
  const detectedType = detectFileType(buffer, safeFilename);

  // 3. Detect MIME/extension spoofing (e.g. executable with image/jpeg MIME)
  let isDisguisedExecutable = false;
  if (detectedType.isExecutable) {
    const isDeclaredImageOrDoc = declaredMime.startsWith('image/') ||
      declaredMime.startsWith('audio/') ||
      declaredMime.startsWith('video/') ||
      declaredMime === 'application/pdf' ||
      safeFilename.endsWith('.jpg') ||
      safeFilename.endsWith('.png') ||
      safeFilename.endsWith('.pdf') ||
      safeFilename.endsWith('.txt');

    if (isDeclaredImageOrDoc) {
      isDisguisedExecutable = true;
    }

    if (disallowExecutables) {
      return {
        valid: false,
        status: 415,
        error: `Executable binary uploads are prohibited for this endpoint. Detected format: ${detectedType.type}`,
        detectedType,
      };
    }
  }

  // 4. Archive Safety Inspection
  const archiveSafety = inspectArchiveSafety(buffer);
  if (archiveSafety.isArchive && !archiveSafety.safe) {
    if (archiveSafety.hasZipSlip) {
      return {
        valid: false,
        status: 400,
        error: 'Critical Security Alert: Archive contains Zip Slip path traversal sequences.',
        archiveSafety,
      };
    }
    if (archiveSafety.isDecompressionBomb) {
      return {
        valid: false,
        status: 413,
        error: `Archive decompression bomb detected! Expansion ratio: ${archiveSafety.expansionRatio}:1 (Limit: ${MAX_ARCHIVE_EXPANSION_RATIO}:1).`,
        archiveSafety,
      };
    }
  }

  return {
    valid: true,
    safeFilename,
    isDoubleExtension,
    detectedExtensions,
    detectedType,
    isDisguisedExecutable,
    archiveSafety,
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
    sizeBytes: buffer.length,
  };
}

/**
 * Prunes quarantined samples older than maxAgeMs from disk and in-memory cache.
 */
function pruneExpiredQuarantine(quarantineDir, inMemoryVault, maxAgeMs = DEFAULT_RETENTION_TTL_MS) {
  const now = Date.now();
  let prunedCount = 0;

  // 1. Prune in-memory vault entries
  if (inMemoryVault instanceof Map) {
    for (const [id, entry] of inMemoryVault.entries()) {
      const recordTime = new Date(entry.record?.quarantinedAt || 0).getTime();
      if (now - recordTime > maxAgeMs) {
        // Remove disk file if it exists
        if (entry.record?.diskPath && fs.existsSync(entry.record.diskPath)) {
          try {
            fs.unlinkSync(entry.record.diskPath);
          } catch (_) {}
        }
        inMemoryVault.delete(id);
        prunedCount++;
      }
    }
  }

  // 2. Scan disk directory for orphaned quarantine files
  if (quarantineDir && fs.existsSync(quarantineDir)) {
    try {
      const files = fs.readdirSync(quarantineDir);
      for (const file of files) {
        if (file.endsWith('.quarantine')) {
          const fullPath = path.join(quarantineDir, file);
          const stat = fs.statSync(fullPath);
          if (now - stat.mtimeMs > maxAgeMs) {
            fs.unlinkSync(fullPath);
            prunedCount++;
          }
        }
      }
    } catch (_) {}
  }

  return { prunedCount, timestamp: new Date().toISOString() };
}

module.exports = {
  sanitizeFilename,
  inspectArchiveSafety,
  validateFileUpload,
  pruneExpiredQuarantine,
  DEFAULT_MAX_BINARY_SIZE,
};
