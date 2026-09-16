/**
 * eventNormalizer.js
 * Comprehensive Normalization & Canonical Schema Transformation Engine.
 * 
 * Ingests heterogeneous endpoint and network telemetry streams (Agent, Syslog,
 * Windows Event Logs, Simulator, Firewalls, ThreatFeeds), sanitizes payloads,
 * defends against prototype pollution / malformed structures, and outputs
 * the strict Cyber Sentinel Canonical Event Schema.
 */

const crypto = require('crypto');
const {
  EventTypes,
  SeverityLevels,
  NetworkProtocols,
  NetworkDirections,
  FileActions,
  SchemaLimits,
} = require('./eventSchema');

const {
  isValidEventId,
  isValidTimestamp,
  sanitizeString,
  sanitizeIp,
  sanitizePort,
  sanitizeNestedObject,
} = require('./eventValidator');

/**
 * Normalizes event type string to standard EventTypes enum.
 */
function normalizeEventType(rawType, raw = {}) {
  // Check Windows Event ID codes
  const winEventId = raw.EventID || raw.event_code || raw.EventCode;
  if (winEventId == 4625) return EventTypes.AUTH_FAILURE;
  if (winEventId == 4624) return EventTypes.AUTH_SUCCESS;
  if (winEventId == 4688 || winEventId == 7045) return EventTypes.PROCESS_EXECUTION;
  if (winEventId == 5156) return EventTypes.NETWORK_CONNECTION;

  const combined = [
    rawType,
    raw.action,
    raw.act,
    raw.msg,
    raw.message,
    raw.description,
    raw.dataType
  ].filter(Boolean).map(String).join(' ').toUpperCase();

  if (!combined.trim()) return EventTypes.SYSTEM_ANOMALY;
  const upper = combined;

  if (upper.includes('LOGIN') && upper.includes('FAIL')) return EventTypes.AUTH_FAILURE;
  if (upper.includes('AUTH') && upper.includes('FAIL')) return EventTypes.AUTH_FAILURE;
  if (upper.includes('LOGIN') && upper.includes('SUCC')) return EventTypes.AUTH_SUCCESS;
  if (upper.includes('AUTH') && upper.includes('SUCC')) return EventTypes.AUTH_SUCCESS;
  if (upper.includes('SQL') || upper.includes('XSS') || upper.includes('EXPLOIT') || upper.includes('RCE')) {
    return EventTypes.EXPLOIT_PROBE;
  }
  if (upper.includes('CONN') || upper.includes('TCP') || upper.includes('UDP') || upper.includes('SOCKET') || upper.includes('NETWORK')) {
    return EventTypes.NETWORK_CONNECTION;
  }
  if (upper.includes('PROC') || upper.includes('EXEC') || upper.includes('POWERSHELL') || upper.includes('CMD')) {
    return EventTypes.PROCESS_EXECUTION;
  }
  if (upper.includes('FILE') || upper.includes('WRITE') || upper.includes('DROP')) {
    return EventTypes.FILE_MODIFICATION;
  }
  if (upper.includes('IOC') || upper.includes('THREAT_INTEL')) return EventTypes.IOC_MATCH;
  if (upper.includes('PORT') || upper.includes('SCAN') || upper.includes('PROBE')) {
    return EventTypes.PORT_SCAN;
  }
  if (upper.includes('PRIV') || upper.includes('ESCALAT') || upper.includes('ELEVAT')) {
    return EventTypes.PRIVILEGE_ESCALATION;
  }
  if (upper.includes('PERSIST') || upper.includes('AUTORUN') || upper.includes('CRON')) {
    return EventTypes.PERSISTENCE;
  }
  if (upper.includes('LATERAL') || upper.includes('MOVEMENT') || upper.includes('PS_EXEC')) {
    return EventTypes.LATERAL_MOVEMENT;
  }
  if (upper.includes('EVASION') || upper.includes('DEFENSE') || upper.includes('OBFUSCAT')) {
    return EventTypes.DEFENSE_EVASION;
  }

  // Check direct match
  if (typeof rawType === 'string' && Object.values(EventTypes).includes(rawType.trim().toUpperCase())) {
    return rawType.trim().toUpperCase();
  }

  return EventTypes.SYSTEM_ANOMALY;
}

/**
 * Normalizes severity level string to standard SeverityLevels enum.
 */
function normalizeSeverity(rawSeverity) {
  if (!rawSeverity || typeof rawSeverity !== 'string') return SeverityLevels.MEDIUM;
  const upper = rawSeverity.trim().toUpperCase();
  if (Object.values(SeverityLevels).includes(upper)) {
    return upper;
  }
  if (upper.includes('CRIT')) return SeverityLevels.CRITICAL;
  if (upper.includes('HIGH') || upper.includes('WARN')) return SeverityLevels.HIGH;
  if (upper.includes('LOW')) return SeverityLevels.LOW;
  if (upper.includes('INFO')) return SeverityLevels.INFORMATIONAL;
  return SeverityLevels.MEDIUM;
}

/**
 * Main Normalization Function: Transforms arbitrary raw telemetry into the Canonical Schema.
 * 
 * @param {Object} rawInput - Inbound raw telemetry event.
 * @returns {Object} Standardized, fully validated Canonical Event.
 */
function normalizeEvent(rawInput = {}) {
  // 1. Guard against non-object or invalid types
  const raw = (rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput)) ? rawInput : {};
  const now = new Date().toISOString();

  // 2. Event Identifier (Preserve valid UUID / evt-..., otherwise generate fresh UUIDv4)
  const rawId = raw.event_id || raw.eventId || raw.id;
  const event_id = (rawId && isValidEventId(rawId))
    ? sanitizeString(rawId, SchemaLimits.MAX_EVENT_ID_LEN)
    : crypto.randomUUID();

  // 3. Timestamp Normalization (ISO-8601 UTC)
  const rawTs = raw.timestamp || raw.observed_at || raw.observedAt || raw.TimeCreated || raw.time || raw['@timestamp'];
  let timestamp = now;
  if (rawTs && isValidTimestamp(rawTs)) {
    if (typeof rawTs === 'number') {
      const ms = rawTs > 1e11 ? rawTs : rawTs * 1000;
      timestamp = new Date(ms).toISOString();
    } else if (rawTs instanceof Date) {
      timestamp = rawTs.toISOString();
    } else if (typeof rawTs === 'string') {
      const parsed = Date.parse(rawTs.trim());
      if (!isNaN(parsed)) {
        timestamp = new Date(parsed).toISOString();
      }
    }
  }

  // 4. Device Identification
  const rawDeviceId = raw.device_id || raw.deviceId || raw.hostname || raw.Computer || raw.host || raw.node;
  const device_id = sanitizeString(rawDeviceId, SchemaLimits.MAX_DEVICE_ID_LEN) || 'DEV-LOCAL-NODE';

  // 5. Classification
  const event_type = normalizeEventType(raw.event_type || raw.eventType || raw.type || raw.action, raw);
  const severity = normalizeSeverity(raw.severity || raw.level || raw.priority);
  const source = sanitizeString(raw.source || raw.data_source || raw.dataSource, SchemaLimits.MAX_SOURCE_LEN) || 'endpoint-agent';

  // 6. Process Sub-Object Normalization
  const procRaw = (raw.process && typeof raw.process === 'object' && !Array.isArray(raw.process)) ? raw.process : {};
  const processName = sanitizeString(
    procRaw.name || raw.process_name || raw.processName || raw.details?.processName || raw.details?.process_name,
    SchemaLimits.MAX_NAME_LEN
  );
  const commandLine = sanitizeString(
    procRaw.command_line || procRaw.commandLine || raw.command_line || raw.commandLine || raw.details?.commandLine || raw.details?.command_line,
    SchemaLimits.MAX_CMDLINE_LEN
  );
  const processPath = sanitizeString(
    procRaw.path || raw.process_path || raw.processPath || raw.details?.processPath,
    SchemaLimits.MAX_PATH_LEN
  );
  const processHash = sanitizeString(
    procRaw.hash || raw.process_hash || raw.processHash || raw.details?.processHash,
    SchemaLimits.MAX_HASH_LEN
  );
  const processParent = sanitizeString(
    procRaw.parent_name || procRaw.parentName || raw.parent_process || raw.parentProcess,
    SchemaLimits.MAX_NAME_LEN
  );

  const processPid = (procRaw.pid !== undefined && procRaw.pid !== null)
    ? Number(procRaw.pid) || null
    : (raw.pid !== undefined && raw.pid !== null ? Number(raw.pid) || null : (raw.details?.pid ? Number(raw.details.pid) || null : null));
  const processPpid = (procRaw.ppid !== undefined && procRaw.ppid !== null)
    ? Number(procRaw.ppid) || null
    : (raw.ppid !== undefined && raw.ppid !== null ? Number(raw.ppid) || null : null);

  const process = {
    name: processName,
    pid: processPid,
    ppid: processPpid,
    path: processPath,
    command_line: commandLine,
    hash: processHash,
    parent_name: processParent,
  };

  // 7. Network Sub-Object Normalization
  const netRaw = (raw.network && typeof raw.network === 'object' && !Array.isArray(raw.network)) ? raw.network : {};
  const rawSourceIp = netRaw.source_ip || netRaw.sourceIp || raw.source_ip || raw.sourceIp || raw.IpAddress || raw.src || raw.remote_ip || raw.remoteIp || raw.ip;
  let sourceIp = null;
  let rawDestPort = netRaw.dest_port !== undefined ? netRaw.dest_port : (netRaw.destPort !== undefined ? netRaw.destPort : (raw.dest_port !== undefined ? raw.dest_port : (raw.destPort !== undefined ? raw.destPort : (raw.dpt !== undefined ? raw.dpt : (raw.port !== undefined ? raw.port : raw.details?.destPort)))));
  let rawSourcePort = netRaw.source_port !== undefined ? netRaw.source_port : (netRaw.sourcePort !== undefined ? netRaw.sourcePort : (raw.source_port !== undefined ? raw.source_port : (raw.sourcePort !== undefined ? raw.sourcePort : (raw.IpPort !== undefined ? raw.IpPort : (raw.spt !== undefined ? raw.spt : raw.details?.sourcePort)))));

  if (typeof rawSourceIp === 'string') {
    if (rawSourceIp.startsWith('[') && rawSourceIp.includes(']:')) {
      const parts = rawSourceIp.split(']:');
      sourceIp = sanitizeIp(parts[0].slice(1)) || parts[0].slice(1);
      if (rawDestPort === undefined || rawDestPort === null) {
        rawDestPort = parseInt(parts[1], 10) || null;
      }
    } else if (!rawSourceIp.startsWith('[') && rawSourceIp.includes(':') && rawSourceIp.split(':').length === 2) {
      const parts = rawSourceIp.split(':');
      sourceIp = sanitizeIp(parts[0]) || parts[0];
      if (rawDestPort === undefined || rawDestPort === null) {
        rawDestPort = parseInt(parts[1], 10) || null;
      }
    } else {
      sourceIp = sanitizeIp(rawSourceIp);
    }
  }

  let destIp = sanitizeIp(netRaw.dest_ip || netRaw.destIp || raw.dest_ip || raw.destIp || raw.dst || raw.details?.destIp || raw.details?.dest_ip);
  let sourcePort = (rawSourcePort !== undefined && rawSourcePort !== null) ? Number(rawSourcePort) : null;
  let destPort = (rawDestPort !== undefined && rawDestPort !== null) ? Number(rawDestPort) : null;

  const rawProtocol = sanitizeString(netRaw.protocol || raw.protocol || raw.details?.protocol, 16) || 'TCP';
  const protocol = Object.values(NetworkProtocols).includes(rawProtocol.toUpperCase()) ? rawProtocol.toUpperCase() : 'TCP';
  const rawDirection = sanitizeString(netRaw.direction || raw.direction || raw.details?.direction, 16);
  const direction = (rawDirection && Object.values(NetworkDirections).includes(rawDirection.toUpperCase()))
    ? rawDirection.toUpperCase()
    : (destIp && destIp !== '127.0.0.1' ? 'OUTBOUND' : 'INBOUND');
  const domain = sanitizeString(netRaw.domain || raw.domain || raw.details?.domain, SchemaLimits.MAX_DOMAIN_LEN);

  const network = {
    source_ip: sourceIp || '127.0.0.1',
    source_port: sourcePort,
    dest_ip: destIp,
    dest_port: destPort,
    protocol,
    direction,
    domain,
    bytes_sent: Number.isFinite(netRaw.bytes_sent) ? netRaw.bytes_sent : null,
    bytes_received: Number.isFinite(netRaw.bytes_received) ? netRaw.bytes_received : null,
  };

  // 8. File Sub-Object Normalization
  const fileRaw = (raw.file && typeof raw.file === 'object' && !Array.isArray(raw.file)) ? raw.file : {};
  const filePath = sanitizeString(
    fileRaw.path || raw.file_path || raw.filePath || raw.path || raw.details?.filePath,
    SchemaLimits.MAX_PATH_LEN
  );
  const fileName = sanitizeString(
    fileRaw.name || raw.file_name || raw.fileName || raw.details?.fileName || (filePath ? filePath.split(/[\/\\]/).pop() : null),
    SchemaLimits.MAX_NAME_LEN
  );
  const rawFileAction = sanitizeString(fileRaw.action || raw.file_action || raw.fileAction || raw.action, 32);
  const fileAction = (rawFileAction && Object.values(FileActions).includes(rawFileAction.toUpperCase()))
    ? rawFileAction.toUpperCase()
    : (filePath ? 'MODIFIED' : null);
  const fileHash = sanitizeString(fileRaw.hash || raw.file_hash || raw.fileHash || raw.sha256 || raw.md5, SchemaLimits.MAX_HASH_LEN);
  const fileExt = fileName && fileName.includes('.') ? fileName.split('.').pop().toLowerCase() : null;

  const file = {
    path: filePath,
    name: fileName,
    action: fileAction,
    size_bytes: Number.isFinite(fileRaw.size_bytes) ? fileRaw.size_bytes : (Number.isFinite(raw.size_bytes) ? raw.size_bytes : null),
    hash: fileHash,
    extension: fileExt ? sanitizeString(fileExt, 16) : null,
  };

  // 9. User Sub-Object Normalization
  const userRaw = (raw.user && typeof raw.user === 'object' && !Array.isArray(raw.user)) ? raw.user : {};
  const rawUserName = typeof raw.user === 'string'
    ? raw.user
    : (userRaw.name || userRaw.username || raw.TargetUserName || raw.username || raw.email || raw.account || raw.details?.user || 'system');
  const userName = sanitizeString(rawUserName, SchemaLimits.MAX_USER_LEN) || 'system';
  const userDomain = sanitizeString(userRaw.domain || raw.TargetDomainName || raw.domain || raw.user_domain, SchemaLimits.MAX_NAME_LEN);
  const userId = sanitizeString(userRaw.id || raw.user_id || raw.userId, 64);
  const userEmail = sanitizeString(userRaw.email || raw.user_email || raw.email, 128);
  const userIsAdmin = userRaw.is_admin !== undefined ? Boolean(userRaw.is_admin) : (userName.toLowerCase() === 'root' || userName.toLowerCase() === 'administrator');

  const user = {
    name: userName,
    domain: userDomain,
    id: userId,
    email: userEmail,
    is_admin: userIsAdmin,
  };

  // 10. Custom Metadata Sanitization & Unknown Field Harvester
  const knownKeys = new Set([
    'event_id', 'eventId', 'id',
    'timestamp', 'observed_at', 'observedAt', 'time', '@timestamp', 'ingested_at', 'ingestedAt',
    'device_id', 'deviceId', 'hostname', 'host', 'node',
    'event_type', 'eventType', 'type', 'action',
    'severity', 'level', 'priority',
    'source', 'data_source', 'dataSource',
    'process', 'process_name', 'processName', 'command_line', 'commandLine', 'process_path', 'processPath', 'process_hash', 'processHash', 'parent_process', 'parentProcess', 'pid', 'ppid',
    'network', 'source_ip', 'sourceIp', 'dest_ip', 'destIp', 'source_port', 'sourcePort', 'dest_port', 'destPort', 'port', 'protocol', 'direction', 'remote_ip', 'remoteIp', 'ip',
    'file', 'file_path', 'filePath', 'file_name', 'fileName', 'file_action', 'fileAction', 'file_hash', 'fileHash', 'sha256', 'md5', 'size_bytes',
    'user', 'username', 'user_id', 'userId', 'user_domain', 'user_email', 'email', 'account',
    'metadata', 'details', 'data', 'tags', 'mitre_technique', 'mitreTechnique', 'ioc_match', 'iocMatch', 'iocEnrichment', 'isSimulation', 'simulation'
  ]);

  // Extract raw details object if present
  const baseDetails = (raw.details && typeof raw.details === 'object' && !Array.isArray(raw.details))
    ? raw.details
    : ((raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data)) ? raw.data : {});

  // Collect unknown top-level keys
  const unknownProps = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!knownKeys.has(key)) {
      unknownProps[key] = value;
    }
  }

  const mergedCustom = { ...baseDetails, ...unknownProps };
  const sanitizedCustom = sanitizeNestedObject(mergedCustom) || {};

  // Extract tags safely
  const rawTags = Array.isArray(raw.tags) ? raw.tags : (Array.isArray(raw.metadata?.tags) ? raw.metadata.tags : []);
  const tags = [];
  for (let i = 0; i < Math.min(rawTags.length, SchemaLimits.MAX_TAGS_COUNT); i++) {
    const cleanTag = sanitizeString(rawTags[i], SchemaLimits.MAX_TAG_LEN);
    if (cleanTag) tags.push(cleanTag);
  }

  const mitreTechnique = sanitizeString(raw.mitre_technique || raw.mitreTechnique || raw.metadata?.mitre_technique, 64);
  const iocMatch = raw.ioc_match || raw.iocMatch || raw.iocEnrichment || raw.metadata?.ioc_match || null;
  const isSimulation = Boolean(raw.isSimulation || raw.simulation || source === 'cyber-sentinel-simulator');

  const metadata = {
    schema_version: '1.0.0',
    ingested_at: now,
    tags,
    mitre_technique: mitreTechnique,
    ioc_match: iocMatch ? sanitizeNestedObject(iocMatch) : null,
    is_simulation: isSimulation,
    custom: sanitizedCustom,
  };

  // 11. Assemble the Canonical Event with Backward Compatibility Accessors
  const canonicalEvent = {
    // Canonical Schema Fields (snake_case)
    event_id,
    timestamp,
    device_id,
    event_type,
    severity,
    source,
    process,
    network,
    file,
    user,
    metadata,

    // Backward-Compatible Accessor Aliases (camelCase for existing components/SIEM)
    eventId: event_id,
    deviceId: device_id,
    hostname: device_id,
    eventType: event_type,
    observedAt: timestamp,
    ingestedAt: now,
    dataSource: source,
    sourceIp: network.source_ip,
    destIp: network.dest_ip,
    destPort: network.dest_port,
    sourcePort: network.source_port,
    protocol: network.protocol,
    processName: process.name,
    commandLine: process.command_line,
    filePath: file.path,
    fileName: file.name,
    mitreTechnique: metadata.mitre_technique,
    iocEnrichment: metadata.ioc_match,
    isSimulation: isSimulation,
    details: sanitizedCustom,
  };

  return canonicalEvent;
}

module.exports = {
  EventTypes,
  SeverityLevels,
  NetworkProtocols,
  NetworkDirections,
  FileActions,
  SchemaLimits,
  normalizeEvent,
  normalizeEventType,
  normalizeSeverity,
};
