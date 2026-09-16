/**
 * ruleRegistry.js
 * Rule Registry & Catalog for Cyber Sentinel Detection Engine.
 * 
 * Supports:
 * - Single-Event Rules
 * - Threshold Rules (count over sliding time window)
 * - Sequence Rules (ordered state machine transitions over time window)
 * - Correlation Rules (cross-source multi-dimensional entity correlation)
 * - Severity, Confidence (0-100), MITRE ATT&CK Mapping
 * - Rule Versioning & Enable/Disable State Toggles
 */

const { mitreRegistry } = require('./mitreRegistry');

const RuleTypes = Object.freeze({
  SINGLE_EVENT: 'SINGLE_EVENT',
  THRESHOLD: 'THRESHOLD',
  SEQUENCE: 'SEQUENCE',
  CORRELATION: 'CORRELATION',
});

class RuleRegistry {
  constructor() {
    this.rules = new Map();
    this._seedBuiltinRules();
  }

  /**
   * Registers or updates a detection rule.
   */
  registerRule(rule) {
    if (!rule || !rule.id || typeof rule.id !== 'string') {
      throw new Error('Detection rule must have a valid string identifier (id).');
    }
    if (!rule.type || !Object.values(RuleTypes).includes(rule.type)) {
      throw new Error(`Invalid rule type '${rule.type}'. Allowed types: ${Object.values(RuleTypes).join(', ')}`);
    }

    const rawMitre = Array.isArray(rule.mitreTechniques)
      ? rule.mitreTechniques
      : (rule.mitreTechnique ? [rule.mitreTechnique] : (rule.mitre_techniques ? rule.mitre_techniques : []));

    const resolvedMitre = mitreRegistry.resolveTechniques(rawMitre);

    const validatedRule = {
      id: rule.id.trim(),
      name: rule.name || rule.id,
      description: rule.description || '',
      version: rule.version || '1.0.0',
      enabled: rule.enabled !== undefined ? Boolean(rule.enabled) : true,
      type: rule.type,
      severity: rule.severity || 'MEDIUM',
      confidence: typeof rule.confidence === 'number' ? Math.min(Math.max(rule.confidence, 0), 100) : 80,
      mitreTechniques: resolvedMitre,
      rawMitreReferences: rawMitre,
      timeWindowMs: rule.timeWindowMs || (rule.windowSeconds ? rule.windowSeconds * 1000 : 120000), // Default 2 mins
      threshold: typeof rule.threshold === 'number' ? rule.threshold : 1,
      groupBy: Array.isArray(rule.groupBy) ? rule.groupBy : (rule.groupBy ? [rule.groupBy] : ['device_id']),
      sequence: Array.isArray(rule.sequence) ? rule.sequence : [],
      match: typeof rule.match === 'function' ? rule.match : () => false,
      recommendedInvestigation: Array.isArray(rule.recommendedInvestigation)
        ? rule.recommendedInvestigation
        : [rule.recommendedInvestigation || 'Investigate source endpoint and correlate network activity.'],
      metadata: rule.metadata || {},
    };

    this.rules.set(validatedRule.id, validatedRule);
    return validatedRule;
  }

  getRule(id) {
    return this.rules.get(id) || null;
  }

  getAllRules(options = {}) {
    let list = Array.from(this.rules.values());
    if (options.enabledOnly) {
      list = list.filter(r => r.enabled);
    }
    if (options.type) {
      list = list.filter(r => r.type === options.type);
    }
    if (options.severity) {
      list = list.filter(r => r.severity === options.severity);
    }
    return list;
  }

  enableRule(id) {
    const rule = this.getRule(id);
    if (rule) {
      rule.enabled = true;
      return true;
    }
    return false;
  }

  disableRule(id) {
    const rule = this.getRule(id);
    if (rule) {
      rule.enabled = false;
      return true;
    }
    return false;
  }

  removeRule(id) {
    return this.rules.delete(id);
  }

  /**
   * Seeds production-grade baseline detection rules.
   */
  _seedBuiltinRules() {
    // ── 1. Single-Event Rule: Mimikatz Credential Dumping ──
    this.registerRule({
      id: 'RULE_MIMIKATZ_CRED_DUMP_001',
      name: 'Mimikatz LSASS Credential Dumping Activity',
      description: 'Detects command-line parameters and process behaviors indicative of LSASS memory credential harvesting.',
      version: '1.2.0',
      type: RuleTypes.SINGLE_EVENT,
      severity: 'CRITICAL',
      confidence: 98,
      mitreTechniques: ['T1003.001 - OS Credential Dumping: LSASS Memory'],
      match: (event) => {
        const cmd = (event.process?.command_line || event.commandLine || '').toLowerCase();
        const proc = (event.process?.name || event.processName || '').toLowerCase();
        return (
          cmd.includes('sekurlsa') ||
          cmd.includes('logonpasswords') ||
          cmd.includes('lsadump') ||
          cmd.includes('mimikatz') ||
          (proc.includes('procdump') && cmd.includes('lsass'))
        );
      },
      recommendedInvestigation: [
        '1. Immediately isolate endpoint from the enterprise network.',
        '2. Force enterprise-wide credential resets for accounts active on this workstation.',
        '3. Inspect memory dump locations and purge artifacts from disk.',
      ],
    });

    // ── 2. Single-Event Rule: Suspicious Obfuscated PowerShell ──
    this.registerRule({
      id: 'RULE_OBFUSCATED_POWERSHELL_002',
      name: 'Obfuscated PowerShell Script Execution',
      description: 'Detects encoded, hidden, or unconstrained execution policy PowerShell invocations.',
      version: '1.1.0',
      type: RuleTypes.SINGLE_EVENT,
      severity: 'HIGH',
      confidence: 90,
      mitreTechniques: ['T1059.001 - Command and Scripting: PowerShell', 'T1027 - Obfuscated Files or Information'],
      match: (event) => {
        const cmd = (event.process?.command_line || event.commandLine || '').toLowerCase();
        const proc = (event.process?.name || event.processName || '').toLowerCase();
        const isPs = proc.includes('powershell') || cmd.includes('powershell');
        return isPs && (
          cmd.includes('-enc') ||
          cmd.includes('-encodedcommand') ||
          cmd.includes('-w hidden') ||
          cmd.includes('-windowstyle hidden') ||
          cmd.includes('bypass') ||
          cmd.includes('downloadstring') ||
          cmd.includes('iex(')
        );
      },
      recommendedInvestigation: [
        '1. Decode Base64 payload in commandLine evidence.',
        '2. Inspect script block logging (EID 4104) on host.',
        '3. Check parent process hierarchy (e.g. Word, Excel, or Web Server).',
      ],
    });

    // ── 3. Single-Event Rule: Shadow Copy Deletion (Ransomware Preparation) ──
    this.registerRule({
      id: 'RULE_SHADOW_COPY_DELETION_003',
      name: 'Volume Shadow Copy Deletion (Inhibit System Recovery)',
      description: 'Detects execution of vssadmin or wmic commands attempting to destroy backup snapshots.',
      version: '1.0.0',
      type: RuleTypes.SINGLE_EVENT,
      severity: 'CRITICAL',
      confidence: 99,
      mitreTechniques: ['T1490 - Inhibit System Recovery'],
      match: (event) => {
        const cmd = (event.process?.command_line || event.commandLine || '').toLowerCase();
        return (
          (cmd.includes('vssadmin') && cmd.includes('delete') && cmd.includes('shadows')) ||
          (cmd.includes('wmic') && cmd.includes('shadowcopy') && cmd.includes('delete')) ||
          (cmd.includes('wbadmin') && cmd.includes('delete') && cmd.includes('catalog'))
        );
      },
      recommendedInvestigation: [
        '1. Initiate immediate emergency host isolation; high probability of ransomware encryption.',
        '2. Scan active processes for mass file rename/encryption loops.',
        '3. Verify immutable off-site backup health.',
      ],
    });

    // ── 4. Single-Event Rule: Web Application SQL Injection Success ──
    this.registerRule({
      id: 'RULE_SQLI_SUCCESS_004',
      name: 'Potential Successful Web SQL Injection Exploit',
      description: 'Detects SQL injection syntax probes in HTTP requests that return HTTP 200 status codes.',
      version: '1.0.0',
      type: RuleTypes.SINGLE_EVENT,
      severity: 'CRITICAL',
      confidence: 95,
      mitreTechniques: ['T1190 - Exploit Public-Facing Application'],
      match: (event) => {
        const path = (event.metadata?.custom?.path || event.details?.path || event.network?.domain || '').toLowerCase();
        const payload = (event.metadata?.custom?.payload || event.details?.payload || '').toLowerCase();
        const status = Number(event.metadata?.custom?.statusCode || event.details?.statusCode || 0);
        const isSqli = /union\s+select|or\s+1=1|--|;\s*drop/i.test(path) || /union\s+select|or\s+1=1|--|;\s*drop/i.test(payload);
        return isSqli && status >= 200 && status < 300;
      },
      recommendedInvestigation: [
        '1. Review application web access logs for backend database errors.',
        '2. Inspect web server query parameters and backend database transaction traces.',
        '3. Block source IP address at WAF/perimeter firewall.',
      ],
    });

    // ── 5. Threshold Rule: Brute Force Authentication Campaign ──
    this.registerRule({
      id: 'RULE_BRUTE_FORCE_005',
      name: 'Brute Force Authentication Campaign',
      description: 'Flags 5 or more failed authentication attempts from the same source IP within a 2-minute window.',
      version: '1.3.0',
      type: RuleTypes.THRESHOLD,
      severity: 'HIGH',
      confidence: 90,
      threshold: 5,
      timeWindowMs: 120 * 1000, // 2 minutes
      groupBy: ['network.source_ip'],
      mitreTechniques: ['T1110.001 - Password Guessing', 'T1110.003 - Password Spraying'],
      match: (event) => {
        return event.event_type === 'AUTH_FAILURE' || event.eventType === 'AUTH_FAILURE';
      },
      recommendedInvestigation: [
        '1. Check Threat Intelligence reputation for attacking source IP.',
        '2. Verify whether targeted accounts have experienced subsequent successful logons.',
        '3. Enforce MFA or temporarily lock out compromised account names.',
      ],
    });

    // ── 6. Threshold Rule: Port Scan Reconnaissance ──
    this.registerRule({
      id: 'RULE_PORT_SCAN_006',
      name: 'Horizontal / Vertical Port Scan Reconnaissance',
      description: 'Detects a single source IP probing 8 or more distinct destination ports within a 1-minute window.',
      version: '1.0.0',
      type: RuleTypes.THRESHOLD,
      severity: 'MEDIUM',
      confidence: 85,
      threshold: 8,
      timeWindowMs: 60 * 1000, // 1 minute
      groupBy: ['network.source_ip'],
      mitreTechniques: ['T1046 - Network Service Discovery'],
      match: (event) => {
        return (
          event.event_type === 'PORT_SCAN' ||
          event.event_type === 'NETWORK_CONNECTION' ||
          event.eventType === 'PORT_SCAN' ||
          event.eventType === 'NETWORK_CONNECTION'
        );
      },
      recommendedInvestigation: [
        '1. Review perimeter firewall logs for dropped probe packets.',
        '2. Check if source IP belongs to an internal vulnerability scanner.',
        '3. Apply rate-limiting or firewall drop rule for attacking IP.',
      ],
    });

    // ── 7. Threshold Rule: High-Volume Rapid File Modification (Ransomware Burst) ──
    this.registerRule({
      id: 'RULE_RANSOMWARE_BURST_007',
      name: 'Rapid Mass File Modification / Encryption Burst',
      description: 'Detects 10 or more rapid file modifications within a 30-second window on the same endpoint.',
      version: '1.0.0',
      type: RuleTypes.THRESHOLD,
      severity: 'CRITICAL',
      confidence: 96,
      threshold: 10,
      timeWindowMs: 30 * 1000, // 30 seconds
      groupBy: ['device_id'],
      mitreTechniques: ['T1486 - Data Encrypted for Impact'],
      match: (event) => {
        return event.event_type === 'FILE_MODIFICATION' || event.eventType === 'FILE_MODIFICATION';
      },
      recommendedInvestigation: [
        '1. Immediately isolate host to prevent network share traversal.',
        '2. Kill suspicious high-IOPS processes.',
        '3. Check file extensions for known ransomware extensions (.locked, .crypto, .enc).',
      ],
    });

    // ── 8. Sequence Rule: Multi-Stage Kill Chain (Exploit -> Privilege Escalation -> Ransomware) ──
    this.registerRule({
      id: 'RULE_KILL_CHAIN_SEQUENCE_008',
      name: 'Multi-Stage Attack Kill Chain (Exploit -> Execution -> Defense Inhibition)',
      description: 'Correlates an initial exploit probe followed by suspicious script execution and recovery inhibition within 5 minutes.',
      version: '1.0.0',
      type: RuleTypes.SEQUENCE,
      severity: 'CRITICAL',
      confidence: 99,
      timeWindowMs: 5 * 60 * 1000, // 5 minutes
      groupBy: ['device_id'],
      mitreTechniques: ['T1190 - Exploit Public-Facing Application', 'T1059.001 - PowerShell', 'T1490 - Inhibit System Recovery'],
      sequence: [
        {
          name: 'Stage 1: Web Exploit Probe',
          match: (e) => e.event_type === 'EXPLOIT_PROBE' || e.eventType === 'EXPLOIT_PROBE',
        },
        {
          name: 'Stage 2: Process Execution',
          match: (e) => e.event_type === 'PROCESS_EXECUTION' || e.eventType === 'PROCESS_EXECUTION',
        },
        {
          name: 'Stage 3: Defense Evasion or Ransomware',
          match: (e) => {
            const cmd = (e.process?.command_line || e.commandLine || '').toLowerCase();
            return cmd.includes('vssadmin') || cmd.includes('shadow') || e.event_type === 'DEFENSE_EVASION';
          },
        },
      ],
      recommendedInvestigation: [
        '1. CRITICAL: High-sophistication multi-stage attack confirmed on endpoint.',
        '2. Enforce immediate network containment.',
        '3. Gather forensic triage bundle (memory dump, MFT, process tree).',
      ],
    });

    // ── 9. Sequence Rule: Account Takeover Sequence ──
    this.registerRule({
      id: 'RULE_ACCOUNT_TAKEOVER_SEQUENCE_009',
      name: 'Account Takeover Sequence (Failed Logins -> Success -> Priv Escalation)',
      description: 'Correlates repeated authentication failures followed by a successful login and permission elevation within 5 minutes.',
      version: '1.0.0',
      type: RuleTypes.SEQUENCE,
      severity: 'HIGH',
      confidence: 92,
      timeWindowMs: 5 * 60 * 1000,
      groupBy: ['user.name'],
      mitreTechniques: ['T1110 - Brute Force', 'T1078 - Valid Accounts', 'T1098 - Account Manipulation'],
      sequence: [
        {
          name: 'Stage 1: Authentication Failure',
          match: (e) => e.event_type === 'AUTH_FAILURE' || e.eventType === 'AUTH_FAILURE',
        },
        {
          name: 'Stage 2: Successful Authentication',
          match: (e) => e.event_type === 'AUTH_SUCCESS' || e.eventType === 'AUTH_SUCCESS',
        },
        {
          name: 'Stage 3: Privilege Escalation',
          match: (e) => e.event_type === 'PRIVILEGE_ESCALATION' || e.eventType === 'PRIVILEGE_ESCALATION',
        },
      ],
      recommendedInvestigation: [
        '1. Confirm with user whether login was legitimate.',
        '2. Inspect geolocation of the successful login IP compared to prior baselines.',
        '3. Revert unauthorized role assignment and reset credential.',
      ],
    });

    // ── 10. Correlation Rule: Suspicious Process with C2 Network Beaconing ──
    this.registerRule({
      id: 'RULE_C2_PROCESS_CORRELATION_010',
      name: 'Suspicious Process Correlated with C2 Network Connection',
      description: 'Correlates suspicious script execution with an outbound network socket connection to an external or IOC-matched IP.',
      version: '1.2.0',
      type: RuleTypes.CORRELATION,
      severity: 'CRITICAL',
      confidence: 98,
      timeWindowMs: 60 * 1000, // 1 minute
      groupBy: ['device_id'],
      mitreTechniques: ['T1059.001 - PowerShell', 'T1071.001 - Application Layer Protocol: C2'],
      match: (event, state) => {
        const isProc = event.event_type === 'PROCESS_EXECUTION' || event.eventType === 'PROCESS_EXECUTION';
        const isNet = event.event_type === 'NETWORK_CONNECTION' || event.eventType === 'NETWORK_CONNECTION' || event.event_type === 'IOC_MATCH';
        
        const cmd = (event.process?.command_line || event.commandLine || '').toLowerCase();
        const isSuspProc = isProc && (cmd.includes('powershell') || cmd.includes('certutil') || cmd.includes('curl') || cmd.includes('-enc'));
        const destIp = event.network?.dest_ip || event.destIp;
        const hasExternalDest = isNet && (destIp && destIp !== '127.0.0.1' && destIp !== 'localhost');

        if (isSuspProc) {
          state.hasSuspiciousProcess = true;
          state.processEvent = event;
        }
        if (hasExternalDest || event.iocEnrichment) {
          state.hasNetworkBeacon = true;
          state.networkEvent = event;
        }

        return Boolean(state.hasSuspiciousProcess && state.hasNetworkBeacon);
      },
      recommendedInvestigation: [
        '1. Inspect active network connections for PID indicated in evidence.',
        '2. Add remote destination IP to firewall blocklist.',
        '3. Terminate process and extract binary for static/dynamic analysis.',
      ],
    });
  }
}

const ruleRegistry = new RuleRegistry();

module.exports = {
  ruleRegistry,
  RuleRegistry,
  RuleTypes,
};
