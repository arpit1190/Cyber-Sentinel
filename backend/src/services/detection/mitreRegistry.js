/**
 * mitreRegistry.js
 * Centralized Knowledge Base & Canonical Registry for MITRE ATT&CK Enterprise Framework.
 * 
 * Provides structured mappings:
 * - Tactic (ID and Name)
 * - Technique ID & Technique Name
 * - Sub-Technique ID & Sub-Technique Name
 * - Official URL, Matrix & Descriptions
 * 
 * Supports on-demand custom technique registration and automatic resolution
 * for detection rules, SIEM alerts, and forensic incident investigations.
 */

const ATTACK_TACTICS = Object.freeze({
  TA0043: { id: 'TA0043', name: 'Reconnaissance', description: 'Gather information to plan future adversary operations.' },
  TA0042: { id: 'TA0042', name: 'Resource Development', description: 'Establish resources to support operations.' },
  TA0001: { id: 'TA0001', name: 'Initial Access', description: 'Gain initial foothold within the network.' },
  TA0002: { id: 'TA0002', name: 'Execution', description: 'Run adversary-controlled code on local or remote systems.' },
  TA0003: { id: 'TA0003', name: 'Persistence', description: 'Maintain foothold across restarts and credential rotations.' },
  TA0004: { id: 'TA0004', name: 'Privilege Escalation', description: 'Gain higher-level permissions on system or network.' },
  TA0005: { id: 'TA0005', name: 'Defense Evasion', description: 'Avoid detection throughout their compromise lifecycle.' },
  TA0006: { id: 'TA0006', name: 'Credential Access', description: 'Steal credentials like account names and passwords.' },
  TA0007: { id: 'TA0007', name: 'Discovery', description: 'Observe environment and post-compromise surroundings.' },
  TA0008: { id: 'TA0008', name: 'Lateral Movement', description: 'Access and control remote systems on a network.' },
  TA0009: { id: 'TA0009', name: 'Collection', description: 'Gather data of interest to adversary goals.' },
  TA0011: { id: 'TA0011', name: 'Command and Control', description: 'Communicate with systems under adversary control.' },
  TA0010: { id: 'TA0010', name: 'Exfiltration', description: 'Steal and package data from the enterprise.' },
  TA0040: { id: 'TA0040', name: 'Impact', description: 'Disrupt availability or compromise data integrity.' },
});

function createMitreTechniqueObject(def) {
  if (!def || !def.id) return null;
  const id = def.id.trim().toUpperCase();
  const isSubTechnique = id.includes('.');
  const parentId = isSubTechnique ? id.split('.')[0] : id;
  const techName = def.technique_name || def.name || parentId;
  const subName = isSubTechnique ? (def.sub_technique_name || (def.name !== techName ? def.name : null)) : null;
  const fullName = subName ? `${techName}: ${subName}` : techName;

  const obj = {
    id,
    technique_id: parentId,
    technique_name: techName,
    sub_technique_id: isSubTechnique ? id : (def.sub_technique_id || null),
    sub_technique_name: subName,
    tactic_id: def.tactic_id || 'TA0002',
    tactic: def.tactic || 'Execution',
    matrix: def.matrix || 'Enterprise ATT&CK',
    description: def.description || '',
    url: def.url || (isSubTechnique 
      ? `https://attack.mitre.org/techniques/${parentId}/${id.split('.')[1]}/`
      : `https://attack.mitre.org/techniques/${parentId}/`),
    platforms: Array.isArray(def.platforms) ? def.platforms : ['Windows', 'Linux', 'macOS'],
    toString() {
      return `${this.id} - ${fullName}`;
    },
    includes(pattern) {
      if (typeof pattern !== 'string') return false;
      const p = pattern.toLowerCase();
      return (
        (this.id && this.id.toLowerCase().includes(p)) ||
        (this.technique_name && this.technique_name.toLowerCase().includes(p)) ||
        (this.sub_technique_name && this.sub_technique_name.toLowerCase().includes(p)) ||
        (this.tactic && this.tactic.toLowerCase().includes(p)) ||
        this.toString().toLowerCase().includes(p)
      );
    }
  };

  return obj;
}

class MitreRegistry {
  constructor() {
    this.techniques = new Map();
    this.tactics = new Map(Object.entries(ATTACK_TACTICS));
    this._seedEnterpriseCatalog();
  }

  /**
   * Registers or updates a MITRE ATT&CK technique or sub-technique.
   */
  registerTechnique(def) {
    if (!def || !def.id) {
      throw new Error('MITRE technique registration requires a valid string id (e.g. T1003 or T1003.001).');
    }

    const entry = createMitreTechniqueObject(def);
    this.techniques.set(entry.id, entry);
    return entry;
  }

  /**
   * Retrieves a technique or sub-technique by its canonical ID.
   */
  getTechnique(id) {
    if (!id || typeof id !== 'string') return null;
    const cleanId = id.trim().toUpperCase();
    return this.techniques.get(cleanId) || null;
  }

  /**
   * Resolves an array of technique IDs or descriptive strings into structured MITRE ATT&CK objects.
   * e.g. ['T1003.001', 'T1059.001 - Command and Scripting: PowerShell'] -> Structured Array
   * 
   * @param {Array<string|Object>} references 
   * @returns {Array<Object>} Structured MITRE technique objects
   */
  resolveTechniques(references) {
    if (!references) return [];
    const list = Array.isArray(references) ? references : [references];
    const results = [];
    const seenIds = new Set();

    for (const ref of list) {
      if (!ref) continue;

      // Handle direct object input
      if (typeof ref === 'object' && (ref.technique_id || ref.id)) {
        const canonical = createMitreTechniqueObject(ref);
        if (canonical && !seenIds.has(canonical.id)) {
          results.push(canonical);
          seenIds.add(canonical.id);
        }
        continue;
      }

      if (typeof ref === 'string') {
        // Extract technique ID (e.g. "T1003.001" from "T1003.001 - OS Credential Dumping")
        const match = ref.match(/(T\d{4}(?:\.\d{3})?)/i);
        if (match) {
          const matchedId = match[1].toUpperCase();
          const canonical = this.getTechnique(matchedId);
          if (canonical && !seenIds.has(canonical.id)) {
            results.push(canonical);
            seenIds.add(canonical.id);
          } else if (!canonical && !seenIds.has(matchedId)) {
            // Unregistered but valid ID format fallback
            const isSub = matchedId.includes('.');
            const pId = isSub ? matchedId.split('.')[0] : matchedId;
            const extractedName = ref.includes(' - ') ? ref.split(' - ')[1] : matchedId;
            const fallback = createMitreTechniqueObject({
              id: matchedId,
              technique_id: pId,
              technique_name: extractedName,
              sub_technique_id: isSub ? matchedId : null,
              sub_technique_name: isSub ? extractedName : null,
              tactic: 'Execution',
            });
            results.push(fallback);
            seenIds.add(matchedId);
          }
        }
      }
    }

    return results;
  }

  /**
   * Returns all registered techniques in the catalog.
   */
  getAllTechniques() {
    return Array.from(this.techniques.values());
  }

  /**
   * Returns all ATT&CK tactics.
   */
  getAllTactics() {
    return Array.from(this.tactics.values());
  }

  /**
   * Seeds official enterprise ATT&CK techniques and sub-techniques.
   */
  _seedEnterpriseCatalog() {
    // ── Credential Access (TA0006) ──
    this.registerTechnique({
      id: 'T1003',
      technique_name: 'OS Credential Dumping',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
    });
    this.registerTechnique({
      id: 'T1003.001',
      technique_name: 'OS Credential Dumping',
      sub_technique_id: 'T1003.001',
      sub_technique_name: 'LSASS Memory',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).',
    });
    this.registerTechnique({
      id: 'T1003.002',
      technique_name: 'OS Credential Dumping',
      sub_technique_id: 'T1003.002',
      sub_technique_name: 'Security Account Manager',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may attempt to extract password hashes from the Security Account Manager (SAM) database.',
    });
    this.registerTechnique({
      id: 'T1110',
      technique_name: 'Brute Force',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.',
    });
    this.registerTechnique({
      id: 'T1110.001',
      technique_name: 'Brute Force',
      sub_technique_id: 'T1110.001',
      sub_technique_name: 'Password Guessing',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may systematically guess passwords to gain authentication.',
    });
    this.registerTechnique({
      id: 'T1110.003',
      technique_name: 'Brute Force',
      sub_technique_id: 'T1110.003',
      sub_technique_name: 'Password Spraying',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may use a single password against many different accounts to avoid lockouts.',
    });
    this.registerTechnique({
      id: 'T1539',
      technique_name: 'Steal Web Session Cookie',
      tactic_id: 'TA0006',
      tactic: 'Credential Access',
      description: 'Adversaries may steal web application session cookies to bypass multifactor authentication.',
    });

    // ── Execution (TA0002) ──
    this.registerTechnique({
      id: 'T1059',
      technique_name: 'Command and Scripting Interpreter',
      tactic_id: 'TA0002',
      tactic: 'Execution',
      description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    });
    this.registerTechnique({
      id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter',
      sub_technique_id: 'T1059.001',
      sub_technique_name: 'PowerShell',
      tactic_id: 'TA0002',
      tactic: 'Execution',
      description: 'Adversaries may abuse PowerShell commands and scripts for execution.',
    });
    this.registerTechnique({
      id: 'T1059.003',
      technique_name: 'Command and Scripting Interpreter',
      sub_technique_id: 'T1059.003',
      sub_technique_name: 'Windows Command Shell',
      tactic_id: 'TA0002',
      tactic: 'Execution',
      description: 'Adversaries may abuse cmd.exe to execute commands or batch files.',
    });
    this.registerTechnique({
      id: 'T1059.006',
      technique_name: 'Command and Scripting Interpreter',
      sub_technique_id: 'T1059.006',
      sub_technique_name: 'Python',
      tactic_id: 'TA0002',
      tactic: 'Execution',
      description: 'Adversaries may execute malicious Python scripts on target systems.',
    });

    // ── Defense Evasion (TA0005) ──
    this.registerTechnique({
      id: 'T1027',
      technique_name: 'Obfuscated Files or Information',
      tactic_id: 'TA0005',
      tactic: 'Defense Evasion',
      description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze.',
    });
    this.registerTechnique({
      id: 'T1027.002',
      technique_name: 'Obfuscated Files or Information',
      sub_technique_id: 'T1027.002',
      sub_technique_name: 'Software Packing',
      tactic_id: 'TA0005',
      tactic: 'Defense Evasion',
      description: 'Adversaries may compress or encrypt an executable to evade static signatures.',
    });
    this.registerTechnique({
      id: 'T1070',
      technique_name: 'Indicator Removal',
      tactic_id: 'TA0005',
      tactic: 'Defense Evasion',
      description: 'Adversaries may delete or modify artifacts generated on a host to cover their tracks.',
    });

    // ── Initial Access (TA0001) ──
    this.registerTechnique({
      id: 'T1190',
      technique_name: 'Exploit Public-Facing Application',
      tactic_id: 'TA0001',
      tactic: 'Initial Access',
      description: 'Adversaries may exploit vulnerabilities in Internet-facing software to gain unauthorized access.',
    });
    this.registerTechnique({
      id: 'T1566',
      technique_name: 'Phishing',
      tactic_id: 'TA0001',
      tactic: 'Initial Access',
      description: 'Adversaries may send phishing messages to gain access to victim systems.',
    });
    this.registerTechnique({
      id: 'T1195',
      technique_name: 'Supply Chain Compromise',
      tactic_id: 'TA0001',
      tactic: 'Initial Access',
      description: 'Adversaries may manipulate software packages or dependencies before receipt by the target.',
    });

    // ── Discovery (TA0007) ──
    this.registerTechnique({
      id: 'T1046',
      technique_name: 'Network Service Discovery',
      tactic_id: 'TA0007',
      tactic: 'Discovery',
      description: 'Adversaries may attempt to get a listing of services running on remote hosts and local networks.',
    });
    this.registerTechnique({
      id: 'T1082',
      technique_name: 'System Information Discovery',
      tactic_id: 'TA0007',
      tactic: 'Discovery',
      description: 'Adversaries may attempt to get detailed information about the operating system and hardware.',
    });

    // ── Impact (TA0040) ──
    this.registerTechnique({
      id: 'T1490',
      technique_name: 'Inhibit System Recovery',
      tactic_id: 'TA0040',
      tactic: 'Impact',
      description: 'Adversaries may delete or remove built-in data and operating system recovery features.',
    });
    this.registerTechnique({
      id: 'T1486',
      technique_name: 'Data Encrypted for Impact',
      tactic_id: 'TA0040',
      tactic: 'Impact',
      description: 'Adversaries may encrypt data on target systems to interrupt system and network resource availability.',
    });
    this.registerTechnique({
      id: 'T1499',
      technique_name: 'Endpoint Denial of Service',
      tactic_id: 'TA0040',
      tactic: 'Impact',
      description: 'Adversaries may perform endpoint denial of service attacks to degrade service availability.',
    });

    // ── Persistence & Privilege Escalation (TA0003, TA0004) ──
    this.registerTechnique({
      id: 'T1078',
      technique_name: 'Valid Accounts',
      tactic_id: 'TA0003',
      tactic: 'Persistence',
      description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access and persistence.',
    });
    this.registerTechnique({
      id: 'T1098',
      technique_name: 'Account Manipulation',
      tactic_id: 'TA0004',
      tactic: 'Privilege Escalation',
      description: 'Adversaries may manipulate accounts to maintain access to victim systems.',
    });
    this.registerTechnique({
      id: 'T1068',
      technique_name: 'Exploitation for Privilege Escalation',
      tactic_id: 'TA0004',
      tactic: 'Privilege Escalation',
      description: 'Adversaries may exploit software vulnerabilities to elevate access privileges.',
    });

    // ── Command and Control (TA0011) ──
    this.registerTechnique({
      id: 'T1071',
      technique_name: 'Application Layer Protocol',
      tactic_id: 'TA0011',
      tactic: 'Command and Control',
      description: 'Adversaries may communicate using application layer protocols to avoid detection.',
    });
    this.registerTechnique({
      id: 'T1071.001',
      technique_name: 'Application Layer Protocol',
      sub_technique_id: 'T1071.001',
      sub_technique_name: 'Web Protocols',
      tactic_id: 'TA0011',
      tactic: 'Command and Control',
      description: 'Adversaries may communicate using application layer web protocols (HTTP/HTTPS) to blend in with normal network traffic.',
    });
  }
}

const mitreRegistry = new MitreRegistry();

module.exports = {
  mitreRegistry,
  MitreRegistry,
  ATTACK_TACTICS,
};
