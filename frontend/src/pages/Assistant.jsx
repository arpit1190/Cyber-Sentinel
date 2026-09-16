import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import client from '../api/client';
import { useRealTime } from '../context/RealTimeContext';
import { io as socketIO } from 'socket.io-client';

// ── Quick action prompts organized by module ──────────────────────────────────
const QUICK_ACTIONS = [
  { label: '⚡ Actions', icon: '⚡', color: '#ff6b35', prompts: [
    { text: 'Run a full vulnerability scan right now and show me the results', icon: '🔬' },
    { text: 'Scan my network and show all suspicious connections', icon: '🕵️' },
    { text: 'Generate a complete incident report for me', icon: '📊' },
    { text: 'Block all critical-severity IPs on my network', icon: '🚫' },
  ]},
  { label: 'System', icon: '📊', color: '#00d4ff', prompts: [
    { text: 'What is my current system status and threat score?', icon: '🖥️' },
    { text: 'Analyze my CPU and memory usage trends', icon: '📈' },
    { text: 'Are there any suspicious processes running right now?', icon: '⚠️' },
    { text: 'How many attacks were detected and blocked today?', icon: '🔴' },
  ]},
  { label: 'Vulnerabilities', icon: '🔍', color: '#ff4560', prompts: [
    { text: 'Run a quick vulnerability check on my system', icon: '🔍' },
    { text: 'Fetch the latest CISA KEV CVEs and explain them', icon: '📰' },
    { text: 'Show my critical CVEs and remediation steps', icon: '🩹' },
    { text: 'What is my current risk score and what drives it?', icon: '📊' },
  ]},
  { label: 'Threat Intel', icon: '📡', color: '#00ff88', prompts: [
    { text: 'What malware families are active in the threat feed right now?', icon: '🦠' },
    { text: 'Scan this URL: https://example.com — is it malicious?', icon: '🔗' },
    { text: 'Explain the top threats in the current CISA KEV list', icon: '📡' },
    { text: 'Correlate attack feed data with threat intelligence', icon: '⚔️' },
  ]},
  { label: 'Network', icon: '🌐', color: '#f0c040', prompts: [
    { text: 'Show all suspicious network connections on my machine', icon: '🌐' },
    { text: 'List all listening ports and flag the risky ones', icon: '🔌' },
    { text: 'Run a full network scan against the IOC pool', icon: '🕵️' },
    { text: 'Show me all currently blocked IPs', icon: '🚫' },
  ]},
  { label: 'Sandbox', icon: '⚗️', color: '#b47eff', prompts: [
    { text: "Run an SQL injection test: ' OR 1=1-- with WAF disabled", icon: '💉' },
    { text: "Simulate XSS: <script>alert('xss')</script> and show WAF result", icon: '🕸️' },
    { text: 'Simulate command injection and show if WAF blocks it', icon: '💻' },
    { text: 'Analyze my last sandbox simulation result in detail', icon: '⚗️' },
  ]},
  { label: 'Log Analysis', icon: '📋', color: '#00d4ff', prompts: [
    { text: 'Analyze my last log scan and summarize the threats', icon: '📋' },
    { text: 'What attack patterns were found in the logs?', icon: '🔍' },
    { text: 'How do I detect brute force attacks in SSH logs?', icon: '🔐' },
    { text: 'Classify and triage the most critical log events', icon: '🚨' },
  ]},
];

// ── Tool icon map ─────────────────────────────────────────────────────────────
const TOOL_ICONS = {
  // Read tools
  get_system_status: '🖥️',
  get_attack_feed: '🔴',
  get_threat_intel: '📡',
  get_vuln_scan: '🔍',
  get_log_analysis: '📋',
  get_protection_scan: '🛡️',
  get_sandbox_result: '⚗️',
  get_network_connections: '🌐',
  get_listening_ports: '🔌',
  get_blocked_ips: '🚫',
  // Action tools
  run_vulnerability_scan: '🔬',
  run_network_scan: '🕵️',
  run_sandbox_attack: '💥',
  block_ip_address: '🚫',
  scan_url_or_email: '🔗',
  fetch_cve_details: '📰',
  generate_incident_report: '📊',
};

const TOOL_LABELS = {
  // Read tools
  get_system_status: 'System Status',
  get_attack_feed: 'Attack Feed',
  get_threat_intel: 'Threat Intel',
  get_vuln_scan: 'Vuln Scan',
  get_log_analysis: 'Log Analysis',
  get_protection_scan: 'Protection Scan',
  get_sandbox_result: 'Sandbox Result',
  get_network_connections: 'Network Conns',
  get_listening_ports: 'Listening Ports',
  get_blocked_ips: 'Blocked IPs',
  // Action tools (prefix ⚡ to distinguish)
  run_vulnerability_scan: '⚡ Vuln Scan',
  run_network_scan: '⚡ Network Scan',
  run_sandbox_attack: '⚡ Sandbox Attack',
  block_ip_address: '⚡ Block IP',
  scan_url_or_email: '⚡ URL/Email Scan',
  fetch_cve_details: 'CVE Details',
  generate_incident_report: '⚡ Incident Report',
};

// Action tools set (for distinct styling)
const ACTION_TOOLS = new Set([
  'run_vulnerability_scan', 'run_network_scan', 'run_sandbox_attack',
  'block_ip_address', 'scan_url_or_email', 'generate_incident_report',
]);

// ── Markdown renderer ─────────────────────────────────────────────────────────
function renderMarkdown(text) {
  if (!text) return null;
  const lines = text.split('\n');
  const elements = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Table detection
    if (trimmed.startsWith('|') && lines[i + 1]?.trim().startsWith('|--')) {
      const headers = trimmed.split('|').filter(Boolean).map(h => h.trim());
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(lines[i].split('|').filter(Boolean).map(c => c.trim()));
        i++;
      }
      elements.push(
        <div key={elements.length} style={{ overflowX: 'auto', margin: '8px 0' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead>
              <tr>{headers.map((h, j) => (
                <th key={j} style={{ padding: '4px 8px', borderBottom: '1px solid var(--border)', color: 'var(--accent-cyan)', textAlign: 'left', fontFamily: 'Space Grotesk', letterSpacing: '0.06em', fontSize: 10 }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {rows.map((row, ri) => (
                <tr key={ri} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  {row.map((cell, ci) => (
                    <td key={ci} style={{ padding: '4px 8px', color: 'var(--text-dim)', fontSize: 11 }}>{renderInline(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    if (trimmed.startsWith('## ')) {
      elements.push(<h3 key={elements.length} style={{ color: 'var(--accent-cyan)', margin: '14px 0 6px', fontSize: 13, letterSpacing: '0.06em', textTransform: 'uppercase', borderBottom: '1px solid rgba(0,212,255,0.2)', paddingBottom: 4 }}>{trimmed.slice(3)}</h3>);
    } else if (trimmed.startsWith('### ')) {
      elements.push(<h4 key={elements.length} style={{ color: 'var(--accent-cyan)', margin: '10px 0 4px', fontSize: 12, letterSpacing: '0.05em' }}>{trimmed.slice(4)}</h4>);
    } else if (trimmed.startsWith('- ') || trimmed.startsWith('• ')) {
      elements.push(<li key={elements.length} style={{ marginLeft: 18, marginBottom: 3, fontSize: 12, color: 'var(--text-dim)', listStyleType: 'none', position: 'relative' }}>
        <span style={{ position: 'absolute', left: -14, color: 'var(--accent-cyan)' }}>▸</span>
        {renderInline(trimmed.slice(2))}
      </li>);
    } else if (/^\d+\.\s/.test(trimmed)) {
      elements.push(<li key={elements.length} style={{ marginLeft: 18, marginBottom: 3, fontSize: 12, color: 'var(--text-dim)' }}>{renderInline(trimmed.replace(/^\d+\.\s/, ''))}</li>);
    } else if (trimmed === '') {
      if (elements.length > 0) elements.push(<div key={elements.length} style={{ height: 6 }} />);
    } else {
      elements.push(<p key={elements.length} style={{ margin: '0 0 5px', fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.65 }}>{renderInline(line)}</p>);
    }
    i++;
  }
  return <>{elements}</>;
}

function renderInline(text) {
  if (!text) return text;
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((p, i) => {
    if (p.startsWith('**') && p.endsWith('**')) return <strong key={i} style={{ color: 'var(--text)', fontWeight: 700 }}>{p.slice(2, -2)}</strong>;
    if (p.startsWith('`') && p.endsWith('`')) return <code key={i} style={{ background: 'rgba(0,212,255,0.12)', color: 'var(--accent-cyan)', borderRadius: 3, padding: '1px 5px', fontSize: 11, fontFamily: 'monospace' }}>{p.slice(1, -1)}</code>;
    return p;
  });
}

// ── Agent Step Viewer ─────────────────────────────────────────────────────────
function AgentSteps({ steps, toolsUsed, isStreaming, liveSteps }) {
  const [expanded, setExpanded] = useState(false);
  const allSteps = liveSteps?.length > 0 ? liveSteps : steps;

  if (!allSteps?.length && !isStreaming) return null;

  return (
    <div style={{
      marginTop: 8, borderRadius: 6, overflow: 'hidden',
      border: '1px solid rgba(0,212,255,0.2)',
      background: 'rgba(0,212,255,0.03)',
    }}>
      {/* Header */}
      <button
        onClick={() => setExpanded(p => !p)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '6px 10px', background: 'none', border: 'none', cursor: 'pointer',
          borderBottom: expanded ? '1px solid rgba(0,212,255,0.15)' : 'none',
        }}
      >
        <span style={{ fontSize: 9, color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk', letterSpacing: '0.1em', fontWeight: 700 }}>
          {isStreaming ? '🤖 REASONING...' : '🤖 AGENT STEPS'}
        </span>
        {isStreaming && (
          <span style={{ display: 'flex', gap: 3 }}>
            {[0,1,2].map(j => (
              <span key={j} style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--accent-cyan)', opacity: 0.7, animation: `pulse ${0.5 + j * 0.15}s ease-in-out infinite alternate` }} />
            ))}
          </span>
        )}
        {toolsUsed?.length > 0 && (
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', flex: 1 }}>
            {toolsUsed.map((t, i) => (
              <span key={i} style={{
                fontSize: 9, padding: '1px 6px', borderRadius: 3,
                background: 'rgba(0,212,255,0.1)', color: 'var(--accent-cyan)',
                border: '1px solid rgba(0,212,255,0.3)', fontFamily: 'Space Grotesk',
              }}>
                {TOOL_ICONS[t] || '🔧'} {TOOL_LABELS[t] || t}
              </span>
            ))}
          </div>
        )}
        <span style={{ marginLeft: 'auto', color: 'var(--text-faint)', fontSize: 10 }}>{expanded ? '▲' : '▼'}</span>
      </button>

      {/* Step list */}
      {expanded && (
        <div style={{ padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 260, overflowY: 'auto' }}>
          {allSteps.map((step, i) => (
            <div key={i} style={{
              padding: '6px 10px', borderRadius: 4, fontSize: 11,
              background: step.type === 'thought' ? 'rgba(0,212,255,0.05)'
                : step.type === 'action' ? 'rgba(0,255,136,0.05)'
                : step.type === 'observation' ? 'rgba(240,192,64,0.05)'
                : 'rgba(180,126,255,0.05)',
              border: `1px solid ${step.type === 'thought' ? 'rgba(0,212,255,0.15)'
                : step.type === 'action' ? 'rgba(0,255,136,0.15)'
                : step.type === 'observation' ? 'rgba(240,192,64,0.15)'
                : 'rgba(180,126,255,0.15)'}`,
            }}>
              <div style={{ fontSize: 9, fontFamily: 'Space Grotesk', letterSpacing: '0.08em', fontWeight: 700, marginBottom: 3,
                color: step.type === 'thought' ? 'var(--accent-cyan)'
                  : step.type === 'action' ? 'var(--accent-green)'
                  : step.type === 'observation' ? '#f0c040'
                  : '#b47eff',
              }}>
                {step.type === 'thought' ? `💭 THOUGHT (iter ${step.iteration || ''})`
                  : step.type === 'action' ? `⚡ ACTION — ${TOOL_ICONS[step.tool] || '🔧'} ${TOOL_LABELS[step.tool] || step.tool}`
                  : step.type === 'observation' ? `👁️ OBSERVATION — ${TOOL_LABELS[step.tool] || step.tool}`
                  : step.type === 'offline' ? '📴 OFFLINE MODE'
                  : '✅ FINAL'}
              </div>
              {step.content && (
                <p style={{ margin: 0, color: 'var(--text-dim)', lineHeight: 1.55, fontSize: 11 }}>{step.content}</p>
              )}
              {step.type === 'observation' && step.result && (
                <details style={{ marginTop: 4 }}>
                  <summary style={{ cursor: 'pointer', fontSize: 9, color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>View raw data</summary>
                  <pre style={{ margin: '4px 0 0', fontSize: 9, color: 'var(--text-faint)', overflowX: 'auto', maxHeight: 100, background: 'rgba(0,0,0,0.3)', padding: 4, borderRadius: 3 }}>
                    {JSON.stringify(step.result, null, 2)}
                  </pre>
                </details>
              )}
              {step.type === 'offline' && step.message && (
                <p style={{ margin: 0, color: '#f0c040', fontSize: 11 }}>{step.message}</p>
              )}
            </div>
          ))}
          {isStreaming && (
            <div style={{ padding: '6px 10px', borderRadius: 4, border: '1px solid rgba(0,212,255,0.15)', background: 'rgba(0,212,255,0.04)', display: 'flex', gap: 6, alignItems: 'center' }}>
              {[0,1,2].map(j => <span key={j} style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--accent-cyan)', opacity: 0.7, animation: `pulse ${0.5 + j * 0.2}s ease-in-out infinite alternate` }} />)}
              <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>Processing...</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function Assistant() {
  const { connected, systemMetrics, liveAttackCount, intelStatus } = useRealTime();

  // Generate a stable session ID for this browser session
  const sessionId = useMemo(() => {
    const existing = sessionStorage.getItem('sentinel-session-id');
    if (existing) return existing;
    const id = `session-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    sessionStorage.setItem('sentinel-session-id', id);
    return id;
  }, []);

  const [messages, setMessages] = useState([{
    role: 'bot',
    text: `## 🤖 SENTINEL AI — FULLY OPERATIONAL

I'm your **agentic SOC AI** with **18 live tools** — I can read real-time data AND actively execute security operations.

### 📖 Read Tools (live data)
- 🖥️ **get_system_status** — CPU, RAM, Disk, Network, ThreatScore
- 🔴 **get_attack_feed** — 24h attack timeline & block rate
- 📡 **get_threat_intel** — IOC pool, malware families (ThreatFox + CISA KEV)
- 🔍 **get_vuln_scan** — last vulnerability scan results + CVEs
- 📋 **get_log_analysis** — log event analysis & attack categories
- 🛡️ **get_protection_scan** — email/link/file protection results
- ⚗️ **get_sandbox_result** — WAF simulation outcome
- 🌐 **get_network_connections** — live suspicious TCP connections
- 🔌 **get_listening_ports** — open ports & active connections
- 🚫 **get_blocked_ips** — currently blocked IPs

### ⚡ Action Tools (I can EXECUTE these)
- 🔬 **run_vulnerability_scan** — trigger a live vuln scan
- 🕵️ **run_network_scan** — scan network vs IOC pool
- 💥 **run_sandbox_attack** — run SQLi/XSS/CMD simulations
- 🚫 **block_ip_address** — block a specific IP in real-time
- 🔗 **scan_url_or_email** — check URL/email against threat feeds
- 📰 **fetch_cve_details** — look up CVEs from CISA KEV
- 📊 **generate_incident_report** — create a full incident report

**Ask me to run any action** — like *"Scan my network"*, *"Block suspicious IPs"*, or *"Generate an incident report"* — and I'll DO it!`,
  }]);

  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [isExpanded, setIsExpanded] = useState(false);
  const [agentMode, setAgentMode] = useState(null);   // 'agentic' | 'offline'
  const [liveSteps, setLiveSteps] = useState([]);     // streaming steps for current message
  const [msgSteps, setMsgSteps] = useState({});       // { [msgIndex]: {steps, toolsUsed} }

  const bottomRef = useRef(null);
  const inputRef = useRef(null);
  const socketRef = useRef(null);

  // ── Socket.IO for streaming agent steps ─────────────────────────────────────
  useEffect(() => {
    try {
      const serverUrl = import.meta.env.VITE_SOCKET_URL ||
        (import.meta.env.VITE_API_URL && import.meta.env.VITE_API_URL !== '/api'
          ? import.meta.env.VITE_API_URL.replace(/\/api$/, '')
          : (import.meta.env.DEV ? 'http://localhost:5000' : (typeof window !== 'undefined' ? window.location.origin : '')));
      // Read JWT from localStorage — same key used by AuthContext
      const token = localStorage.getItem('cs_token');
      const socket = socketIO(serverUrl, {
        auth: { token },
        transports: ['websocket', 'polling'],
      });
      socketRef.current = socket;

      // Listen for session-specific agent steps
      socket.on(`agent:step:${sessionId}`, (step) => {
        setLiveSteps(prev => {
          // Deduplicate by type+content+tool
          const key = `${step.type}-${step.tool || ''}-${step.iteration}`;
          const alreadyHas = prev.some(s => `${s.type}-${s.tool || ''}-${s.iteration}` === key);
          if (alreadyHas) return prev;
          return [...prev, step];
        });
      });

      socket.on('connect_error', (err) => {
        console.warn('[Assistant WS] Connection rejected:', err?.message);
      });

      return () => socket.disconnect();
    } catch (e) {
      // Socket.IO not available — graceful degradation
    }
  }, [sessionId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const send = useCallback(async (text) => {
    const trimmed = text?.trim();
    if (!trimmed || loading) return;

    const userMsgIndex = messages.length; // index of the bot reply about to be added
    setMessages(m => [...m, { role: 'user', text: trimmed }]);
    setInput('');
    setLoading(true);
    setLiveSteps([]);

    try {
      const { data } = await client.post('/chatbot/message', { message: trimmed, sessionId });
      const botMsgIndex = userMsgIndex + 1;

      setMsgSteps(prev => ({
        ...prev,
        [botMsgIndex]: { steps: data.steps || [], toolsUsed: data.toolsUsed || [] },
      }));

      if (data.mode) setAgentMode(data.mode);

      setMessages(m => [...m, {
        role: 'bot',
        text: data.reply,
        timestamp: new Date(),
        toolsUsed: data.toolsUsed || [],
        steps: data.steps || [],
        mode: data.mode,
      }]);
    } catch {
      setMessages(m => [...m, {
        role: 'bot',
        text: '[ERROR] Neural link disrupted. Check backend connection and retry.',
        isError: true,
      }]);
    } finally {
      setLoading(false);
      setLiveSteps([]);
    }
  }, [loading, messages.length, sessionId]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); }
  };

  const clearChat = async () => {
    try {
      await client.delete(`/chatbot/session/${sessionId}`);
    } catch {}
    setMessages([{ role: 'bot', text: 'Session cleared. My memory of our conversation has been reset. How can I help you?' }]);
    setMsgSteps({});
    setLiveSteps([]);
  };

  const copyMessage = (text) => { navigator.clipboard.writeText(text); };

  const threatColor = (score) => score >= 70 ? 'var(--accent-red)' : score >= 40 ? 'var(--accent-orange)' : '#f0c040';

  return (
    <div className="page">
      {/* HUD Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">NEURAL CORE · SENTINEL AGENT</div>
          <h2 className="hud-page-title">AGENTIC AI ANALYST</h2>
          <p className="hud-page-desc">
            ReAct-loop SOC agent with 18 live tools — reads data AND executes actions. Run scans, block IPs, simulate attacks, generate incident reports, and answer any question.
          </p>
        </div>
        <div className="hud-page-header-right" style={{ gap: 8 }}>
          <div className="hud-stat-badge" style={{ borderColor: connected ? 'var(--accent-green)' : 'var(--accent-red)', color: connected ? 'var(--accent-green)' : 'var(--accent-red)' }}>
            <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: connected ? 'var(--accent-green)' : 'var(--accent-red)', marginRight: 6, animation: 'pulse 2s infinite' }} />
            <span className="hud-stat-badge-label">AGENT</span>
            <span className="hud-stat-badge-value">{connected ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
          {agentMode && (
            <div className="hud-stat-badge" style={{ borderColor: agentMode === 'agentic' ? 'var(--accent-cyan)' : '#f0c040' }}>
              <span className="hud-stat-badge-label">MODE</span>
              <span className="hud-stat-badge-value" style={{ color: agentMode === 'agentic' ? 'var(--accent-cyan)' : '#f0c040' }}>
                {agentMode === 'agentic' ? '🤖 AGENTIC' : '📴 OFFLINE'}
              </span>
            </div>
          )}
          {systemMetrics && (
            <div className="hud-stat-badge" style={{ borderColor: threatColor(systemMetrics.threatScore) }}>
              <span className="hud-stat-badge-label">THREAT</span>
              <span className="hud-stat-badge-value" style={{ color: threatColor(systemMetrics.threatScore) }}>{systemMetrics.threatScore}/100</span>
            </div>
          )}
          {liveAttackCount > 0 && (
            <div className="hud-stat-badge" style={{ borderColor: 'var(--accent-red)' }}>
              <span className="hud-stat-badge-label">ATTACKS</span>
              <span className="hud-stat-badge-value" style={{ color: 'var(--accent-red)' }}>{liveAttackCount}</span>
            </div>
          )}
        </div>
      </div>

      {/* Live context ribbon */}
      {systemMetrics && (
        <div style={{
          display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16,
          padding: '8px 14px',
          background: 'linear-gradient(90deg, rgba(0,212,255,0.06), rgba(0,255,136,0.04))',
          border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8,
        }}>
          <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'Space Grotesk', letterSpacing: '0.1em', alignSelf: 'center', marginRight: 4 }}>AGENT TOOLS CONNECTED TO:</span>
          {[
            { label: '🖥️ System', val: `${systemMetrics.cpuUsage}% CPU · ${systemMetrics.memoryUsage}% RAM`, col: '#00d4ff' },
            { label: '⚠️ Threat', val: `${systemMetrics.threatScore}/100 ${systemMetrics.riskLevel}`, col: threatColor(systemMetrics.threatScore) },
            { label: '🔴 Attacks', val: `${liveAttackCount} detected`, col: '#ff4560' },
            { label: '📡 IOCs', val: `${intelStatus?.iocCount || 0} loaded`, col: '#00ff88' },
            { label: '💾 Session', val: sessionId.slice(-8), col: '#b47eff' },
          ].map(item => (
            <span key={item.label} style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 4, fontFamily: 'Space Grotesk',
              background: `${item.col}18`, color: item.col, border: `1px solid ${item.col}40`,
            }}>{item.label} <strong>{item.val}</strong></span>
          ))}
        </div>
      )}

      <div className="panel" style={{ padding: 0, display: 'flex', flexDirection: 'column', height: isExpanded ? '80vh' : 640, transition: 'height 0.3s ease' }}>

        {/* Chat toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-green)', boxShadow: '0 0 8px var(--accent-green)', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 11, fontFamily: 'Space Grotesk', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--accent-green)' }}>SENTINEL AGENT</span>
            <span style={{ fontSize: 10, color: 'var(--text-faint)', marginLeft: 4 }}>{messages.length - 1} messages · session …{sessionId.slice(-6)}</span>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button onClick={() => setIsExpanded(p => !p)} className="btn-outline" style={{ fontSize: 10, padding: '3px 8px' }}>
              {isExpanded ? '⊟ COLLAPSE' : '⊞ EXPAND'}
            </button>
            <button onClick={clearChat} className="btn-outline" style={{ fontSize: 10, padding: '3px 8px', color: 'var(--text-faint)', borderColor: 'var(--border)' }}>
              ✕ CLEAR SESSION
            </button>
          </div>
        </div>

        {/* Chat window */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 16px 8px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          {messages.map((m, i) => (
            <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: m.role === 'user' ? 'flex-end' : 'flex-start' }}>
              {/* Label */}
              <div style={{ fontSize: 9, fontFamily: 'Space Grotesk', letterSpacing: '0.12em', color: m.role === 'user' ? 'var(--accent-cyan)' : 'var(--accent-green)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                {m.role === 'bot' && <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--accent-green)', display: 'inline-block' }} />}
                {m.role === 'bot' ? 'SENTINEL AGENT' : 'OPERATOR INPUT'}
                {m.role === 'bot' && m.mode && (
                  <span style={{ fontSize: 9, padding: '0 5px', borderRadius: 3, background: m.mode === 'agentic' ? 'rgba(0,212,255,0.1)' : 'rgba(240,192,64,0.1)', color: m.mode === 'agentic' ? 'var(--accent-cyan)' : '#f0c040', border: `1px solid ${m.mode === 'agentic' ? 'rgba(0,212,255,0.3)' : 'rgba(240,192,64,0.3)'}` }}>
                    {m.mode === 'agentic' ? '🤖 AGENTIC' : '📴 OFFLINE'}
                  </span>
                )}
                {m.role === 'bot' && (
                  <button onClick={() => copyMessage(m.text)} title="Copy response" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-faint)', fontSize: 10, padding: '0 3px', marginLeft: 4 }}>⧉</button>
                )}
              </div>

              {/* Bubble */}
              <div style={{
                maxWidth: '90%',
                padding: m.role === 'bot' ? '12px 16px' : '9px 14px',
                borderRadius: m.role === 'user' ? '12px 12px 2px 12px' : '2px 12px 12px 12px',
                background: m.role === 'user'
                  ? 'linear-gradient(135deg, rgba(0,212,255,0.18), rgba(0,212,255,0.08))'
                  : m.isError ? 'rgba(255,70,96,0.1)' : 'var(--surface)',
                border: `1px solid ${m.role === 'user' ? 'rgba(0,212,255,0.3)' : m.isError ? 'rgba(255,70,96,0.3)' : 'var(--border)'}`,
                width: m.role === 'bot' ? '100%' : undefined,
              }}>
                {m.role === 'bot' ? renderMarkdown(m.text) : <p style={{ margin: 0, fontSize: 13, color: 'var(--text)' }}>{m.text}</p>}
              </div>

              {/* Agent steps panel (only for bot messages with steps or tools) */}
              {m.role === 'bot' && !m.isError && (m.toolsUsed?.length > 0 || m.steps?.length > 0) && (
                <div style={{ width: '100%', marginTop: 4 }}>
                  <AgentSteps
                    steps={m.steps || []}
                    toolsUsed={m.toolsUsed || []}
                    isStreaming={false}
                    liveSteps={null}
                  />
                </div>
              )}

              {m.timestamp && m.role === 'bot' && (
                <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 3 }}>
                  {m.timestamp.toLocaleTimeString()}
                </div>
              )}
            </div>
          ))}

          {/* Loading state — show live streaming agent steps */}
          {loading && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', width: '100%' }}>
              <div style={{ fontSize: 9, fontFamily: 'Space Grotesk', letterSpacing: '0.12em', color: 'var(--accent-green)', marginBottom: 4, display: 'flex', gap: 4, alignItems: 'center' }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--accent-green)', display: 'inline-block', animation: 'pulse 1s infinite' }} />
                SENTINEL AGENT
                <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>· {liveSteps.length > 0 ? `${liveSteps.length} step${liveSteps.length > 1 ? 's' : ''} complete` : 'thinking...'}</span>
              </div>

              <div style={{ width: '100%', padding: '12px 16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '2px 12px 12px 12px' }}>
                {liveSteps.length > 0 ? (
                  <AgentSteps
                    steps={[]}
                    toolsUsed={liveSteps.filter(s => s.type === 'action').map(s => s.tool)}
                    isStreaming={true}
                    liveSteps={liveSteps}
                  />
                ) : (
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    {[0, 1, 2].map(j => (
                      <span key={j} style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-green)', opacity: 0.7, animation: `pulse ${0.6 + j * 0.2}s ease-in-out infinite alternate` }} />
                    ))}
                    <span style={{ fontSize: 11, color: 'var(--text-faint)', fontFamily: 'Space Grotesk', marginLeft: 4 }}>🤖 Agent reasoning — selecting tools...</span>
                  </div>
                )}
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Quick Actions Tabs */}
        <div style={{ borderTop: '1px solid var(--border)', background: 'var(--bg)' }}>
          <div style={{ display: 'flex', overflowX: 'auto', borderBottom: '1px solid var(--border)', padding: '0 8px' }}>
            {QUICK_ACTIONS.map((tab, idx) => (
              <button
                key={idx}
                onClick={() => setActiveTab(idx)}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer', padding: '8px 14px',
                  fontSize: 10, fontFamily: 'Space Grotesk', fontWeight: 700, letterSpacing: '0.08em',
                  whiteSpace: 'nowrap', borderBottom: `2px solid ${activeTab === idx ? tab.color : 'transparent'}`,
                  color: activeTab === idx ? tab.color : 'var(--text-faint)',
                  transition: 'color 0.2s, border-color 0.2s',
                }}
              >{tab.icon} {tab.label}</button>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 6, padding: '8px 12px', overflowX: 'auto', flexWrap: 'nowrap' }}>
            {QUICK_ACTIONS[activeTab].prompts.map((prompt, idx) => (
              <button
                key={idx}
                onClick={() => send(prompt.text)}
                disabled={loading}
                style={{
                  background: `${QUICK_ACTIONS[activeTab].color}12`,
                  border: `1px solid ${QUICK_ACTIONS[activeTab].color}40`,
                  color: QUICK_ACTIONS[activeTab].color,
                  borderRadius: 6, cursor: loading ? 'not-allowed' : 'pointer',
                  padding: '5px 11px', fontSize: 11, fontFamily: 'Space Grotesk',
                  whiteSpace: 'nowrap', transition: 'all 0.2s', opacity: loading ? 0.5 : 1,
                  flexShrink: 0,
                }}
                onMouseEnter={e => !loading && (e.target.style.background = `${QUICK_ACTIONS[activeTab].color}28`)}
                onMouseLeave={e => (e.target.style.background = `${QUICK_ACTIONS[activeTab].color}12`)}
              >{prompt.icon} {prompt.text}</button>
            ))}
          </div>
        </div>

        {/* Input row */}
        <div style={{ borderTop: '1px solid var(--border)', padding: '10px 12px' }}>
          <form onSubmit={(e) => { e.preventDefault(); send(input); }} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--accent-cyan)', fontSize: 12, fontFamily: 'monospace', pointerEvents: 'none' }}>▷</span>
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask the agent — it will reason, call tools, and synthesize a grounded answer..."
                rows={1}
                style={{
                  width: '100%', paddingLeft: 30, paddingTop: 9, paddingBottom: 9, paddingRight: 12,
                  background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6,
                  color: 'var(--text)', fontSize: 12, resize: 'none', fontFamily: 'inherit',
                  outline: 'none', lineHeight: 1.5,
                }}
                onFocus={e => e.target.style.borderColor = 'var(--accent-cyan)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
            </div>
            <button type="submit" className="btn-primary" disabled={loading || !input.trim()} style={{ width: 'auto', minWidth: 90, height: 38, fontSize: 11, letterSpacing: '0.06em' }}>
              {loading ? '⟳' : '▷ SEND'}
            </button>
          </form>
          <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 5, fontFamily: 'Space Grotesk', textAlign: 'right' }}>
            Enter to send · Shift+Enter for new line · ReAct agent with 8 live tools · session memory active
          </div>
        </div>
      </div>
    </div>
  );
}
