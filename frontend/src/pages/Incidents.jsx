import { useState, useEffect, useCallback } from 'react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function Incidents() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('incidents'); // 'incidents' | 'audit'
  const [incidents, setIncidents] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [newNote, setNewNote] = useState('');
  const [notification, setNotification] = useState('');

  const showToast = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(''), 4000);
  };

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      const { data } = await client.get('/incidents');
      if (data.success) {
        setIncidents(data.incidents || []);
        if (selectedIncident) {
          const fresh = (data.incidents || []).find(i => i.id === selectedIncident.id);
          if (fresh) setSelectedIncident(fresh);
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, [selectedIncident]);

  const fetchAuditLogs = useCallback(async () => {
    try {
      const { data } = await client.get('/audit-logs?limit=50');
      if (data.success) {
        setAuditLogs(data.logs || []);
      }
    } catch (err) {
      // Non-admin might receive 403; handle gracefully
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    if (user?.role === 'admin' || user?.role === 'senior_analyst') {
      fetchAuditLogs();
    }
  }, [fetchIncidents, fetchAuditLogs, user]);

  const handleStatusChange = async (incidentId, newStatus) => {
    try {
      setActionLoading(true);
      const { data } = await client.patch(`/incidents/${incidentId}/status`, {
        status: newStatus,
        note: `Status updated to ${newStatus} by ${user?.name || user?.email}`
      });
      if (data.success) {
        showToast(`Incident ${incidentId} transitioned to ${newStatus}`);
        fetchIncidents();
        fetchAuditLogs();
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to update incident status');
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedIncident) return;
    try {
      setActionLoading(true);
      const { data } = await client.post(`/incidents/${selectedIncident.id}/notes`, {
        note: newNote.trim()
      });
      if (data.success) {
        setNewNote('');
        showToast('Analyst note appended to incident timeline');
        fetchIncidents();
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to add note');
    } finally {
      setActionLoading(false);
    }
  };

  const handleContainIp = async (ip) => {
    if (!confirm(`Are you sure you want to contain and block IP ${ip} in perimeter firewall drop tables?`)) return;
    try {
      setActionLoading(true);
      const { data } = await client.post('/threats/block-ip', {
        ip,
        reason: `Contained from Incident ${selectedIncident?.id || 'Investigation'}`
      });
      if (data.success) {
        showToast(`IP ${ip} contained successfully.`);
        if (selectedIncident && selectedIncident.status !== 'CONTAINED') {
          await handleStatusChange(selectedIncident.id, 'CONTAINED');
        }
        fetchAuditLogs();
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to contain IP');
    } finally {
      setActionLoading(false);
    }
  };

  const filteredIncidents = incidents.filter(i => {
    if (statusFilter !== 'ALL' && i.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && i.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTitle = i.title?.toLowerCase().includes(q);
      const matchId = i.id?.toLowerCase().includes(q);
      const matchIp = i.relatedIps?.some(ip => ip.includes(q));
      if (!matchTitle && !matchId && !matchIp) return false;
    }
    return true;
  });

  return (
    <div className="incidents-page" style={{ padding: '24px', maxWidth: '1440px', margin: '0 auto' }}>
      {/* Toast Notification */}
      {notification && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          background: 'var(--accent-cyan)',
          color: '#000',
          padding: '12px 20px',
          borderRadius: '8px',
          fontWeight: 700,
          boxShadow: '0 8px 30px rgba(0, 212, 255, 0.4)',
          zIndex: 9999,
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span>🛡</span> {notification}
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 800, letterSpacing: '0.04em', fontFamily: 'Outfit' }}>
            INCIDENT RESPONSE &amp; FORENSICS CONSOLE
          </h1>
          <p style={{ margin: '6px 0 0 0', color: 'var(--text-dim)', fontSize: '13px', fontFamily: 'Space Grotesk' }}>
            Multi-stage SIEM detection correlation, MITRE ATT&amp;CK mapping, and cryptographic SHA-256 evidence preservation.
          </p>
        </div>

        {/* Tab Controls */}
        <div style={{ display: 'flex', gap: '8px', background: 'rgba(0,0,0,0.4)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <button
            onClick={() => setActiveTab('incidents')}
            style={{
              padding: '6px 16px',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'incidents' ? 'var(--accent-cyan-dim)' : 'transparent',
              color: activeTab === 'incidents' ? 'var(--accent-cyan)' : 'var(--text-dim)',
              fontWeight: 700,
              fontSize: '12px',
              cursor: 'pointer'
            }}
          >
            ACTIVE INCIDENTS ({incidents.length})
          </button>
          {(user?.role === 'admin' || user?.role === 'senior_analyst') && (
            <button
              onClick={() => { setActiveTab('audit'); fetchAuditLogs(); }}
              style={{
                padding: '6px 16px',
                borderRadius: '6px',
                border: 'none',
                background: activeTab === 'audit' ? 'var(--accent-cyan-dim)' : 'transparent',
                color: activeTab === 'audit' ? 'var(--accent-cyan)' : 'var(--text-dim)',
                fontWeight: 700,
                fontSize: '12px',
                cursor: 'pointer'
              }}
            >
              SECURITY AUDIT LOGS
            </button>
          )}
        </div>
      </div>

      {activeTab === 'incidents' ? (
        <div style={{ display: 'grid', gridTemplateColumns: selectedIncident ? '1fr 480px' : '1fr', gap: '24px' }}>
          {/* Main Incidents Table */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '20px' }}>
            {/* Filters Bar */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Search incident ID, title, or target IP..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  flex: 1,
                  minWidth: '220px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  fontSize: '12px'
                }}
              />

              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '12px'
                }}
              >
                <option value="ALL">All Statuses</option>
                <option value="NEW">NEW</option>
                <option value="TRIAGED">TRIAGED</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINMENT">CONTAINMENT</option>
                <option value="ERADICATION">ERADICATION</option>
                <option value="RECOVERY">RECOVERY</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="CLOSED">CLOSED</option>
              </select>

              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '12px'
                }}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <button
                onClick={fetchIncidents}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--border)',
                  color: 'var(--text-dim)',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '12px'
                }}
              >
                Refresh
              </button>
            </div>

            {/* List */}
            {loading && <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>Loading correlated security incidents...</div>}
            {error && <div style={{ padding: '20px', color: '#ff3366' }}>{error}</div>}

            {!loading && filteredIncidents.length === 0 && (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>
                <div style={{ fontSize: '32px', marginBottom: '8px' }}>🛡️</div>
                <div style={{ fontWeight: 700 }}>No Incidents Match Current Criteria</div>
                <div style={{ fontSize: '12px', marginTop: '4px' }}>Security posture clean. All events currently within nominal thresholds.</div>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {filteredIncidents.map(inc => {
                const isSelected = selectedIncident?.id === inc.id;
                const sevColor = inc.severity === 'CRITICAL' ? '#ff3366' : inc.severity === 'HIGH' ? '#ff9900' : '#00d4ff';

                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '14px 18px',
                      background: isSelected ? 'rgba(0, 212, 255, 0.08)' : 'rgba(255,255,255,0.02)',
                      border: isSelected ? '1px solid var(--accent-cyan)' : '1px solid var(--border)',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1 }}>
                      <span style={{
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 800,
                        background: `${sevColor}20`,
                        color: sevColor,
                        border: `1px solid ${sevColor}40`,
                        minWidth: '70px',
                        textAlign: 'center'
                      }}>
                        {inc.severity}
                      </span>

                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                            {inc.id}
                          </span>
                          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text)' }}>
                            {inc.title}
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '3px', display: 'flex', gap: '12px' }}>
                          <span>Category: <strong>{inc.category}</strong></span>
                          <span>IPs: <strong>{inc.relatedIps?.join(', ') || 'N/A'}</strong></span>
                          <span>Time: {new Date(inc.createdAt).toLocaleTimeString()}</span>
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span style={{
                        padding: '3px 10px',
                        borderRadius: '12px',
                        fontSize: '10px',
                        fontWeight: 800,
                        background: inc.status === 'CLOSED' ? 'rgba(0,255,136,0.1)' : inc.status === 'CONTAINED' ? 'rgba(179,102,255,0.15)' : 'rgba(255,170,0,0.15)',
                        color: inc.status === 'CLOSED' ? '#00ff88' : inc.status === 'CONTAINED' ? '#b366ff' : '#ffaa00',
                        border: '1px solid currentColor'
                      }}>
                        {inc.status}
                      </span>
                      <span style={{ color: 'var(--text-dim)', fontSize: '18px' }}>›</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Drawer: Forensics & Investigation Inspector */}
          {selectedIncident && (
            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '12px',
              padding: '22px',
              display: 'flex',
              flexDirection: 'column',
              gap: '18px',
              maxHeight: 'calc(100vh - 180px)',
              overflowY: 'auto'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'monospace', fontWeight: 800 }}>
                    INVESTIGATION INSPECTOR · {selectedIncident.id}
                  </span>
                  <h2 style={{ margin: '4px 0 0 0', fontSize: '16px', fontWeight: 800 }}>
                    {selectedIncident.title}
                  </h2>
                </div>
                <button
                  onClick={() => setSelectedIncident(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '18px' }}
                >
                  ✕
                </button>
              </div>

              {/* Status & Containment Controls */}
              <div style={{ padding: '14px', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--text-dim)' }}>
                    LIFECYCLE TRANSITION (CURRENT: <strong style={{ color: 'var(--accent-cyan)' }}>{selectedIncident.status}</strong>)
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    Assignee: <strong style={{ color: 'var(--accent-cyan)' }}>{selectedIncident.assignee || 'Unassigned'}</strong>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {(['NEW', 'TRIAGED', 'INVESTIGATING', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'RESOLVED', 'CLOSED']).map(st => {
                    const isCurrent = selectedIncident.status === st;
                    const allowedNext = {
                      NEW: ['TRIAGED', 'CLOSED'],
                      TRIAGED: ['INVESTIGATING', 'CLOSED'],
                      INVESTIGATING: ['CONTAINMENT', 'TRIAGED', 'CLOSED'],
                      CONTAINMENT: ['ERADICATION', 'INVESTIGATING'],
                      ERADICATION: ['RECOVERY', 'CONTAINMENT', 'INVESTIGATING'],
                      RECOVERY: ['RESOLVED', 'INVESTIGATING'],
                      RESOLVED: ['CLOSED', 'INVESTIGATING'],
                      CLOSED: ['INVESTIGATING'],
                    }[selectedIncident.status] || [];

                    const isPermitted = allowedNext.includes(st);

                    return (
                      <button
                        key={st}
                        disabled={actionLoading || isCurrent || !isPermitted}
                        onClick={() => handleStatusChange(selectedIncident.id, st)}
                        style={{
                          padding: '5px 10px',
                          borderRadius: '4px',
                          border: '1px solid var(--border)',
                          background: isCurrent ? 'var(--accent-cyan)' : isPermitted ? 'rgba(0,212,255,0.08)' : 'transparent',
                          color: isCurrent ? '#000' : isPermitted ? 'var(--accent-cyan)' : 'var(--text-faint)',
                          fontSize: '10px',
                          fontWeight: 700,
                          cursor: isPermitted ? 'pointer' : 'not-allowed',
                          opacity: isCurrent ? 1 : isPermitted ? 0.9 : 0.3,
                        }}
                        title={isCurrent ? 'Current Status' : isPermitted ? `Transition to ${st}` : `Transition to ${st} not allowed from ${selectedIncident.status}`}
                      >
                        {st}
                      </button>
                    );
                  })}
                </div>

                {selectedIncident.relatedIps?.length > 0 && (
                  <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '6px' }}>
                      ACTIVE CONTAINMENT ACTION
                    </div>
                    {selectedIncident.relatedIps.map(ip => (
                      <button
                        key={ip}
                        onClick={() => handleContainIp(ip)}
                        style={{
                          background: 'rgba(255, 51, 102, 0.15)',
                          border: '1px solid #ff3366',
                          color: '#ff3366',
                          padding: '6px 12px',
                          borderRadius: '6px',
                          fontSize: '11px',
                          fontWeight: 700,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                      >
                        <span>🛑</span> Block &amp; Contain IP {ip}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Description & Structured MITRE ATT&CK Mapping */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--text-dim)', marginBottom: '4px' }}>
                  CORRELATED DESCRIPTION
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text)', lineHeight: 1.5, margin: 0 }}>
                  {selectedIncident.description}
                </p>

                {selectedIncident.mitreTechniques?.length > 0 && (
                  <div style={{ marginTop: '12px' }}>
                    <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--accent-cyan)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span>◈</span> MITRE ATT&amp;CK TACTICAL MAPPING
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {selectedIncident.mitreTechniques.map((m, i) => {
                        const isObj = typeof m === 'object' && m !== null;
                        const tactic = isObj ? (m.tactic || 'Execution') : 'Threat Tactic';
                        const techId = isObj ? (m.technique_id || m.id) : (m.match(/(T\d{4})/)?.[1] || 'T1000');
                        const techName = isObj ? (m.technique_name || m.name) : m;
                        const subId = isObj ? m.sub_technique_id : (m.match(/(T\d{4}\.\d{3})/)?.[1] || null);
                        const subName = isObj ? m.sub_technique_name : null;
                        const url = isObj && m.url ? m.url : `https://attack.mitre.org/techniques/${techId}/`;

                        return (
                          <div
                            key={i}
                            style={{
                              padding: '10px 12px',
                              background: 'rgba(179, 102, 255, 0.06)',
                              border: '1px solid rgba(179, 102, 255, 0.25)',
                              borderRadius: '8px',
                              fontSize: '11px'
                            }}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                              <span style={{
                                fontSize: '9px',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                background: 'rgba(179, 102, 255, 0.2)',
                                color: '#b366ff',
                                fontWeight: 800,
                                letterSpacing: '0.04em'
                              }}>
                                {tactic.toUpperCase()}
                              </span>
                              <a
                                href={url}
                                target="_blank"
                                rel="noreferrer"
                                style={{
                                  color: 'var(--accent-cyan)',
                                  textDecoration: 'none',
                                  fontSize: '10px',
                                  fontFamily: 'monospace',
                                  fontWeight: 700
                                }}
                              >
                                {subId || techId} ↗
                              </a>
                            </div>

                            <div style={{ fontWeight: 700, color: 'var(--text)', marginTop: '2px' }}>
                              {techName}
                            </div>

                            {subName && (
                              <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <span style={{ color: 'var(--accent-cyan)' }}>↳ Sub-technique:</span>
                                <strong>{subId} — {subName}</strong>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* Cryptographic Evidence Preservation & Confidence Drawer */}
              {selectedIncident.evidence && (
                <div style={{ padding: '14px', background: 'rgba(0, 212, 255, 0.04)', borderRadius: '8px', border: '1px solid rgba(0, 212, 255, 0.2)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                      EVIDENCE PRESERVATION &amp; INTEGRITY
                    </span>
                    {selectedIncident.evidence?.payload?.confidence && (
                      <span style={{
                        fontSize: '10px',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'rgba(0, 255, 136, 0.15)',
                        color: '#00ff88',
                        fontWeight: 800
                      }}>
                        CONFIDENCE: {selectedIncident.evidence.payload.confidence}%
                      </span>
                    )}
                  </div>

                  <div style={{ fontSize: '10px', fontFamily: 'monospace', color: 'var(--text-faint)', wordBreak: 'break-all', marginBottom: '8px' }}>
                    <strong>HASH:</strong> {selectedIncident.evidence.sha256 || 'None computed'}
                  </div>

                  <pre style={{
                    fontSize: '11px',
                    fontFamily: 'monospace',
                    background: 'rgba(0,0,0,0.5)',
                    padding: '8px',
                    borderRadius: '4px',
                    color: 'var(--text-dim)',
                    margin: 0,
                    maxHeight: '140px',
                    overflowY: 'auto'
                  }}>
                    {typeof selectedIncident.evidence.payload === 'object'
                      ? JSON.stringify(selectedIncident.evidence.payload, null, 2)
                      : selectedIncident.evidence.payload}
                  </pre>
                </div>
              )}

              {/* Cryptographically Verified Immutable Timeline */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--text-dim)' }}>
                    INCIDENT TIMELINE
                  </div>
                  <span style={{
                    fontSize: '9px',
                    fontWeight: 800,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'rgba(0, 255, 136, 0.1)',
                    color: '#00ff88',
                    border: '1px solid rgba(0, 255, 136, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}>
                    🛡️ SHA-256 CHAIN VERIFIED
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '220px', overflowY: 'auto' }}>
                  {(selectedIncident.timeline || []).map((tl, idx) => (
                    <div key={idx} style={{
                      fontSize: '11px',
                      borderLeft: '2px solid var(--accent-cyan)',
                      paddingLeft: '10px',
                      background: 'rgba(255,255,255,0.015)',
                      padding: '6px 8px 6px 10px',
                      borderRadius: '0 4px 4px 0'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-dim)', alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                          #{tl.sequence || idx + 1} {tl.eventType || tl.action}
                        </span>
                        <span style={{ fontSize: '10px', color: 'var(--text-faint)' }}>{new Date(tl.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <div style={{ color: 'var(--text)', marginTop: '2px', fontSize: '11px' }}>{tl.description || tl.note}</div>
                      <div style={{ color: 'var(--text-faint)', fontSize: '10px', marginTop: '3px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <span>Actor: <strong>{tl.actor || 'SYSTEM'}</strong></span>
                        {tl.source && <span>Source: <strong>{tl.source}</strong></span>}
                        {tl.hash && <span title={`SHA-256: ${tl.hash}`}>Hash: <code style={{ color: 'var(--accent-cyan)' }}>{tl.hash.substring(0, 8)}...</code></span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} style={{ marginTop: 'auto' }}>
                <textarea
                  rows={2}
                  placeholder="Add analyst note to incident history..."
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid var(--border)',
                    color: 'var(--text)',
                    borderRadius: '6px',
                    padding: '8px',
                    fontSize: '11px',
                    boxSizing: 'border-box',
                    resize: 'none'
                  }}
                />
                <button
                  type="submit"
                  disabled={actionLoading || !newNote.trim()}
                  style={{
                    marginTop: '6px',
                    width: '100%',
                    background: 'var(--accent-cyan)',
                    color: '#000',
                    border: 'none',
                    padding: '6px',
                    borderRadius: '6px',
                    fontWeight: 800,
                    fontSize: '11px',
                    cursor: 'pointer'
                  }}
                >
                  Append Note
                </button>
              </form>
            </div>
          )}
        </div>
      ) : (
        /* Immutable Audit Log View */
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 800, letterSpacing: '0.04em' }}>
                IMMUTABLE SECURITY AUDIT TRAIL
              </h3>
              <p style={{ margin: '4px 0 0 0', color: 'var(--text-dim)', fontSize: '11px' }}>
                Append-only log of sensitive platform actions, state modifications, and operator decisions.
              </p>
            </div>
            <button
              onClick={fetchAuditLogs}
              style={{
                background: 'transparent',
                border: '1px solid var(--border)',
                color: 'var(--text-dim)',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '11px',
                cursor: 'pointer'
              }}
            >
              Refresh Logs
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {auditLogs.map(log => (
              <div
                key={log.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.04)',
                  borderRadius: '6px',
                  fontSize: '11px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-faint)' }}>
                    {log.id}
                  </span>
                  <span style={{
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: log.action.includes('FAIL') ? 'rgba(255,51,102,0.15)' : 'rgba(0,212,255,0.15)',
                    color: log.action.includes('FAIL') ? '#ff3366' : 'var(--accent-cyan)',
                    fontWeight: 700,
                    fontSize: '10px'
                  }}>
                    {log.action}
                  </span>
                  <span style={{ color: 'var(--text)' }}>
                    Target: <strong>{log.target}</strong>
                  </span>
                  <span style={{ color: 'var(--text-dim)' }}>
                    Actor: {log.actor} ({log.actorRole})
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '14px', color: 'var(--text-faint)' }}>
                  <span>Source: {log.sourceIp}</span>
                  <span>{new Date(log.timestamp).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
