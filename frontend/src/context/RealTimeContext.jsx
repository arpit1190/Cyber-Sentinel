/**
 * RealTimeContext.jsx
 * Global Socket.IO connection shared across all pages.
 * Provides live system metrics, attack events, and timeline data.
 */
import { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';

const RealTimeContext = createContext(null);

const getSocketUrl = () => {
  if (import.meta.env.VITE_SOCKET_URL) return import.meta.env.VITE_SOCKET_URL;
  if (import.meta.env.VITE_API_URL && import.meta.env.VITE_API_URL !== '/api') {
    return import.meta.env.VITE_API_URL.replace(/\/api$/, '');
  }
  if (import.meta.env.DEV) {
    return 'http://localhost:5000';
  }
  if (typeof window !== 'undefined' && window.location.origin) {
    return window.location.origin;
  }
  return '';
};

const SOCKET_URL = getSocketUrl();
const MAX_FEED_EVENTS = 60; // Rolling window of last 60 attacks
const MAX_TIMELINE_BUCKETS = 24;

const INITIAL_SYSTEM_METRICS = null;
const INITIAL_ATTACK_FEED = [];

const INITIAL_TIMELINE = Array.from({ length: 24 }, (_, i) => {
  const d = new Date(Date.now() - (23 - i) * 30 * 60 * 1000);
  return {
    hour: `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`,
    attacks: 0,
    blocked: 0,
  };
});

const normalizeAttack = (a) => {
  if (!a) return a;
  const ip = a.ip || a.sourceIp || 'Unknown IP';
  const location = a.location || (a.city && a.country ? `${a.city}, ${a.country}` : a.country || 'External Sensor');
  return {
    ...a,
    ip,
    sourceIp: a.sourceIp || ip,
    location,
    timestamp: a.timestamp || a.observedAt || new Date().toISOString(),
    dataSource: a.dataSource || (a.isSimulation ? 'Cyber Sentinel Simulator' : 'ThreatFox'),
    dataType: a.dataType || (a.isSimulation ? 'SIMULATION' : 'IOC'),
    isSimulation: Boolean(a.isSimulation),
  };
};

export function RealTimeProvider({ children }) {
  const { token } = useAuth();
  const socketRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const [connectionState, setConnectionState] = useState('connecting'); // 'connected' | 'connecting' | 'reconnecting'

  // ── Shared Real-Time State (Strictly telemetry-driven, no mocked initial values) ──
  const [systemMetrics, setSystemMetrics] = useState(INITIAL_SYSTEM_METRICS); // CPU, RAM, threat score
  const [attackFeed, setAttackFeed] = useState(INITIAL_ATTACK_FEED);           // Rolling live attack events
  const [timeline, setTimeline] = useState(INITIAL_TIMELINE);                 // 24-bucket attack volume chart
  const [linkedDevices, setLinkedDevices] = useState([]);                     // Real network adapters
  const [systemFindings, setSystemFindings] = useState([]);                   // Security findings
  const [criticalAlert, setCriticalAlert] = useState(null);                   // Latest critical alert
  const [blockedCount, setBlockedCount] = useState(0);                        // Cumulative blocked counter
  const [attacksPerMinute, setAttacksPerMinute] = useState(0);                // Rolling APM
  const [liveAttackCount, setLiveAttackCount] = useState(0);                  // Cumulative live attacks
  const [intelStatus, setIntelStatus] = useState({ source: 'ThreatFox & CISA KEV', iocCount: 0, lastSync: new Date().toISOString() });
  const [listeningPorts, setListeningPorts] = useState([]);                    // Real open ports on this machine

  const [latencyMs, setLatencyMs] = useState(0);
  const [soundEnabled, setSoundEnabled] = useState(false);

  function playCyberAlertBeep() {
    if (!soundEnabled) return;
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, audioCtx.currentTime);
      gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.35);
    } catch (e) {
      // Audio context may be restricted by autoplay policy
    }
  }

  const blockIp = useCallback((ip) => {
    if (socketRef.current) {
      socketRef.current.emit('attack:block_ip', { ip });
    }
    setAttackFeed(prev => prev.map(a => (a.sourceIp === ip || a.ip === ip) ? { ...a, blocked: true } : a));
    setBlockedCount(prev => prev + 1);
  }, []);

  const simulateAttackWave = useCallback((count = 3) => {
    if (socketRef.current && connected) {
      socketRef.current.emit('attack:simulate', { count });
    } else {
      console.warn('[RealTime] Simulation requires an active WebSocket telemetry connection to the backend engine.');
    }
  }, [connected]);

  // Track attacks per minute using a sliding window
  const attackTimestamps = useRef([]);
  const updateApm = useCallback(() => {
    const now = Date.now();
    attackTimestamps.current = attackTimestamps.current.filter(t => now - t < 60000);
    setAttacksPerMinute(attackTimestamps.current.length);
  }, []);

  useEffect(() => {
    // Only connect when authenticated
    if (!token) return;

    let socket = null;
    let active = true;
    let pingInterval = null;

    const initSocket = () => {
      setConnectionState('connecting');

      socket = io(SOCKET_URL, {
        auth: { token },
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        timeout: 10000,
      });
      socketRef.current = socket;

      socket.on('connect', () => {
        setConnected(true);
        setConnectionState('connected');
        console.log('[WS] Connected to real-time engine at:', SOCKET_URL);

        // Measure live round-trip latency every 3 seconds
        pingInterval = setInterval(() => {
          const start = Date.now();
          socket.emit('custom:ping', () => {
            const rtt = Date.now() - start;
            setLatencyMs(rtt);
          });
        }, 3000);
      });

      socket.on('disconnect', () => {
        setConnected(false);
        setConnectionState('reconnecting');
        if (pingInterval) clearInterval(pingInterval);
        console.log('[WS] Disconnected — attempting reconnect...');
      });

      socket.on('connect_error', (err) => {
        console.warn('[WS] Telemetry link retry:', err?.message || err);
        setConnectionState('connecting');
      });

      // ── REAL-TIME EVENTS ──

      // Initial attack history on connect
      socket.on('attack:history', (history) => {
        if (Array.isArray(history)) {
          setAttackFeed(history.map(normalizeAttack));
        }
      });

      // System metrics: CPU, RAM, threat score, network health, live counters — every 2s
      socket.on('system:metrics', (data) => {
        setSystemMetrics(data);
        if (data.liveAttackCount !== undefined) {
          setLiveAttackCount(data.liveAttackCount);
        }
        if (data.blockedToday !== undefined) {
          setBlockedCount(data.blockedToday);
        }
      });

      // New attack event
      socket.on('attack:event', (rawAttack) => {
        const attack = normalizeAttack(rawAttack);
        attackTimestamps.current.push(Date.now());
        updateApm();
        if (attack.severity === 'CRITICAL') {
          playCyberAlertBeep();
        }
        setAttackFeed(prev => {
          const updated = [attack, ...prev.filter(a => a.id !== attack.id)].slice(0, MAX_FEED_EVENTS);
          return updated;
        });
        setLiveAttackCount(prev => prev + 1);
        if (attack.blocked) {
          setBlockedCount(prev => prev + 1);
        }
      });

      // IP blocked broadcast
      socket.on('attack:ip_blocked', ({ ip, blockedCount: newBlocked }) => {
        setAttackFeed(prev => prev.map(a => (a.sourceIp === ip || a.ip === ip) ? { ...a, blocked: true } : a));
        if (newBlocked !== undefined) {
          setBlockedCount(newBlocked);
        }
      });

      // Full timeline on initial connect
      socket.on('timeline:full', (data) => {
        setTimeline(data.slice(-MAX_TIMELINE_BUCKETS));
      });

      // Rolling timeline update — every 30s
      socket.on('timeline:update', ({ timeline: newTimeline }) => {
        setTimeline(newTimeline.slice(-MAX_TIMELINE_BUCKETS));
      });

      // Real network adapters — every 10s
      socket.on('linked:devices', (devices) => {
        setLinkedDevices(devices);
      });

      // Security findings from OS scan
      socket.on('system:findings', (findings) => {
        setSystemFindings(findings);
      });

      // Live threat intelligence status — emitted on connect
      socket.on('intel:status', (status) => {
        setIntelStatus(status);
        console.log('[WS] Threat intel source:', status.source, '| IOCs:', status.iocCount);
      });

      // Real listening ports on this machine
      socket.on('system:ports', ({ listeningPorts: ports, connectionCount }) => {
        if (Array.isArray(ports)) setListeningPorts(ports);
      });

      // Critical alert (threatScore >= 60 + high severity finding)
      socket.on('alert:critical', (alert) => {
        setCriticalAlert(alert);
        playCyberAlertBeep();
        // Auto-clear after 8 seconds
        setTimeout(() => setCriticalAlert(null), 8000);
      });
    };

    initSocket();

    return () => {
      active = false;
      if (pingInterval) clearInterval(pingInterval);
      if (socket) {
        socket.disconnect();
      }
      socketRef.current = null;
      setConnected(false);
    };
  }, [token, updateApm, soundEnabled]);

  // APM decay timer
  useEffect(() => {
    const interval = setInterval(updateApm, 5000);
    return () => clearInterval(interval);
  }, [updateApm]);



  const value = {
    connected,
    connectionState,
    latencyMs,
    systemMetrics,
    attackFeed,
    timeline,
    linkedDevices,
    systemFindings,
    criticalAlert,
    blockedCount,
    attacksPerMinute,
    liveAttackCount,
    intelStatus,
    listeningPorts,
    soundEnabled,
    setSoundEnabled,
    blockIp,
    simulateAttackWave,
  };

  return (
    <RealTimeContext.Provider value={value}>
      {children}
    </RealTimeContext.Provider>
  );
}

export function useRealTime() {
  const ctx = useContext(RealTimeContext);
  if (!ctx) throw new Error('useRealTime must be used inside RealTimeProvider');
  return ctx;
}
