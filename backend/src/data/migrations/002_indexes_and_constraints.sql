-- Migration 002: Production Indexes & Query Optimization
-- Cyber Sentinel Database Performance Layer

-- 1. Users & Auth Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens (expires_at) WHERE revoked_at IS NULL;

-- 2. Telemetry & Events Indexes
CREATE INDEX IF NOT EXISTS idx_telemetry_event_id ON telemetry_events (event_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_type_time ON telemetry_events (event_type, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_source_ip ON telemetry_events (source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_telemetry_device_id ON telemetry_events (device_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_ingested_at ON telemetry_events (ingested_at DESC);

-- 3. SIEM Incidents & Detections Indexes
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assignee_id ON incidents (assignee_id);
CREATE INDEX IF NOT EXISTS idx_incidents_related_ips ON incidents USING GIN (related_ips);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident_id ON incident_events (incident_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detections_rule_time ON detections (rule_id, created_at DESC);

-- 4. Threat Intel & Indicators Indexes
CREATE INDEX IF NOT EXISTS idx_threat_indicators_lookup ON threat_indicators (indicator_type, LOWER(value));
CREATE INDEX IF NOT EXISTS idx_threat_indicators_severity ON threat_indicators (severity);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators (is_active);

-- 5. Malware Analysis Indexes
CREATE INDEX IF NOT EXISTS idx_malware_samples_sha256 ON malware_samples (sha256);
CREATE INDEX IF NOT EXISTS idx_malware_analysis_sha256 ON malware_analysis_results (sha256);
CREATE INDEX IF NOT EXISTS idx_malware_analysis_score ON malware_analysis_results (score DESC);
CREATE INDEX IF NOT EXISTS idx_malware_analysis_analyzed_at ON malware_analysis_results (analyzed_at DESC);

-- 6. Response Actions & Containment Indexes
CREATE INDEX IF NOT EXISTS idx_response_actions_target ON response_actions (target) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_response_actions_incident_id ON response_actions (incident_id);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_active ON firewall_rules (active);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_ip ON firewall_rules (ip);

-- 7. Audit Logs Indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_source_ip ON audit_logs (source_ip);

-- 8. Device Endpoint Security Indexes
CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices (hostname);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices (status);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_device_credentials_token_hash ON device_credentials (token_hash);
