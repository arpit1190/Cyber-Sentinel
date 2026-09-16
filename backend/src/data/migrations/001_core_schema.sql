-- Migration 001: Core Production PostgreSQL Schema
-- Cyber Sentinel Enterprise SOC Platform

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Roles Table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Permissions Table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Role Permissions Mapping
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- 4. Users Table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'ANALYST',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret VARCHAR(128),
    phone VARCHAR(32),
    is_email_verified BOOLEAN DEFAULT TRUE,
    is_phone_verified BOOLEAN DEFAULT TRUE,
    must_change_password BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Refresh Tokens Table (Secure Session Management)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    ip_address VARCHAR(64),
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Devices Table (Enrolled Telemetry Endpoints)
CREATE TABLE IF NOT EXISTS devices (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255),
    platform VARCHAR(128),
    hostname VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    agent_version VARCHAR(32),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Device Credentials Table
CREATE TABLE IF NOT EXISTS device_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    key_identifier VARCHAR(64),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Detection Rules Table
CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    category VARCHAR(64) NOT NULL DEFAULT 'THREAT_DETECTION',
    mitre_technique VARCHAR(64),
    rule_type VARCHAR(64) NOT NULL DEFAULT 'STATEFUL_CORRELATION',
    parameters JSONB DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. Telemetry Events Table
CREATE TABLE IF NOT EXISTS telemetry_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(64) UNIQUE NOT NULL,
    device_id VARCHAR(64) REFERENCES devices(id) ON DELETE SET NULL,
    event_type VARCHAR(64) NOT NULL,
    source VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    source_ip VARCHAR(64),
    source_port INTEGER,
    dest_ip VARCHAR(64),
    dest_port INTEGER,
    protocol VARCHAR(16) DEFAULT 'TCP',
    process_name VARCHAR(255),
    command_line TEXT,
    user_identity VARCHAR(255),
    is_simulation BOOLEAN DEFAULT FALSE,
    raw_payload JSONB DEFAULT '{}'::jsonb,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 10. Detections Table
CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(64) REFERENCES detection_rules(id) ON DELETE SET NULL,
    event_id VARCHAR(64) REFERENCES telemetry_events(event_id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    source_ip VARCHAR(64),
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 11. Incidents Table (Full Response Lifecycle)
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    category VARCHAR(64) NOT NULL DEFAULT 'THREAT_DETECTION',
    status VARCHAR(32) NOT NULL DEFAULT 'NEW',
    description TEXT,
    assignee VARCHAR(255) DEFAULT 'Unassigned',
    assignee_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    related_ips JSONB DEFAULT '[]'::jsonb,
    related_alerts JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '{}'::jsonb,
    evidence_hash VARCHAR(64),
    timeline JSONB DEFAULT '[]'::jsonb,
    created_by VARCHAR(255) DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 12. Incident Events Table (Forensic Audit Chain)
CREATE TABLE IF NOT EXISTS incident_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action VARCHAR(64) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    note TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 13. Threat Indicators Table (Indexed Threat Intelligence)
CREATE TABLE IF NOT EXISTS threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type VARCHAR(32) NOT NULL,
    value VARCHAR(255) NOT NULL,
    malware_family VARCHAR(255),
    threat_type VARCHAR(64),
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    confidence INTEGER NOT NULL DEFAULT 90,
    mitre_technique VARCHAR(64),
    source VARCHAR(64) NOT NULL DEFAULT 'ThreatFox',
    reporter VARCHAR(64),
    reference_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_indicator_type_value UNIQUE (indicator_type, value)
);

-- 14. Malware Samples Table
CREATE TABLE IF NOT EXISTS malware_samples (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sha256 VARCHAR(64) UNIQUE NOT NULL,
    md5 VARCHAR(32),
    sha1 VARCHAR(40),
    filename VARCHAR(255) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    file_type VARCHAR(64),
    uploader VARCHAR(255) DEFAULT 'anonymous',
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 15. Malware Analysis Results Table
CREATE TABLE IF NOT EXISTS malware_analysis_results (
    id VARCHAR(64) PRIMARY KEY,
    sample_id UUID REFERENCES malware_samples(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    score INTEGER NOT NULL,
    severity VARCHAR(32) NOT NULL,
    entropy NUMERIC(6,4),
    is_pe BOOLEAN DEFAULT FALSE,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    findings JSONB DEFAULT '{}'::jsonb,
    details JSONB DEFAULT '{}'::jsonb,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 16. Response Actions Table (Perimeter Containment Rules)
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_type VARCHAR(64) NOT NULL DEFAULT 'BLOCK_IP',
    target VARCHAR(255) NOT NULL,
    reason TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    executed_by VARCHAR(255) NOT NULL,
    incident_id VARCHAR(64) REFERENCES incidents(id) ON DELETE SET NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- 17. Firewall Rules Compatibility Table
CREATE TABLE IF NOT EXISTS firewall_rules (
    ip VARCHAR(64) PRIMARY KEY,
    reason TEXT,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked_by VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    unblocked_at TIMESTAMP WITH TIME ZONE
);

-- 18. Audit Logs Table (Immutable Security Ledger)
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    actor VARCHAR(255) NOT NULL,
    actor_role VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255),
    result VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    source_ip VARCHAR(64),
    details JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
