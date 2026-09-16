-- Migration 003: Seed Baseline RBAC Roles, Permissions & SIEM Correlation Rules
-- Cyber Sentinel SOC Seed Data

-- 1. Insert Standard RBAC Roles
INSERT INTO roles (id, name, description)
VALUES 
    ('a0000000-0000-0000-0000-000000000001', 'ADMIN', 'Super Administrator with unrestricted access to system configuration, RBAC, and containment actions'),
    ('a0000000-0000-0000-0000-000000000002', 'SENIOR_ANALYST', 'Senior SOC Operator authorized for threat triage, incident containment, simulations, and audit inspections'),
    ('a0000000-0000-0000-0000-000000000003', 'ANALYST', 'Standard Tier-1 SOC Analyst with read and diagnostic scan execution privileges'),
    ('a0000000-0000-0000-0000-000000000004', 'VIEWER', 'Read-only observer restricted to dashboard monitoring and telemetry metrics')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

-- 2. Insert Granular Permissions
INSERT INTO permissions (id, code, description)
VALUES
    ('b0000000-0000-0000-0000-000000000001', 'incidents:read', 'View incidents and forensic evidence'),
    ('b0000000-0000-0000-0000-000000000002', 'incidents:write', 'Create, update, and modify incident lifecycles'),
    ('b0000000-0000-0000-0000-000000000003', 'containment:execute', 'Block or unblock network IP addresses on perimeter firewalls'),
    ('b0000000-0000-0000-0000-000000000004', 'telemetry:ingest', 'Ingest host telemetry and event streams'),
    ('b0000000-0000-0000-0000-000000000005', 'scans:execute', 'Execute vulnerability scans, log analysis, and malware inspections'),
    ('b0000000-0000-0000-0000-000000000006', 'audit:read', 'View immutable security audit trails'),
    ('b0000000-0000-0000-0000-000000000007', 'users:manage', 'Manage user operator accounts and role assignments'),
    ('b0000000-0000-0000-0000-000000000008', 'ai:chat', 'Interact with the Sentinel autonomous AI copilot')
ON CONFLICT (code) DO NOTHING;

-- 3. Link Permissions to Roles
-- ADMIN: All permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- SENIOR_ANALYST: incidents:read, incidents:write, containment:execute, scans:execute, audit:read, ai:chat, telemetry:ingest
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE code IN ('incidents:read', 'incidents:write', 'containment:execute', 'scans:execute', 'audit:read', 'ai:chat', 'telemetry:ingest')
ON CONFLICT DO NOTHING;

-- ANALYST: incidents:read, scans:execute, ai:chat, telemetry:ingest
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE code IN ('incidents:read', 'scans:execute', 'ai:chat', 'telemetry:ingest')
ON CONFLICT DO NOTHING;

-- VIEWER: incidents:read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE code IN ('incidents:read')
ON CONFLICT DO NOTHING;

-- 4. Seed Baseline SIEM Correlation Detection Rules
INSERT INTO detection_rules (id, name, description, severity, category, mitre_technique, rule_type, parameters)
VALUES
    (
        'RULE_BRUTE_FORCE_001',
        'Brute Force Authentication Campaign',
        'Flags 5+ failed login attempts from a single source IP within a 2-minute window',
        'HIGH',
        'BRUTE_FORCE',
        'T1110.001',
        'STATEFUL_CORRELATION',
        '{"threshold": 5, "windowSeconds": 120, "targetType": "AUTH_FAILURE"}'::jsonb
    ),
    (
        'RULE_SQLI_SUCCESS_002',
        'Successful Web Application SQL Injection',
        'Detects SQLi exploit pattern resulting in HTTP 200 OK response status',
        'CRITICAL',
        'APPLICATION_EXPLOIT',
        'T1190',
        'STATEFUL_CORRELATION',
        '{"patternMatch": "SQLI", "httpStatusRange": [200, 299]}'::jsonb
    ),
    (
        'RULE_SUSPICIOUS_EXEC_004',
        'Suspicious Process Execution with C2 Socket Connection',
        'Identifies suspicious PowerShell execution (-enc/-nop) paired with outbound socket connection',
        'CRITICAL',
        'ENDPOINT_EXECUTION',
        'T1059.001',
        'STATEFUL_CORRELATION',
        '{"process": "powershell.exe", "indicators": ["-enc", "-nop", "-w hidden"]}'::jsonb
    ),
    (
        'RULE_IOC_MATCH_005',
        'Threat Intelligence Indicator of Compromise (IOC) Match',
        'Matches telemetry coordinates against verified ThreatFox / CISA KEV feeds',
        'CRITICAL',
        'THREAT_INTEL_MATCH',
        'T1071.001',
        'IOC_MATCH',
        '{"confidenceThreshold": 80}'::jsonb
    )
ON CONFLICT (id) DO UPDATE SET 
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    parameters = EXCLUDED.parameters;
