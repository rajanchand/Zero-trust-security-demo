-- ==============================
-- Zero Trust Security Features
-- Run this in Supabase SQL Editor
-- ==============================
-- 1. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    event_type text NOT NULL,
    severity text NOT NULL DEFAULT 'info',
    user_email text,
    user_id uuid,
    ip_address text,
    details text,
    metadata jsonb DEFAULT '{}',
    created_at timestamptz DEFAULT now ()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_logs (severity);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_email);

-- 2. Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    user_id uuid NOT NULL,
    user_email text NOT NULL,
    user_name text,
    ip_address text,
    browser text,
    os text,
    fingerprint text,
    geo_location text,
    expires_at timestamptz NOT NULL,
    is_active boolean DEFAULT true,
    revoked_by text,
    revoked_at timestamptz,
    created_at timestamptz DEFAULT now ()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions (is_active);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- 3. IP Rules Table
CREATE TABLE IF NOT EXISTS ip_rules (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    ip_pattern text NOT NULL,
    rule_type text NOT NULL CHECK (rule_type IN ('allow', 'block')),
    label text,
    created_by text,
    created_at timestamptz DEFAULT now ()
);

CREATE INDEX IF NOT EXISTS idx_ip_rules_type ON ip_rules (rule_type);

-- 4. Security Policies Table
CREATE TABLE IF NOT EXISTS security_policies (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    policy_key text UNIQUE NOT NULL,
    policy_value text NOT NULL,
    description text,
    updated_by text,
    updated_at timestamptz DEFAULT now ()
);

-- Insert default policies
INSERT INTO
    security_policies (policy_key, policy_value, description)
VALUES
    (
        'session_timeout_minutes',
        '30',
        'Session timeout duration in minutes'
    ),
    (
        'max_failed_logins',
        '5',
        'Maximum failed login attempts before lockout'
    ),
    (
        'mfa_required',
        'true',
        'Require multi-factor authentication for all users'
    ),
    (
        'password_min_length',
        '8',
        'Minimum password length'
    ),
    (
        'device_approval_required',
        'true',
        'Require device approval before access'
    ),
    (
        'ip_restriction_enabled',
        'false',
        'Enable IP allowlist/blocklist enforcement'
    ) ON CONFLICT (policy_key) DO NOTHING;

-- 5. Add risk score column to users table
ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_risk_score integer DEFAULT 0;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS failed_login_count integer DEFAULT 0;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_login_ip text DEFAULT '';

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_login_at timestamptz;