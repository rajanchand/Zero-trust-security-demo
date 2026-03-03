-- ============================================
-- ZTS — Zero Trust Security Demo
-- Database Migration for Supabase
-- Run in Supabase SQL Editor
-- ============================================
-- 1. Audit Logs Table
-- NIST SP 800-207: Continuous monitoring and logging
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
-- NIST SP 800-207: Continuous session validation
CREATE TABLE IF NOT EXISTS sessions (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    user_id uuid NOT NULL,
    user_email text NOT NULL,
    user_name text,
    user_role text,
    ip_address text,
    browser text,
    os text,
    fingerprint text,
    geo_location text,
    country text,
    expires_at timestamptz NOT NULL,
    is_active boolean DEFAULT true,
    revoked_by text,
    revoked_at timestamptz,
    created_at timestamptz DEFAULT now ()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions (is_active);

-- 3. IP Rules Table
-- NIST SP 800-207: Network-based access control
CREATE TABLE IF NOT EXISTS ip_rules (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    ip_pattern text NOT NULL,
    rule_type text NOT NULL CHECK (rule_type IN ('allow', 'block')),
    label text,
    created_by text,
    created_at timestamptz DEFAULT now ()
);

-- 4. Security Policies Table
-- NIST SP 800-207: Centralized policy management
CREATE TABLE IF NOT EXISTS security_policies (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    policy_key text UNIQUE NOT NULL,
    policy_value text NOT NULL,
    description text,
    updated_by text,
    updated_at timestamptz DEFAULT now ()
);

-- 5. Login History Table
-- NIST SP 800-207: Continuous monitoring, risk assessment
CREATE TABLE IF NOT EXISTS login_history (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    user_id uuid,
    user_email text,
    ip_address text,
    country text,
    city text,
    browser text,
    os text,
    device_fingerprint text,
    risk_score integer DEFAULT 0,
    risk_level text DEFAULT 'low',
    risk_factors jsonb DEFAULT '[]',
    vpn_detected boolean DEFAULT false,
    is_suspicious boolean DEFAULT false,
    login_success boolean DEFAULT true,
    created_at timestamptz DEFAULT now ()
);

CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history (user_id);

CREATE INDEX IF NOT EXISTS idx_login_history_created ON login_history (created_at DESC);

-- 6. Device Approvals Table
CREATE TABLE IF NOT EXISTS device_approvals (
    id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
    user_id uuid,
    user_email text,
    user_name text,
    ip_address text,
    geo_location text,
    device_health text,
    browser text,
    os text,
    fingerprint text,
    status text DEFAULT 'Pending',
    approved_by text,
    approved_at timestamptz,
    created_at timestamptz DEFAULT now ()
);

-- 7. Ensure users table has required columns
ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS phone text DEFAULT '';

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS gender text DEFAULT '';

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_risk_score integer DEFAULT 0;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS failed_login_count integer DEFAULT 0;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_login_ip text DEFAULT '';

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_login_at timestamptz;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS last_country text DEFAULT '';

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS locked_until timestamptz;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS force_mfa boolean DEFAULT true;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS is_blocked boolean DEFAULT false;

-- 8. Default Security Policies
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
    ),
    (
        'lockout_duration_minutes',
        '15',
        'Account lockout duration in minutes'
    ) ON CONFLICT (policy_key) DO NOTHING;