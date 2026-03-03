-- ============================================================
-- Device Approvals table for Zero Trust Security
-- Run this in Supabase SQL Editor: https://supabase.com/dashboard
-- ============================================================

CREATE TABLE IF NOT EXISTS public.device_approvals (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid REFERENCES public.users(id) ON DELETE CASCADE,
  user_email text NOT NULL,
  user_name text NOT NULL DEFAULT '',
  ip_address text NOT NULL DEFAULT '',
  geo_location text NOT NULL DEFAULT '',
  device_health text NOT NULL DEFAULT 'Unknown',
  browser text NOT NULL DEFAULT '',
  os text NOT NULL DEFAULT '',
  fingerprint text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'Pending',
  action text NOT NULL DEFAULT 'Awaiting Review',
  approved_by text DEFAULT NULL,
  approved_at timestamptz DEFAULT NULL,
  created_at timestamptz DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.device_approvals ENABLE ROW LEVEL SECURITY;

-- Allow full access via service_role key
CREATE POLICY "Service role full access on device_approvals"
  ON public.device_approvals
  FOR ALL
  USING (true)
  WITH CHECK (true);

-- Index for fast lookup by user + fingerprint
CREATE INDEX IF NOT EXISTS idx_device_user_fingerprint
  ON public.device_approvals(user_id, fingerprint);

-- Index for fast lookup by status
CREATE INDEX IF NOT EXISTS idx_device_status
  ON public.device_approvals(status);
