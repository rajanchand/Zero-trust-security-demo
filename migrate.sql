-- =============================================
-- Zero Trust Security App - Database Migration
-- Run this in Supabase SQL Editor (one time)
-- =============================================

-- Add phone column
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS phone text DEFAULT '';

-- Add gender column
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS gender text DEFAULT '';

-- Create a helper function so the app can run migrations automatically
CREATE OR REPLACE FUNCTION run_migration(sql_text text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  EXECUTE sql_text;
END;
$$;
