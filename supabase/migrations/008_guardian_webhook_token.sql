-- ============================================================
-- EdgeKeeper — Guardian webhook token for MT4/MT5 EA auth
-- Migration: 008_guardian_webhook_token.sql
-- ============================================================

ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS guardian_webhook_token TEXT UNIQUE;
