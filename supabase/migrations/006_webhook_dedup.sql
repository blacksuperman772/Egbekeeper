-- ============================================================
-- 006_webhook_dedup.sql
-- Idempotency table for Paystack webhook events.
-- Prevents a retried webhook delivery from applying side effects twice.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.webhook_events (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      TEXT        NOT NULL,
  event_type    TEXT        NOT NULL,
  processed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (event_id, event_type)
);

-- Service role writes; no client-side access needed.
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;

-- No SELECT policy — app reads via service role which bypasses RLS.
-- No INSERT policy — same reason.

-- Cleanup: auto-delete records older than 90 days to keep this table small.
-- Run via a Supabase pg_cron job or a periodic Edge Function.
-- Example pg_cron (run in Supabase SQL editor once pg_cron is enabled):
-- SELECT cron.schedule('cleanup-webhook-events', '0 3 * * *',
--   $$DELETE FROM public.webhook_events WHERE processed_at < NOW() - INTERVAL '90 days'$$);

-- ── END OF MIGRATION ─────────────────────────────────────────
