-- ============================================================
-- EdgeKeeper — Migration 016
-- Monthly behavioral reports for Fellow+ users
-- ============================================================

CREATE TABLE IF NOT EXISTS public.behavioral_reports (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID         NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  report_month TEXT         NOT NULL,          -- 'YYYY-MM' e.g. '2026-05'
  mentor       TEXT         NOT NULL DEFAULT 'mike',
  summary      TEXT         NOT NULL,          -- AI-generated narrative (800-1500 chars)
  strengths    JSONB        DEFAULT '[]',      -- array of strings
  patterns     JSONB        DEFAULT '[]',      -- behavioural patterns spotted
  focus_areas  JSONB        DEFAULT '[]',      -- where to improve next month
  stats        JSONB        DEFAULT '{}',      -- { journal_entries, violations, sessions, voice_sessions }
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, report_month)
);

ALTER TABLE public.behavioral_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_reports"
  ON public.behavioral_reports FOR SELECT
  USING (auth.uid() = user_id);

CREATE INDEX idx_behavioral_reports_user
  ON public.behavioral_reports (user_id, report_month DESC);

-- ── END OF MIGRATION ──────────────────────────────────────────────────
