-- ============================================================
-- EdgeKeeper — Migration 014
-- Fixes three outstanding schema problems:
--   1. user_profiles missing guardian_level column
--   2. journal_entries schema mismatch (migration 004 replaced
--      the original columns server.js still expects)
--   3. webhook_events UNIQUE should be on event_id alone
-- ============================================================

-- ── 1. Add guardian_level to user_profiles ────────────────────────────
-- The onboarding register endpoint writes this column; it was never
-- added to the schema, causing silent failures on every registration.
ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS guardian_level TEXT DEFAULT 'warn'
    CHECK (guardian_level IN ('warn', 'intervene', 'lock', 'offline'));

-- ── 2. Unified journal_entries schema ────────────────────────────────
-- Migration 004 dropped the migration-001 journal_entries and recreated
-- it with rules-engine column names (entry_text, badge, mentor_context…)
-- that differ from what server.js uses (content, entry_type, trade_data,
-- mentor_notes). This migration drops and recreates with a unified schema
-- that satisfies BOTH the server API and the rules engine.

-- Drop dependents first
DROP VIEW  IF EXISTS rule_violation_summary CASCADE;
DROP TABLE IF EXISTS rule_violations        CASCADE;
DROP TABLE IF EXISTS journal_entries        CASCADE;

CREATE TABLE public.journal_entries (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID         NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

  -- Core text (used by /api/journal POST + GET)
  content            TEXT         NOT NULL,
  entry_type         TEXT         DEFAULT 'free'
                                    CHECK (entry_type IN ('free','pre_trade','post_trade','weekly','monthly')),
  trade_data         JSONB,
  mentor_notes       TEXT,

  -- Enriched tagging written from workspace UI
  badge              TEXT         CHECK (badge IN ('good','consistent','flag')),
  financial_outcome  TEXT,
  identity_outcome   TEXT,
  mentor_context     TEXT         DEFAULT 'mike'
                                    CHECK (mentor_context IN ('mike','ashley')),

  -- AI rule-check pipeline
  ai_check_status    TEXT         NOT NULL DEFAULT 'pending'
                                    CHECK (ai_check_status IN ('pending','processing','done','skipped')),
  ai_analysis_raw    JSONB,

  created_at         TIMESTAMPTZ  DEFAULT NOW(),
  updated_at         TIMESTAMPTZ  DEFAULT NOW()
);

ALTER TABLE public.journal_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_journal"
  ON public.journal_entries FOR ALL
  USING  (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE INDEX idx_journal_user_created
  ON public.journal_entries (user_id, created_at DESC);

CREATE INDEX idx_journal_ai_pending
  ON public.journal_entries (user_id, ai_check_status)
  WHERE ai_check_status IN ('pending','processing');

-- Restore rule_violations (FK was lost when journal_entries was dropped)
CREATE TABLE public.rule_violations (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID         NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  journal_entry_id UUID         NOT NULL REFERENCES public.journal_entries(id) ON DELETE CASCADE,
  rule_id          UUID         NOT NULL REFERENCES public.trading_rules(id)   ON DELETE CASCADE,
  confidence       NUMERIC(4,3) NOT NULL DEFAULT 1.000
                                  CHECK (confidence BETWEEN 0.0 AND 1.0),
  mentor_note      TEXT         NOT NULL
                                  CHECK (char_length(mentor_note) BETWEEN 10 AND 600),
  evidence_quote   TEXT         CHECK (char_length(evidence_quote) <= 500),
  acknowledged     BOOLEAN      NOT NULL DEFAULT FALSE,
  acknowledged_at  TIMESTAMPTZ,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

ALTER TABLE public.rule_violations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_can_read_violations"
  ON public.rule_violations FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "users_can_acknowledge_violations"
  ON public.rule_violations FOR UPDATE
  USING  (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE INDEX idx_rule_violations_rule_id
  ON public.rule_violations (rule_id, created_at DESC);
CREATE INDEX idx_rule_violations_journal
  ON public.rule_violations (journal_entry_id);
CREATE INDEX idx_rule_violations_user_unacked
  ON public.rule_violations (user_id, acknowledged, created_at DESC)
  WHERE acknowledged = FALSE;

-- Restore view
CREATE OR REPLACE VIEW rule_violation_summary AS
SELECT
  tr.id              AS rule_id,
  tr.user_id,
  tr.rule_text,
  tr.category,
  tr.is_active,
  tr.sort_order,
  tr.rationale,
  tr.origin_mentor,
  tr.created_at      AS rule_created_at,
  COUNT(rv.id)       AS total_violations,
  COUNT(rv.id) FILTER (WHERE rv.created_at >= NOW() - INTERVAL '30 days') AS violations_last_30d,
  COUNT(rv.id) FILTER (WHERE rv.created_at >= NOW() - INTERVAL  '7 days') AS violations_last_7d,
  MAX(rv.created_at) AS last_violated_at
FROM public.trading_rules tr
LEFT JOIN public.rule_violations rv ON rv.rule_id = tr.id
GROUP BY
  tr.id, tr.user_id, tr.rule_text, tr.category, tr.is_active,
  tr.sort_order, tr.rationale, tr.origin_mentor, tr.created_at;

-- Restore updated_at trigger for journal_entries
CREATE TRIGGER journal_entries_updated_at
  BEFORE UPDATE ON public.journal_entries
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

-- ── 3. Fix webhook_events UNIQUE constraint ───────────────────────────
-- Paystack event IDs are globally unique; the compound key
-- (event_id, event_type) could theoretically let two deliveries
-- of the same event slip through under different type labels.
ALTER TABLE public.webhook_events
  DROP CONSTRAINT IF EXISTS webhook_events_event_id_event_type_key;

ALTER TABLE public.webhook_events
  DROP CONSTRAINT IF EXISTS webhook_events_event_id_key;

ALTER TABLE public.webhook_events
  ADD CONSTRAINT webhook_events_event_id_key UNIQUE (event_id);

-- ── END OF MIGRATION ──────────────────────────────────────────────────
