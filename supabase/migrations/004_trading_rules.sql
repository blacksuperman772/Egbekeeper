-- ============================================================
-- 004_trading_rules.sql
-- Rules engine for EdgeKeeper workspace
-- Creates: trading_rules, rule_violations, journal_entries
-- ============================================================

-- ── EXTENSIONS ────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── CLEAN SLATE (handles partial prior runs) ──────────────────────────
DROP VIEW  IF EXISTS rule_violation_summary CASCADE;
DROP TABLE IF EXISTS rule_violations  CASCADE;
DROP TABLE IF EXISTS journal_entries  CASCADE;
DROP TABLE IF EXISTS trading_rules    CASCADE;

-- ── TRADING RULES ─────────────────────────────────────────────────────
-- One row per rule the trader has written for themselves.
-- Rules are personal laws — written in the trader's own words.

CREATE TABLE IF NOT EXISTS trading_rules (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

  -- The rule itself, written by the trader
  rule_text     TEXT NOT NULL CHECK (char_length(rule_text) BETWEEN 5 AND 500),

  -- Organizational category, chosen by trader or suggested by AI
  -- Examples: Risk, Volume, Timing, Discipline, Execution, Psychology
  category      TEXT NOT NULL DEFAULT 'General'
                  CHECK (char_length(category) BETWEEN 1 AND 60),

  -- Whether the rule is currently active or archived
  -- Archived rules are kept for history — they still count in analytics
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,

  -- When the rule was written (not updated) — for "how long have you held this rule"
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Soft-sort order so the trader can arrange their rules
  sort_order    INTEGER NOT NULL DEFAULT 0,

  -- Optional: a short note the trader or mentor added about why this rule exists
  rationale     TEXT CHECK (char_length(rationale) <= 1000),

  -- Mentor who helped formulate or first surfaced this rule (mike | ashley | self)
  origin_mentor TEXT NOT NULL DEFAULT 'self'
                  CHECK (origin_mentor IN ('mike', 'ashley', 'self'))
);

-- Trader fetches their own rules ordered by sort position
CREATE INDEX idx_trading_rules_user_active
  ON trading_rules (user_id, is_active, sort_order);

-- ── JOURNAL ENTRIES ───────────────────────────────────────────────────
-- One row per journal entry the trader saves.
-- This table is the primary input the AI reads to find rule violations.

CREATE TABLE IF NOT EXISTS journal_entries (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

  -- Free-text body, written by the trader
  entry_text      TEXT NOT NULL CHECK (char_length(entry_text) BETWEEN 1 AND 8000),

  -- Trader-tagged session quality (matches workspace UI: good | consistent | flag | null)
  badge           TEXT CHECK (badge IN ('good', 'consistent', 'flag')),

  -- Optional structured outcomes filled in from the two outcome inputs in the UI
  financial_outcome TEXT CHECK (char_length(financial_outcome) <= 200),
  identity_outcome  TEXT CHECK (char_length(identity_outcome) <= 400),

  -- Which mentor workspace this was written in
  mentor_context  TEXT NOT NULL DEFAULT 'mike'
                    CHECK (mentor_context IN ('mike', 'ashley')),

  -- AI analysis state for this entry
  -- pending: awaiting rule-check  |  processing: AI call in flight
  -- done: violations stored       |  skipped: no rules exist yet
  ai_check_status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (ai_check_status IN ('pending', 'processing', 'done', 'skipped')),

  -- Raw AI analysis returned (stored for debugging / future display)
  ai_analysis_raw JSONB,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_journal_entries_user_created
  ON journal_entries (user_id, created_at DESC);

CREATE INDEX idx_journal_entries_ai_check
  ON journal_entries (user_id, ai_check_status)
  WHERE ai_check_status IN ('pending', 'processing');

-- ── RULE VIOLATIONS ───────────────────────────────────────────────────
-- One row per rule that was flagged in a specific journal entry.
-- A single journal entry can violate multiple rules.
-- This is the accountability layer — the source of truth for the Rules panel stats.

CREATE TABLE IF NOT EXISTS rule_violations (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

  -- The journal entry that triggered this violation
  journal_entry_id UUID NOT NULL REFERENCES journal_entries(id) ON DELETE CASCADE,

  -- The specific rule that was violated
  rule_id         UUID NOT NULL REFERENCES trading_rules(id) ON DELETE CASCADE,

  -- AI confidence that this is a genuine violation (0.0 – 1.0)
  confidence      NUMERIC(4,3) NOT NULL DEFAULT 1.000
                    CHECK (confidence BETWEEN 0.0 AND 1.0),

  -- Short AI-generated explanation of WHY this was flagged (1–3 sentences)
  -- Written in the mentor's voice, stored and shown in the Rules panel
  mentor_note     TEXT NOT NULL CHECK (char_length(mentor_note) BETWEEN 10 AND 600),

  -- Exact quote from the journal entry that triggered the flag
  -- Helps the trader see precisely what the AI reacted to
  evidence_quote  TEXT CHECK (char_length(evidence_quote) <= 500),

  -- Whether the trader has acknowledged/reviewed this violation
  acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
  acknowledged_at TIMESTAMPTZ,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup: all violations for a given rule (for the violation count badge)
CREATE INDEX idx_rule_violations_rule_id
  ON rule_violations (rule_id, created_at DESC);

-- Fast lookup: all violations from a given journal entry
CREATE INDEX idx_rule_violations_journal_entry
  ON rule_violations (journal_entry_id);

-- Fast lookup: recent unacknowledged violations per user for the panel header
CREATE INDEX idx_rule_violations_user_unacked
  ON rule_violations (user_id, acknowledged, created_at DESC)
  WHERE acknowledged = FALSE;

-- ── RULE VIOLATION SUMMARY VIEW ───────────────────────────────────────
-- Denormalised view used by the Rules panel to show violation count per rule
-- without requiring a COUNT(*) join on every render.

CREATE OR REPLACE VIEW rule_violation_summary AS
SELECT
  tr.id                  AS rule_id,
  tr.user_id,
  tr.rule_text,
  tr.category,
  tr.is_active,
  tr.sort_order,
  tr.rationale,
  tr.origin_mentor,
  tr.created_at          AS rule_created_at,
  COUNT(rv.id)           AS total_violations,
  COUNT(rv.id) FILTER (
    WHERE rv.created_at >= NOW() - INTERVAL '30 days'
  )                      AS violations_last_30d,
  COUNT(rv.id) FILTER (
    WHERE rv.created_at >= NOW() - INTERVAL '7 days'
  )                      AS violations_last_7d,
  MAX(rv.created_at)     AS last_violated_at
FROM trading_rules tr
LEFT JOIN rule_violations rv ON rv.rule_id = tr.id
GROUP BY
  tr.id, tr.user_id, tr.rule_text, tr.category,
  tr.is_active, tr.sort_order, tr.rationale,
  tr.origin_mentor, tr.created_at;

-- ── ROW LEVEL SECURITY ────────────────────────────────────────────────
ALTER TABLE trading_rules    ENABLE ROW LEVEL SECURITY;
ALTER TABLE journal_entries  ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_violations  ENABLE ROW LEVEL SECURITY;

-- trading_rules: trader owns their own rules
CREATE POLICY "Users own their rules"
  ON trading_rules FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- journal_entries: trader owns their own entries
CREATE POLICY "Users own their journal entries"
  ON journal_entries FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- rule_violations: trader can read, AI service (service_role) can write
CREATE POLICY "Users can read their violations"
  ON rule_violations FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can acknowledge their violations"
  ON rule_violations FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Service role (Edge Function) inserts violations — granted via service_role key,
-- which bypasses RLS, so no INSERT policy is needed for the AI writer.

-- ── UPDATED_AT TRIGGER ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_trading_rules_updated_at
  BEFORE UPDATE ON trading_rules
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── SEED: DEFAULT CATEGORY LIST ───────────────────────────────────────
-- Not a table — just a comment for the application layer to use as suggestions
-- when the trader is adding a new rule.
-- Categories: Risk, Volume, Timing, Discipline, Execution, Psychology, General

-- ── END OF MIGRATION ──────────────────────────────────────────────────
