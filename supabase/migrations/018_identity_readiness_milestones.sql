-- ============================================================
-- EdgeKeeper — Migration 018
-- Trader Identity System, Readiness Score, Milestones, Assessment
-- ============================================================

-- Trader Identity System: stage, current/target identity, readiness score
ALTER TABLE user_profiles
  ADD COLUMN IF NOT EXISTS trader_stage        TEXT    NOT NULL DEFAULT 'explorer'
    CHECK (trader_stage IN ('explorer','student','developing','consistent','performance','mentor_candidate')),
  ADD COLUMN IF NOT EXISTS current_identity    TEXT,
  ADD COLUMN IF NOT EXISTS target_identity     TEXT,
  ADD COLUMN IF NOT EXISTS readiness_score     INTEGER NOT NULL DEFAULT 0
    CHECK (readiness_score >= 0 AND readiness_score <= 100),
  ADD COLUMN IF NOT EXISTS assessment_complete BOOLEAN NOT NULL DEFAULT FALSE;

-- Milestones: ceremonies marking real trader development moments
CREATE TABLE IF NOT EXISTS milestones (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type         TEXT        NOT NULL,
  label        TEXT        NOT NULL,
  description  TEXT,
  mentor_note  TEXT,
  achieved_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS milestones_user_id_idx ON milestones(user_id);
CREATE INDEX IF NOT EXISTS milestones_type_idx    ON milestones(user_id, type);

-- RLS for milestones
ALTER TABLE milestones ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own milestones"
  ON milestones FOR SELECT
  USING (auth.uid() = user_id);

-- ── END OF MIGRATION ──────────────────────────────────────────────────
