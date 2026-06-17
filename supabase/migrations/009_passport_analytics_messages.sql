-- ============================================================
-- EdgeKeeper — Decision Passport, Analytics & Mentor Messages
-- Migration: 009_passport_analytics_messages.sql
-- ============================================================

-- ── discipline_scores extended ────────────────────────────────────────────────
-- Already exists from 003; add missing columns if not present
ALTER TABLE public.discipline_scores
  ADD COLUMN IF NOT EXISTS patience      INTEGER DEFAULT 0 CHECK (patience BETWEEN 0 AND 100),
  ADD COLUMN IF NOT EXISTS post_loss     INTEGER DEFAULT 0 CHECK (post_loss BETWEEN 0 AND 100),
  ADD COLUMN IF NOT EXISTS execution     INTEGER DEFAULT 0 CHECK (execution BETWEEN 0 AND 100),
  ADD COLUMN IF NOT EXISTS mentor        TEXT DEFAULT 'mike' CHECK (mentor IN ('mike', 'ashley')),
  ADD COLUMN IF NOT EXISTS session_notes TEXT;

-- ── passport_entries ──────────────────────────────────────────────────────────
-- One entry per significant session — the Decision Passport log
CREATE TABLE IF NOT EXISTS public.passport_entries (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  entry_date    DATE NOT NULL DEFAULT CURRENT_DATE,
  summary       TEXT NOT NULL CHECK (char_length(summary) BETWEEN 5 AND 1000),
  badge         TEXT CHECK (badge IN ('disciplined', 'flagged', 'neutral', 'breakthrough')),
  score         INTEGER CHECK (score BETWEEN 0 AND 100),
  mentor        TEXT DEFAULT 'mike' CHECK (mentor IN ('mike', 'ashley')),
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, entry_date)
);

ALTER TABLE public.passport_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "passport_entries: user owns their rows"
  ON public.passport_entries FOR ALL
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE INDEX passport_entries_user_date ON public.passport_entries(user_id, entry_date DESC);

-- ── mentor_messages ───────────────────────────────────────────────────────────
-- Proactive messages initiated by the mentor (AI-generated, scheduled)
CREATE TABLE IF NOT EXISTS public.mentor_messages (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  mentor        TEXT DEFAULT 'mike' CHECK (mentor IN ('mike', 'ashley')),
  content       TEXT NOT NULL CHECK (char_length(content) BETWEEN 10 AND 2000),
  trigger_type  TEXT NOT NULL CHECK (trigger_type IN ('inactivity', 'milestone', 'pattern', 'weekly_check', 'manual')),
  read_at       TIMESTAMPTZ,
  email_sent    BOOLEAN DEFAULT FALSE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.mentor_messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "mentor_messages: user reads their own"
  ON public.mentor_messages FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY "mentor_messages: user can mark read"
  ON public.mentor_messages FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE INDEX mentor_messages_user_unread ON public.mentor_messages(user_id, created_at DESC)
  WHERE read_at IS NULL;

-- ── settings table ────────────────────────────────────────────────────────────
-- Per-user preferences (notification frequency, etc.)
ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS email_notifications BOOLEAN DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS proactive_messages  BOOLEAN DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS display_name        TEXT CHECK (char_length(display_name) <= 60),
  ADD COLUMN IF NOT EXISTS timezone            TEXT DEFAULT 'UTC';
