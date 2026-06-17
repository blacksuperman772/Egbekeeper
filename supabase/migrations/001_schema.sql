-- ============================================================
-- EdgeKeeper — Initial Schema
-- Migration: 001_schema.sql
-- ============================================================

-- ── user_profiles ─────────────────────────────────────────────────────────────
-- Extends auth.users; created automatically via trigger on signup.
CREATE TABLE public.user_profiles (
  id                   UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  mentor               TEXT DEFAULT 'mike' CHECK (mentor IN ('mike', 'ashley')),
  north_star           TEXT,
  living_identity      TEXT,
  private_notes        TEXT,
  onboarding_complete  BOOLEAN DEFAULT FALSE,
  subscription_status  TEXT DEFAULT 'free'
                         CHECK (subscription_status IN ('free', 'starter', 'pro', 'institutional')),
  stripe_customer_id   TEXT,
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  updated_at           TIMESTAMPTZ DEFAULT NOW()
);

-- ── notebooks ─────────────────────────────────────────────────────────────────
-- Replaces localStorage ek_notebook_mike / ek_notebook_ashley.
-- One row per (user, mentor) — enforced by UNIQUE constraint.
CREATE TABLE public.notebooks (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  mentor           TEXT NOT NULL CHECK (mentor IN ('mike', 'ashley')),
  session_count    INTEGER DEFAULT 0,
  trust_level      INTEGER DEFAULT 1,
  current_theory   TEXT,
  theory_history   JSONB DEFAULT '[]',
  facts            JSONB DEFAULT '[]',
  theories         JSONB DEFAULT '[]',
  open_questions   JSONB DEFAULT '[]',
  uncertainties    JSONB DEFAULT '[]',
  observations     JSONB DEFAULT '[]',
  patterns         JSONB DEFAULT '[]',
  emotional_map    JSONB DEFAULT '{"confidence":[],"avoidance":[],"shame":[],"excitement":[]}',
  strengths        JSONB DEFAULT '[]',
  concerns         JSONB DEFAULT '[]',
  breakthroughs    JSONB DEFAULT '[]',
  commitments      JSONB DEFAULT '[]',
  story_moments    JSONB DEFAULT '[]',
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, mentor)
);

-- ── journal_entries ───────────────────────────────────────────────────────────
CREATE TABLE public.journal_entries (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  content      TEXT NOT NULL,
  entry_type   TEXT DEFAULT 'free'
                 CHECK (entry_type IN ('free', 'pre_trade', 'post_trade', 'weekly', 'monthly')),
  trade_data   JSONB,
  mentor_notes TEXT,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── trading_rules ─────────────────────────────────────────────────────────────
CREATE TABLE public.trading_rules (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  rule_text  TEXT NOT NULL,
  category   TEXT,
  active     BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── subscriptions ─────────────────────────────────────────────────────────────
CREATE TABLE public.subscriptions (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  stripe_subscription_id  TEXT UNIQUE,
  stripe_customer_id      TEXT,
  plan                    TEXT DEFAULT 'free',
  status                  TEXT DEFAULT 'active',
  current_period_end      TIMESTAMPTZ,
  created_at              TIMESTAMPTZ DEFAULT NOW(),
  updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ── voice_sessions ────────────────────────────────────────────────────────────
CREATE TABLE public.voice_sessions (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  mentor                      TEXT NOT NULL,
  duration_seconds            INTEGER,
  elevenlabs_conversation_id  TEXT,
  summary                     TEXT,
  started_at                  TIMESTAMPTZ DEFAULT NOW(),
  ended_at                    TIMESTAMPTZ
);

-- ── Row Level Security ────────────────────────────────────────────────────────
ALTER TABLE public.user_profiles  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notebooks       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.journal_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.trading_rules   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.voice_sessions  ENABLE ROW LEVEL SECURITY;

-- Users can only read and write their own rows
CREATE POLICY "users_own_profile"
  ON public.user_profiles FOR ALL
  USING (auth.uid() = id);

CREATE POLICY "users_own_notebooks"
  ON public.notebooks FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY "users_own_journal"
  ON public.journal_entries FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY "users_own_rules"
  ON public.trading_rules FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY "users_own_subscriptions"
  ON public.subscriptions FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY "users_own_voice_sessions"
  ON public.voice_sessions FOR ALL
  USING (auth.uid() = user_id);

-- ── Auto-create profile on signup ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.user_profiles (id)
  VALUES (NEW.id)
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- ── updated_at auto-refresh helper ───────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER user_profiles_updated_at
  BEFORE UPDATE ON public.user_profiles
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

CREATE TRIGGER notebooks_updated_at
  BEFORE UPDATE ON public.notebooks
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

CREATE TRIGGER journal_entries_updated_at
  BEFORE UPDATE ON public.journal_entries
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

CREATE TRIGGER subscriptions_updated_at
  BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
