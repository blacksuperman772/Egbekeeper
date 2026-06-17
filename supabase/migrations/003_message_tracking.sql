-- ============================================================
-- EdgeKeeper — Migration 003
-- Message usage tracking + session analytics + voice logs
-- ============================================================

-- ── message_usage — tracks per-user monthly AI message counts ────────────────
CREATE TABLE IF NOT EXISTS public.message_usage (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  mentor       TEXT NOT NULL CHECK (mentor IN ('mike', 'ashley')),
  month_key    TEXT NOT NULL,  -- format: 'YYYY-MM'
  message_count INTEGER DEFAULT 0,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, mentor, month_key)
);

ALTER TABLE public.message_usage ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_usage"
  ON public.message_usage FOR ALL
  USING (auth.uid() = user_id);

CREATE TRIGGER message_usage_updated_at
  BEFORE UPDATE ON public.message_usage
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

-- ── discipline_scores — feeds the Passport panel ─────────────────────────────
CREATE TABLE IF NOT EXISTS public.discipline_scores (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  score_date     DATE NOT NULL DEFAULT CURRENT_DATE,
  overall_score  INTEGER DEFAULT 0 CHECK (overall_score BETWEEN 0 AND 100),
  rule_adherence INTEGER DEFAULT 0 CHECK (rule_adherence BETWEEN 0 AND 100),
  emotional_ctrl INTEGER DEFAULT 0 CHECK (emotional_ctrl BETWEEN 0 AND 100),
  consistency    INTEGER DEFAULT 0 CHECK (consistency BETWEEN 0 AND 100),
  notes          TEXT,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, score_date)
);

ALTER TABLE public.discipline_scores ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_scores"
  ON public.discipline_scores FOR ALL
  USING (auth.uid() = user_id);

-- ── session_events — lightweight analytics (no 3rd-party tracker needed) ─────
CREATE TABLE IF NOT EXISTS public.session_events (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  event_name TEXT NOT NULL,
  properties JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.session_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_events"
  ON public.session_events FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "users_read_own_events"
  ON public.session_events FOR SELECT
  USING (auth.uid() = user_id);

-- ── Function: increment message count, return new count + whether limit hit ───
CREATE OR REPLACE FUNCTION public.increment_message_usage(
  p_user_id  UUID,
  p_mentor   TEXT,
  p_month    TEXT  -- 'YYYY-MM'
)
RETURNS TABLE(new_count INTEGER, limit_reached BOOLEAN)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_count INTEGER;
  v_plan  TEXT;
  v_limit INTEGER;
BEGIN
  -- Get user plan
  SELECT subscription_status INTO v_plan
  FROM public.user_profiles WHERE id = p_user_id;

  -- Plan limits: free=50, starter=500, pro=2000, institutional=unlimited
  v_limit := CASE v_plan
    WHEN 'free'          THEN 50
    WHEN 'starter'       THEN 500
    WHEN 'pro'           THEN 2000
    WHEN 'institutional' THEN 999999
    ELSE 50
  END;

  -- Upsert and increment
  INSERT INTO public.message_usage (user_id, mentor, month_key, message_count)
  VALUES (p_user_id, p_mentor, p_month, 1)
  ON CONFLICT (user_id, mentor, month_key)
  DO UPDATE SET
    message_count = public.message_usage.message_count + 1,
    updated_at    = NOW()
  RETURNING message_count INTO v_count;

  RETURN QUERY SELECT v_count, (v_count > v_limit);
END;
$$;
