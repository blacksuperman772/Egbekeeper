-- ============================================================
-- EdgeKeeper — Migration 012
-- Voice session usage tracking + per-plan monthly limits
-- Free: 1/mo · Resident: 3/mo · Fellow: 8/mo · Private Office: unlimited
-- ============================================================

CREATE TABLE IF NOT EXISTS public.voice_usage (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  month_key     TEXT NOT NULL,  -- 'YYYY-MM'
  session_count INTEGER NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, month_key)
);

ALTER TABLE public.voice_usage ENABLE ROW LEVEL SECURITY;

CREATE POLICY "voice_usage: user owns their rows"
  ON public.voice_usage FOR ALL
  USING (auth.uid() = user_id);

CREATE INDEX voice_usage_user_month ON public.voice_usage(user_id, month_key);

-- Increment and check in one round-trip
CREATE OR REPLACE FUNCTION public.increment_voice_usage(
  p_user_id UUID,
  p_month   TEXT
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
  SELECT subscription_status INTO v_plan
  FROM public.user_profiles WHERE id = p_user_id;

  v_limit := CASE v_plan
    WHEN 'free'          THEN 1
    WHEN 'starter'       THEN 3
    WHEN 'pro'           THEN 8
    WHEN 'institutional' THEN 999
    ELSE 1
  END;

  INSERT INTO public.voice_usage (user_id, month_key, session_count)
  VALUES (p_user_id, p_month, 1)
  ON CONFLICT (user_id, month_key)
  DO UPDATE SET
    session_count = public.voice_usage.session_count + 1,
    updated_at    = NOW()
  RETURNING session_count INTO v_count;

  RETURN QUERY SELECT v_count, (v_count > v_limit);
END;
$$;
