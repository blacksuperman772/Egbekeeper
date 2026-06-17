-- ============================================================
-- EdgeKeeper — Migration 010
-- 10-message grace buffer + updated plan limits
-- ============================================================

-- Must drop first because the return type (OUT columns) changed
DROP FUNCTION IF EXISTS public.increment_message_usage(UUID, TEXT, TEXT);

-- Replace the message usage function to add a 10-message grace buffer
-- before hard cutoff. Users get a warning at the hard limit but can
-- send 10 more messages before being blocked. This prevents abrupt
-- mid-conversation cutoffs.

CREATE OR REPLACE FUNCTION public.increment_message_usage(
  p_user_id  UUID,
  p_mentor   TEXT,
  p_month    TEXT  -- 'YYYY-MM'
)
RETURNS TABLE(new_count INTEGER, limit_reached BOOLEAN, near_limit BOOLEAN)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_count  INTEGER;
  v_plan   TEXT;
  v_limit  INTEGER;
  v_grace  CONSTANT INTEGER := 10;
BEGIN
  -- Get user plan
  SELECT subscription_status INTO v_plan
  FROM public.user_profiles WHERE id = p_user_id;

  -- Updated plan limits
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

  -- limit_reached = true only after the grace buffer is exhausted
  -- near_limit    = true when at or past the hard limit (warning zone)
  RETURN QUERY SELECT
    v_count,
    (v_count > v_limit + v_grace),   -- hard block
    (v_count >= v_limit AND v_count <= v_limit + v_grace);  -- grace window
END;
$$;
