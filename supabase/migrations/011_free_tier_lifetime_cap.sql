-- ============================================================
-- EdgeKeeper — Migration 011
-- Free tier: 7 lifetime messages (not 50/month)
-- ============================================================

-- Drop current function signature so we can replace it cleanly
DROP FUNCTION IF EXISTS public.increment_message_usage(UUID, TEXT, TEXT);

CREATE OR REPLACE FUNCTION public.increment_message_usage(
  p_user_id UUID,
  p_mentor  TEXT,
  p_month   TEXT
)
RETURNS TABLE(new_count INTEGER, limit_reached BOOLEAN, near_limit BOOLEAN)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_count    INTEGER;
  v_lifetime INTEGER;
  v_plan     TEXT;
  v_limit    INTEGER;
  v_grace    CONSTANT INTEGER := 10;
BEGIN
  SELECT subscription_status INTO v_plan
  FROM public.user_profiles WHERE id = p_user_id;

  -- Always increment (tracks usage across all plans)
  INSERT INTO public.message_usage (user_id, mentor, month_key, message_count)
  VALUES (p_user_id, p_mentor, p_month, 1)
  ON CONFLICT (user_id, mentor, month_key)
  DO UPDATE SET
    message_count = public.message_usage.message_count + 1,
    updated_at    = NOW()
  RETURNING message_count INTO v_count;

  -- Free plan: 7 total lifetime messages, no grace buffer
  IF v_plan = 'free' OR v_plan IS NULL THEN
    SELECT COALESCE(SUM(message_count), 0) INTO v_lifetime
    FROM public.message_usage WHERE user_id = p_user_id;
    RETURN QUERY SELECT v_lifetime, (v_lifetime > 7), FALSE;
    RETURN;
  END IF;

  -- Paid plans: monthly cap + 10-message grace buffer
  v_limit := CASE v_plan
    WHEN 'starter'        THEN 500
    WHEN 'pro'            THEN 2000
    WHEN 'institutional'  THEN 999999
    ELSE 500
  END;

  RETURN QUERY SELECT
    v_count,
    (v_count > v_limit + v_grace),
    (v_count >= v_limit AND v_count <= v_limit + v_grace);
END;
$$;
