-- ============================================================
-- EdgeKeeper — Migration 013
-- Fix handle_new_user() trigger: remove full_name column
-- reference that never existed in user_profiles, causing
-- "Database error creating new user" on every registration.
-- ============================================================

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.user_profiles (
    id,
    onboarding_complete,
    subscription_status,
    bypass_subscription,
    created_at
  )
  VALUES (
    NEW.id,
    false,
    'free',
    false,
    NOW()
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;
