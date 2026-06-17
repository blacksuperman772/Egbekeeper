-- ============================================================
-- 005_auto_user_profile.sql
-- Automatically creates a user_profiles row on every new signup.
-- Without this, new users have no profile row until onboarding
-- completes, causing /api/usage and plan checks to see a missing row.
-- ============================================================

-- ── TRIGGER FUNCTION ─────────────────────────────────────────
-- Runs as SECURITY DEFINER so it can write to public.user_profiles
-- even when invoked from the auth schema.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.user_profiles (
    id,
    full_name,
    onboarding_complete,
    subscription_status,
    bypass_subscription,
    created_at
  )
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
    false,
    'free',
    false,
    NOW()
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

-- ── TRIGGER ──────────────────────────────────────────────────
-- Fires after every INSERT on auth.users (i.e. every new signup).
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- ── END OF MIGRATION ─────────────────────────────────────────
