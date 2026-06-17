-- ============================================================
-- EdgeKeeper — Migration 002
-- Admin flag + bypass subscription + payment-agnostic billing
-- ============================================================

-- ── Add admin and bypass fields to user_profiles ─────────────────────────────
ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS bypass_subscription BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS is_admin             BOOLEAN DEFAULT FALSE;

-- ── Rename Stripe-specific columns → payment-agnostic ────────────────────────
ALTER TABLE public.user_profiles
  RENAME COLUMN stripe_customer_id TO payment_customer_code;

ALTER TABLE public.subscriptions
  RENAME COLUMN stripe_subscription_id TO payment_subscription_id;
ALTER TABLE public.subscriptions
  RENAME COLUMN stripe_customer_id TO payment_customer_code;

-- ── Drop old UNIQUE on stripe column (now named) ─────────────────────────────
-- (Paystack subscription codes are unique per subscription, not per customer)
-- Keep unique constraint on the renamed column
-- Nothing to drop — the UNIQUE was on stripe_subscription_id, now payment_subscription_id

-- ── Update subscription_status check to include all plan codes ────────────────
ALTER TABLE public.user_profiles
  DROP CONSTRAINT IF EXISTS user_profiles_subscription_status_check;

ALTER TABLE public.user_profiles
  ADD CONSTRAINT user_profiles_subscription_status_check
  CHECK (subscription_status IN ('free', 'starter', 'pro', 'institutional'));

-- ── Add subscriptions upsert constraint if missing ───────────────────────────
ALTER TABLE public.subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_user_id_key;
ALTER TABLE public.subscriptions
  ADD CONSTRAINT subscriptions_user_id_key UNIQUE (user_id);

-- ── Policy: admin can read all profiles ──────────────────────────────────────
-- We use the service role key server-side so RLS bypass is handled there.
-- No additional policy needed — admin API calls bypass RLS via service role.
