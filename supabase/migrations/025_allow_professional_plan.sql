-- 025_allow_professional_plan.sql
--
-- Bug: Private Office subscribers are stored as subscription_status = 'professional'
-- (server.js safePlan list, billing-success update, and the Polar webhook all write
-- 'professional'), but the existing CHECK constraint only allowed
-- ('free','starter','pro','institutional'). A successful Private Office payment was
-- therefore REJECTED by the database (error 23514) and the plan was never recorded —
-- the top tier ($599/mo) was broken end-to-end on the data side.
--
-- Fix: allow 'professional'. Keep 'institutional' so any legacy rows stay valid; the
-- application already treats both as the top tier (see the ['professional','institutional']
-- entitlement checks throughout server.js). Non-destructive — only loosens the constraint.

ALTER TABLE public.user_profiles
  DROP CONSTRAINT IF EXISTS user_profiles_subscription_status_check;

ALTER TABLE public.user_profiles
  ADD CONSTRAINT user_profiles_subscription_status_check
  CHECK (subscription_status IN ('free', 'starter', 'pro', 'professional', 'institutional'));
