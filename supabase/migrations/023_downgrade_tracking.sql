-- ============================================================
-- EdgeKeeper — Migration 023
-- Track the last paid plan before a downgrade to free.
-- Allows the mentor to acknowledge the change naturally
-- on the user's next session without repeating it forever.
-- ============================================================

ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS last_paid_plan TEXT DEFAULT NULL;
