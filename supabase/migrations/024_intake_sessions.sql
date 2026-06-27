-- ============================================================
-- EdgeKeeper — Migration 024
-- Server-side intake session persistence.
-- Solves data loss from tab close, device switch, or private
-- browsing during the onboarding intake conversation.
-- Authenticated users get their in-progress intake mirrored
-- server-side; anonymous first-time users still use localStorage.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.intake_sessions (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  mentor_key     TEXT        NOT NULL DEFAULT 'mike',
  exchange_count INT         NOT NULL DEFAULT 0,
  history        JSONB       NOT NULL DEFAULT '[]'::jsonb,
  level          TEXT        NOT NULL DEFAULT '',
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One active session per user (not per mentor — intake always uses Marcus)
CREATE UNIQUE INDEX IF NOT EXISTS intake_sessions_user_idx
  ON public.intake_sessions(user_id);

-- RLS: users can only read/write their own session
ALTER TABLE public.intake_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "intake_sessions_user_policy"
  ON public.intake_sessions
  FOR ALL
  TO authenticated
  USING  (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Index for fast lookups by user_id
CREATE INDEX IF NOT EXISTS intake_sessions_user_id_idx
  ON public.intake_sessions(user_id);
