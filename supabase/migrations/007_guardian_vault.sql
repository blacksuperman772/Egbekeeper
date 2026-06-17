-- ============================================================
-- EdgeKeeper — Guardian Layer & The Vault
-- Migration: 007_guardian_vault.sql
-- ============================================================

-- ── guardian_data ─────────────────────────────────────────────────────────────
-- Real-time account state. One row per user, upserted on each update.
-- Data arrives via /api/guardian/update (MT4/MT5 EA webhook or manual entry).
CREATE TABLE public.guardian_data (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  balance              NUMERIC,
  equity               NUMERIC,
  daily_pnl            NUMERIC,
  daily_pnl_pct        NUMERIC,
  consecutive_losses   INTEGER DEFAULT 0,
  open_lots            NUMERIC DEFAULT 0,
  max_drawdown_pct     NUMERIC DEFAULT 0,
  platform             TEXT DEFAULT 'manual'
                         CHECK (platform IN ('metatrader4', 'metatrader5', 'ctrader', 'tradingview', 'manual')),
  lock_level           INTEGER DEFAULT 1 CHECK (lock_level BETWEEN 1 AND 5),
  is_connected         BOOLEAN DEFAULT FALSE,
  last_updated         TIMESTAMPTZ DEFAULT NOW(),
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

ALTER TABLE public.guardian_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY "guardian_data: user owns their row"
  ON public.guardian_data
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- ── vault_entries ─────────────────────────────────────────────────────────────
-- Every time a Break Room triggers or the mentor intervenes, a vault entry
-- is logged here. One entry per intercepted decision.
CREATE TABLE public.vault_entries (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  instrument           TEXT,
  direction            TEXT CHECK (direction IN ('buy', 'sell', 'close', NULL)),
  lot_size             NUMERIC,
  lock_level           INTEGER CHECK (lock_level BETWEEN 1 AND 5),
  reason               TEXT NOT NULL,
  estimated_outcome    TEXT,
  account_balance      NUMERIC,
  daily_pnl_pct        NUMERIC,
  consecutive_losses   INTEGER,
  mentor               TEXT DEFAULT 'mike' CHECK (mentor IN ('mike', 'ashley'))
);

ALTER TABLE public.vault_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "vault_entries: user owns their rows"
  ON public.vault_entries
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Index for fast chronological fetch per user
CREATE INDEX vault_entries_user_created ON public.vault_entries(user_id, created_at DESC);

-- ── guardian_data admin access ─────────────────────────────────────────────────
-- Service role has full access via supabaseAdmin client (bypasses RLS).
-- No additional policy needed.
