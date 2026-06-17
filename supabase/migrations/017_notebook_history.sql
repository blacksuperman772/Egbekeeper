-- ============================================================
-- EdgeKeeper — Migration 017
-- Add conversation_history to notebooks for cross-device continuity
-- ============================================================

ALTER TABLE public.notebooks
  ADD COLUMN IF NOT EXISTS conversation_history JSONB DEFAULT '[]';

-- ── END OF MIGRATION ──────────────────────────────────────────────────
