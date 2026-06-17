-- ============================================================
-- EdgeKeeper — Migration 015
-- Internal office communication tables:
--   office_messages — group chat between workers
-- Admin-only; accessed via service role key (no RLS policies needed
-- for reads/writes — service role bypasses RLS).
-- ============================================================

CREATE TABLE IF NOT EXISTS public.office_messages (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  worker_id    TEXT        NOT NULL,
  worker_name  TEXT        NOT NULL,
  avatar_char  TEXT        NOT NULL DEFAULT '?',
  content      TEXT        NOT NULL CHECK (char_length(content) BETWEEN 1 AND 4000),
  msg_type     TEXT        NOT NULL DEFAULT 'chat'
                             CHECK (msg_type IN ('chat','task','status','system','director')),
  metadata     JSONB,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.office_messages ENABLE ROW LEVEL SECURITY;
-- No user-facing policies — all access goes via service role server-side.

CREATE INDEX idx_office_messages_created
  ON public.office_messages (created_at DESC);

-- Seed with a startup status burst so the office feels alive on first load
INSERT INTO public.office_messages (worker_id, worker_name, avatar_char, content, msg_type) VALUES
  ('system',   'System',   'S', 'EdgeKeeper Internal Office — session started.', 'system'),
  ('atlas',    'Atlas',    'A', 'Product audit complete. 14 features shipped, 15 queued. Prop firm landing page is the highest-leverage item we haven''t touched yet.', 'status'),
  ('rex',      'Rex',      'R', 'Security hardening applied. HSTS, rate limits, input validation all live. Webhook dedup constraint tightened this session.', 'status'),
  ('zara',     'Zara',     'Z', 'Three.js particle removed from landing. Pricing page visual pass complete. Ready for the next design brief.', 'status'),
  ('kai',      'Kai',      'K', 'Voice sessions now open to all plans with monthly limits enforced server-side. Guardian AI disclaimer corrected.', 'status'),
  ('milo',     'Milo',     'M', 'Watching prop firm subreddits. FTMO and The5ers communities are asking for exactly what we build. Outreach strategy ready when you are.', 'status'),
  ('nova',     'Nova',     'N', 'Cross-page visual audit queued. Will flag any tokens still using Knoxx violet after this session''s updates.', 'status'),
  ('sage',     'Sage',     'S', 'Customer success framework drafted. Onboarding flow converts well but users drop off before voice session — need a prompt nudge.', 'status'),
  ('phoenix',  'Phoenix',  'P', 'Paystack plan codes still pending from founder. Revenue blocked until those are in .env. Priority one for next action item.', 'status'),
  ('leo',      'Leo',      'L', 'Analytics schema defined. Ready to instrument session events once the PostHog or Plausible decision is made.', 'status');

-- ── END OF MIGRATION ──────────────────────────────────────────────────
