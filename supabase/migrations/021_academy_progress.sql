-- Academy module progress persisted server-side.
-- Stored as JSONB: { "module_key": { "started": epoch_ms, "completed": epoch_ms|null } }
alter table user_profiles
  add column if not exists academy_progress jsonb default '{}';

-- Index for fast lookups
create index if not exists idx_user_profiles_academy_track
  on user_profiles(academy_track) where academy_track is not null;
