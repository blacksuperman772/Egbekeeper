/**
 * One-time script: create or reset the admin account in Supabase.
 *
 * Usage:
 *   node scripts/create-admin.js
 *
 * What it does:
 *   1. Looks up the admin email in Supabase auth
 *   2. If the account doesn't exist → creates it with a temporary password
 *   3. If it does exist → sends a password-reset email so you can set your own
 *   4. Ensures the user_profiles row has is_admin = true
 *
 * Requires: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const SUPABASE_URL      = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY  = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_EMAIL       = process.env.ADMIN_EMAIL || 'alexandermwhitmore@gmail.com';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error('\n  ✗  SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env\n');
  process.exit(1);
}

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// Anon client for sending password-reset email (requires anon key)
const anon = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })
  : null;

async function run() {
  console.log(`\n  EdgeKeeper — Admin Account Setup`);
  console.log(`  Email: ${ADMIN_EMAIL}\n`);

  // ── 1. Find existing user by querying auth via RPC ──────────────────────────
  // listUsers can miss soft-deleted or specially-created accounts.
  // We also do a case-insensitive search across all pages.
  let existing = null;
  let page = 1;
  while (true) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 1000 });
    if (error) { console.error('  ✗  Could not list users:', error.message); process.exit(1); }
    const found = data.users.find(
      u => (u.email || '').trim().toLowerCase() === ADMIN_EMAIL.toLowerCase()
    );
    if (found) { existing = found; break; }
    if (data.users.length < 1000) break;
    page++;
  }

  // If listUsers missed them, try fetching via user_profiles (is_admin flag)
  if (!existing) {
    const { data: profiles } = await admin
      .from('user_profiles')
      .select('id')
      .eq('is_admin', true)
      .maybeSingle();
    if (profiles?.id) {
      const { data: authUser } = await admin.auth.admin.getUserById(profiles.id);
      if (authUser?.user?.email?.toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
        existing = authUser.user;
      }
    }
  }

  let userId;
  const tempPassword = crypto.randomBytes(12).toString('base64url');

  if (!existing) {
    // ── 2a. Account not found — create it ───────────────────────────────────
    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email:         ADMIN_EMAIL,
      password:      tempPassword,
      email_confirm: true,
    });

    if (createErr) {
      // "Database error" often means email already exists in a deleted state.
      // The Supabase dashboard → Authentication → Users is the fix path.
      console.error('  ✗  Could not create admin user:', createErr.message);
      if (createErr.message.includes('Database error')) {
        console.error('\n  This usually means the email already exists in a deleted/banned state.');
        console.error('  Fix: Supabase dashboard → Authentication → Users');
        console.error(`  Search for ${ADMIN_EMAIL} and either restore or permanently delete it,`);
        console.error('  then run this script again.\n');
      }
      process.exit(1);
    }

    userId = created.user.id;
    console.log('  ✓  Admin account created.');

  } else {
    // ── 2b. Account found — reset password directly ──────────────────────────
    userId = existing.id;
    console.log(`  ✓  Admin account found (id: ${userId}). Resetting password…`);

    const { error: updateErr } = await admin.auth.admin.updateUserById(userId, {
      password:      tempPassword,
      email_confirm: true,
    });

    if (updateErr) {
      console.error('  ✗  Could not reset password:', updateErr.message);
      process.exit(1);
    }
    console.log('  ✓  Password reset.');
  }

  console.log(`\n  ┌──────────────────────────────────────────────────`);
  console.log(`  │  Temporary password: ${tempPassword}`);
  console.log(`  │`);
  console.log(`  │  1. Go to /auth.html and sign in with this password`);
  console.log(`  │  2. Then go to Settings → Change Password to set`);
  console.log(`  │     your permanent password.`);
  console.log(`  └──────────────────────────────────────────────────\n`);

  // ── 3. Ensure user_profiles row has is_admin = true ─────────────────────────
  const { error: profileErr } = await admin.from('user_profiles').upsert(
    {
      id:                  userId,
      is_admin:            true,
      onboarding_complete: true,
      subscription_status: 'institutional',
      bypass_subscription: true,
    },
    { onConflict: 'id' }
  );

  if (profileErr) {
    console.warn('  ⚠  Could not set admin profile flags:', profileErr.message);
    console.warn('     You may need to run this again after running migrations.\n');
  } else {
    console.log('  ✓  Admin profile flags set (is_admin, bypass_subscription).\n');
  }

  console.log('  Done. Sign in at /auth.html then navigate to /admin.html\n');
}

run().catch(err => {
  console.error('\n  ✗  Unexpected error:', err.message, '\n');
  process.exit(1);
});
