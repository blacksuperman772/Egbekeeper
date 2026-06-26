'use strict';

// ── Entitlement module ─────────────────────────────────────────────────────────
// Single source of truth for plan feature access. Every gate in server.js calls
// can(profile, feature) instead of re-listing plan keys inline.
//
// plan slug map:
//   free          → Free trial
//   starter       → Resident
//   pro           → Fellow
//   professional  → Private Office
//   institutional → Institution

const PAID_PLANS      = new Set(['starter', 'pro', 'professional', 'institutional']);
const GUARDIAN_PLANS  = new Set(['pro', 'professional', 'institutional']);
const VAULT_PLANS     = new Set(['professional', 'institutional']);
const ACADEMY_PAID    = PAID_PLANS; // any paid plan unlocks Tracks 2-6

// Feature → minimum plan set required (bypass_subscription overrides all)
const GATES = {
  chat:          null,                // always available (usage-limited by quota)
  voice:         null,                // always available (session-limited)
  academy_free:  null,                // Track 1 always free
  journal:       PAID_PLANS,
  rules:         PAID_PLANS,
  academy_paid:  ACADEMY_PAID,
  guardian:      GUARDIAN_PLANS,
  analytics:     GUARDIAN_PLANS,
  vault:         VAULT_PLANS,
  passport:      VAULT_PLANS,
  reports:       VAULT_PLANS,
};

/**
 * can(profile, feature) — returns true if the profile has access to the feature.
 * profile must have { subscription_status, bypass_subscription }.
 * If profile is null/undefined, treats as free plan without bypass.
 */
function can(profile, feature) {
  if (profile?.bypass_subscription) return true;
  const requiredSet = GATES[feature];
  if (requiredSet === null || requiredSet === undefined) return true; // always allowed
  const plan = profile?.subscription_status || 'free';
  return requiredSet.has(plan);
}

/**
 * planLabel(slug) — human-readable plan name.
 */
const PLAN_LABELS = {
  free:          'Free Trial',
  starter:       'Resident',
  pro:           'Fellow',
  professional:  'Private Office',
  institutional: 'Institution',
};
function planLabel(slug) { return PLAN_LABELS[slug] || slug; }

/**
 * nextPlan(slug) — the next upgrade tier, or null at the top.
 */
const NEXT_PLAN = {
  free:          'starter',
  starter:       'pro',
  pro:           'professional',
  professional:  'institutional',
  institutional: null,
};
function nextPlan(slug) { return NEXT_PLAN[slug] ?? null; }

module.exports = { can, planLabel, nextPlan, PAID_PLANS, GUARDIAN_PLANS, VAULT_PLANS };
