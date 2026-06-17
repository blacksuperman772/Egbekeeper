# Logic Gaps — Founder Action Required

Gaps that were identified during the SAGE logic audit but cannot be fixed purely in code. Each requires a database migration, external service configuration, or a product decision.

---

## GAP-1: Infinite redirect loop if Supabase service role key is misconfigured

**Risk:** High  
**Where:** `server.js` — `verifySession` middleware

**What happens:** If `SUPABASE_SERVICE_ROLE_KEY` is wrong or missing, `supabaseAdmin.auth.getUser(token)` will always throw or return an error. `verifySession` silently treats this as unauthenticated and calls `next()`. `requireAuthPage` then redirects to `/auth.html`. The user signs in, gets a new cookie, hits `/workspace.html` again — and the same verification failure immediately sends them back to `/auth.html`. Result: infinite redirect loop with no visible error.

**Fix needed (founder action):**
- Ensure `SUPABASE_SERVICE_ROLE_KEY` is set correctly in `.env` and on the deployment platform.
- Add a startup health check that verifies the admin client can reach Supabase before the server begins accepting requests. Consider a `/health` route that returns 503 with a clear message if the admin client is broken.

---

## GAP-2: `user_profiles` row is never created automatically after sign-up

**Risk:** High  
**Where:** Supabase database / onboarding flow

**What happens:** After a new user registers via `signUp()`, the `auth.users` row exists but `user_profiles` has no corresponding row until onboarding writes one. During this window:
- `/api/usage` returned HTTP 500 (fixed — now uses `maybeSingle()` and defaults to `free` plan).
- `/api/chat` usage enforcement silently skips the limit check if the profile is missing (non-fatal, but means new users can exceed limits before the row exists).
- `/api/billing/initiate` plan pre-check treats a missing row as `free` plan (correct behavior, but the row should exist).

**Fix needed (founder action):**
- Create a Supabase database trigger (or Edge Function) on `auth.users INSERT` that automatically inserts a default row into `user_profiles` with `onboarding_complete = false` and `subscription_status = 'free'`.
- Migration file path: `supabase/migrations/YYYYMMDDHHMMSS_auto_create_user_profile.sql`
- Example trigger:
  ```sql
  CREATE OR REPLACE FUNCTION public.handle_new_user()
  RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
  BEGIN
    INSERT INTO public.user_profiles (id, onboarding_complete, subscription_status)
    VALUES (NEW.id, false, 'free')
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
  END;
  $$;

  CREATE OR REPLACE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();
  ```

---

## GAP-3: Paystack webhook has no deduplication — retried events apply twice

**Risk:** Medium  
**Where:** `server.js` — `/api/billing/webhook`

**What happens:** Paystack retries webhook delivery if the endpoint returns a non-2xx response or times out. The current handler acknowledges immediately (`res.json({ status: true })`) which is correct, but the subsequent DB updates (`user_profiles.subscription_status` update, etc.) are not idempotent against exact duplicate events. Running `update { subscription_status: plan }` twice is harmless for the same plan, but a `charge.success` followed by a retried `charge.success` for a different plan in a race condition could leave the account in an inconsistent state.

**Fix needed (founder action):**
- Create a `webhook_events` table with a unique constraint on `(event_id, event_type)` and record each processed event before applying side effects.
- Migration:
  ```sql
  CREATE TABLE IF NOT EXISTS public.webhook_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id    text NOT NULL,
    event_type  text NOT NULL,
    processed_at timestamptz DEFAULT now(),
    UNIQUE (event_id, event_type)
  );
  ```
- In the webhook handler, attempt an insert into `webhook_events` before processing. If the insert fails with a unique violation, skip the event.

---

## GAP-4: `subscriptions` table upserts on `onConflict: 'user_id'` — one row per user, not per subscription

**Risk:** Medium  
**Where:** `server.js` — `/billing/callback` and webhook handler

**What happens:** The `subscriptions` upsert uses `user_id` as the conflict key, meaning a user who upgrades from `starter` to `pro` will overwrite the old subscription record rather than keeping a history. This is fine for current state tracking but means there is no audit trail of subscription changes in this table.

**Fix needed (founder action, product decision):**
- If an audit trail is required, add a `subscription_history` table with an append-only insert on every plan change.
- Alternatively, add a `plan_history jsonb[]` column to `subscriptions` and append to it on each change.
- If no history is needed, document this decision explicitly so future engineers know it is intentional.

---

## GAP-5: `ek_plan` / `ek_billing` stored in `sessionStorage` — lost if user opens auth in a new tab

**Risk:** Low  
**Where:** `auth.html` — `redirectAfterAuth()`

**What happens:** When a pricing page stores `ek_plan` in `sessionStorage` and then the user navigates to `/auth.html`, the intent survives (same tab). However, if the user opens `/auth.html` in a new tab — or if the browser restores a previous session — `sessionStorage` is empty and the plan intent is silently lost. The user lands in the workspace without the billing flow being triggered.

**Fix needed (founder action):**
- Pricing pages should pass `?plan=pro` as a URL parameter to `/auth.html` (already done for some flows via `_plan`). Ensure all upgrade CTAs on `edgekeeper.html` and `pricing.html` use URL params rather than relying on `sessionStorage` as the primary vector.
- Alternatively, use `localStorage` for plan intent with a short TTL (e.g. 30 minutes) so it survives across tabs.

---

## GAP-6: No CSRF protection on state-mutating API routes

**Risk:** Medium (mitigated by `SameSite=Strict` cookie)  
**Where:** `server.js` — all POST/PATCH routes

**What happens:** The `ek_session` cookie is set with `SameSite=Strict`, which prevents it from being sent on cross-site requests in modern browsers. This is the primary CSRF mitigation. However, `SameSite=Strict` is not universally enforced in older browsers and some edge cases (e.g. top-level navigations from external sites on some browsers). There is no secondary CSRF token mechanism.

**Fix needed (founder action, if compliance requires it):**
- If strict compliance (PCI-DSS, SOC2) or support for older browsers is required, implement a CSRF token: generate a random token on session creation, store it server-side (or in a separate non-`HttpOnly` cookie), and require it as a header (`X-CSRF-Token`) on all state-mutating requests.
- For the current risk profile (no financial transactions handled directly — only Paystack redirect links), the `SameSite=Strict` mitigation is likely sufficient.

---

*Audit performed: 2026-06-14. Files reviewed: server.js, auth.html, workspace.html, onboarding.html.*
