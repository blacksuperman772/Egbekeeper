# EdgeKeeper — Rules Panel Product Spec
**Status:** Ready for implementation
**Author:** ATLAS, Head of Product Strategy
**Date:** 2026-06-14
**Panel:** Personal Laws (keyboard shortcut: R)

---

## 1. What the Rules Panel Is

The Rules panel is not a checklist tool. It is an accountability ledger. The trader writes their own laws — in their own voice — and the AI reads every journal entry against those laws. When a law is broken, the panel records it. The trader cannot hide from their own rules.

The panel answers one question every time a trader opens it: **How many of my own laws am I actually keeping?**

---

## 2. Data Model

### 2.1 Tables

#### `trading_rules`
One row per rule the trader has written.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID FK → auth.users | RLS enforced |
| `rule_text` | TEXT | 5–500 chars. Written by the trader in their own words. |
| `category` | TEXT | Risk / Volume / Timing / Discipline / Execution / Psychology / General |
| `is_active` | BOOLEAN | FALSE = archived. Archived rules kept for history. |
| `sort_order` | INTEGER | Trader-controlled display order |
| `rationale` | TEXT | Optional: why this rule exists. Up to 1000 chars. |
| `origin_mentor` | TEXT | mike / ashley / self — who first surfaced this rule |
| `created_at` | TIMESTAMPTZ | When the trader wrote it |
| `updated_at` | TIMESTAMPTZ | Auto-updated by trigger |

#### `journal_entries`
One row per journal entry saved by the trader.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID FK → auth.users | |
| `entry_text` | TEXT | 1–8000 chars |
| `badge` | TEXT | good / consistent / flag / null |
| `financial_outcome` | TEXT | e.g. "+$180, -$90" |
| `identity_outcome` | TEXT | e.g. "+patience, -discipline" |
| `mentor_context` | TEXT | mike / ashley — which workspace |
| `ai_check_status` | TEXT | pending / processing / done / skipped |
| `ai_analysis_raw` | JSONB | Full AI response for debugging |
| `created_at` | TIMESTAMPTZ | |

#### `rule_violations`
One row per rule flagged per journal entry. A single entry can violate multiple rules.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `user_id` | UUID FK → auth.users | |
| `journal_entry_id` | UUID FK → journal_entries | |
| `rule_id` | UUID FK → trading_rules | |
| `confidence` | NUMERIC(4,3) | 0.0–1.0. AI certainty this is a real violation. |
| `mentor_note` | TEXT | 1–3 sentences in mentor voice explaining why it was flagged |
| `evidence_quote` | TEXT | Verbatim excerpt from journal entry that triggered the flag |
| `acknowledged` | BOOLEAN | Has the trader reviewed this? |
| `acknowledged_at` | TIMESTAMPTZ | |
| `created_at` | TIMESTAMPTZ | |

### 2.2 View: `rule_violation_summary`

Denormalised view joining `trading_rules` + `rule_violations`. Provides per-rule counts without join overhead in the panel.

Fields: `rule_id, user_id, rule_text, category, is_active, sort_order, rationale, origin_mentor, rule_created_at, total_violations, violations_last_30d, violations_last_7d, last_violated_at`

### 2.3 Relationships

```
auth.users
  │
  ├── trading_rules (many per user)
  │
  ├── journal_entries (many per user)
  │     │
  │     └── rule_violations (many per entry)
  │           └── → trading_rules (the rule that was broken)
```

---

## 3. UI Spec

### 3.1 Panel Header

```
PERSONAL LAWS                                    [✕]
────────────────────────────────────────────────────
[ Active Rules ]   [ History ]
```

No violation count in the header — keep it clean. The counts live on individual rules.

### 3.2 Active Rules Tab

**Section: Violation Alert (conditional)**
Only shown when there are unacknowledged violations from the last 7 days.

```
┌─────────────────────────────────────────────────┐
│  RECENT FLAGS — 3 violations in last 7 days     │
│  Your journal triggered rules you set yourself. │
└─────────────────────────────────────────────────┘
```
Uses `border-left: 2px solid #a06450` (the flag/red color from the existing palette). Styled like `guardian-suggestion` but with the flag color.

**Section: Rule List**

Each rule renders as:
```
┌─────────────────────────────────────────────────┐
│  [category tag]                    [3 flags]    │
│  Never risk above 1% per trade                  │
│                                                 │
│  Last flagged: June 10                          │
│  — "You mentioned doubling the position size    │
│     after the morning loss."                    │
└─────────────────────────────────────────────────┘
```

Rules with recent violations (last 7 days) get a subtle left border in the flag color (`#6a3838`). Clean rules have the standard `var(--border)` left border.

**Violation count badge** on each rule card:
- 0 violations: no badge shown
- 1–3: muted gold badge ("2 flags")
- 4+: flag-colored badge ("6 flags") — signals a pattern

**Rule card expanded state** (click to expand):
Shows up to 3 most recent violations, each with:
- Date of journal entry
- Evidence quote (verbatim excerpt)
- Mentor note (1–3 sentences in serif italic)
- [Mark reviewed] button → sets `acknowledged = TRUE`

**Add Rule Form** (bottom of active rules list):
```
┌──────────────────────────────────────────────────────────┐
│  Write your rule in your own words...                    │
└──────────────────────────────────────────────────────────┘
[ Risk ▾ ]  [ Category ▾ ]           [ Add Personal Law ]
```
- Textarea, not input — rules can be nuanced
- Category dropdown: Risk / Volume / Timing / Discipline / Execution / Psychology / General
- Button disabled until text is present
- On save: inserts to `trading_rules`, immediately appears in list
- No AI reformulation — the trader's exact words are preserved. The AI reads their words, not a cleaned version.

### 3.3 History Tab

A flat chronological list of ALL violations, newest first, grouped by journal entry date.

```
MON 10 JUNE 2026
────────────────
  ↳ Never move a stop loss against the position
    "I moved the stop down because I was convinced..."
    — Mike: You did it again. This is the third time in two weeks.

  ↳ No trading after 3 consecutive losses
    "After the third loss I told myself one more..."
    — Mike: Three losses is the signal. You already knew that.

THU 5 JUNE 2026
────────────────
  ↳ Maximum 2 trades per session
    "Opened a fourth position late in the day..."
```

Each violation entry links back to the journal entry it came from (opens Journal panel, scrolled to that entry).

### 3.4 Styling Notes (consistent with existing workspace aesthetic)

- No checkboxes (the existing `rule-check` shell UI uses them — this spec replaces that pattern). The rules are laws, not a daily checklist to tick off.
- Rule cards: `background: var(--stone); border: 1px solid var(--border)`
- Category tag: `font-family: var(--mono); font-size: 0.55rem; color: var(--muted)` — same as existing `.rule-tag`
- Violation count badge: same structure as `.nav-badge` but colored contextually
- Mentor notes: `font-family: var(--serif); font-style: italic; color: rgba(212,208,200,0.7)` — same as `.gr-narration`
- Evidence quotes: `font-family: var(--mono); font-size: 0.6rem; color: var(--muted)` with left border

---

## 4. AI Integration

### 4.1 When It Runs

When a trader saves a journal entry (clicks "Save Entry" in the Journal panel), the following sequence fires:

1. Entry is inserted into `journal_entries` with `ai_check_status = 'pending'`
2. A Supabase Edge Function `check-journal-against-rules` is invoked (via `supabase.functions.invoke()` from the client, or via a database webhook trigger on `journal_entries` INSERT)
3. Function sets `ai_check_status = 'processing'`
4. Function fetches all active rules for this user from `trading_rules WHERE is_active = TRUE`
5. If no active rules exist: sets `ai_check_status = 'skipped'`, exits
6. Function calls OpenAI with the prompt below
7. Parses response, inserts violation rows into `rule_violations`
8. Sets `ai_check_status = 'done'`

### 4.2 The Prompt

```
System:
You are a trading psychology AI working at EdgeKeeper. Your job is to read a trader's journal entry and identify whether they broke any of their own personal trading rules. You are not a therapist. You are not giving advice. You are reading their words and flagging specific rule violations with precision.

Rules for your analysis:
- Only flag a rule if there is clear evidence in the text that it was broken. Do not flag on inference or implication alone.
- A trader saying "I considered breaking the rule" is NOT a violation. A trader saying "I did X" or "I ended up doing X" where X violates a rule IS a violation.
- Assign a confidence score (0.0–1.0). Only include violations where confidence >= 0.65.
- For each violation: write a mentor_note in the voice of [MENTOR_NAME] — direct, observational, 1–3 sentences. No soft language. No "great job" for other rules followed. Only address the violation.
- Extract an evidence_quote: the shortest verbatim excerpt (under 200 chars) from the journal entry that most directly proves the violation.
- Return only valid JSON. No markdown. No explanation outside the JSON.

The trader's active rules:
[RULES_LIST]

Journal entry:
[JOURNAL_TEXT]

Return format:
{
  "violations": [
    {
      "rule_id": "<uuid>",
      "confidence": 0.92,
      "mentor_note": "You moved the stop. Third time this month. The rule exists because you asked me to hold you to it.",
      "evidence_quote": "I moved the stop down a bit because the setup still looked good"
    }
  ],
  "summary": "One-sentence assessment of the entry's overall rule discipline for this session."
}

If no violations are found, return: { "violations": [], "summary": "..." }
```

**Variable substitutions:**
- `[MENTOR_NAME]` → the trader's current mentor (Mike or Ashley) — affects tone of `mentor_note`
- `[RULES_LIST]` → formatted as numbered list: `1. (rule_id: abc123) Never risk above 1%...`
- `[JOURNAL_TEXT]` → the full `entry_text` from the journal entry

**Model:** `gpt-4o-mini` (existing stack). Max tokens: 800. Temperature: 0.2 (factual extraction, not creative).

### 4.3 Edge Function Signature

```javascript
// supabase/functions/check-journal-against-rules/index.ts
export default async function handler(req: Request) {
  const { journal_entry_id, user_id } = await req.json();

  // 1. Fetch journal entry
  // 2. Fetch active rules for user
  // 3. Early exit if no rules
  // 4. Build prompt
  // 5. Call OpenAI
  // 6. Parse JSON response
  // 7. Insert violations (filter by confidence >= 0.65)
  // 8. Update journal entry ai_check_status
  // 9. Return summary
}
```

### 4.4 What Gets Stored

Per violation row in `rule_violations`:
- `rule_id` — foreign key to the broken rule
- `confidence` — AI certainty score
- `mentor_note` — shown in the Rules panel and History tab
- `evidence_quote` — the exact words that triggered the flag

The `ai_analysis_raw` JSONB on `journal_entries` stores the full OpenAI response for debugging and potential future features (summary display, pattern detection).

### 4.5 UI Feedback After Save

When the trader saves a journal entry:
1. Entry appears immediately in the Journal panel (optimistic UI)
2. A subtle status indicator shows "Checking against your rules..." (mono label, no spinner — consistent with the aesthetic)
3. After the Edge Function returns (typically 2–4 seconds): if violations were found, the Rules nav badge in the sidebar increments and the panel, if open, refreshes
4. If open, a mentor-voiced line appears below the new entry: `— [n] of your laws were flagged in this entry.` in the same style as `journal-obs`

---

## 5. Implementation Plan

### Phase 1 — Data Layer (no AI yet)
1. Run `004_trading_rules.sql` migration via `npm run db:push`
2. Wire up the Add Rule form: real insert to `trading_rules`, real fetch on panel open
3. Replace hardcoded `buildRules()` with a live query from `rule_violation_summary` view
4. Rule cards show violation counts (all zeroes at this point — that's fine)

### Phase 2 — Journal Save
5. Wire up the Save Entry button: insert into `journal_entries` with `ai_check_status = 'pending'`
6. Persist journal entries for the logged-in user
7. Journal panel reads from `journal_entries` (replaces `getDefaultJournalEntries()`)

### Phase 3 — AI Check
8. Write and deploy the `check-journal-against-rules` Edge Function
9. Call it from the client after journal save (or trigger via DB webhook)
10. Insert violations, refresh Rules panel badge and card counts

### Phase 4 — History Tab
11. Build the History tab: query `rule_violations` joined to `journal_entries`, grouped by entry date
12. Wire acknowledge button

### Phase 5 — Panel Refinement
13. Expanded card state with violation list and mentor notes
14. Unacknowledged violations alert at top of Active Rules tab
15. Flag color treatment for rules with recent violations

---

## 6. Open Questions

1. **Trigger mechanism**: Should the Edge Function be invoked client-side (fetch after save) or server-side (Supabase DB webhook on INSERT to `journal_entries`)? Client-side is simpler given the current no-framework stack. DB webhook is more reliable but requires additional Supabase setup.

2. **Rule editing**: Can traders edit a rule after creating it? Editing changes the text the AI reads going forward. Recommend: allow editing but version the rule — freeze the `rule_text` on `created_at` snapshot and update the display. Alternatively, archive and recreate.

3. **Confidence threshold**: 0.65 is a starting point. If traders complain of false positives, raise to 0.75. If violations are being missed, lower to 0.55. This is a tunable product lever.

4. **Category suggestions**: Should the AI suggest a category when a rule is added? Low-cost enhancement: call GPT-4o-mini to classify the rule text into one of the 7 categories before insert. Non-blocking.

---

## 7. Top Concern

**The AI will produce false positives, and a false positive on a rule the trader wrote themselves is a trust-destroying event.**

If the AI flags a rule violation and the trader knows with certainty they did NOT break that rule, the entire accountability premise collapses. They stop believing the system. They stop writing honest journal entries. The product fails at its core value proposition.

Mitigations:
- The `confidence` threshold (>= 0.65) filters weak signals
- The `evidence_quote` makes every flag auditable — the trader can see exactly what the AI reacted to
- The `acknowledged` field lets traders mark false positives without deleting them (for analytics integrity)
- The prompt explicitly instructs the model NOT to flag on inference — only on direct statement

But the real mitigation is product design: never present a violation as definitive. Present it as a flag for review. The mentor note should be phrased as an observation, not a verdict. "This looked like it might touch your stop-loss rule — worth looking at" rather than "You broke rule 3."

This is why the `mentor_note` voice matters more than the violation count.
