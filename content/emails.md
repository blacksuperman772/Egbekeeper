# EdgeKeeper — Welcome Email Sequence
**Sent via Resend. Trigger: user completes onboarding and enters workspace for the first time.**
**Sender name: Mike (or Ashley, depending on chosen mentor). Sender address: mike@edgekeeper.io / ashley@edgekeeper.io**

---

## Email 1 — Day 0 (sent 2–4 hours after first session)
**Subject:** You showed up.
**From:** Mike (or Ashley)

---

**[MIKE VERSION]**

You did something most people don't.

You sat down, answered honestly, and didn't try to make yourself look better than you are. That's rarer than you think. Most traders come in with a version of themselves they've rehearsed. You didn't.

I've got what I need to get started. I'll be thinking about what you told me.

Come back when you're ready — or when you're not. Either way, I'll be here.

— Mike

---

**[ASHLEY VERSION]**

You showed up. That matters more than you know.

The first conversation is always the hardest — not because the questions are difficult, but because being honest with someone new takes something out of you. You did that. I noticed.

I'm still sitting with a few things you said. I'll have more to share when you're back.

Take some time. Then come find me.

— Ashley

---
**[TECHNICAL NOTES]**
- Delay: 2–4 hours post-onboarding completion (not immediate — feels more like the mentor reflected on the session)
- Plain text preferred. No images, no header graphic, no footer CTA bar.
- If Resend supports it: no "unsubscribe" in body — move to footer only, as small legal text.

---

## Email 2 — Day 3
**Subject:** Something I noticed.
**From:** Mike (or Ashley)

---

**[MIKE VERSION]**

Three days. You've either been back to the markets or you've been avoiding them. Either way, something's happened.

You mentioned [PATTERN_FROM_INTAKE] — I've been thinking about that. Not because it's unusual. Because it's specific to how you're wired, and it tends to show up at predictable moments.

Next time you feel that pressure — before you do anything — come talk to me first. Even just for five minutes.

That's how this works.

— Mike

P.S. If the week went sideways, that's exactly why I'm here. Don't wait until things are clean.

---

**[ASHLEY VERSION]**

I've been thinking about you.

There was something you said — [PATTERN_FROM_INTAKE] — that stayed with me. You said it quietly, like you weren't sure it was worth mentioning. It was.

That's usually where the real work lives — in the things we say under our breath.

Come back when you're ready. If the past few days have been hard, I want to hear about it. If they've been fine, I want to hear about that too.

— Ashley

---
**[TECHNICAL NOTES]**
- `[PATTERN_FROM_INTAKE]` should be dynamically populated from the notebook `patterns[]` or `observations[]` field generated during onboarding. Pull the first or highest-confidence pattern. If unavailable, substitute a generic but non-hollow placeholder: "what happens to your rules under pressure" (Mike) / "the gap between how you trade and how you want to trade" (Ashley).
- Subject line should feel like something a real person sent — not a marketing sequence. Consider A/B: "Something I noticed." vs. "Three days."

---

## Email 3 — Day 7
**Subject:** One week in.
**From:** Mike (or Ashley)

---

**[MIKE VERSION]**

A week ago you walked into an intake room and answered questions most traders won't even ask themselves.

Here's what I want to know: did anything from that conversation actually change how you operated this week? Not dramatically. Even something small — a moment of pause, a rule you actually followed, a trade you didn't take.

If yes: that's the signal. Build on it.

If no: that's fine too. The gap between knowing and doing takes time to close. That's exactly what we're here for.

Come in. Tell me about the week.

— Mike

---

**[ASHLEY VERSION]**

It's been a week.

I'm curious about you — not your P&L. I want to know what this week actually felt like. Were you patient with yourself? Did something familiar happen that you saw coming this time?

You don't have to have had a good week to come back. You just have to come back.

One conversation this week. That's all I'm asking for.

— Ashley

---
**[TECHNICAL NOTES]**
- This email should include a single CTA button if Resend supports HTML: "Talk to [Mike/Ashley] →" linking to workspace.html?mentor=[mike|ashley]
- If no HTML email: plain link on its own line.
- Do not include: pricing upsell, feature list, social links, or anything that breaks the mentor-voice immersion.
- All three emails should come from the same sender name and address as the chosen mentor — not from "EdgeKeeper" or "The Team."

---

## Implementation Notes for Founder

**Before wiring Resend:**
1. Confirm the intake notebook (`ek_notebook_mike` / `ek_notebook_ashley` in localStorage, or Supabase equivalent) is accessible server-side for Email 2 pattern injection.
2. Decide on HTML vs plain text format. Recommendation: plain text for Email 1 and 2 (feels personal), minimal HTML for Email 3 (single CTA button only).
3. The `[PATTERN_FROM_INTAKE]` injection in Email 2 is the highest-value element — it's what makes these feel like a real mentor reaching out, not a drip sequence. Prioritize getting this working.
4. Sender domain: ensure mike@edgekeeper.io and ashley@edgekeeper.io are verified in Resend before sending. Reply-to should route somewhere monitored.
5. Review tone against your actual intake AI output — if the mentor voice during onboarding has drifted from the voice in these emails, the user will feel the seam.
