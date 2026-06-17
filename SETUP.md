# EdgeKeeper — Production Setup Guide

## Prerequisites
- Node.js 18+
- A Supabase account (supabase.com)
- A Stripe account (stripe.com)
- An ElevenLabs account (elevenlabs.io)
- Your OpenAI API key (already configured)

---

## Step 1 — Supabase

### 1.1 Create a project
1. Go to https://supabase.com and create a new project
2. Choose a strong database password and save it
3. Wait for the project to provision (~2 minutes)

### 1.2 Get your API keys
1. Go to **Project Settings → API**
2. Copy:
   - **Project URL** → `SUPABASE_URL`
   - **anon / public key** → `SUPABASE_ANON_KEY`
   - **service_role / secret key** → `SUPABASE_SERVICE_ROLE_KEY`
3. Paste all three into `.env`

### 1.3 Run the database migration
1. Go to **SQL Editor** in your Supabase dashboard
2. Paste the contents of `supabase/migrations/001_schema.sql`
3. Click **Run**
4. Verify all tables appear in **Table Editor**

### 1.4 Configure Auth
1. Go to **Authentication → Settings**
2. Set **Site URL** to your production domain (e.g. `https://edgekeeper.io`)
3. Add `http://localhost:3000` to **Redirect URLs** for local dev
4. Under **Email**, enable **Magic Links**
5. Customize the email template subject: *"Your EdgeKeeper access link"*

---

## Step 2 — Stripe

### 2.1 Get API keys
1. Go to https://dashboard.stripe.com → **Developers → API keys**
2. Copy **Secret key** → `STRIPE_SECRET_KEY`
3. Copy **Publishable key** → `STRIPE_PUBLISHABLE_KEY`

### 2.2 Create products
Create two products in Stripe Dashboard → **Products**:

**Starter** — $39/month
- Add monthly price: `$39.00 USD / month`
- Add annual price: `$390.00 USD / year`
- Note the price IDs (starts with `price_`)

**Pro** — $89/month
- Add monthly price: `$89.00 USD / month`
- Add annual price: `$890.00 USD / year`
- Note the price IDs

### 2.3 Configure webhook
1. Go to **Developers → Webhooks → Add endpoint**
2. Endpoint URL: `https://yourdomain.com/api/billing/webhook`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`
4. Copy **Signing secret** → `STRIPE_WEBHOOK_SECRET`

### 2.4 Update pricing.html
In `pricing.html`, find the `PRICE_IDS` object and replace with your actual Stripe price IDs:
```javascript
const PRICE_IDS = {
  starter_monthly: 'price_xxxxxxxxxxxxxxxx',
  starter_annual:  'price_xxxxxxxxxxxxxxxx',
  pro_monthly:     'price_xxxxxxxxxxxxxxxx',
  pro_annual:      'price_xxxxxxxxxxxxxxxx',
};
```

---

## Step 3 — ElevenLabs Voice Agents

### 3.1 Get API key
1. Go to https://elevenlabs.io → **Profile Settings → API Keys**
2. Create a new key → `ELEVENLABS_API_KEY`

### 3.2 Create Mike's voice agent
1. Go to **Conversational AI → Create Agent**
2. Name: **Mike — EdgeKeeper**
3. Voice: Choose a deep, authoritative male voice (e.g. *Adam* or *Antoni*)
4. System prompt:
```
You are Mike, a Senior Mentor at EdgeKeeper. You are 52 years old. Former professional trader — 18 years trading before transitioning to coaching. Direct, surgical, logical. You ask the uncomfortable question first. Short responses. Questions with purpose. Challenges excuses. Dry humor, earned slowly. You are not an AI. You are a long-term mentor. Never say "As an AI", "Great question", "I understand", "Absolutely", or "Thanks for sharing".
```
5. Copy the **Agent ID** → `ELEVENLABS_MIKE_AGENT_ID`

### 3.3 Create Ashley's voice agent
1. Create another agent: **Ashley — EdgeKeeper**
2. Voice: Choose a warm, clear female voice (e.g. *Bella* or *Elli*)
3. System prompt:
```
You are Ashley, a Senior Mentor at EdgeKeeper. You are 42 years old. Performance psychologist — 15 years working with traders and athletes. Warm, reflective, emotion-focused. You notice what is unsaid. Comfortable with silence. You are not an AI. You are a long-term mentor. Never say "As an AI", "That's great", "Thanks for sharing", "Of course", "Absolutely", or "Certainly".
```
4. Copy the **Agent ID** → `ELEVENLABS_ASHLEY_AGENT_ID`

---

## Step 4 — Complete the Stripe checkout integration

The server.js has placeholder routes for billing. To complete them:

### 4.1 Install Stripe (already done)
```bash
npm install stripe  # already installed
```

### 4.2 Update `/api/billing/checkout` in server.js
Replace the placeholder with:
```javascript
app.post('/api/billing/checkout', requireAuthApi, apiLimiter, async (req, res) => {
  const { priceId, plan } = req.body;
  if (!priceId) return res.status(400).json({ error: 'priceId required' });

  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

  // Get or create Stripe customer
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('stripe_customer_id')
    .eq('id', req.user.id)
    .single();

  let customerId = profile?.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({ email: req.user.email });
    customerId = customer.id;
    await supabaseAdmin.from('user_profiles')
      .update({ stripe_customer_id: customerId })
      .eq('id', req.user.id);
  }

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    mode: 'subscription',
    success_url: `${process.env.SITE_URL || 'http://localhost:3000'}/workspace.html?checkout=success`,
    cancel_url:  `${process.env.SITE_URL || 'http://localhost:3000'}/pricing.html`,
    metadata: { userId: req.user.id, plan },
  });

  res.json({ url: session.url });
});
```

### 4.3 Update `/api/billing/webhook` in server.js
Replace the placeholder with a proper Stripe signature verification handler.

---

## Step 5 — Start the server

```bash
# Install dependencies (already done)
npm install

# Start in development
npm start

# For production, use PM2 or a similar process manager:
npm install -g pm2
pm2 start server.js --name edgekeeper
pm2 save
```

---

## Environment Variables Reference

| Variable | Required | Source |
|---|---|---|
| `OPENAI_API_KEY` | ✅ | OpenAI dashboard |
| `OPENAI_MODEL` | ✅ | `gpt-5.5` |
| `SUPABASE_URL` | ✅ | Supabase → Project Settings → API |
| `SUPABASE_ANON_KEY` | ✅ | Supabase → Project Settings → API |
| `SUPABASE_SERVICE_ROLE_KEY` | ✅ | Supabase → Project Settings → API |
| `STRIPE_SECRET_KEY` | ✅ | Stripe → Developers → API keys |
| `STRIPE_PUBLISHABLE_KEY` | ✅ | Stripe → Developers → API keys |
| `STRIPE_WEBHOOK_SECRET` | ✅ | Stripe → Developers → Webhooks |
| `ELEVENLABS_API_KEY` | ✅ | ElevenLabs → Profile → API Keys |
| `ELEVENLABS_MIKE_AGENT_ID` | ✅ | ElevenLabs → Conversational AI |
| `ELEVENLABS_ASHLEY_AGENT_ID` | ✅ | ElevenLabs → Conversational AI |
| `PORT` | optional | Default: 3000 |
| `SITE_URL` | production | Your live domain, e.g. `https://edgekeeper.io` |

---

## Security checklist before going live

- [ ] `.env` is in `.gitignore` and never committed
- [ ] Supabase service role key is only in `.env`, never in HTML
- [ ] Stripe webhook signature verification is active
- [ ] All Supabase RLS policies are enabled (run `001_schema.sql`)
- [ ] HTTPS is enforced on your domain (Supabase auth requires it)
- [ ] Session cookie gets `Secure` flag in production (add `; Secure` when `NODE_ENV=production`)
- [ ] Rate limits are tested under load
- [ ] ElevenLabs agent prompts do not expose internal data

---

## Pages

| URL | Auth required | Purpose |
|---|---|---|
| `/` | No | Redirects to `/edgekeeper.html` |
| `/edgekeeper.html` | No | Landing page |
| `/pricing.html` | No | Pricing + signup CTA |
| `/auth.html` | No | Sign in / Sign up |
| `/onboarding.html` | Yes | Intake flow (first-time users) |
| `/workspace.html` | Yes | Main mentor workspace |
