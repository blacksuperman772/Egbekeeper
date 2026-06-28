#!/usr/bin/env node
/**
 * polar-create-subscriptions.js
 *
 * EdgeKeeper's Polar products were created as ONE-TIME purchases
 * (recurring_interval = null), so "monthly"/"annual" plans would charge once
 * and never rebill, and the subscription.* webhooks the server relies on would
 * never fire. This script creates proper RECURRING subscription products that
 * mirror the existing ones (same name + amount), with the correct interval.
 *
 * It reads the 6 current product IDs from the POLAR_PRODUCT_* env vars, looks
 * up each existing product for its name and price, then creates a recurring
 * counterpart. It prints the new IDs and the exact .env block to paste, and
 * (with --commit) archives the old one-time products so each plan has exactly
 * one active product.
 *
 *   node scripts/polar-create-subscriptions.js            # dry run (no writes)
 *   node scripts/polar-create-subscriptions.js --commit   # create + archive
 *
 * Nothing here moves money or accepts payments — it only configures products,
 * and every action is reversible (products can be un-archived in the dashboard).
 */
require('dotenv').config();

const API = 'https://api.polar.sh/v1';
const TOKEN = process.env.POLAR_ACCESS_TOKEN;
const ORG = process.env.POLAR_ORGANIZATION_ID;
const COMMIT = process.argv.includes('--commit');

// envVar -> { interval } ; MONTHLY => month, ANNUAL => year
const PLANS = [
  { env: 'POLAR_PRODUCT_STARTER_MONTHLY',       interval: 'month' },
  { env: 'POLAR_PRODUCT_STARTER_ANNUAL',        interval: 'year'  },
  { env: 'POLAR_PRODUCT_PRO_MONTHLY',           interval: 'month' },
  { env: 'POLAR_PRODUCT_PRO_ANNUAL',            interval: 'year'  },
  { env: 'POLAR_PRODUCT_PROFESSIONAL_MONTHLY',  interval: 'month' },
  { env: 'POLAR_PRODUCT_PROFESSIONAL_ANNUAL',   interval: 'year'  },
];

async function api(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${JSON.stringify(json)}`);
  return json;
}

(async () => {
  if (!TOKEN || !ORG) { console.error('Missing POLAR_ACCESS_TOKEN or POLAR_ORGANIZATION_ID'); process.exit(1); }
  console.log(`Mode: ${COMMIT ? 'COMMIT (will create + archive)' : 'DRY RUN (no writes)'}\n`);

  const results = [];
  for (const plan of PLANS) {
    const oldId = process.env[plan.env];
    if (!oldId) { console.log(`! ${plan.env} not set — skipping`); continue; }

    const existing = await api('GET', `/products/${oldId}`);
    const price = (existing.prices || [])[0] || {};
    const amount = price.price_amount;
    const currency = price.price_currency || 'usd';
    const name = existing.name;

    if (existing.is_recurring) {
      console.log(`✓ ${plan.env}: "${name}" is ALREADY recurring (${existing.recurring_interval}) — leaving as-is`);
      results.push({ ...plan, newId: oldId, name, amount, unchanged: true });
      continue;
    }

    console.log(`• ${plan.env}: "${name}" $${(amount/100).toFixed(2)} one-time  =>  recurring/${plan.interval}`);

    if (!COMMIT) { results.push({ ...plan, oldId, name, amount, newId: '(dry-run)' }); continue; }

    // NB: organization_id must be omitted with an organization token (it's inferred).
    const created = await api('POST', '/products', {
      name,
      recurring_interval: plan.interval,
      prices: [{ amount_type: 'fixed', price_currency: currency, price_amount: amount }],
    });
    if (!created.is_recurring) throw new Error(`Created product ${created.id} is not recurring — aborting before archiving anything`);
    console.log(`    created ${created.id} (recurring=${created.is_recurring}/${created.recurring_interval})`);

    // archive the old one-time product so each plan has one active product
    await api('PATCH', `/products/${oldId}`, { is_archived: true });
    console.log(`    archived old one-time product ${oldId}`);

    results.push({ ...plan, oldId, name, amount, newId: created.id });
  }

  console.log('\n================ .env block ================');
  for (const r of results) console.log(`${r.env}=${r.newId}`);
  console.log('============================================');
  if (!COMMIT) console.log('\nDry run only — re-run with --commit to create the products and update the IDs above.');
  else console.log('\nDone. Paste the .env block above into .env AND your Vercel project env vars, then redeploy.');
})().catch(e => { console.error('\nFAILED:', e.message); process.exit(1); });
