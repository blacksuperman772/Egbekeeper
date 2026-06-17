'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const fs    = require('fs');
const path  = require('path');
const https = require('https');

const PROJECT_REF = (process.env.SUPABASE_URL || '').replace('https://', '').split('.')[0];
const TOKEN       = process.env.SUPABASE_MANAGEMENT_TOKEN;

if (!PROJECT_REF) { console.error('SUPABASE_URL missing in .env'); process.exit(1); }
if (!TOKEN)        { console.error('SUPABASE_MANAGEMENT_TOKEN missing in .env'); process.exit(1); }

function query(sql) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ query: sql });
    const opts = {
      hostname: 'api.supabase.com',
      path:     `/v1/projects/${PROJECT_REF}/database/query`,
      method:   'POST',
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error(`Bad JSON: ${data}`)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function ensureMigrationsTable() {
  await query(`
    CREATE TABLE IF NOT EXISTS public._migrations (
      id         SERIAL PRIMARY KEY,
      filename   TEXT UNIQUE NOT NULL,
      applied_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

async function appliedMigrations() {
  const rows = await query('SELECT filename FROM public._migrations ORDER BY id');
  return new Set(rows.map(r => r.filename));
}

async function main() {
  const migrationsDir = path.join(__dirname, '../supabase/migrations');
  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  if (files.length === 0) {
    console.log('No migration files found.');
    return;
  }

  await ensureMigrationsTable();
  const applied = await appliedMigrations();

  let ran = 0;
  for (const file of files) {
    if (applied.has(file)) {
      console.log(`  skip  ${file}`);
      continue;
    }

    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    console.log(`  run   ${file} ...`);
    const result = await query(sql);

    if (result && result.message) {
      console.error(`  ERROR in ${file}: ${result.message}`);
      process.exit(1);
    }

    await query(`INSERT INTO public._migrations (filename) VALUES ('${file.replace(/'/g, "''")}') ON CONFLICT DO NOTHING`);
    console.log(`  done  ${file}`);
    ran++;
  }

  if (ran === 0) console.log('Already up to date.');
  else console.log(`\n${ran} migration(s) applied.`);
}

main().catch(err => { console.error(err.message); process.exit(1); });
