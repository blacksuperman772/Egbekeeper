'use strict';
require('dns').setDefaultResultOrder('ipv4first');
require('dotenv').config();

const fs   = require('fs');
const path = require('path');
const https = require('https');

const API_KEY = process.env.OPENAI_API_KEY;
if (!API_KEY) { console.error('No OPENAI_API_KEY in .env'); process.exit(1); }

const ASSETS_DIR = path.join(__dirname, 'assets');
if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR);

async function generateImage(prompt, filename, size = '1536x1024') {
  console.log(`\nGenerating: ${filename}...`);
  const body = JSON.stringify({
    model:           'gpt-image-2',
    prompt,
    n:               1,
    size,
    output_format:   'png',
    quality:         'high',
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.openai.com',
      path:     '/v1/images/generations',
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Authorization':  `Bearer ${API_KEY}`,
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) { console.error('  ✗ API error:', json.error.message); return resolve(null); }
          const b64 = json.data?.[0]?.b64_json;
          const url = json.data?.[0]?.url;
          const dest = path.join(ASSETS_DIR, filename);
          if (b64) {
            fs.writeFileSync(dest, Buffer.from(b64, 'base64'));
            console.log(`  ✓ Saved: ${dest}`);
            return resolve(dest);
          }
          if (url) {
            console.log(`  → Downloading from URL...`);
            return downloadImage(url, dest).then(resolve).catch(reject);
          }
          console.error('  ✗ No image data in response:', JSON.stringify(json).slice(0, 200));
          resolve(null);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function downloadImage(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, res => {
      res.pipe(file);
      file.on('finish', () => { file.close(); console.log(`  ✓ Saved: ${dest}`); resolve(dest); });
    }).on('error', e => { fs.unlink(dest, () => {}); reject(e); });
  });
}

const ASSETS = [
  {
    filename: 'hero-landing.png',
    prompt: 'A cinematic wide photograph of an empty, dimly lit private trading room at 4am. Mahogany desk, multiple dark monitors with subtle amber glows showing price charts, no people. Floor-to-ceiling windows revealing a dark city skyline with faint lights. Deep blacks, warm amber accent lighting from desk lamp. Institutional, serious, private. Shot on medium format film. Extremely high detail. Atmosphere of focused discipline and solitude. No text.',
  },
  {
    filename: 'mike-portrait.png',
    prompt: 'A professional portrait photograph of a 52-year-old man who is a former professional trader turned performance coach. Strong, composed face. Salt and pepper short hair, clean shaven. Wearing a dark navy dress shirt, no tie. Sitting at a desk in a dim private office, bookshelves behind. Direct eye contact with camera. Expression: calm, observant, slightly guarded. Not smiling but not cold. Institutional. Shot on 85mm portrait lens, shallow depth of field. Cinematic lighting, dramatic shadows. No text, no graphics.',
  },
  {
    filename: 'ashley-portrait.png',
    prompt: 'A professional portrait photograph of a 42-year-old woman who is a performance psychologist. Intelligent, composed face. Dark hair pulled back simply. Wearing a dark charcoal blazer over a simple black top. Seated in a clean, minimalist office. Expression: warm but professional, attentive, thoughtful. Direct eye contact. Shot on 85mm portrait lens, shallow depth of field. Soft cinematic lighting. Atmosphere of trust and expertise. No text, no graphics.',
  },
  {
    filename: 'workspace-ambient.png',
    prompt: 'A close-up atmospheric photograph of a single trading workstation at night. Dark mechanical keyboard, a notebook open with handwritten notes, a pen, a coffee cup with faint steam. Multiple monitors visible in background showing candlestick charts in dark mode. Warm amber desk lamp casting a pool of light. Extreme shallow depth of field. Shot on film. Mood: disciplined solitude, focused work, late night. No people visible. No text.',
  },
  {
    filename: 'hero-mobile.png',
    prompt: 'A cinematic portrait-orientation photograph of a person\'s hands on a dark desk at night, one hand holding a pen over an open trading journal. Dark background. Amber light from an unseen lamp falls across the hands and journal. The journal shows handwritten notes, no readable text. Background: dark monitors with subtle glow. Mood: quiet discipline, reflection, accountability. Extreme close up, shallow focus. Shot on film. Vertical composition. No text.',
  },
  {
    filename: 'auth-bg.png',
    size: '1024x1024',
    prompt: 'An extremely close-up macro photograph of a single dark trading monitor, screen glowing amber and gold, showing abstract candlestick price chart lines in dark mode. The surrounding room is in near-total darkness. The glow bleeds softly into the black background. Extreme shallow depth of field, edges blurred. Mood: private, focused, late night. Shot on film. No text, no numbers, no readable data. Square composition.',
  },
  {
    filename: 'onboarding-ambient.png',
    size: '1536x1024',
    prompt: 'An overhead cinematic photograph of a sparse, dark desk at night. An open leather-bound notebook with blank pages, a fountain pen resting on it, a faint pool of amber light from an unseen lamp. Surrounding objects barely visible in shadow: a coffee mug, a closed book, a small plant. Extreme shallow depth of field, soft bokeh. Mood: introspective, beginning of something, a session about to start. Shot on medium format film. No text, no charts, no screens. Dark, intimate, still.',
  },
  {
    filename: 'mentor-space.png',
    size: '1024x1024',
    prompt: 'A very close-up, abstract cinematic photograph of two empty leather chairs facing each other in a dark, minimalist private room. A faint amber glow from an unseen source falls between them. The mood is anticipatory, like a coaching session about to begin. No people. Extreme shallow focus, deep blacks, warm golden accent. Shot on film. Square composition. No text.',
  },
];

async function generateWithRetry(prompt, filename, size, attempts = 3) {
  for (let i = 1; i <= attempts; i++) {
    try {
      const result = await generateImage(prompt, filename, size);
      if (result) return result;
    } catch (err) {
      console.error(`  Attempt ${i} failed: ${err.message}`);
      if (i < attempts) {
        console.log(`  Retrying in 5s...`);
        await new Promise(r => setTimeout(r, 5000));
      }
    }
  }
  console.error(`  ✗ Failed after ${attempts} attempts: ${filename}`);
  return null;
}

(async () => {
  console.log('EdgeKeeper Visual Assets Generator');
  console.log('====================================');
  for (const asset of ASSETS) {
    const dest = path.join(ASSETS_DIR, asset.filename);
    if (fs.existsSync(dest)) { console.log(`  → Skipping (exists): ${asset.filename}`); continue; }
    await generateWithRetry(asset.prompt, asset.filename, asset.size);
    await new Promise(r => setTimeout(r, 3000));
  }
  console.log('\n✓ All assets generated in /assets/');
  console.log('\nNext: reference these in edgekeeper.html:');
  console.log('  Hero:      /assets/hero-landing.png');
  console.log('  Marcus:      /assets/mike-portrait.png');
  console.log('  Iris:    /assets/ashley-portrait.png');
  console.log('  Workspace: /assets/workspace-ambient.png');
  console.log('  Mobile:    /assets/hero-mobile.png');
})();
