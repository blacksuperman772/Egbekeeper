/**
 * Second-pass: remove inline cursor JS from files that still have it.
 * Runs after extract-shared-assets.js has already added shared.css.
 *
 * Targets any HTML file that still contains requestAnimationFrame in a
 * cursor context, removes the cursor JS block, and adds the external
 * /assets/cursor.js script tag.
 */
'use strict';
const fs   = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// Files confirmed to still have inline cursor JS
const htmlFiles = fs.readdirSync(ROOT)
  .filter(f => f.endsWith('.html'))
  .map(f => path.join(ROOT, f));

// Matches a // CURSOR comment line (any case, any surrounding decoration)
// followed by 5–22 non-blank code lines, then a blank line.
// The lazy [^\n]*? ensures we don't overshoot to another section.
const CURSOR_BLOCK_RE =
  /[ \t]*\/\/ [^\n]*?[Cc][Uu][Rr][Ss][Oo][Rr][^\n]*\r?\n(?:[^\n]+\r?\n){5,22}[ \t]*\r?\n/;

const CURSOR_JS_TAG = '<script src="/assets/cursor.js"></script>';

let changed = 0;

for (const file of htmlFiles) {
  const name = path.basename(file);
  let content = fs.readFileSync(file, 'utf8');

  // Skip files that don't have requestAnimationFrame (no cursor JS at all)
  if (!content.includes('requestAnimationFrame')) continue;

  // Skip files that already have cursor.js external script
  if (content.includes('/assets/cursor.js')) {
    console.log('  already done:', name);
    continue;
  }

  const original = content;

  // Remove the cursor block
  if (CURSOR_BLOCK_RE.test(content)) {
    content = content.replace(CURSOR_BLOCK_RE, '\n');
    console.log('  removed cursor block:', name);
  } else {
    console.log('  REGEX MISS — manual edit needed:', name);
    continue;
  }

  // Add cursor.js before </body>
  content = content.replace('</body>', CURSOR_JS_TAG + '\n</body>');

  if (content !== original) {
    fs.writeFileSync(file, content, 'utf8');
    changed++;
  }
}

console.log(`\nDone. ${changed} files updated.`);
