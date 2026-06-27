/**
 * Task 14 migration: extract shared CSS/JS assets.
 *
 * For every HTML file in the project root:
 *   1. Remove the three Google Fonts <link> tags (preconnect x2 + href).
 *   2. Insert <link rel="stylesheet" href="/assets/shared.css"> in their place.
 *      shared.css contains the superset @import + box-sizing reset.
 *   3. Remove the inline *, *::before, *::after box-sizing reset (now in shared.css).
 *   4. Remove the inline cursor JS block (now in /assets/cursor.js).
 *   5. Add <script src="/assets/cursor.js"></script> before </body> for files
 *      that had cursor JS.
 *
 * Safe to re-run — idempotent checks prevent double-application.
 */

'use strict';
const fs   = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

const htmlFiles = fs.readdirSync(ROOT)
  .filter(f => f.endsWith('.html'))
  .map(f => path.join(ROOT, f));

// ── Font link pattern ────────────────────────────────────────────────────────
// Matches the 2-3 lines of preconnect + Google Fonts href in one shot.
// Handles all whitespace/self-closing variants found across the project.
const FONT_BLOCK_RE =
  /[ \t]*<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com"[^>]*>\r?\n[ \t]*<link rel="preconnect" href="https:\/\/fonts\.gstatic\.com"[^>]*>\r?\n[ \t]*<link href="https:\/\/fonts\.googleapis\.com\/css2\?[^"]*" rel="stylesheet"[^>]*>/g;

// Replacement — single shared CSS link (no preconnect needed; @import in CSS
// uses the browser's own speculative prefetch for the fonts domain)
const SHARED_CSS_LINK = '  <link rel="stylesheet" href="/assets/shared.css" />';

// ── Box-sizing reset pattern ─────────────────────────────────────────────────
// Matches the one-liner reset in various spacing styles, with trailing newline.
const RESET_LINE_RE =
  /[ \t]*\*,\s*\*::before,\s*\*::after\s*\{\s*box-sizing:\s*border-box;\s*margin:\s*0;\s*padding:\s*0;\s*\}\r?\n/;

// ── Cursor JS block pattern ──────────────────────────────────────────────────
// Matches cursor comment + 5–20 non-blank code lines + one trailing blank line.
// Works for: plain IIFE, named-function, and matchMedia-wrapped variants.
// Case-insensitive match for CURSOR/Cursor/cursor, any surrounding decorators.
const CURSOR_BLOCK_RE =
  /[ \t]*\/\/ [^\n]*?[Cc][Uu][Rr][Ss][Oo][Rr][^\n]*\n(?:[^\n]+\n){5,20}[ \t]*\n/;

const CURSOR_JS_TAG = '<script src="/assets/cursor.js"></script>';

let changed = 0;
let skipped = 0;

for (const file of htmlFiles) {
  const name = path.basename(file);
  let content = fs.readFileSync(file, 'utf8');
  const original = content;

  // Guard: skip if already migrated
  if (content.includes('/assets/shared.css')) {
    console.log('  skip (already migrated):', name);
    skipped++;
    continue;
  }

  // 1. Replace font block with shared.css link
  if (FONT_BLOCK_RE.test(content)) {
    FONT_BLOCK_RE.lastIndex = 0; // reset after .test()
    content = content.replace(FONT_BLOCK_RE, SHARED_CSS_LINK);
  } else {
    // Some files only have the font href without preconnect — handle that
    const FONT_ONLY_RE =
      /[ \t]*<link href="https:\/\/fonts\.googleapis\.com\/css2\?[^"]*" rel="stylesheet"[^>]*>/;
    if (FONT_ONLY_RE.test(content)) {
      content = content.replace(FONT_ONLY_RE, SHARED_CSS_LINK);
    }
  }

  // 2. Remove box-sizing reset (now in shared.css)
  content = content.replace(RESET_LINE_RE, '');

  // 3. Remove cursor JS block + add external script tag
  const hasCursor = CURSOR_BLOCK_RE.test(content);
  if (hasCursor) {
    CURSOR_BLOCK_RE.lastIndex = 0;
    content = content.replace(CURSOR_BLOCK_RE, '\n');
    // Add cursor.js before </body>
    content = content.replace('</body>', CURSOR_JS_TAG + '\n</body>');
  }

  if (content !== original) {
    fs.writeFileSync(file, content, 'utf8');
    console.log('  updated:', name, hasCursor ? '(+cursor.js)' : '');
    changed++;
  } else {
    console.log('  no change:', name);
    skipped++;
  }
}

console.log(`\nDone. ${changed} files updated, ${skipped} skipped.`);
