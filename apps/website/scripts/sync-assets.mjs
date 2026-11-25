#!/usr/bin/env node
/**
 * Sync repository documentation media (`../../docs/assets/**`) into
 * `apps/website/public/media/` before `next dev` and `next build`.
 *
 * - Never fails when optional or concurrently generated assets are absent.
 * - Cleans stale files in `public/media/` so deleted assets do not linger.
 * - `public/media/` is gitignored via `apps/website/.gitignore`.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const websiteRoot = path.resolve(__dirname, '..');
const sourceRoot = path.resolve(websiteRoot, '../../docs/assets');
const destRoot = path.resolve(websiteRoot, 'public/media');

const ALLOWED_EXTENSIONS = new Set([
  '.png',
  '.svg',
  '.jpg',
  '.jpeg',
  '.webp',
  '.ico',
  '.avif',
  '.gif',
]);

function syncDirectory(srcDir, dstDir, stats) {
  let entries;
  try {
    entries = fs.readdirSync(srcDir, { withFileTypes: true });
  } catch (err) {
    stats.skipped += 1;
    console.warn(`[sync-assets] Skipping unreadable directory ${srcDir}: ${err.message}`);
    return;
  }

  fs.mkdirSync(dstDir, { recursive: true });

  for (const entry of entries) {
    if (entry.name.startsWith('.')) {
      continue;
    }
    const srcPath = path.join(srcDir, entry.name);
    const dstPath = path.join(dstDir, entry.name);

    try {
      const lstat = fs.lstatSync(srcPath);
      if (lstat.isSymbolicLink()) {
        stats.skipped += 1;
        continue;
      }
      if (lstat.isDirectory()) {
        syncDirectory(srcPath, dstPath, stats);
      } else if (lstat.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!ALLOWED_EXTENSIONS.has(ext)) {
          stats.skipped += 1;
          continue;
        }
        fs.copyFileSync(srcPath, dstPath);
        stats.copied += 1;
      }
    } catch (err) {
      stats.skipped += 1;
      console.warn(`[sync-assets] Skipping ${srcPath}: ${err.message}`);
    }
  }
}

function main() {
  fs.rmSync(destRoot, { recursive: true, force: true });
  fs.mkdirSync(destRoot, { recursive: true });

  if (!fs.existsSync(sourceRoot)) {
    console.log(`[sync-assets] Source directory not found (${sourceRoot}); continuing with fallbacks.`);
    return;
  }

  const stats = { copied: 0, skipped: 0 };
  syncDirectory(sourceRoot, destRoot, stats);
  console.log(
    `[sync-assets] Synced ${stats.copied} asset(s) into public/media` +
      (stats.skipped > 0 ? ` (${stats.skipped} skipped)` : '') +
      '.'
  );
}

main();
