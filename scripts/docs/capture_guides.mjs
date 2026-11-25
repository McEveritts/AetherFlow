#!/usr/bin/env node
/**
 * AetherFlow v4.0.0 — Annotated Step-by-Step Guide Screenshot Capture Script
 *
 * Drives the real compiled Leptos/WASM UI with Playwright against deterministic
 * synthetic fixtures, injects a non-destructive HTML/SVG callout overlay
 * (dimming mask, 3px brand highlight rings, numbered circular badges, and
 * subtle connector lines), crops to the relevant UI context, and optimizes
 * every PNG below 600 KiB.
 *
 * Usage:
 *   node scripts/docs/capture_guides.mjs
 *   node scripts/docs/capture_guides.mjs --dist /path/to/web/dist
 *   node scripts/docs/capture_guides.mjs --guides quickstart,marketplace
 *   node scripts/docs/capture_guides.mjs --guides peer-pairing/02-open-window
 */

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REPO_ROOT,
  VIEWPORT,
  loadPlaywright,
  resolveWebDist,
  startStaticServer,
  buildFixtures,
  installMocks,
  waitForSettle,
  optimizePng,
  commandExists,
} from './capture_screenshots.mjs';

const __filename = fileURLToPath(import.meta.url);

function parseArgs(argv) {
  const opts = {
    dist: process.env.AETHERFLOW_WEB_DIST || '',
    out: path.join(REPO_ROOT, 'docs', 'assets', 'guides'),
    release: 'v4.0.0',
    guides: null,
    optimize: true,
    keepTemp: false,
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dist' && argv[i + 1]) {
      opts.dist = path.resolve(argv[++i]);
    } else if (arg === '--out' && argv[i + 1]) {
      opts.out = path.resolve(argv[++i]);
    } else if (arg === '--release' && argv[i + 1]) {
      opts.release = argv[++i];
    } else if (arg === '--guides' && argv[i + 1]) {
      opts.guides = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (arg === '--no-optimize') {
      opts.optimize = false;
    } else if (arg === '--keep-temp') {
      opts.keepTemp = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log(`Usage: node scripts/docs/capture_guides.mjs [options]

Options:
  --dist <dir>       Path to compiled web/dist directory
  --out <dir>        Output directory (default: docs/assets/guides)
  --release <tag>    GitHub release tag to download if web/dist is absent (default: v4.0.0)
  --guides <list>    Comma-separated guide slugs or guide/step IDs (default: all 33 steps)
  --no-optimize      Skip PNG optimization step
  --help             Show this message
`);
      process.exit(0);
    }
  }
  return opts;
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function unionBoxes(boxes) {
  const valid = boxes.filter(Boolean);
  if (valid.length === 0) return null;
  let x1 = Infinity;
  let y1 = Infinity;
  let x2 = -Infinity;
  let y2 = -Infinity;
  for (const b of valid) {
    x1 = Math.min(x1, b.x);
    y1 = Math.min(y1, b.y);
    x2 = Math.max(x2, b.x + b.width);
    y2 = Math.max(y2, b.y + b.height);
  }
  return { x: x1, y: y1, width: x2 - x1, height: y2 - y1 };
}

async function resolveTargetBox(target) {
  if (target.box) return target.box;
  if (target.locators && target.locators.length > 0) {
    const boxes = [];
    for (const loc of target.locators) {
      await loc.waitFor({ state: 'visible', timeout: 15_000 });
      const b = await loc.boundingBox();
      if (b) boxes.push(b);
    }
    return unionBoxes(boxes);
  }
  if (target.locator) {
    await target.locator.waitFor({ state: 'visible', timeout: 15_000 });
    return target.locator.boundingBox();
  }
  return null;
}

function optimizeGuidePng(filePath) {
  let method = optimizePng(filePath);
  const maxBytes = 590 * 1024;
  if (fs.existsSync(filePath) && fs.statSync(filePath).size > maxBytes && commandExists('convert')) {
    const tmp = `${filePath}.tight.png`;
    const res = spawnSync('convert', [
      filePath,
      '-strip',
      '-dither', 'FloydSteinberg',
      '-colors', '160',
      '-define', 'png:compression-level=9',
      '-define', 'png:compression-filter=5',
      `PNG8:${tmp}`,
    ]);
    if (res.status === 0 && fs.existsSync(tmp) && fs.statSync(tmp).size < fs.statSync(filePath).size) {
      fs.renameSync(tmp, filePath);
      method = 'imagemagick-png8-160';
    } else {
      fs.rmSync(tmp, { force: true });
    }
  }
  return method;
}

/**
 * Injects an HTML/SVG callout overlay (dimming mask + brand highlight rings +
 * numbered circular badges + optional short connector lines), captures the
 * cropped PNG, removes the overlay, and optimizes the file below 600 KiB.
 */
async function annotateAndCrop(page, outPath, spec, optimize = true) {
  const {
    annotations = [],
    contextLocator = null,
    contextLocators = [],
    smallDialog = false,
    minWidth = smallDialog ? 760 : 1280,
    minHeight = smallDialog ? 420 : 520,
    padX = 56,
    padY = 56,
    dimOpacity = 0.45,
    clipOverride = null,
  } = spec;

  const badgeRadius = 18; // 36px circle
  const badgeGap = 14;
  const resolved = [];

  for (const ann of annotations) {
    const rawBox = await resolveTargetBox(ann);
    if (!rawBox) {
      throw new Error(`Annotation #${ann.num} could not resolve a visible bounding box for ${outPath}`);
    }
    const pad = ann.pad ?? 6;
    const rx = clamp(rawBox.x - pad, 4, VIEWPORT.width - 8);
    const ry = clamp(rawBox.y - pad, 4, VIEWPORT.height - 8);
    const rw = clamp(rawBox.width + pad * 2, 16, VIEWPORT.width - rx - 4);
    const rh = clamp(rawBox.height + pad * 2, 16, VIEWPORT.height - ry - 4);
    const rect = { x: rx, y: ry, width: rw, height: rh };

    const placement = ann.placement || 'top-left';
    let bx;
    let by;
    let ax;
    let ay;
    switch (placement) {
      case 'top-right':
        bx = rx + rw + badgeGap;
        by = ry - badgeGap;
        ax = rx + rw - 4;
        ay = ry + 4;
        break;
      case 'bottom-left':
        bx = rx - badgeGap;
        by = ry + rh + badgeGap;
        ax = rx + 4;
        ay = ry + rh - 4;
        break;
      case 'bottom-right':
        bx = rx + rw + badgeGap;
        by = ry + rh + badgeGap;
        ax = rx + rw - 4;
        ay = ry + rh - 4;
        break;
      case 'top':
        bx = rx + rw / 2;
        by = ry - badgeRadius - badgeGap;
        ax = rx + rw / 2;
        ay = ry;
        break;
      case 'bottom':
        bx = rx + rw / 2;
        by = ry + rh + badgeRadius + badgeGap;
        ax = rx + rw / 2;
        ay = ry + rh;
        break;
      case 'left':
        bx = rx - badgeRadius - badgeGap;
        by = ry + rh / 2;
        ax = rx;
        ay = ry + rh / 2;
        break;
      case 'right':
        bx = rx + rw + badgeRadius + badgeGap;
        by = ry + rh / 2;
        ax = rx + rw;
        ay = ry + rh / 2;
        break;
      case 'top-left-inside':
        bx = rx - 6;
        by = ry - 6;
        ax = rx;
        ay = ry;
        break;
      case 'top-left':
      default:
        bx = rx - badgeGap;
        by = ry - badgeGap;
        ax = rx + 4;
        ay = ry + 4;
        break;
    }

    if (ann.dx) bx += ann.dx;
    if (ann.dy) by += ann.dy;

    bx = clamp(bx, badgeRadius + 8, VIEWPORT.width - badgeRadius - 8);
    by = clamp(by, badgeRadius + 8, VIEWPORT.height - badgeRadius - 8);

    resolved.push({
      num: String(ann.num),
      rect,
      bx,
      by,
      ax,
      ay,
      arrow: ann.arrow !== false,
    });
  }

  // Gentle collision avoidance so adjacent badges never overlap.
  for (let pass = 0; pass < 4; pass += 1) {
    for (let i = 0; i < resolved.length; i += 1) {
      for (let j = i + 1; j < resolved.length; j += 1) {
        const a = resolved[i];
        const b = resolved[j];
        const dx = b.bx - a.bx;
        const dy = b.by - a.by;
        const dist = Math.hypot(dx, dy);
        const minDist = badgeRadius * 2 + 8;
        if (dist < minDist) {
          const shift = (minDist - dist) / 2 + 2;
          if (Math.abs(dx) >= Math.abs(dy)) {
            const sign = dx >= 0 ? 1 : -1;
            a.bx = clamp(a.bx - sign * shift, badgeRadius + 8, VIEWPORT.width - badgeRadius - 8);
            b.bx = clamp(b.bx + sign * shift, badgeRadius + 8, VIEWPORT.width - badgeRadius - 8);
          } else {
            const sign = dy >= 0 ? 1 : -1;
            a.by = clamp(a.by - sign * shift, badgeRadius + 8, VIEWPORT.height - badgeRadius - 8);
            b.by = clamp(b.by + sign * shift, badgeRadius + 8, VIEWPORT.height - badgeRadius - 8);
          }
        }
      }
    }
  }

  // Compute crop region from annotations + badges + optional context containers.
  const boxesToFrame = [];
  for (const r of resolved) {
    boxesToFrame.push(r.rect);
    boxesToFrame.push({
      x: r.bx - badgeRadius - 6,
      y: r.by - badgeRadius - 6,
      width: (badgeRadius + 6) * 2,
      height: (badgeRadius + 6) * 2,
    });
  }
  const allContextLocs = [
    ...(contextLocator ? [contextLocator] : []),
    ...contextLocators,
  ];
  for (const loc of allContextLocs) {
    const b = await loc.boundingBox().catch(() => null);
    if (b) boxesToFrame.push(b);
  }

  let clip;
  if (clipOverride) {
    clip = {
      x: Math.round(clamp(clipOverride.x, 0, VIEWPORT.width - 10)),
      y: Math.round(clamp(clipOverride.y, 0, VIEWPORT.height - 10)),
      width: Math.round(clamp(clipOverride.width, 200, VIEWPORT.width - clamp(clipOverride.x, 0, VIEWPORT.width - 10))),
      height: Math.round(clamp(clipOverride.height, 200, VIEWPORT.height - clamp(clipOverride.y, 0, VIEWPORT.height - 10))),
    };
  } else {
    const framed = unionBoxes(boxesToFrame);
    let x1 = framed.x - padX;
    let y1 = framed.y - padY;
    let x2 = framed.x + framed.width + padX;
    let y2 = framed.y + framed.height + padY;

    if (x2 - x1 < minWidth) {
      const cx = (x1 + x2) / 2;
      x1 = cx - minWidth / 2;
      x2 = cx + minWidth / 2;
    }
    if (y2 - y1 < minHeight) {
      const cy = (y1 + y2) / 2;
      y1 = cy - minHeight / 2;
      y2 = cy + minHeight / 2;
    }

    if (x1 < 0) {
      x2 = Math.min(VIEWPORT.width, x2 - x1);
      x1 = 0;
    }
    if (x2 > VIEWPORT.width) {
      x1 = Math.max(0, x1 - (x2 - VIEWPORT.width));
      x2 = VIEWPORT.width;
    }
    if (y1 < 0) {
      y2 = Math.min(VIEWPORT.height, y2 - y1);
      y1 = 0;
    }
    if (y2 > VIEWPORT.height) {
      y1 = Math.max(0, y1 - (y2 - VIEWPORT.height));
      y2 = VIEWPORT.height;
    }

    clip = {
      x: Math.round(x1),
      y: Math.round(y1),
      width: Math.round(x2 - x1),
      height: Math.round(y2 - y1),
    };
  }

  // Inject the SVG + HTML annotation overlay.
  // When an app <dialog open> is in the browser top layer, render the overlay
  // inside a transparent top-layer <dialog> opened via showModal() so rings
  // and numbered badges always render crisp and bright ABOVE modal dialogs.
  await page.evaluate(({ items, vw, vh, radius, dim }) => {
    const existing = document.getElementById('af-guide-overlay');
    if (existing) {
      if (existing.open && typeof existing.close === 'function') existing.close();
      existing.remove();
    }
    const existingStyle = document.getElementById('af-guide-overlay-style');
    if (existingStyle) existingStyle.remove();

    const useTopLayer = Boolean(document.querySelector('dialog[open]'));
    if (useTopLayer) {
      const style = document.createElement('style');
      style.id = 'af-guide-overlay-style';
      style.textContent = '#af-guide-overlay::backdrop { background: transparent !important; }';
      document.head.appendChild(style);
    }

    const root = document.createElement(useTopLayer ? 'dialog' : 'div');
    root.id = 'af-guide-overlay';
    root.style.cssText = [
      'position:fixed',
      'inset:0',
      'margin:0',
      'padding:0',
      'border:none',
      'outline:none',
      'background:transparent',
      'max-width:none',
      'max-height:none',
      `width:${vw}px`,
      `height:${vh}px`,
      'pointer-events:none',
      'z-index:2147483647',
      'overflow:hidden',
    ].join(';');

    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('width', String(vw));
    svg.setAttribute('height', String(vh));
    svg.setAttribute('viewBox', `0 0 ${vw} ${vh}`);
    svg.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;display:block;';

    const defs = document.createElementNS(ns, 'defs');
    const grad = document.createElementNS(ns, 'linearGradient');
    grad.setAttribute('id', 'af-guide-grad');
    grad.setAttribute('x1', '0%');
    grad.setAttribute('y1', '0%');
    grad.setAttribute('x2', '100%');
    grad.setAttribute('y2', '100%');
    const s1 = document.createElementNS(ns, 'stop');
    s1.setAttribute('offset', '0%');
    s1.setAttribute('stop-color', '#818cf8');
    const s2 = document.createElementNS(ns, 'stop');
    s2.setAttribute('offset', '55%');
    s2.setAttribute('stop-color', '#a855f7');
    const s3 = document.createElementNS(ns, 'stop');
    s3.setAttribute('offset', '100%');
    s3.setAttribute('stop-color', '#e879f9');
    grad.append(s1, s2, s3);
    defs.appendChild(grad);

    const glow = document.createElementNS(ns, 'filter');
    glow.setAttribute('id', 'af-ring-glow');
    glow.setAttribute('x', '-25%');
    glow.setAttribute('y', '-25%');
    glow.setAttribute('width', '150%');
    glow.setAttribute('height', '150%');
    const drop = document.createElementNS(ns, 'feDropShadow');
    drop.setAttribute('dx', '0');
    drop.setAttribute('dy', '0');
    drop.setAttribute('stdDeviation', '5');
    drop.setAttribute('flood-color', '#818cf8');
    drop.setAttribute('flood-opacity', '0.65');
    glow.appendChild(drop);
    defs.appendChild(glow);

    const mask = document.createElementNS(ns, 'mask');
    mask.setAttribute('id', 'af-dim-mask');
    const bg = document.createElementNS(ns, 'rect');
    bg.setAttribute('x', '0');
    bg.setAttribute('y', '0');
    bg.setAttribute('width', String(vw));
    bg.setAttribute('height', String(vh));
    bg.setAttribute('fill', 'white');
    mask.appendChild(bg);
    for (const item of items) {
      const cut = document.createElementNS(ns, 'rect');
      cut.setAttribute('x', String(item.rect.x));
      cut.setAttribute('y', String(item.rect.y));
      cut.setAttribute('width', String(item.rect.width));
      cut.setAttribute('height', String(item.rect.height));
      cut.setAttribute('rx', '12');
      cut.setAttribute('ry', '12');
      cut.setAttribute('fill', 'black');
      mask.appendChild(cut);
    }
    defs.appendChild(mask);
    svg.appendChild(defs);

    // Dimming layer outside highlight rings
    if (dim > 0) {
      const dimRect = document.createElementNS(ns, 'rect');
      dimRect.setAttribute('x', '0');
      dimRect.setAttribute('y', '0');
      dimRect.setAttribute('width', String(vw));
      dimRect.setAttribute('height', String(vh));
      dimRect.setAttribute('fill', `rgba(2, 6, 23, ${dim})`);
      dimRect.setAttribute('mask', 'url(#af-dim-mask)');
      svg.appendChild(dimRect);
    }

    // Highlight rings and short connector arrows
    for (const item of items) {
      const ring = document.createElementNS(ns, 'rect');
      ring.setAttribute('x', String(item.rect.x));
      ring.setAttribute('y', String(item.rect.y));
      ring.setAttribute('width', String(item.rect.width));
      ring.setAttribute('height', String(item.rect.height));
      ring.setAttribute('rx', '12');
      ring.setAttribute('ry', '12');
      ring.setAttribute('fill', 'rgba(99, 102, 241, 0.06)');
      ring.setAttribute('stroke', 'url(#af-guide-grad)');
      ring.setAttribute('stroke-width', '3');
      ring.setAttribute('filter', 'url(#af-ring-glow)');
      svg.appendChild(ring);

      const dist = Math.hypot(item.ax - item.bx, item.ay - item.by);
      if (item.arrow && dist > radius + 6) {
        const ux = (item.ax - item.bx) / dist;
        const uy = (item.ay - item.by) / dist;
        const sx = item.bx + ux * (radius - 1);
        const sy = item.by + uy * (radius - 1);
        const line = document.createElementNS(ns, 'line');
        line.setAttribute('x1', String(sx));
        line.setAttribute('y1', String(sy));
        line.setAttribute('x2', String(item.ax));
        line.setAttribute('y2', String(item.ay));
        line.setAttribute('stroke', '#e0e7ff');
        line.setAttribute('stroke-width', '2.5');
        line.setAttribute('stroke-linecap', 'round');
        svg.appendChild(line);

        const dot = document.createElementNS(ns, 'circle');
        dot.setAttribute('cx', String(item.ax));
        dot.setAttribute('cy', String(item.ay));
        dot.setAttribute('r', '3.5');
        dot.setAttribute('fill', '#e879f9');
        dot.setAttribute('stroke', '#ffffff');
        dot.setAttribute('stroke-width', '1.2');
        svg.appendChild(dot);
      }
    }

    root.appendChild(svg);

    // Numbered circular badges
    for (const item of items) {
      const badge = document.createElement('div');
      badge.textContent = item.num;
      badge.style.cssText = [
        'position:absolute',
        `left:${item.bx - radius}px`,
        `top:${item.by - radius}px`,
        `width:${radius * 2}px`,
        `height:${radius * 2}px`,
        'border-radius:9999px',
        'background:linear-gradient(135deg,#6366f1 0%,#9333ea 55%,#d946ef 100%)',
        'border:2.5px solid rgba(255,255,255,0.94)',
        'box-shadow:0 6px 18px rgba(0,0,0,0.72),0 0 14px rgba(139,92,246,0.55)',
        'color:#ffffff',
        'font-family:Inter,system-ui,-apple-system,sans-serif',
        'font-weight:800',
        'font-size:18px',
        'line-height:1',
        'display:flex',
        'align-items:center',
        'justify-content:center',
        'letter-spacing:-0.02em',
      ].join(';');
      root.appendChild(badge);
    }

    document.body.appendChild(root);
    if (useTopLayer && typeof root.showModal === 'function') {
      root.showModal();
    }
  }, { items: resolved, vw: VIEWPORT.width, vh: VIEWPORT.height, radius: badgeRadius, dim: dimOpacity });

  await page.waitForTimeout(80);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  await page.screenshot({ path: outPath, type: 'png', clip });

  await page.evaluate(() => {
    const existing = document.getElementById('af-guide-overlay');
    if (existing) {
      if (existing.open && typeof existing.close === 'function') existing.close();
      existing.remove();
    }
    const existingStyle = document.getElementById('af-guide-overlay-style');
    if (existingStyle) existingStyle.remove();
  });

  const optimizer = optimize ? optimizeGuidePng(outPath) : 'skipped';
  const bytes = fs.statSync(outPath).size;
  return { bytes, optimizer, clip };
}

async function openFreshContext(browser, fixtures, unmockedLog, consoleErrors, customSetup = null) {
  const context = await browser.newContext({
    viewport: VIEWPORT,
    deviceScaleFactor: 1,
    colorScheme: 'dark',
    reducedMotion: 'no-preference',
    serviceWorkers: 'block',
  });
  const page = await context.newPage();
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => {
    consoleErrors.push(`PAGEERROR: ${err.message}`);
  });
  await installMocks(page, fixtures, unmockedLog, { theme: 'dark' });
  if (customSetup) {
    await customSetup(page, fixtures);
  }
  return { context, page };
}

function fakePubKey(seed) {
  return crypto.createHash('sha256').update(`aetherflow-guide-wg-${seed}`).digest('base64');
}

const GUIDE_STEPS = [
  // =========================================================================
  // 1. quickstart
  // =========================================================================
  {
    guide: 'quickstart',
    step: '01-sign-in',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          // Override session to 401 so /login renders the sign-in form cleanly.
          await p.route(/\/api(\/v1)?(\/auth)?\/session(?:\?.*)?$/, (route) =>
            route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'unauthorized' }) }),
          );
          await p.route(/\/api(\/v1)?(\/public)?\/auth\/oidc\/providers(?:\?.*)?$/, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ providers: [] }) }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
        await page.locator('html[data-theme="dark"]').waitFor({ timeout: 15_000 });
        const userInput = page.locator('input[autocomplete="username"], input[name="username"], input[type="text"]').first();
        const passInput = page.locator('input[type="password"]').first();
        const signInBtn = page.locator('button[type="submit"]').first();
        await userInput.waitFor({ state: 'visible', timeout: 15_000 });
        await userInput.fill('alex');
        await passInput.fill('••••••••••••••••');
        await waitForSettle(page);
        const card = page.locator('form').first().locator('..');
        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: userInput, placement: 'left' },
            { num: 2, locator: passInput, placement: 'left' },
            { num: 3, locator: signInBtn, placement: 'right' },
          ],
          contextLocator: card,
          smallDialog: true,
          minWidth: 1080,
          minHeight: 680,
          padX: 80,
          padY: 70,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'quickstart',
    step: '02-overview-tour',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=overview`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('heading', { name: 'Overview', exact: true }).waitFor({ timeout: 20_000 });
        await page.locator('.af-chart svg').first().waitFor({ timeout: 15_000 });
        await waitForSettle(page);

        const sidebarNav = page.locator('aside nav').first();
        const switcher = page.locator('select[data-testid="server-switcher"]');
        const apiPill = page.getByText('API Connected').locator('..');
        const searchBtn = page.locator('header button', { hasText: /Search/i }).first();
        const themeBtn = page.locator('header button[aria-label*="theme" i], header button[title*="theme" i], header button[aria-label*="mode" i]').first();

        // Highlight top half of sidebar nav cleanly so it fits inside a wide top-half overview crop.
        const navBox = await sidebarNav.boundingBox();
        const navSlice = { x: navBox.x + 4, y: navBox.y + 4, width: navBox.width - 8, height: Math.min(navBox.height, 740) };

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, box: navSlice, placement: 'right' },
            { num: 2, locator: switcher, placement: 'bottom' },
            { num: 3, locator: apiPill, placement: 'bottom', dy: 24 },
            { num: 4, locator: searchBtn, placement: 'bottom' },
            { num: 5, locator: themeBtn, placement: 'bottom', dy: 24 },
          ],
          clipOverride: { x: 0, y: 0, width: 2560, height: 920 },
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'quickstart',
    step: '03-marketplace-install',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=marketplace`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('heading', { name: 'Audiobookshelf', exact: true }).waitFor({ timeout: 20_000 });
        await waitForSettle(page);

        const searchInput = page.locator('#main-content input[type="search"], #main-content input[placeholder*="Search" i]').first();
        const mediaPill = page.locator('#main-content button', { hasText: 'Media & IPTV' }).first();
        const autobrrCard = page.locator('#main-content article', { hasText: 'Autobrr' }).first();
        const installBtn = autobrrCard.getByRole('button', { name: 'Install', exact: true });

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: searchInput, placement: 'top-left' },
            { num: 2, locator: mediaPill, placement: 'bottom' },
            { num: 3, locator: installBtn, placement: 'right' },
          ],
          contextLocators: [searchInput, autobrrCard, page.locator('#main-content article', { hasText: 'AdGuard Home' }).first()],
          minWidth: 1860,
          padX: 60,
          padY: 70,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 2. marketplace
  // =========================================================================
  {
    guide: 'marketplace',
    step: '01-find-app',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=marketplace`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('heading', { name: 'Audiobookshelf', exact: true }).waitFor({ timeout: 20_000 });
        const mediaPill = page.locator('#main-content button', { hasText: 'Media & IPTV' }).first();
        await mediaPill.click();
        await waitForSettle(page);

        const searchInput = page.locator('#main-content input[type="search"], #main-content input[placeholder*="Search" i]').first();
        const pillBar = mediaPill.locator('..');
        const firstCard = page.locator('#main-content article').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: searchInput, placement: 'top-left' },
            { num: 2, locator: pillBar, placement: 'bottom-left' },
          ],
          contextLocators: [searchInput, pillBar, firstCard],
          minWidth: 1860,
          minHeight: 740,
          padX: 60,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'marketplace',
    step: '02-install',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=marketplace`, { waitUntil: 'domcontentloaded' });
        const autobrrCard = page.locator('#main-content article', { hasText: 'Autobrr' }).first();
        await autobrrCard.waitFor({ state: 'visible', timeout: 20_000 });
        await waitForSettle(page);

        const installBtn = autobrrCard.getByRole('button', { name: 'Install', exact: true });
        const neighbors = page.locator('#main-content article', { hasText: 'Audiobookshelf' }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: installBtn, placement: 'right' },
          ],
          contextLocators: [autobrrCard, neighbors],
          minWidth: 1320,
          minHeight: 540,
          padX: 64,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'marketplace',
    step: '03-progress',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p, fx) => {
          const modded = fx.marketplaceApps.map((app) =>
            app.id === 'autobrr'
              ? {
                  ...app,
                  status: 'installing',
                  job_id: 'job-autobrr-4001',
                  started_at: fx.isoAgo(18_000),
                  progress: 64,
                  log_line: 'Configuring systemd unit autobrr.service and verifying checksum…',
                }
              : app,
          );
          await p.route(/\/api(\/v1)?(\/(public|auth|admin))?\/marketplace(?:\?.*)?$/, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(modded) }),
          );
          await p.route(/\/api\/v1\/auth\/packages\/autobrr\/progress(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                job_id: 'job-autobrr-4001',
                status: 'installing',
                progress: 64,
                log_line: 'Configuring systemd unit autobrr.service and verifying checksum…',
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=marketplace`, { waitUntil: 'domcontentloaded' });
        const autobrrCard = page.locator('#main-content article', { hasText: 'Autobrr' }).first();
        const prog = autobrrCard.locator('progress');
        await prog.waitFor({ state: 'visible', timeout: 20_000 });
        await waitForSettle(page);

        const logBtn = autobrrCard.getByRole('button', { name: /Deployment logs/i });
        const neighbor = page.locator('#main-content article', { hasText: 'Audiobookshelf' }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [prog, logBtn], placement: 'top-right' },
          ],
          contextLocators: [autobrrCard, neighbor],
          minWidth: 1360,
          minHeight: 560,
          padX: 64,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'marketplace',
    step: '04-update',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=marketplace`, { waitUntil: 'domcontentloaded' });
        const absCard = page.locator('#main-content article', { hasText: 'Audiobookshelf' }).first();
        await absCard.waitFor({ state: 'visible', timeout: 20_000 });
        await waitForSettle(page);

        const badge = absCard.getByText(/Update v2\.20\.0/i).first();
        const updateBtn = absCard.getByRole('button', { name: 'Update', exact: true });
        const leftNeighbor = page.locator('#main-content article', { hasText: 'AdGuard Home' }).first();
        const rightNeighbor = page.locator('#main-content article', { hasText: 'Autobrr' }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: badge, placement: 'top' },
            { num: 2, locator: updateBtn, placement: 'bottom-left' },
          ],
          contextLocators: [leftNeighbor, absCard, rightNeighbor],
          minWidth: 1600,
          minHeight: 540,
          padX: 60,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'marketplace',
    step: '05-external-access',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=marketplace`, { waitUntil: 'domcontentloaded' });
        const adguardCard = page.locator('#main-content article', { hasText: 'AdGuard Home' }).first();
        await adguardCard.waitFor({ state: 'visible', timeout: 20_000 });
        await waitForSettle(page);

        const extBtn = adguardCard.getByRole('button', { name: 'External access', exact: true });
        const neighbor = page.locator('#main-content article', { hasText: 'Audiobookshelf' }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: extBtn, placement: 'bottom' },
          ],
          contextLocators: [adguardCard, neighbor],
          minWidth: 1360,
          minHeight: 540,
          padX: 64,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 3. peer-pairing
  // =========================================================================
  {
    guide: 'peer-pairing',
    step: '01-allow-server',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const allowBtn = page.getByRole('button', { name: /Allow a server to manage this one/i });
        await allowBtn.waitFor({ state: 'visible', timeout: 20_000 });
        await waitForSettle(page);

        const headerCard = allowBtn.locator('xpath=ancestor::section[1] | ancestor::*[contains(@class,"glass-card")][1]').first();
        const novaCard = page.locator('#main-content .af-tab-content').getByText('nova.example.com').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: allowBtn, placement: 'bottom' },
          ],
          contextLocators: [headerCard, novaCard],
          minWidth: 1680,
          minHeight: 540,
          padX: 60,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-pairing',
    step: '02-open-window',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p, fx) => {
          const nowSec = Math.floor(Date.now() / 1000);
          let openedWindow = null;
          const pairingPayload = {
            window_id: 'pw-9182',
            expires_at: nowSec + 585,
            ttl_seconds: 600,
            pairing_string: 'afpair1:eyJ2IjoxLCJ1cmwiOiJodHRwczovL2F0bGFzLmV4YW1wbGUuY29tOjg0NDMiLCJlcCI6IjE5OC41MS4xMDAuMTA6NTE4MjEiLCJwdWJrZXkiOiJrZXlfZXhhbXBsZV8xMjM0NTY3ODkwIiwidG9rZW4iOiJ0b2tlbl9zeW50aGV0aWNfMDAxIn0',
            https_url: 'https://atlas.example.com:8443',
            endpoint: '198.51.100.10',
            wg_port: 51821,
            tunnel_ip: '10.231.0.1',
            wg_pubkey: fx.peersSnapshot.identity.wg_pubkey,
          };
          await p.route(/\/api\/v1\/admin\/peers\/pairing-window(?:\?.*)?$/, (route) => {
            openedWindow = { id: 'pw-9182', expires_at: nowSec + 585 };
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(pairingPayload) });
          });
          await p.route(/\/api\/v1\/admin\/peers(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                ...fx.peersSnapshot,
                pairing_windows: openedWindow ? [openedWindow] : [],
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('button', { name: /Allow a server to manage this one/i }).click();
        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        await dialog.getByRole('button', { name: /Open pairing window/i }).click();
        const copyBtn = dialog.getByRole('button', { name: /Copy pairing string/i });
        await copyBtn.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const stringBox = dialog.locator('textarea, input[readonly], pre, code').first();
        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: stringBox, placement: 'top-left' },
            { num: 2, locator: copyBtn, placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-pairing',
    step: '03-pair-with-server',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('button', { name: /Pair with a server/i }).click();
        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });

        const strInput = dialog.locator('textarea, input').first();
        await strInput.fill('afpair1:eyJ2IjoxLCJ1cmwiOiJodHRwczovL2x5cmEuZXhhbXBsZS5jb206ODQ0MyIsImVwIjoiMjAzLjAuMTEzLjc3OjUxODIxIiwicHVia2V5Ijoia2V5X2V4YW1wbGVfbHlyYSIsInRva2VuIjoidG9rZW5fc3ludGhldGljXzAwMiJ9');
        const nameInput = dialog.locator('input[type="text"]').first();
        if (await nameInput.isVisible().catch(() => false)) {
          await nameInput.fill('lyra.example.com');
        }
        await waitForSettle(page);

        const endpointSelect = dialog.locator('select').first();
        const submitBtn = dialog.locator('button[type="submit"]').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: strInput, placement: 'top-left' },
            { num: 2, locator: endpointSelect, placement: 'left' },
            { num: 3, locator: submitBtn, placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-pairing',
    step: '04-verify-codes',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p, fx) => {
          const nowSec = Math.floor(Date.now() / 1000);
          await p.route(/\/api\/v1\/admin\/peers(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                ...fx.peersSnapshot,
                pairing_attempts: [
                  {
                    id: 'att-482917',
                    window_id: 'pw-9182',
                    remote_name: 'lyra.example.com',
                    remote_pubkey: fakePubKey(44),
                    remote_tunnel_ip: '10.231.0.44',
                    remote_endpoint: '203.0.113.77',
                    source_ip: '203.0.113.77',
                    status: 'pending',
                    comparison_code: '482917',
                    expires_at: nowSec + 420,
                    created_at: fx.isoAgo(30_000),
                  },
                ],
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const approveBtn = page.locator('#main-content button', { hasText: /Approve/i }).first();
        await approveBtn.waitFor({ state: 'visible', timeout: 20_000 });
        await waitForSettle(page);

        const codeEl = page.locator('#main-content').getByText(/482\s*[-–]?\s*917/).first();
        const attemptCard = approveBtn.locator('xpath=ancestor::div[contains(@class,"glass-card") or contains(@class,"rounded")][1]').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: codeEl, placement: 'left' },
            { num: 2, locator: approveBtn, placement: 'right' },
          ],
          contextLocator: attemptCard,
          minWidth: 1480,
          minHeight: 560,
          padX: 72,
          padY: 72,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-pairing',
    step: '05-linked',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const main = page.locator('#main-content .af-tab-content');
        await main.getByText('nova.example.com').first().waitFor({ timeout: 20_000 });
        await waitForSettle(page);

        const novaCard = main.locator('[role="listitem"]').filter({ hasText: 'nova.example.com' }).first();
        const statusBadge = novaCard.getByText('Linked, healthy').first();
        const versionEl = novaCard.getByText(/4\.0\.0.*protocol v1/i).first();
        const rttEl = novaCard.getByText('4.2 ms').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: statusBadge, placement: 'top' },
            { num: 2, locator: versionEl, placement: 'bottom' },
            { num: 3, locator: rttEl, placement: 'bottom-left' },
          ],
          contextLocator: novaCard,
          minWidth: 1620,
          minHeight: 540,
          padX: 60,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 4. peer-grants
  // =========================================================================
  {
    guide: 'peer-grants',
    step: '01-grants-editor',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p, fx) => {
          const nova = fx.peersSnapshot.peers.find((peer) => peer.id === 'peer-nova');
          await p.route(/\/api\/v1\/admin\/peers\/peer-nova\/grant(?:\?.*)?$/, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(nova.grants) }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const main = page.locator('#main-content .af-tab-content');
        await main.getByText('nova.example.com').first().waitFor({ timeout: 20_000 });
        await main.locator('button', { hasText: /^Grants$/ }).first().click();

        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        await dialog.locator('#cluster-grant-area-services').waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const firstSelect = dialog.locator('#cluster-grant-area-services');
        const lastSelect = dialog.locator('#cluster-grant-area-transcoding');
        const saveBtn = dialog.getByRole('button', { name: /Save grant/i }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [firstSelect, lastSelect], placement: 'left' },
            { num: 2, locator: saveBtn, placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-grants',
    step: '02-manage-server',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const main = page.locator('#main-content .af-tab-content');
        await main.getByText('nova.example.com').first().waitFor({ timeout: 20_000 });
        await waitForSettle(page);

        const switcher = page.locator('select[data-testid="server-switcher"]');
        const manageBtn = main.locator('button', { hasText: /^Manage server$/ }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: switcher, placement: 'left' },
            { num: 2, locator: manageBtn, placement: 'bottom' },
          ],
          clipOverride: { x: 240, y: 0, width: 2320, height: 760 },
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-grants',
    step: '03-identity-bar',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p, fx) => {
          // Keep remote peer WebSocket open so the header shows emerald "API Connected" cleanly.
          await p.routeWebSocket(/\/api\/v1\/peers\/peer-nova\/.*ws/, (ws) => {
            ws.onMessage((message) => {
              try {
                const parsed = JSON.parse(String(message));
                if (parsed?.type === 'PING' || parsed?.type === 'ping') {
                  ws.send(JSON.stringify({ type: 'PONG' }));
                }
              } catch {
                // ignore
              }
            });
          });
          // Proxy all /api/v1/peers/peer-nova/* requests cleanly with nova.example.com identity.
          await p.route(/\/api\/v1\/peers\/peer-nova\/(.*)$/, (route) => {
            const sub = new URL(route.request().url()).pathname.replace('/api/v1/peers/peer-nova', '');
            const json = (payload) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(payload) });
            if (sub.includes('/ws/ticket')) return json({ ticket: 'mock-ws-ticket-nova' });
            if (sub.includes('/system/metrics/history')) {
              const u = new URL(route.request().url());
              if (u.searchParams.get('aggregate') === 'daily_transfer') {
                return json(fx.makeDailyTransfer(u.searchParams.get('days')));
              }
              return json(fx.makeTelemetryHistory(u.searchParams.get('window') || '5m'));
            }
            if (sub.includes('/system/metrics')) return json({ ...fx.metrics, cpu_usage: 28.4, uptime: '19d 04h 22m' });
            if (sub.includes('/system/hardware')) return json({ ...fx.hardware, hostname: 'nova.example.com' });
            if (sub.includes('/system/topology')) return json(fx.topology);
            if (sub.includes('/services')) return json(fx.servicesMap);
            if (sub.includes('/settings')) return json({ ...fx.settings, baseDomain: 'nova.example.com' });
            if (sub.includes('/notifications')) return json(fx.notifications);
            if (sub.includes('/actions/pending')) return json({ total: 1, count: 1, actions: [fx.pendingActions[2]] });
            if (sub.includes('/ready')) return json({ service: 'aetherflow-api', status: 'ready', database: 'ok' });
            return json({});
          });
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const main = page.locator('#main-content .af-tab-content');
        await main.getByText('nova.example.com').first().waitFor({ timeout: 20_000 });
        await main.locator('button', { hasText: /^Manage server$/ }).first().click();

        const exitBtn = page.getByRole('button', { name: /Exit to This server|Return to This server/i }).first();
        await exitBtn.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const banner = page.locator('[data-testid="active-server-bar"], [data-testid="remote-server-banner"], [role="status"]').filter({ hasText: 'nova.example.com' }).first();
        const bannerTarget = (await banner.isVisible().catch(() => false)) ? banner : exitBtn.locator('..');

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: bannerTarget, placement: 'bottom-left' },
            { num: 2, locator: exitBtn, placement: 'bottom-right' },
          ],
          clipOverride: { x: 0, y: 0, width: 2560, height: 640 },
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 5. peer-storage
  // =========================================================================
  {
    guide: 'peer-storage',
    step: '01-share-folder',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p, fx) => {
          const nova = fx.peersSnapshot.peers.find((peer) => peer.id === 'peer-nova');
          await p.route(/\/api\/v1\/admin\/peers\/peer-nova\/exports(?:\?.*)?$/, (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ exports: nova.exports }) }),
          );
          await p.route(/\/api\/v1\/admin\/peers\/peer-nova\/mounts(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                mounts: nova.mounts,
                available_exports: [
                  { id: 'rem-exp-archive', link_id: 'peer-nova', path: '/srv/media/archive', writable: false, created_at: fx.isoAgo(20 * 86_400_000) },
                  { id: 'rem-exp-4k', link_id: 'peer-nova', path: '/srv/media/4k-remux', writable: true, created_at: fx.isoAgo(5 * 86_400_000) },
                ],
                exports_error: null,
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const main = page.locator('#main-content .af-tab-content');
        await main.getByText('nova.example.com').first().waitFor({ timeout: 20_000 });
        await main.locator('button', { hasText: /^Storage$/ }).first().click();

        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        await dialog.locator('select option[value="rem-exp-4k"]').waitFor({ state: 'attached', timeout: 15_000 });
        await waitForSettle(page);

        const pathInput = dialog.locator('input[type="text"], input:not([type])').first();
        await pathInput.fill('/mnt/media/4k');
        const shareBtn = dialog.getByRole('button', { name: /Share folder|Export folder/i }).first();
        const remoteSelect = dialog.locator('select').last();
        const mountBtn = dialog.getByRole('button', { name: 'Mount folder', exact: true }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [pathInput, shareBtn], placement: 'left' },
            { num: 2, locators: [remoteSelect, mountBtn], placement: 'left' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 1020,
          padX: 72,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'peer-storage',
    step: '02-transcode',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=cluster`, { waitUntil: 'domcontentloaded' });
        const section = page.locator('[data-testid="cluster-transcode-section"]').first();
        await section.waitFor({ state: 'visible', timeout: 20_000 });
        await section.scrollIntoViewIfNeeded();
        await waitForSettle(page);

        const card = section.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const globalToggle = section.getByText(/Use paired servers for Jellyfin transcoding/i).first().locator('xpath=ancestor::div[contains(@class,"rounded")][1]').first();
        const alignmentTable = section.locator('table').first().locator('..');

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: globalToggle, placement: 'left' },
            { num: 2, locator: alignmentTable, placement: 'left' },
          ],
          contextLocators: [globalToggle, alignmentTable, section.getByText('Peer transcode workers').first()],
          minWidth: 1680,
          minHeight: 740,
          padX: 60,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 6. self-update
  // =========================================================================
  {
    guide: 'self-update',
    step: '01-system-updates',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          await p.route(/\/api(\/v1)?(\/(auth|admin))?\/system\/update\/check(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                updateAvailable: true,
                currentVersion: 'v4.0.0',
                latestVersion: 'v4.0.1',
                currentCommit: 'a4f92c1',
                message: 'AetherFlow v4.0.1 is available (Sigstore provenance verified).',
                url: 'https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.1',
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=settings`, { waitUntil: 'domcontentloaded' });
        const checkBtn = page.getByRole('button', { name: 'Check for Updates', exact: true });
        await checkBtn.waitFor({ state: 'visible', timeout: 20_000 });
        await checkBtn.scrollIntoViewIfNeeded();
        await waitForSettle(page);

        const card = checkBtn.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const channelSelect = card.locator('select').first();
        const applyBtn = card.getByRole('button', { name: 'Apply Self-Update', exact: true });

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: channelSelect, placement: 'top-left' },
            { num: 2, locator: checkBtn, placement: 'bottom-left' },
            { num: 3, locator: applyBtn, placement: 'bottom-right' },
          ],
          contextLocator: card,
          minWidth: 1620,
          minHeight: 520,
          padX: 60,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'self-update',
    step: '02-progress',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          await p.route(/\/api(\/v1)?(\/(auth|admin))?\/system\/update\/check(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                updateAvailable: true,
                currentVersion: 'v4.0.0',
                latestVersion: 'v4.0.1',
                currentCommit: 'a4f92c1',
                message: 'AetherFlow v4.0.1 verified — deploying signed release.',
                url: 'https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.1',
              }),
            }),
          );
          await p.route(/\/api(\/v1)?(\/(auth|admin))?\/system\/update\/status(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                state: 'running',
                status: 'running',
                phase: 'deploying',
                operationId: 'aetherflow-self-update-20261125-001',
                error: '',
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=settings`, { waitUntil: 'domcontentloaded' });
        const receiptLine = page.getByText(/aetherflow-self-update-20261125-001/i).first();
        await receiptLine.waitFor({ state: 'visible', timeout: 20_000 });
        await receiptLine.scrollIntoViewIfNeeded();
        await waitForSettle(page);

        const card = receiptLine.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const progressLine = card.getByText(/Update in progress/i).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [receiptLine, progressLine], placement: 'left' },
          ],
          contextLocator: card,
          minWidth: 1620,
          minHeight: 520,
          padX: 64,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 7. flowai
  // =========================================================================
  {
    guide: 'flowai',
    step: '01-providers',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=settings`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('tab', { name: /FlowAI Providers/i }).click();
        const modelInput = page.locator('#main-content input[list="settings-model-presets"]').first();
        await modelInput.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const card = modelInput.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const localSelect = card.locator('select').first();
        const apiKeyInput = card.locator('input[type="password"]').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: modelInput, placement: 'left' },
            { num: 2, locator: localSelect, placement: 'right' },
            { num: 3, locator: apiKeyInput, placement: 'left' },
          ],
          contextLocator: card,
          minWidth: 1680,
          minHeight: 740,
          padX: 64,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'flowai',
    step: '02-ask',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      // Seed a concise starter thread so quick actions + prompt input + Send sit together in view.
      const conciseFx = {
        ...fixtures,
        flowAiThreads: [
          {
            id: 'thread-quick-check',
            title: 'System health check',
            createdAt: fixtures.isoAgo(5 * 60_000),
            messages: [
              {
                role: 'user',
                text: 'Check CPU, NVENC headroom, and failing systemd units on atlas.example.com.',
              },
              {
                role: 'assistant',
                text: 'All **13 systemd units** are active with **34.2% CPU** and **42.5% GPU** utilization. Zero failed units detected.',
              },
            ],
          },
          ...fixtures.flowAiThreads.slice(1),
        ],
      };
      const { context, page } = await openFreshContext(browser, conciseFx, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=ai`, { waitUntil: 'domcontentloaded' });
        const quickBtn = page.getByRole('button', { name: /Analyze CPU & Memory Pressure/i }).first();
        await quickBtn.waitFor({ state: 'visible', timeout: 20_000 });
        const promptInput = page.locator('#main-content textarea').first();
        await promptInput.fill('Should we prune stale HLS transcode segments older than 48h on /mnt/nvme-cache?');
        await waitForSettle(page);

        const quickBar = quickBtn.locator('..');
        const sendBtn = page.locator('#main-content button[type="submit"]').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: quickBar, placement: 'top-left' },
            { num: 2, locators: [promptInput, sendBtn], placement: 'bottom-left' },
          ],
          contextLocators: [quickBar, promptInput, sendBtn],
          minWidth: 1760,
          minHeight: 720,
          padX: 64,
          padY: 64,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'flowai',
    step: '03-proposal',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=ai`, { waitUntil: 'domcontentloaded' });
        const reviewBtn = page.getByRole('button', { name: /Review in Approval Inbox/i }).first();
        await reviewBtn.waitFor({ state: 'visible', timeout: 20_000 });
        await reviewBtn.scrollIntoViewIfNeeded();
        await waitForSettle(page);

        const proposalCard = reviewBtn.locator('xpath=ancestor::div[contains(@class,"rounded")][1]').first();
        const assistantCard = proposalCard.locator('xpath=ancestor::div[contains(@class,"glass-card") or contains(@class,"rounded-2xl")][1]').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: proposalCard, placement: 'top-left' },
            { num: 2, locator: reviewBtn, placement: 'right' },
          ],
          contextLocator: assistantCard,
          minWidth: 1620,
          minHeight: 620,
          padX: 64,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'flowai',
    step: '04-approve',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=inbox`, { waitUntil: 'domcontentloaded' });
        const pruneCard = page.locator('#main-content .af-tab-content').getByText('prune_transcode_cache').first().locator('xpath=ancestor::*[contains(@class,"glass-card")][1]');
        await pruneCard.waitFor({ state: 'visible', timeout: 20_000 });
        await pruneCard.getByRole('button', { name: 'Inspect action', exact: true }).click();

        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        const approveBtn = dialog.getByRole('button', { name: /Approve & Execute/i }).first();
        const rejectBtn = dialog.getByRole('button', { name: 'Reject', exact: true }).first();
        await approveBtn.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const breakdownCard = dialog.locator('dl').first().locator('..');

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: breakdownCard, placement: 'left' },
            { num: 2, locators: [approveBtn, rejectBtn], placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 1020,
          padX: 72,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 8. mcbrowser
  // =========================================================================
  {
    guide: 'mcbrowser',
    step: '01-upload',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=mcbrowser`, { waitUntil: 'domcontentloaded' });
        await page.getByText('atlas-cluster-policy.toml').first().waitFor({ timeout: 20_000 });
        await waitForSettle(page);

        const uploadBtn = page.getByRole('button', { name: 'Upload files', exact: true }).first();
        const dropText = page.getByText(/Drop files here to upload/i).first();
        const firstRow = page.getByText('atlas-cluster-policy.toml').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: uploadBtn, placement: 'top' },
            { num: 2, locator: dropText, placement: 'right' },
          ],
          contextLocators: [uploadBtn, dropText, firstRow, page.getByText('backup-manifest.json').first()],
          minWidth: 1680,
          minHeight: 640,
          padX: 72,
          padY: 72,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'mcbrowser',
    step: '02-share',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=mcbrowser`, { waitUntil: 'domcontentloaded' });
        await page.getByText('atlas-cluster-policy.toml').first().waitFor({ timeout: 20_000 });

        // Select the first file row checkbox (index 0 is "Select visible").
        await page.locator('#main-content input[type="checkbox"]').nth(1).check();
        await page.locator('#main-content button', { hasText: /^Share/ }).first().click();

        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const passInput = dialog.locator('input[type="password"]').first();
        const expiryInput = dialog.locator('input[type="number"], select').first();
        const createBtn = dialog.locator('button[type="submit"], button.glass-button-primary').first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [passInput, expiryInput], placement: 'left' },
            { num: 2, locator: createBtn, placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'mcbrowser',
    step: '03-edit',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const sampleToml = [
        '# AetherFlow Peer Cluster Policy — atlas.example.com',
        '[cluster]',
        'name = "atlas.example.com"',
        'tunnel_cidr = "10.231.0.0/16"',
        'wg_port = 51821',
        'rtt_warn_ms = 120',
        '',
        '[transcode]',
        'enabled = true',
        'package = "jellyfin-ffmpeg8"',
        'version = "8.1.3-1-trixie"',
        'preferred_workers = ["vega.example.com", "nova.example.com"]',
        '',
        '[backup]',
        'schedule = "smart"',
        'window_utc = "03:00"',
        'retention_days = 30',
      ].join('\n');

      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          await p.route(/\/api\/v1\/auth\/mcbrowser\/content(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              headers: { etag: '"sha256-atlas-policy-v4"' },
              contentType: 'application/json',
              body: JSON.stringify({ content: sampleToml, etag: '"sha256-atlas-policy-v4"' }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=mcbrowser`, { waitUntil: 'domcontentloaded' });
        const fileItem = page.locator('#main-content').getByText('atlas-cluster-policy.toml').first();
        await fileItem.waitFor({ state: 'visible', timeout: 20_000 });
        await fileItem.dblclick();

        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        const editorArea = dialog.locator('textarea, [contenteditable="true"], .cm-editor').first();
        await editorArea.waitFor({ state: 'visible', timeout: 15_000 });
        await page.evaluate(() => window.getSelection()?.removeAllRanges());
        await waitForSettle(page);

        const saveBtn = dialog.getByRole('button', { name: /Save/i }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: editorArea, placement: 'left' },
            { num: 2, locator: saveBtn, placement: 'top' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 1120,
          padX: 72,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 9. network
  // =========================================================================
  {
    guide: 'network',
    step: '01-wireguard-add-peer',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          await p.route(/\/api\/v1\/admin\/network\/wireguard\/keygen(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                public_key: fakePubKey(201),
                private_key: fakePubKey(202),
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=network`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('button', { name: 'Create Peer', exact: true }).click();

        const dialog = page.getByRole('dialog').filter({ hasText: 'Create WireGuard peer' }).first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        const nameInput = dialog.locator('input').nth(0);
        const keyInput = dialog.locator('input').nth(1);
        const endpointInput = dialog.locator('input').nth(5);
        await nameInput.fill('travel-laptop');
        await endpointInput.fill('vpn.atlas.example.com:51820');
        await dialog.getByRole('button', { name: /Generate client keypair/i }).first().click();
        await page.waitForFunction(
          () => {
            const dlg = document.querySelector('dialog[open]');
            const inputs = dlg ? dlg.querySelectorAll('input') : [];
            return inputs[1] && inputs[1].value.length > 20;
          },
          { timeout: 10_000 },
        );
        await waitForSettle(page);

        const submitBtn = dialog.getByRole('button', { name: /Enroll peer/i }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [nameInput, keyInput], placement: 'left' },
            { num: 2, locator: submitBtn, placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 60,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'network',
    step: '02-wireguard-qr',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          await p.route(/\/api\/v1\/admin\/network\/wireguard\/keygen(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                public_key: fakePubKey(201),
                private_key: fakePubKey(202),
              }),
            }),
          );
          await p.route(/\/api\/v1\/admin\/network\/wireguard\/peers(?:\?.*)?$/, async (route) => {
            if (route.request().method() === 'POST') {
              const body = route.request().postDataJSON();
              return route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                  message: 'WireGuard peer enrolled',
                  peer: {
                    name: body.name || 'travel-laptop',
                    public_key: body.public_key,
                    allowed_ips: body.allowed_ips || '10.66.66.6/32',
                    endpoint: body.endpoint || '',
                    persistent_keepalive: body.persistent_keepalive || 25,
                  },
                }),
              });
            }
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({}) });
          });
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=network`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('button', { name: 'Create Peer', exact: true }).click();

        const createDialog = page.getByRole('dialog').filter({ hasText: 'Create WireGuard peer' }).first();
        await createDialog.waitFor({ state: 'visible', timeout: 15_000 });
        await createDialog.locator('input').nth(0).fill('travel-laptop');
        await createDialog.locator('input').nth(5).fill('vpn.atlas.example.com:51820');
        await createDialog.getByRole('button', { name: /Generate client keypair/i }).first().click();
        await page.waitForFunction(
          () => {
            const dlg = document.querySelector('dialog[open]');
            const inputs = dlg ? dlg.querySelectorAll('input') : [];
            return inputs[1] && inputs[1].value.length > 20;
          },
          { timeout: 10_000 },
        );
        await createDialog.getByRole('button', { name: /Enroll peer/i }).first().click();

        const exportDialog = page.getByRole('dialog').filter({ hasText: /One-time WireGuard client configuration/i }).first();
        const dlBtn = exportDialog.getByRole('button', { name: /Download \.conf/i }).first();
        await dlBtn.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const qrBox = exportDialog.locator('svg[aria-label*="QR" i], svg').first().locator('..');

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: qrBox, placement: 'right' },
            { num: 2, locator: dlBtn, placement: 'right' },
          ],
          contextLocator: exportDialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'network',
    step: '03-tailscale',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=network`, { waitUntil: 'domcontentloaded' });
        const tsHeading = page.getByText('Tailscale Mesh VPN', { exact: true }).first();
        await tsHeading.waitFor({ state: 'visible', timeout: 20_000 });
        await page.evaluate(() => {
          const main = document.querySelector('#main-content');
          if (main) main.scrollTop = 900;
        });
        await waitForSettle(page);

        const card = tsHeading.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const routesInput = card.locator('input[type="text"], input:not([type="checkbox"])').first();
        const acceptBox = card.getByText(/Accept routes from other nodes/i).first().locator('..');
        const exitBox = card.getByText(/Advertise this host as an exit node/i).first().locator('..');

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: routesInput, placement: 'left' },
            { num: 2, locators: [acceptBox, exitBox], placement: 'right' },
          ],
          contextLocator: card,
          minWidth: 1680,
          minHeight: 560,
          padX: 60,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 10. security
  // =========================================================================
  {
    guide: 'security',
    step: '01-enable-2fa',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(
        browser,
        fixtures,
        unmockedLog,
        consoleErrors,
        async (p) => {
          await p.route(/\/api\/v1\/auth\/user\/2fa\/setup(?:\?.*)?$/, (route) =>
            route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                otpauth_uri: 'otpauth://totp/AetherFlow:alex%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=AetherFlow',
                secret: 'JBSWY3DPEHPK3PXP',
              }),
            }),
          );
        },
      );
      try {
        await page.goto(`${baseUrl}/?tab=settings`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('tab', { name: /Security/i }).click();
        await page.getByRole('button', { name: 'Enroll authenticator', exact: true }).click();

        const dialog = page.getByRole('dialog').first();
        await dialog.waitFor({ state: 'visible', timeout: 15_000 });
        const qrSvg = dialog.locator('svg[aria-label*="QR" i], svg[role="img"], svg').first();
        await qrSvg.waitFor({ state: 'visible', timeout: 15_000 });
        const codeInput = dialog.locator('input').first();
        await codeInput.fill('482917');
        await waitForSettle(page);

        const verifyBtn = dialog.getByRole('button', { name: /Verify and enable 2FA/i }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: qrSvg, placement: 'left' },
            { num: 2, locators: [codeInput, verifyBtn], placement: 'right' },
          ],
          contextLocator: dialog,
          smallDialog: true,
          minWidth: 960,
          padX: 72,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
  {
    guide: 'security',
    step: '02-sessions',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=settings`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('tab', { name: /Security/i }).click();
        const heading = page.getByText('Active session families', { exact: true }).first();
        await heading.waitFor({ state: 'visible', timeout: 15_000 });
        await page.evaluate(() => {
          const main = document.querySelector('#main-content');
          if (main) main.scrollTop = main.scrollHeight;
        });
        await waitForSettle(page);

        const card = heading.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const firstSession = card.getByText(/sess-fam-9a41f0c2/).first().locator('xpath=ancestor::div[contains(@class,"border-t")][1]');
        const lastSession = card.getByText(/sess-fam-3d92a7e5/).first().locator('xpath=ancestor::div[contains(@class,"border-t")][1]');
        const revokeAllBtn = card.getByRole('button', { name: 'Revoke all other sessions', exact: true }).first();

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locators: [firstSession, lastSession], placement: 'left' },
            { num: 2, locator: revokeAllBtn, placement: 'right' },
          ],
          contextLocator: card,
          minWidth: 1680,
          minHeight: 540,
          padX: 64,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },

  // =========================================================================
  // 11. backups
  // =========================================================================
  {
    guide: 'backups',
    step: '01-backups',
    run: async ({ browser, baseUrl, fixtures, unmockedLog, consoleErrors, outPath, optimize }) => {
      const { context, page } = await openFreshContext(browser, fixtures, unmockedLog, consoleErrors);
      try {
        await page.goto(`${baseUrl}/?tab=settings`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('tab', { name: /Backups & Restore/i }).click();
        const snapBtn = page.getByRole('button', { name: /Create database snapshot|Create snapshot|Create Backup/i }).first();
        await snapBtn.waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        const card = snapBtn.locator('xpath=ancestor::*[contains(@class,"glass-card")][1]').first();
        const manifestTable = card.locator('[role="grid"], table').first();
        await page.getByText(/aetherflow-db-20261125-0300\.sqlite\.zst/).first().waitFor({ state: 'visible', timeout: 15_000 });
        await waitForSettle(page);

        return await annotateAndCrop(page, outPath, {
          annotations: [
            { num: 1, locator: snapBtn, placement: 'top-left' },
            { num: 2, locator: manifestTable, placement: 'left' },
          ],
          contextLocator: card,
          minWidth: 1680,
          minHeight: 680,
          padX: 64,
          padY: 56,
        }, optimize);
      } finally {
        await context.close();
      }
    },
  },
];

async function main() {
  const opts = parseArgs(process.argv);
  const { chromium } = loadPlaywright();
  fs.mkdirSync(opts.out, { recursive: true });

  const selected = opts.guides
    ? GUIDE_STEPS.filter((s) =>
        opts.guides.includes(s.guide) || opts.guides.includes(`${s.guide}/${s.step}`),
      )
    : GUIDE_STEPS;

  if (selected.length === 0) {
    const valid = [...new Set(GUIDE_STEPS.map((s) => s.guide))].join(', ');
    throw new Error(`No matching guide steps for --guides. Valid guides: ${valid}`);
  }

  const { distDir, tempDir } = resolveWebDist(opts);
  const { server, baseUrl } = await startStaticServer(distDir);
  const fixtures = buildFixtures();

  let browser;
  const unmockedLog = [];
  const consoleErrors = [];
  const results = [];

  try {
    browser = await chromium.launch({ headless: true });

    for (const item of selected) {
      const outPath = path.join(opts.out, item.guide, `${item.step}.png`);
      const { bytes, optimizer, clip } = await item.run({
        browser,
        baseUrl,
        fixtures,
        unmockedLog,
        consoleErrors,
        outPath,
        optimize: opts.optimize,
      });
      results.push({
        id: `${item.guide}/${item.step}.png`,
        path: outPath,
        bytes,
        optimizer,
        dims: `${clip.width}x${clip.height}`,
      });
      console.log(`Captured ${item.guide}/${item.step}.png (${clip.width}x${clip.height}, ${(bytes / 1024).toFixed(1)} KiB, opt=${optimizer})`);
    }
  } finally {
    if (browser) await browser.close();
    await new Promise((resolve) => server.close(resolve));
    if (tempDir && !opts.keepTemp) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  console.log('\n--- Guide Capture Summary ---');
  for (const r of results) {
    console.log(`  ${r.id.padEnd(36)} ${r.dims.padStart(10)}  ${(r.bytes / 1024).toFixed(1).padStart(7)} KiB`);
  }
  if (unmockedLog.length > 0) {
    console.warn('\nUnmocked API requests encountered:');
    for (const entry of [...new Set(unmockedLog)]) {
      console.warn(`  - ${entry}`);
    }
  }
  if (consoleErrors.length > 0) {
    console.warn('\nBrowser console errors:');
    for (const err of [...new Set(consoleErrors)]) {
      console.warn(`  - ${err}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
