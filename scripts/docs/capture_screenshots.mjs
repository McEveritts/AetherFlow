#!/usr/bin/env node
/**
 * AetherFlow v4.0.0 — 1440p Dashboard Screenshot Capture Script (Dark & Light)
 *
 * Launches a local static HTTP server serving the compiled Leptos/WASM
 * `web/dist` bundle (either local or downloaded from a GitHub release) and
 * captures deterministic 2560x1440 PNG screenshots across all 16 dashboard
 * tabs plus the Security & 2FA subtab (17 views × dark & light = 34 PNGs)
 * plus the 1280x640 dark social-crop preview, using 100% synthetic fixture
 * data (RFC 5737/ULA IPs, example.com hostnames, fictional users).
 *
 * Usage:
 *   node scripts/docs/capture_screenshots.mjs
 *   node scripts/docs/capture_screenshots.mjs --theme dark
 *   node scripts/docs/capture_screenshots.mjs --theme light --tabs overview,inbox,quotas
 *   node scripts/docs/capture_screenshots.mjs --dist /path/to/web/dist
 *   node scripts/docs/capture_screenshots.mjs --guides
 *   node scripts/docs/capture_screenshots.mjs --release v4.0.0
 */

import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

const VIEWPORT = { width: 2560, height: 1440 };
const SOCIAL_CROP = { width: 1280, height: 640 };

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt': 'text/plain; charset=utf-8',
};

function parseArgs(argv) {
  const opts = {
    dist: process.env.AETHERFLOW_WEB_DIST || '',
    out: path.join(REPO_ROOT, 'docs', 'assets', 'screenshots'),
    release: 'v4.0.0',
    theme: 'both',
    tabs: null,
    guides: false,
    guidesFilter: null,
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
    } else if (arg === '--theme' && argv[i + 1]) {
      const value = argv[++i].trim().toLowerCase();
      if (!['dark', 'light', 'both'].includes(value)) {
        throw new Error(`Invalid --theme "${value}". Expected dark, light, or both.`);
      }
      opts.theme = value;
    } else if (arg === '--tabs' && argv[i + 1]) {
      opts.tabs = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (arg === '--guides') {
      opts.guides = true;
      if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        opts.guidesFilter = argv[++i];
      }
    } else if (arg === '--no-optimize') {
      opts.optimize = false;
    } else if (arg === '--keep-temp') {
      opts.keepTemp = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log(`Usage: node scripts/docs/capture_screenshots.mjs [options]

Options:
  --dist <dir>       Path to compiled web/dist directory (default: web/dist or download release)
  --out <dir>        Output directory (default: docs/assets/screenshots)
  --release <tag>    GitHub release tag to download if web/dist is not present (default: v4.0.0)
  --theme <mode>     Theme mode: dark, light, or both (default: both)
  --tabs <list>      Comma-separated shot names to capture (default: all 17 views)
  --guides [list]    Run annotated guide captures via scripts/docs/capture_guides.mjs
  --no-optimize      Skip PNG optimization step
  --help             Show this message
`);
      process.exit(0);
    }
  }
  return opts;
}

function loadPlaywright() {
  const candidates = [];
  if (process.env.PLAYWRIGHT_MODULE_PATH) {
    candidates.push(process.env.PLAYWRIGHT_MODULE_PATH);
  }
  candidates.push(
    path.join(REPO_ROOT, 'node_modules', '@playwright', 'test'),
    path.join(REPO_ROOT, 'e2e', 'node_modules', '@playwright', 'test'),
    path.join(REPO_ROOT, 'node_modules', 'playwright'),
    path.join(REPO_ROOT, 'node_modules', 'playwright-core'),
  );

  // Support git worktrees where node_modules lives in the main checkout.
  try {
    const commonDir = execFileSync('git', ['rev-parse', '--git-common-dir'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (commonDir) {
      const mainRoot = path.resolve(REPO_ROOT, commonDir, '..');
      candidates.push(
        path.join(mainRoot, 'node_modules', '@playwright', 'test'),
        path.join(mainRoot, 'e2e', 'node_modules', '@playwright', 'test'),
        path.join(mainRoot, 'node_modules', 'playwright'),
        path.join(mainRoot, 'node_modules', 'playwright-core'),
      );
    }
  } catch {
    // Non-git checkout; ignore.
  }

  const req = createRequire(import.meta.url);
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return req(candidate);
    }
  }
  for (const bare of ['@playwright/test', 'playwright', 'playwright-core']) {
    try {
      return req(bare);
    } catch {
      // Try next.
    }
  }
  throw new Error(
    'Could not resolve Playwright. Run `npm ci` in the repo root (or set PLAYWRIGHT_MODULE_PATH).',
  );
}

function resolveWebDist(opts) {
  const hasBundle = (dir) => dir && fs.existsSync(path.join(dir, 'index.html'));
  if (opts.dist) {
    if (!hasBundle(opts.dist)) {
      throw new Error(`Provided --dist directory lacks index.html: ${opts.dist}`);
    }
    return { distDir: opts.dist, tempDir: null };
  }
  const repoDist = path.join(REPO_ROOT, 'web', 'dist');
  if (hasBundle(repoDist)) {
    return { distDir: repoDist, tempDir: null };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'af-screenshots-'));
  console.log(`Downloading AetherFlow ${opts.release} web/dist bundle to ${tempDir}…`);
  execFileSync(
    'gh',
    ['release', 'download', opts.release, '-p', 'aetherflow-linux-amd64.tar.gz', '-D', tempDir],
    { cwd: REPO_ROOT, stdio: 'inherit' },
  );
  execFileSync(
    'tar',
    ['-xzf', path.join(tempDir, 'aetherflow-linux-amd64.tar.gz'), '-C', tempDir, './web/dist'],
    { stdio: 'inherit' },
  );
  const extracted = path.join(tempDir, 'web', 'dist');
  if (!hasBundle(extracted)) {
    throw new Error(`Extracted release archive did not contain web/dist/index.html in ${tempDir}`);
  }
  return { distDir: extracted, tempDir };
}

function startStaticServer(distDir) {
  const indexPath = path.join(distDir, 'index.html');
  const server = http.createServer((req, res) => {
    const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
    const cleanPath = decodeURIComponent(reqUrl.pathname).replace(/^\/+/, '');
    if (cleanPath.startsWith('api/')) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unmocked API route', path: reqUrl.pathname }));
      return;
    }

    let filePath = path.resolve(distDir, cleanPath);
    if (!filePath.startsWith(path.resolve(distDir))) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = indexPath;
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'content-type': contentType,
      'cache-control': 'no-cache',
    });
    fs.createReadStream(filePath).pipe(res);
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${addr.port}` });
    });
  });
}

function buildPosterSvg(title, subtitle, c1, c2, badge) {
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 360" width="240" height="360">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${c1}"/>
      <stop offset="100%" stop-color="${c2}"/>
    </linearGradient>
    <radialGradient id="glow" cx="50%" cy="32%" r="55%">
      <stop offset="0%" stop-color="rgba(255,255,255,0.28)"/>
      <stop offset="100%" stop-color="rgba(0,0,0,0)"/>
    </radialGradient>
  </defs>
  <rect width="240" height="360" fill="url(#bg)"/>
  <rect width="240" height="360" fill="url(#glow)"/>
  <circle cx="120" cy="126" r="56" fill="none" stroke="rgba(255,255,255,0.35)" stroke-width="2"/>
  <circle cx="120" cy="126" r="34" fill="rgba(255,255,255,0.14)" stroke="rgba(255,255,255,0.55)" stroke-width="1.5"/>
  <rect x="20" y="20" width="76" height="24" rx="12" fill="rgba(7,9,14,0.68)"/>
  <text x="58" y="36" fill="#e2e8f0" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="700" text-anchor="middle">${esc(badge)}</text>
  <rect x="0" y="246" width="240" height="114" fill="rgba(7,9,14,0.72)"/>
  <text x="18" y="286" fill="#f8fafc" font-family="Inter,system-ui,sans-serif" font-size="18" font-weight="700">${esc(title)}</text>
  <text x="18" y="312" fill="#94a3b8" font-family="Inter,system-ui,sans-serif" font-size="12">${esc(subtitle)}</text>
</svg>`;
}

function buildAvatarDataUri() {
  // Crisp geometric dark-indigo operator monogram PNG/SVG? Note security.rs only accepts PNG/JPEG/WEBP/GIF data URIs or relative paths, so we return a clean relative path served via route!
  return '/api/v1/auth/profile/avatar';
}

function buildAvatarSvg() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="av" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#6366f1"/>
      <stop offset="55%" stop-color="#8b5cf6"/>
      <stop offset="100%" stop-color="#22d3ee"/>
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="28" fill="url(#av)"/>
  <text x="64" y="80" fill="#ffffff" font-family="Inter,system-ui,sans-serif" font-size="52" font-weight="700" text-anchor="middle">A</text>
</svg>`;
}

function buildFixtures() {
  const nowMs = Date.now();
  const isoAgo = (ms) => new Date(nowMs - ms).toISOString();
  const sqlUtc = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
  const dateDay = (daysAgo) => {
    const d = new Date(nowMs - daysAgo * 86_400_000);
    return d.toISOString().slice(0, 10);
  };

  // Smooth deterministic pseudo-wave telemetry history (120 samples across last 5m)
  const makeTelemetryHistory = (windowKey) => {
    const spanMs =
      windowKey === '1m' ? 60_000 :
      windowKey === '15m' ? 15 * 60_000 :
      windowKey === '1h' ? 60 * 60_000 :
      windowKey === '6h' ? 6 * 60 * 60_000 :
      windowKey === '24h' ? 24 * 60 * 60_000 :
      5 * 60_000;
    const count = 96;
    const points = [];
    let rxAcc = 14.8 * 1024 ** 4;
    let txAcc = 9.2 * 1024 ** 4;
    const stepMs = spanMs / count;
    const targetCpu = 34.2;
    const targetMemPct = 38.0;
    const targetRxBps = Math.round(84.6 * 1_048_576);
    const targetTxBps = Math.round(31.2 * 1_048_576);
    const targetReadBps = Math.round(142.8 * 1_048_576);
    const targetWriteBps = Math.round(58.4 * 1_048_576);
    for (let i = 0; i <= count; i += 1) {
      const t = nowMs - spanMs + i * stepMs;
      const p = i / count;
      // Smooth ease-in blend over the last 12% so history meets live metrics seamlessly.
      const tail = p > 0.88 ? ((p - 0.88) / 0.12) ** 2 : 0;
      const lerp = (a, b) => a + (b - a) * tail;
      const rawCpu = 29.5 + 8.5 * Math.sin(p * Math.PI * 3.2) + 4.2 * Math.cos(p * Math.PI * 7.5) + 1.8 * Math.sin(p * 19);
      const rawMemPct = 37.4 + 1.6 * Math.sin(p * Math.PI * 1.8) + 0.5 * Math.cos(p * 11);
      const rawRxBps = (72 + 28 * Math.sin(p * Math.PI * 4.1) + 14 * Math.cos(p * 13)) * 1_048_576;
      const rawTxBps = (28 + 11 * Math.cos(p * Math.PI * 3.4) + 5 * Math.sin(p * 15)) * 1_048_576;
      const rawReadBps = (135 + 48 * Math.sin(p * Math.PI * 2.8 + 0.7) + 18 * Math.cos(p * 17)) * 1_048_576;
      const rawWriteBps = (52 + 22 * Math.cos(p * Math.PI * 3.6) + 9 * Math.sin(p * 14)) * 1_048_576;
      const cpu = Number(lerp(rawCpu, targetCpu).toFixed(1));
      const memPct = Number(lerp(rawMemPct, targetMemPct).toFixed(1));
      const memUsedGb = Number(((memPct / 100) * 128).toFixed(2));
      const rxBps = Math.round(lerp(rawRxBps, targetRxBps));
      const txBps = Math.round(lerp(rawTxBps, targetTxBps));
      const readBps = Math.round(lerp(rawReadBps, targetReadBps));
      const writeBps = Math.round(lerp(rawWriteBps, targetWriteBps));
      rxAcc += rxBps * (stepMs / 1000);
      txAcc += txBps * (stepMs / 1000);
      points.push({
        timestamp: sqlUtc(t),
        cpu_avg: cpu,
        cpu_usage: cpu,
        mem_used_gb: memUsedGb,
        mem_total_gb: 128.0,
        memory_pct: memPct,
        net_rx_bps: rxBps,
        net_tx_bps: txBps,
        net_rx_bytes: Math.round(rxAcc),
        net_tx_bytes: Math.round(txAcc),
        disk_read_bps: readBps,
        disk_write_bps: writeBps,
      });
    }
    return points;
  };

  // Daily transfer history for 7d / 30d / 90d
  const makeDailyTransfer = (daysCount) => {
    const n = Math.min(Math.max(Number(daysCount) || 30, 7), 90);
    const days = [];
    for (let i = n - 1; i >= 0; i -= 1) {
      const wave = Math.sin((n - i) * 0.45) * 0.3 + Math.cos((n - i) * 0.9) * 0.15;
      const downGib = 285 + wave * 170 + ((i % 7 === 0 || i % 7 === 6) ? 140 : 0);
      const upGib = 142 + wave * 75 + ((i % 7 === 0 || i % 7 === 6) ? 55 : 0);
      days.push({
        date: dateDay(i),
        downloaded_bytes: Math.round(downGib * 1024 ** 3),
        uploaded_bytes: Math.round(upGib * 1024 ** 3),
      });
    }
    return {
      days,
      counter_resets: 0,
      invalid_samples: 0,
      conflicting_samples: 0,
      duplicate_samples: 0,
    };
  };

  // 30-day capacity prediction series
  const capacityHistory30d = [];
  let capRx = 4.2 * 1024 ** 4;
  let capTx = 2.1 * 1024 ** 4;
  for (let i = 29; i >= 0; i -= 1) {
    const t = nowMs - i * 86_400_000;
    const p = (30 - i) / 30;
    const cpu = Number((26.0 + 7.2 * Math.sin(p * Math.PI * 2.5) + p * 3.5).toFixed(1));
    const memUsed = Number((44.5 + p * 4.8 + 2.1 * Math.cos(p * 8)).toFixed(1));
    const readBps = Math.round((110 + p * 36 + 22 * Math.sin(p * 7)) * 1_048_576);
    const writeBps = Math.round((46 + p * 15 + 11 * Math.cos(p * 9)) * 1_048_576);
    capRx += Math.round((310 + 90 * Math.sin(p * 6)) * 1024 ** 3);
    capTx += Math.round((155 + 45 * Math.cos(p * 5)) * 1024 ** 3);
    capacityHistory30d.push({
      timestamp: sqlUtc(t),
      cpu_avg: cpu,
      mem_used_gb: memUsed,
      mem_total_gb: 128.0,
      disk_read_bps: readBps,
      disk_write_bps: writeBps,
      net_rx_bytes: capRx,
      net_tx_bytes: capTx,
    });
  }

  // Load real 77-package catalog from config/packages.json
  const rawCatalog = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, 'config', 'packages.json'), 'utf8'),
  );
  const installedMeta = {
    adguardhome: { installed: '0.107.57', latest: '0.107.57', hits: 14920 },
    audiobookshelf: { installed: '2.19.4', latest: '2.20.0', update: true, hits: 13840 },
    emby: { installed: '4.8.11', latest: '4.8.11', hits: 12180 },
    jellyfin: { installed: '12.4.0', latest: '12.4.0', hits: 18420 },
    plex: { installed: '1.41.5', latest: '1.41.5', hits: 16890 },
    sonarr: { installed: '4.0.12', latest: '4.0.14', update: true, hits: 15210 },
    radarr: { installed: '5.19.3', latest: '5.19.3', hits: 14780 },
    prowlarr: { installed: '1.31.2', latest: '1.31.2', hits: 12950 },
    bazarr: { installed: '1.5.1', latest: '1.5.1', hits: 10840 },
    qbittorrent: { installed: '5.0.4', latest: '5.0.4', hits: 14120 },
    sabnzbd: { installed: '4.4.1', latest: '4.4.1', hits: 9430 },
    grafana: { installed: '11.5.1', latest: '11.6.0', update: true, hits: 11880 },
    prometheus: { installed: '3.2.1', latest: '3.2.1', hits: 10620 },
    vaultwarden: { installed: '1.33.2', latest: '1.33.2', hits: 13200 },
    nextcloud: { installed: '31.0.2', latest: '31.0.2', hits: 12460 },
    librespeed: { installed: '4.0.0', latest: '4.0.0', hits: 8910 },
    uptimekuma: { installed: '1.23.16', latest: '1.23.16', hits: 11340 },
  };
  const marketplaceApps = rawCatalog.map((pkg, idx) => {
    const id = pkg.name;
    const inst = installedMeta[id];
    const isRetired = pkg.status === 'retired';
    return {
      id,
      name: pkg.label || pkg.name,
      desc: pkg.description || '',
      hits: inst?.hits ?? Math.max(1200, 9600 - idx * 95),
      category: pkg.category || 'Utilities',
      status: inst ? 'installed' : isRetired ? 'retired' : 'available',
      progress: 0,
      ...(inst ? { installed_version: inst.installed, latest_version: inst.latest } : {}),
      update_available: Boolean(inst?.update),
      inventory_known: true,
      inventory_authenticated: true,
      default_port: pkg.default_port || 0,
      web_path: pkg.web_path || '/',
      ...(inst?.update ? { update_url: `https://github.com/McEveritts/AetherFlow/releases` } : {}),
    };
  });

  // Services map (all healthy, zero failed units!)
  const servicesMap = {
    'aetherflow-api': {
      id: 'aetherflow-api',
      name: 'AetherFlow API',
      slug: 'aetherflow-api',
      status: 'running',
      version: '4.0.0',
      installed_version: '4.0.0',
      latest_version: '4.0.0',
      uptime: '42d 11h 18m',
      cpu_pct: 1.4,
      memory_mb: 118.4,
      default_port: 8443,
      active_port: 8443,
      managed_by: 'systemd',
      process: 'aetherflow-api',
      health: 'healthy',
      components: [{ unit: 'aetherflow-api.service', status: 'running', role: 'required' }],
    },
    'aetherflow-runner': {
      id: 'aetherflow-runner',
      name: 'AetherFlow Runner',
      slug: 'aetherflow-runner',
      status: 'running',
      version: '4.0.0',
      installed_version: '4.0.0',
      latest_version: '4.0.0',
      uptime: '42d 11h 18m',
      cpu_pct: 0.3,
      memory_mb: 24.2,
      managed_by: 'systemd',
      process: 'aetherflow-runner',
      health: 'healthy',
      components: [{ unit: 'aetherflow-runner.service', status: 'running', role: 'required' }],
    },
    'af-transcode-worker': {
      id: 'af-transcode-worker',
      name: 'Transcode Worker',
      slug: 'af-transcode-worker',
      status: 'running',
      version: '4.0.0',
      installed_version: '4.0.0',
      latest_version: '4.0.0',
      uptime: '18d 06h 42m',
      cpu_pct: 11.8,
      memory_mb: 642.0,
      managed_by: 'systemd',
      process: 'af-transcode',
      health: 'healthy',
      components: [{ unit: 'af-transcode-worker.service', status: 'running', role: 'worker' }],
    },
    jellyfin: {
      id: 'jellyfin',
      name: 'Jellyfin',
      slug: 'jellyfin',
      status: 'running',
      version: '12.4.0',
      installed_version: '12.4.0',
      latest_version: '12.4.0',
      uptime: '29d 04h 15m',
      cpu_pct: 8.6,
      memory_mb: 2140.5,
      default_port: 8096,
      active_port: 8096,
      wired: true,
      auto_configured: true,
      public_url: 'https://jellyfin.atlas.example.com',
      managed_by: 'systemd',
      process: 'jellyfin',
      health: 'healthy',
      components: [{ unit: 'jellyfin.service', status: 'running', role: 'required' }],
    },
    plex: {
      id: 'plex',
      name: 'Plex Media Server',
      slug: 'plex',
      status: 'running',
      version: '1.41.5',
      installed_version: '1.41.5',
      latest_version: '1.41.5',
      uptime: '29d 04h 12m',
      cpu_pct: 3.1,
      memory_mb: 1480.2,
      default_port: 32400,
      active_port: 32400,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'plexmediaserver',
      health: 'healthy',
      components: [{ unit: 'plexmediaserver.service', status: 'running', role: 'required' }],
    },
    jellyseerr: {
      id: 'jellyseerr',
      name: 'Jellyseerr',
      slug: 'jellyseerr',
      status: 'running',
      version: '2.5.1',
      installed_version: '2.5.1',
      latest_version: '2.5.1',
      uptime: '24d 07h 20m',
      cpu_pct: 0.4,
      memory_mb: 186.2,
      default_port: 5055,
      active_port: 5055,
      wired: true,
      auto_configured: true,
      public_url: 'https://requests.atlas.example.com',
      managed_by: 'systemd',
      process: 'jellyseerr',
      health: 'healthy',
      components: [{ unit: 'jellyseerr.service', status: 'running', role: 'required' }],
    },
    sonarr: {
      id: 'sonarr',
      name: 'Sonarr',
      slug: 'sonarr',
      status: 'running',
      version: '4.0.12',
      installed_version: '4.0.12',
      latest_version: '4.0.14',
      update_available: true,
      update_url: 'https://github.com/Sonarr/Sonarr/releases',
      uptime: '21d 19h 04m',
      cpu_pct: 1.2,
      memory_mb: 392.0,
      default_port: 8989,
      active_port: 8989,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'sonarr',
      health: 'healthy',
      components: [{ unit: 'sonarr.service', status: 'running', role: 'required' }],
    },
    radarr: {
      id: 'radarr',
      name: 'Radarr',
      slug: 'radarr',
      status: 'running',
      version: '5.19.3',
      installed_version: '5.19.3',
      latest_version: '5.19.3',
      uptime: '21d 19h 02m',
      cpu_pct: 0.9,
      memory_mb: 356.8,
      default_port: 7878,
      active_port: 7878,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'radarr',
      health: 'healthy',
      components: [{ unit: 'radarr.service', status: 'running', role: 'required' }],
    },
    prowlarr: {
      id: 'prowlarr',
      name: 'Prowlarr',
      slug: 'prowlarr',
      status: 'running',
      version: '1.31.2',
      installed_version: '1.31.2',
      latest_version: '1.31.2',
      uptime: '21d 19h 00m',
      cpu_pct: 0.4,
      memory_mb: 214.6,
      default_port: 9696,
      active_port: 9696,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'prowlarr',
      health: 'healthy',
      components: [{ unit: 'prowlarr.service', status: 'running', role: 'required' }],
    },
    bazarr: {
      id: 'bazarr',
      name: 'Bazarr',
      slug: 'bazarr',
      status: 'running',
      version: '1.5.1',
      installed_version: '1.5.1',
      latest_version: '1.5.1',
      uptime: '14d 08h 33m',
      cpu_pct: 0.3,
      memory_mb: 168.0,
      default_port: 6767,
      active_port: 6767,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'bazarr',
      health: 'healthy',
      components: [{ unit: 'bazarr.service', status: 'running', role: 'required' }],
    },
    qbittorrent: {
      id: 'qbittorrent',
      name: 'qBittorrent',
      slug: 'qbittorrent',
      status: 'running',
      version: '5.0.4',
      installed_version: '5.0.4',
      latest_version: '5.0.4',
      uptime: '36d 14h 51m',
      cpu_pct: 4.5,
      memory_mb: 1620.4,
      default_port: 8080,
      active_port: 8080,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'qbittorrent-nox',
      health: 'healthy',
      components: [{ unit: 'qbittorrent-nox@aetherflow.service', status: 'running', role: 'required' }],
    },
    sabnzbd: {
      id: 'sabnzbd',
      name: 'SABnzbd',
      slug: 'sabnzbd',
      status: 'running',
      version: '4.4.1',
      installed_version: '4.4.1',
      latest_version: '4.4.1',
      uptime: '31d 02h 14m',
      cpu_pct: 1.1,
      memory_mb: 312.5,
      default_port: 8085,
      active_port: 8085,
      wired: true,
      auto_configured: true,
      managed_by: 'systemd',
      process: 'sabnzbdplus',
      health: 'healthy',
      components: [{ unit: 'sabnzbd.service', status: 'running', role: 'required' }],
    },
    grafana: {
      id: 'grafana',
      name: 'Grafana',
      slug: 'grafana',
      status: 'running',
      version: '11.5.1',
      installed_version: '11.5.1',
      latest_version: '11.6.0',
      update_available: true,
      update_url: 'https://github.com/grafana/grafana/releases',
      uptime: '42d 11h 10m',
      cpu_pct: 0.7,
      memory_mb: 284.1,
      default_port: 3000,
      active_port: 3000,
      managed_by: 'systemd',
      process: 'grafana-server',
      health: 'healthy',
      components: [{ unit: 'grafana-server.service', status: 'running', role: 'required' }],
    },
    prometheus: {
      id: 'prometheus',
      name: 'Prometheus',
      slug: 'prometheus',
      status: 'running',
      version: '3.2.1',
      installed_version: '3.2.1',
      latest_version: '3.2.1',
      uptime: '42d 11h 12m',
      cpu_pct: 1.1,
      memory_mb: 512.7,
      default_port: 9090,
      active_port: 9090,
      managed_by: 'systemd',
      process: 'prometheus',
      health: 'healthy',
      components: [{ unit: 'prometheus.service', status: 'running', role: 'required' }],
    },
    vaultwarden: {
      id: 'vaultwarden',
      name: 'Vaultwarden',
      slug: 'vaultwarden',
      status: 'running',
      version: '1.33.2',
      installed_version: '1.33.2',
      latest_version: '1.33.2',
      uptime: '42d 11h 15m',
      cpu_pct: 0.2,
      memory_mb: 68.4,
      default_port: 8222,
      active_port: 8222,
      managed_by: 'systemd',
      process: 'vaultwarden',
      health: 'healthy',
      components: [{ unit: 'vaultwarden.service', status: 'running', role: 'required' }],
    },
    librespeed: {
      id: 'librespeed',
      name: 'LibreSpeed (Rust)',
      slug: 'librespeed',
      status: 'running',
      version: '4.0.0',
      installed_version: '4.0.0',
      latest_version: '4.0.0',
      uptime: '42d 11h 18m',
      cpu_pct: 0.1,
      memory_mb: 18.6,
      default_port: 8988,
      active_port: 8988,
      managed_by: 'systemd',
      process: 'speedtest-backend',
      health: 'healthy',
      components: [{ unit: 'af-librespeed.service', status: 'running', role: 'required' }],
    },
  };

  // Peer Cluster (3 remote peers connected to local atlas.example.com)
  const fakePubKey = (seed) =>
    crypto.createHash('sha256').update(`aetherflow-example-wg-key-${seed}`).digest('base64');
  const fullWriteAccess = {
    services: 'write',
    marketplace: 'write',
    settings: 'write',
    files: 'write',
    users: 'read',
    network: 'read',
    updates: 'write',
    transcoding: 'write',
  };
  const transcodeAccess = {
    services: 'write',
    marketplace: 'read',
    settings: 'read',
    files: 'read',
    users: 'none',
    network: 'none',
    updates: 'write',
    transcoding: 'write',
  };
  const backupReadAccess = {
    services: 'read',
    marketplace: 'read',
    settings: 'none',
    files: 'write',
    users: 'none',
    network: 'none',
    updates: 'none',
    transcoding: 'none',
  };

  const peersSnapshot = {
    identity: {
      wg_pubkey: fakePubKey(11),
      tunnel_ip: '10.231.0.1',
      wg_port: 51821,
      listen_port: 8443,
      created_at: isoAgo(38 * 86_400_000),
    },
    peer_protocol: 1,
    capabilities: ['links', 'grants', 'proxy', 'storage', 'transcode'],
    rtt_warn_ms: 120,
    peers: [
      {
        id: 'peer-nova',
        name: 'nova.example.com',
        wg_pubkey: fakePubKey(21),
        tunnel_ip: '10.231.0.21',
        endpoint: '198.51.100.21',
        wg_port: 51821,
        state: 'active',
        peer_version: '4.0.0',
        peer_protocol: 1,
        capabilities: ['links', 'grants', 'proxy', 'storage', 'transcode'],
        compatibility: 'compatible',
        missing_capabilities: [],
        rtt_ms: 4.2,
        high_latency: false,
        last_ok_at: isoAgo(4_000),
        last_error: null,
        consecutive_failures: 0,
        pending_attempt_id: null,
        pending_expires_at: null,
        created_at: isoAgo(34 * 86_400_000),
        updated_at: isoAgo(120_000),
        grants: {
          outbound: {
            id: 'grant-out-nova',
            run_as_user_id: 1,
            access: fullWriteAccess,
            created_by: 'alex',
            created_at: isoAgo(34 * 86_400_000),
          },
          inbound: {
            id: 'grant-in-nova',
            run_as_user_id: 1,
            access: transcodeAccess,
            created_by: 'alex',
            created_at: isoAgo(34 * 86_400_000),
          },
        },
        exports: [
          {
            id: 'exp-atlas-movies',
            link_id: 'peer-nova',
            path: '/mnt/media/movies',
            writable: false,
            squash_uid: 1000,
            squash_gid: 1000,
            created_at: isoAgo(28 * 86_400_000),
          },
          {
            id: 'exp-atlas-tv',
            link_id: 'peer-nova',
            path: '/mnt/media/tv',
            writable: false,
            squash_uid: 1000,
            squash_gid: 1000,
            created_at: isoAgo(28 * 86_400_000),
          },
        ],
        mounts: [
          {
            id: 'mnt-nova-archive',
            link_id: 'peer-nova',
            remote_path: '/srv/media/archive',
            mount_path: '/mnt/af-peers/nova/archive',
            unit_name: 'mnt-af\\x2dpeers-nova-archive.mount',
            writable: false,
            purpose: 'media',
            state: 'mounted',
            last_error: null,
          },
        ],
      },
      {
        id: 'peer-vega',
        name: 'vega.example.com',
        wg_pubkey: fakePubKey(22),
        tunnel_ip: '10.231.0.22',
        endpoint: '203.0.113.42',
        wg_port: 51821,
        state: 'active',
        peer_version: '4.0.0',
        peer_protocol: 1,
        capabilities: ['links', 'grants', 'proxy', 'storage', 'transcode'],
        compatibility: 'compatible',
        missing_capabilities: [],
        rtt_ms: 11.8,
        high_latency: false,
        last_ok_at: isoAgo(3_000),
        last_error: null,
        consecutive_failures: 0,
        pending_attempt_id: null,
        pending_expires_at: null,
        created_at: isoAgo(21 * 86_400_000),
        updated_at: isoAgo(60_000),
        grants: {
          outbound: {
            id: 'grant-out-vega',
            run_as_user_id: 1,
            access: transcodeAccess,
            created_by: 'alex',
            created_at: isoAgo(21 * 86_400_000),
          },
          inbound: null,
        },
        exports: [
          {
            id: 'exp-atlas-media-vega',
            link_id: 'peer-vega',
            path: '/mnt/media',
            writable: false,
            squash_uid: 1000,
            squash_gid: 1000,
            created_at: isoAgo(20 * 86_400_000),
          },
        ],
        mounts: [],
      },
      {
        id: 'peer-orion',
        name: 'orion.example.com',
        wg_pubkey: fakePubKey(23),
        tunnel_ip: '10.231.0.23',
        endpoint: '192.0.2.55',
        wg_port: 51821,
        state: 'active',
        peer_version: '4.0.0',
        peer_protocol: 1,
        capabilities: ['links', 'grants', 'proxy', 'storage'],
        compatibility: 'compatible',
        missing_capabilities: [],
        rtt_ms: 18.4,
        high_latency: false,
        last_ok_at: isoAgo(6_000),
        last_error: null,
        consecutive_failures: 0,
        pending_attempt_id: null,
        pending_expires_at: null,
        created_at: isoAgo(12 * 86_400_000),
        updated_at: isoAgo(300_000),
        grants: {
          outbound: {
            id: 'grant-out-orion',
            run_as_user_id: 1,
            access: backupReadAccess,
            created_by: 'alex',
            created_at: isoAgo(12 * 86_400_000),
          },
          inbound: null,
        },
        exports: [],
        mounts: [
          {
            id: 'mnt-orion-backups',
            link_id: 'peer-orion',
            remote_path: '/srv/vault/snapshots',
            mount_path: '/mnt/af-peers/orion/snapshots',
            unit_name: 'mnt-af\\x2dpeers-orion-snapshots.mount',
            writable: true,
            purpose: 'backup',
            state: 'mounted',
            last_error: null,
          },
        ],
      },
    ],
    pairing_windows: [],
    pairing_attempts: [],
    detected_endpoints: [
      { address: '198.51.100.10', interface: 'enp5s0', family: 'ipv4', recommended: true },
      { address: 'fd42:42:42::10', interface: 'enp5s0', family: 'ipv6', recommended: false },
    ],
  };

  const transcodeConfig = {
    enabled: true,
    worker_service_enabled: true,
    worker_service_active: true,
    dispatcher_active: true,
    dispatcher_socket: '/run/aetherflow/transcode.sock',
    shim_installed: true,
    shim_path: '/usr/local/lib/aetherflow/bin/af-transcode',
    jellyfin_dropin_enabled: true,
    jellyfin_reported_ffmpeg: '/usr/local/lib/aetherflow/bin/af-transcode',
    api_restart_scheduled: false,
    local: {
      server_name: 'atlas.example.com',
      ffmpeg_version: '7.1.1-7',
      package_name: 'jellyfin-ffmpeg8',
      package_version: '8.1.3-1-trixie',
      encoders: ['h264_nvenc', 'hevc_nvenc', 'av1_nvenc', 'h264_vaapi', 'hevc_vaapi'],
      render_nodes: [{ path: '/dev/dri/renderD128', vendor_id: '0x10de', vendor: 'NVIDIA' }],
      primary_render_node: '/dev/dri/renderD128',
      transcoding_temp_path: '/mnt/nvme-cache/transcodes',
      tmp_dir: '/mnt/nvme-cache/tmp',
    },
    workers: [
      {
        link_id: 'peer-vega',
        peer_name: 'vega.example.com',
        link_state: 'active',
        compatibility: 'compatible',
        supports_transcode: true,
        has_transcode_write_grant: true,
        has_updates_write_grant: true,
        enabled: true,
        eligible: true,
        ineligible_reason: null,
        weight: 100,
        max_jobs: 6,
        active_jobs: 2,
        unhealthy_until: null,
        ffmpeg_version: '7.1.1-7',
        package_version: '8.1.3-1-trixie',
        ffmpeg_mismatch: false,
        ffmpeg_mismatch_message: null,
        align_target: null,
        encoders: ['h264_nvenc', 'hevc_nvenc', 'av1_nvenc'],
        render_node: '/dev/dri/renderD128',
        parity_ok: true,
        parity_error: null,
      },
      {
        link_id: 'peer-nova',
        peer_name: 'nova.example.com',
        link_state: 'active',
        compatibility: 'compatible',
        supports_transcode: true,
        has_transcode_write_grant: true,
        has_updates_write_grant: true,
        enabled: true,
        eligible: true,
        ineligible_reason: null,
        weight: 70,
        max_jobs: 4,
        active_jobs: 1,
        unhealthy_until: null,
        ffmpeg_version: '7.1.1-7',
        package_version: '8.1.3-1-trixie',
        ffmpeg_mismatch: false,
        ffmpeg_mismatch_message: null,
        align_target: null,
        encoders: ['h264_qsv', 'hevc_qsv', 'av1_qsv'],
        render_node: '/dev/dri/renderD128',
        parity_ok: true,
        parity_error: null,
      },
    ],
    recent_jobs: [
      {
        id: 'tc-9841',
        link_id: 'peer-vega',
        peer_name: 'vega.example.com',
        started_at: isoAgo(14 * 60_000),
        ended_at: null,
        exit_code: null,
        request_id: 'req-tc-9841',
        ran_locally: false,
      },
      {
        id: 'tc-9839',
        link_id: 'peer-nova',
        peer_name: 'nova.example.com',
        started_at: isoAgo(38 * 60_000),
        ended_at: isoAgo(19 * 60_000),
        exit_code: 0,
        request_id: 'req-tc-9839',
        ran_locally: false,
      },
      {
        id: 'tc-9834',
        link_id: 'peer-vega',
        peer_name: 'vega.example.com',
        started_at: isoAgo(112 * 60_000),
        ended_at: isoAgo(64 * 60_000),
        exit_code: 0,
        request_id: 'req-tc-9834',
        ran_locally: false,
      },
      {
        id: 'tc-9828',
        link_id: null,
        peer_name: null,
        started_at: isoAgo(185 * 60_000),
        ended_at: isoAgo(141 * 60_000),
        exit_code: 0,
        request_id: 'req-tc-9828',
        ran_locally: true,
      },
    ],
  };

  // Streaming dashboard + analytics + history
  const streamingTimeSeries = [];
  for (let i = 29; i >= 0; i -= 1) {
    const wave = Math.sin((30 - i) * 0.55);
    const weekend = i % 7 === 0 || i % 7 === 6 ? 7 : 0;
    const plays = Math.round(11 + 4 * wave + weekend);
    const directPlay = Math.round(plays * 0.68);
    const directStream = Math.round(plays * 0.18);
    const transcode = Math.max(0, plays - directPlay - directStream);
    streamingTimeSeries.push({
      date: dateDay(i),
      plays,
      watchTimeSecs: plays * 2650,
      dataUsedBytes: Math.round(plays * 6.2 * 1024 ** 3),
      peakBandwidthMbps: Number((42 + 24 * Math.abs(wave) + weekend * 3.1).toFixed(1)),
      directPlayCount: directPlay,
      directStreamCount: directStream,
      transcodeCount: transcode,
    });
  }

  const streamingDashboard = {
    servers: [
      {
        provider: 'jellyfin',
        name: 'Atlas Jellyfin',
        status: 'connected',
        serverId: 'jf-atlas-01',
        version: '12.4.0',
        url: 'https://jellyfin.atlas.example.com',
        enabled: true,
      },
      {
        provider: 'plex',
        name: 'Atlas Plex',
        status: 'connected',
        serverId: 'px-atlas-01',
        version: '1.41.5',
        url: 'https://plex.atlas.example.com',
        enabled: true,
      },
      {
        provider: 'emby',
        name: 'Nova Emby',
        status: 'connected',
        serverId: 'em-nova-01',
        version: '4.8.11',
        url: 'https://emby.nova.example.com',
        enabled: true,
      },
    ],
    activeSessions: [
      {
        provider: 'jellyfin',
        sessionId: 'sess-jf-101',
        serverId: 'jf-atlas-01',
        serverName: 'Atlas Jellyfin',
        itemName: 'Interstellar Horizon',
        itemType: 'Movie',
        hasArtwork: true,
        artworkItemId: 'art-horizon',
        userName: 'maya',
        seriesName: '',
        seasonNumber: '',
        episodeNumber: '',
        playMethod: 'DirectPlay',
        state: 'Playing',
        progressPct: 62.4,
        positionSecs: 5240,
        durationSecs: 8400,
        videoResolution: '4K HDR',
        videoCodec: 'HEVC',
        audioCodec: 'TrueHD Atmos',
        audioChannels: '7.1',
        container: 'mkv',
        bandwidthMbps: '48.2',
        bitrateBps: '48200000',
        clientName: 'Swiftfin',
        deviceName: 'Living Room Apple TV 4K',
        supportsMediaControl: true,
        canSendMessage: true,
      },
      {
        provider: 'jellyfin',
        sessionId: 'sess-jf-102',
        serverId: 'jf-atlas-01',
        serverName: 'Atlas Jellyfin',
        itemName: 'The Silent Meridian',
        itemType: 'Episode',
        hasArtwork: true,
        artworkItemId: 'art-meridian',
        userName: 'sam',
        seriesName: 'Orbital Drift',
        seasonNumber: '2',
        episodeNumber: '7',
        playMethod: 'Transcode',
        state: 'Playing',
        progressPct: 38.5,
        positionSecs: 1340,
        durationSecs: 3480,
        videoResolution: '1080p',
        videoCodec: 'HEVC → H.264 (NVENC · vega)',
        audioCodec: 'AAC',
        audioChannels: '5.1',
        container: 'hls',
        bandwidthMbps: '14.8',
        bitrateBps: '14800000',
        clientName: 'Jellyfin Web',
        deviceName: 'Firefox · Workstation',
        supportsMediaControl: true,
        canSendMessage: true,
      },
      {
        provider: 'plex',
        sessionId: 'sess-px-204',
        serverId: 'px-atlas-01',
        serverName: 'Atlas Plex',
        itemName: 'Nocturne in Glass',
        itemType: 'Audio',
        hasArtwork: true,
        artworkItemId: 'art-nocturne',
        userName: 'jordan',
        seriesName: 'Midnight Symphony',
        seasonNumber: '',
        episodeNumber: '',
        playMethod: 'DirectStream',
        state: 'Playing',
        progressPct: 74.0,
        positionSecs: 266,
        durationSecs: 360,
        videoResolution: 'Lossless',
        videoCodec: 'Audio',
        audioCodec: 'FLAC 24-bit',
        audioChannels: '2.0',
        container: 'flac',
        bandwidthMbps: '2.4',
        bitrateBps: '2400000',
        clientName: 'Plexamp',
        deviceName: 'Studio Desktop',
        supportsMediaControl: false,
        canSendMessage: false,
      },
    ],
    liveSummary: {
      activeStreams: 3,
      directPlayCount: 1,
      directStreamCount: 1,
      transcodeCount: 1,
      totalBandwidthMbps: 65.4,
      isDemoMode: false,
      updatedAt: isoAgo(2_000),
    },
    updatedAt: isoAgo(2_000),
    analytics: {
      windowDays: 30,
      totalPlays: 418,
      totalWatchTimeSecs: 1_124_800,
      totalDataUsedBytes: Math.round(2.48 * 1024 ** 4),
      uniqueUsers: 6,
      uniqueTitles: 142,
      avgCompletionPct: 86.4,
      peakBandwidthMbps: 92.4,
      streamTypes: {
        directPlayCount: 284,
        directPlayPct: 67.9,
        directStreamCount: 76,
        directStreamPct: 18.2,
        transcodeCount: 58,
        transcodePct: 13.9,
      },
      mediaTypeBreakdown: [
        { label: 'Episode', count: 248, pct: 59.3, watchTimeSecs: 612000, dataUsedBytes: Math.round(1.12 * 1024 ** 4) },
        { label: 'Movie', count: 118, pct: 28.2, watchTimeSecs: 468000, dataUsedBytes: Math.round(1.29 * 1024 ** 4) },
        { label: 'Audio', count: 52, pct: 12.5, watchTimeSecs: 44800, dataUsedBytes: Math.round(0.07 * 1024 ** 4) },
      ],
      resolutionBreakdown: [
        { label: '4K HDR', count: 164, pct: 39.2, watchTimeSecs: 512000, dataUsedBytes: Math.round(1.58 * 1024 ** 4) },
        { label: '1080p', count: 202, pct: 48.3, watchTimeSecs: 568000, dataUsedBytes: Math.round(0.83 * 1024 ** 4) },
        { label: 'Audio / FLAC', count: 52, pct: 12.5, watchTimeSecs: 44800, dataUsedBytes: Math.round(0.07 * 1024 ** 4) },
      ],
      codecBreakdown: [
        { label: 'HEVC / H.265', count: 228, pct: 54.5, watchTimeSecs: 642000, dataUsedBytes: Math.round(1.54 * 1024 ** 4) },
        { label: 'AV1', count: 84, pct: 20.1, watchTimeSecs: 248000, dataUsedBytes: Math.round(0.49 * 1024 ** 4) },
        { label: 'H.264 / AVC', count: 54, pct: 12.9, watchTimeSecs: 190000, dataUsedBytes: Math.round(0.38 * 1024 ** 4) },
        { label: 'FLAC', count: 52, pct: 12.5, watchTimeSecs: 44800, dataUsedBytes: Math.round(0.07 * 1024 ** 4) },
      ],
      timeSeriesGranularity: 'day',
      timeSeries: streamingTimeSeries,
      topUsers: [
        {
          userId: 'u-maya',
          userName: 'maya',
          provider: 'jellyfin',
          totalPlays: 142,
          totalWatchSecs: 412800,
          totalDataBytes: Math.round(0.94 * 1024 ** 4),
          uniqueItems: 54,
          directPlayCount: 112,
          transcodeCount: 14,
          avgCompletionPct: 91.2,
          lastDevice: 'Apple TV 4K',
          lastSeenAt: isoAgo(120_000),
        },
        {
          userId: 'u-alex',
          userName: 'alex',
          provider: 'jellyfin',
          totalPlays: 108,
          totalWatchSecs: 318600,
          totalDataBytes: Math.round(0.76 * 1024 ** 4),
          uniqueItems: 43,
          directPlayCount: 84,
          transcodeCount: 9,
          avgCompletionPct: 88.5,
          lastDevice: 'Shield TV Pro',
          lastSeenAt: isoAgo(3 * 3600_000),
        },
        {
          userId: 'u-sam',
          userName: 'sam',
          provider: 'jellyfin',
          totalPlays: 96,
          totalWatchSecs: 246200,
          totalDataBytes: Math.round(0.48 * 1024 ** 4),
          uniqueItems: 32,
          directPlayCount: 52,
          transcodeCount: 28,
          avgCompletionPct: 82.0,
          lastDevice: 'Firefox · Workstation',
          lastSeenAt: isoAgo(60_000),
        },
        {
          userId: 'u-jordan',
          userName: 'jordan',
          provider: 'plex',
          totalPlays: 72,
          totalWatchSecs: 147200,
          totalDataBytes: Math.round(0.30 * 1024 ** 4),
          uniqueItems: 29,
          directPlayCount: 36,
          transcodeCount: 7,
          avgCompletionPct: 84.1,
          lastDevice: 'Plexamp',
          lastSeenAt: isoAgo(90_000),
        },
      ],
      topTitles: [
        {
          itemId: 'art-horizon',
          itemName: 'Interstellar Horizon',
          itemType: 'Movie',
          seriesName: '',
          productionYear: 2025,
          provider: 'jellyfin',
          videoResolution: '4K HDR',
          videoCodec: 'HEVC',
          totalPlays: 14,
          uniqueViewers: 5,
          totalWatchSecs: 114200,
          totalDataBytes: Math.round(0.42 * 1024 ** 4),
          avgCompletionPct: 96.4,
          lastWatchedAt: isoAgo(120_000),
        },
        {
          itemId: 'art-meridian',
          itemName: 'The Silent Meridian',
          itemType: 'Episode',
          seriesName: 'Orbital Drift',
          productionYear: 2026,
          provider: 'jellyfin',
          videoResolution: '1080p',
          videoCodec: 'AV1',
          totalPlays: 11,
          uniqueViewers: 4,
          totalWatchSecs: 38280,
          totalDataBytes: Math.round(0.14 * 1024 ** 4),
          avgCompletionPct: 92.0,
          lastWatchedAt: isoAgo(60_000),
        },
        {
          itemId: 'art-solaris',
          itemName: 'Glass Archive',
          itemType: 'Movie',
          seriesName: '',
          productionYear: 2024,
          provider: 'plex',
          videoResolution: '4K HDR',
          videoCodec: 'HEVC',
          totalPlays: 9,
          uniqueViewers: 4,
          totalWatchSecs: 68400,
          totalDataBytes: Math.round(0.28 * 1024 ** 4),
          avgCompletionPct: 89.2,
          lastWatchedAt: isoAgo(18 * 3600_000),
        },
        {
          itemId: 'art-chronicle',
          itemName: 'Signal Lost',
          itemType: 'Episode',
          seriesName: 'Deep Relay',
          productionYear: 2025,
          provider: 'emby',
          videoResolution: '1080p',
          videoCodec: 'HEVC',
          totalPlays: 8,
          uniqueViewers: 3,
          totalWatchSecs: 29400,
          totalDataBytes: Math.round(0.09 * 1024 ** 4),
          avgCompletionPct: 91.5,
          lastWatchedAt: isoAgo(28 * 3600_000),
        },
      ],
      recentHistory: [],
      historicalEstimates: [],
    },
  };

  // McBrowser workspace entries
  const mcbrowserEntries = [
    { name: 'Media', path: 'Media', kind: 'directory', size: 0, modified: isoAgo(2 * 3600_000) },
    { name: 'Backups', path: 'Backups', kind: 'directory', size: 0, modified: isoAgo(6 * 3600_000) },
    { name: 'Configs', path: 'Configs', kind: 'directory', size: 0, modified: isoAgo(14 * 3600_000) },
    { name: 'Transcodes', path: 'Transcodes', kind: 'directory', size: 0, modified: isoAgo(12 * 60_000) },
    { name: 'Documents', path: 'Documents', kind: 'directory', size: 0, modified: isoAgo(3 * 86_400_000) },
    { name: 'Scripts', path: 'Scripts', kind: 'directory', size: 0, modified: isoAgo(5 * 86_400_000) },
    { name: 'atlas-cluster-policy.toml', path: 'atlas-cluster-policy.toml', kind: 'file', size: 4820, modified: isoAgo(45 * 60_000) },
    { name: 'nginx-ingress.conf', path: 'nginx-ingress.conf', kind: 'file', size: 3290, modified: isoAgo(4 * 3600_000) },
    { name: 'backup-manifest.json', path: 'backup-manifest.json', kind: 'file', size: 18432, modified: isoAgo(9 * 3600_000) },
    { name: 'storage-audit-2026-11.csv', path: 'storage-audit-2026-11.csv', kind: 'file', size: 94208, modified: isoAgo(18 * 3600_000) },
    { name: 'runbook-peer-failover.md', path: 'runbook-peer-failover.md', kind: 'file', size: 12640, modified: isoAgo(2 * 86_400_000) },
    { name: 'jellyfin-transcode-trace.log', path: 'jellyfin-transcode-trace.log', kind: 'file', size: 2_845_120, modified: isoAgo(8 * 60_000) },
    { name: 'atlas-snapshot-20261125.tar.zst', path: 'atlas-snapshot-20261125.tar.zst', kind: 'file', size: 1_942_310_912, modified: isoAgo(7 * 3600_000) },
    { name: 'network-topology-diagram.png', path: 'network-topology-diagram.png', kind: 'file', size: 648_192, modified: isoAgo(4 * 86_400_000) },
  ];

  // FlowAI pre-seeded sessionStorage conversations
  const flowAiThreads = [
    {
      id: 'thread-transcode-balance',
      title: 'Evening transcode offload & cache tuning',
      createdAt: isoAgo(18 * 60_000),
      messages: [
        {
          role: 'user',
          text: 'Analyze evening 4K transcode pressure across atlas, nova, and vega. Should we rebalance worker weights and prune scratch cache?',
        },
        {
          role: 'assistant',
          text: [
            '### Cluster Transcode & Scratch Cache Analysis',
            '',
            'Based on live host telemetry and the 30-day capacity baseline across **atlas.example.com**, **nova.example.com**, and **vega.example.com**:',
            '',
            '| Node | Accelerator | Active Jobs | Utilization | Weight | Headroom |',
            '| --- | --- | --- | --- | --- | --- |',
            '| `atlas.example.com` | RTX 4000 SFF Ada | 1 local | 42.5% GPU · 54 °C | Dispatcher | High |',
            '| `vega.example.com` | RTX 4000 Ada (NVENC) | 2 / 6 | 31.0% GPU · 49 °C | 100 | Very High |',
            '| `nova.example.com` | Intel QuickSync QSV | 1 / 4 | 28.4% GPU · 44 °C | 70 | Moderate |',
            '',
            '**Findings:**',
            '- All three nodes run aligned `jellyfin-ffmpeg8 8.1.3-1-trixie` builds with passing path-parity verification.',
            '- `/mnt/nvme-cache` is healthy at **20.6%** (412 GB / 2.0 TB), with ~68 GB of stale HLS segments older than 48 hours.',
            '- Routing burst HEVC→H.264 sessions preferentially to `vega.example.com` keeps local NVENC headroom free for interactive 4K streams.',
            '',
            'I prepared a **human-gated remediation proposal** to clean expired transcode cache segments and pin burst policy limits. Review and approve it in the **Approval Inbox** before execution.',
          ].join('\n'),
          payload: {
            action: 'prune_transcode_cache',
            target: 'atlas.example.com',
            path: '/mnt/nvme-cache/transcodes',
            older_than_hours: 48,
            estimated_reclaim_gb: 68.4,
            risk_level: 'low',
          },
          pending_actions: [
            {
              id: 412,
              action: 'prune_transcode_cache',
              status: 'pending',
              risk_level: 'low',
            },
          ],
        },
      ],
    },
    {
      id: 'thread-storage-forecast',
      title: 'ZFS media pool 90-day capacity projection',
      createdAt: isoAgo(5 * 3600_000),
      messages: [
        {
          role: 'user',
          text: 'Project storage growth on /mnt/media over the next quarter.',
        },
        {
          role: 'assistant',
          text: '`/mnt/media` is currently at **59.2%** (28.4 / 48.0 TB). At the observed 30-day growth rate of ~240 GB/week, it will reach 65% in roughly 90 days.',
        },
      ],
    },
    {
      id: 'thread-wg-audit',
      title: 'WireGuard peer handshake & DNS review',
      createdAt: isoAgo(26 * 3600_000),
      messages: [
        {
          role: 'user',
          text: 'Verify all WireGuard and Peer Cluster tunnels have fresh handshakes.',
        },
        {
          role: 'assistant',
          text: 'All 4 `wg0` remote access peers and 3 peer-cluster WireGuard mesh links (`nova`, `vega`, `orion`) completed handshakes within the last 3 minutes with zero packet loss.',
        },
      ],
    },
  ];

  // Network tab status
  const networkStatus = {
    platform: 'Linux 6.12 (Debian 13)',
    runner_available: true,
    checked_at: isoAgo(5_000),
    wireguard: {
      interface: 'wg0',
      state: 'running',
      service_state: 'active',
      listen_port: '51820',
      addresses: ['10.66.66.1/24', 'fd42:42:42::1/64'],
      public_key: fakePubKey(91),
      next_ip: '10.66.66.6/32',
      peers: [
        {
          name: 'alex-workstation',
          public_key: fakePubKey(101),
          allowed_ips: '10.66.66.2/32, fd42:42:42::2/128',
          endpoint: '198.51.100.14:53142',
          latest_handshake: Math.floor((nowMs - 14_000) / 1000),
          transfer_rx: String(48_318_382_080),
          transfer_tx: String(192_414_534_860),
          persistent_keepalive: 25,
        },
        {
          name: 'maya-mobile',
          public_key: fakePubKey(102),
          allowed_ips: '10.66.66.3/32, fd42:42:42::3/128',
          endpoint: '203.0.113.88:41904',
          latest_handshake: Math.floor((nowMs - 42_000) / 1000),
          transfer_rx: String(12_884_901_888),
          transfer_tx: String(64_424_509_440),
          persistent_keepalive: 25,
        },
        {
          name: 'studio-gateway',
          public_key: fakePubKey(103),
          allowed_ips: '10.66.66.4/32, 192.0.2.0/24',
          endpoint: '192.0.2.19:51820',
          latest_handshake: Math.floor((nowMs - 78_000) / 1000),
          transfer_rx: String(214_748_364_800),
          transfer_tx: String(310_421_123_456),
          persistent_keepalive: 25,
        },
        {
          name: 'offsite-backup-nas',
          public_key: fakePubKey(104),
          allowed_ips: '10.66.66.5/32',
          endpoint: '203.0.113.19:51820',
          latest_handshake: Math.floor((nowMs - 165_000) / 1000),
          transfer_rx: String(1_412_884_901_888),
          transfer_tx: String(82_142_614_200),
          persistent_keepalive: 25,
        },
      ],
    },
    tailscale: {
      state: 'running',
      backend_state: 'Running',
      service_state: 'active',
      tailnet_name: 'atlas-mesh.ts.net',
      magic_dns: true,
      accept_routes: true,
      advertise_exit_node: true,
      exit_node: '',
      exit_node_allow_lan_access: true,
      advertised_routes: ['10.66.66.0/24', '198.51.100.0/24'],
      self: {
        tailscale_ip: '100.64.0.10',
        dns_name: 'atlas.atlas-mesh.ts.net',
      },
      peers: [
        {
          name: 'nova',
          dns_name: 'nova.atlas-mesh.ts.net',
          tailscale_ip: '100.64.0.21',
          online: true,
          os: 'linux',
          relay: 'direct',
        },
        {
          name: 'vega',
          dns_name: 'vega.atlas-mesh.ts.net',
          tailscale_ip: '100.64.0.22',
          online: true,
          os: 'linux',
          relay: 'direct',
        },
        {
          name: 'alex-laptop',
          dns_name: 'alex-laptop.atlas-mesh.ts.net',
          tailscale_ip: '100.64.0.44',
          online: true,
          os: 'linux',
          relay: 'direct',
        },
      ],
    },
  };

  const ingressConfigs = {
    configs: [
      { appName: 'jellyfin', publicDomain: 'jellyfin.atlas.example.com', externalAccessEnabled: true, tlsEnabled: true, listenPort: 8096 },
      { appName: 'grafana', publicDomain: 'grafana.atlas.example.com', externalAccessEnabled: true, tlsEnabled: true, listenPort: 3000 },
      { appName: 'vaultwarden', publicDomain: 'vault.atlas.example.com', externalAccessEnabled: true, tlsEnabled: true, listenPort: 8222 },
      { appName: 'nextcloud', publicDomain: 'cloud.atlas.example.com', externalAccessEnabled: true, tlsEnabled: true, listenPort: 8081 },
      { appName: 'librespeed', publicDomain: 'speed.atlas.example.com', externalAccessEnabled: true, tlsEnabled: true, listenPort: 8988 },
    ],
  };

  // Audit log entries
  const auditLogs = [
    { id: 1284, username: 'alex', action: 'action_approved', target_type: 'transcode', target_id: 'peer-vega', detail: 'Approved transcode worker weight update (60 → 100) for vega.example.com', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(12 * 60_000) },
    { id: 1283, username: 'flowai', action: 'ai_action_proposed', target_type: 'storage', target_id: 'nvme-cache', detail: 'Proposed scheduled prune of expired HLS transcode segments (>48h)', ip_address: '127.0.0.1', severity: 'info', created_at: isoAgo(18 * 60_000) },
    { id: 1282, username: 'alex', action: 'peer_grant_updated', target_type: 'cluster', target_id: 'peer-nova', detail: 'Updated bidirectional grant scope (services, files, transcoding) for nova.example.com', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(48 * 60_000) },
    { id: 1281, username: 'alex', action: 'ingress_tls_synced', target_type: 'network', target_id: 'atlas.example.com', detail: 'Synchronized ACME SAN certificate across 5 managed subdomain routes', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(2 * 3600_000) },
    { id: 1280, username: 'alex', action: 'service_restarted', target_type: 'service', target_id: 'af-transcode-worker', detail: 'Graceful systemd reload completed with verified dispatcher socket', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(4 * 3600_000) },
    { id: 1279, username: 'alex', action: 'package_updated', target_type: 'marketplace', target_id: 'jellyfin', detail: 'Upgraded jellyfin to 12.4.0 with verified SHA-256 checksum', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(9 * 3600_000) },
    { id: 1278, username: 'maya', action: 'user_login', target_type: 'auth', target_id: 'user:2', detail: 'Authenticated via OIDC PKCE + TOTP verification', ip_address: '203.0.113.88', severity: 'info', created_at: isoAgo(11 * 3600_000) },
    { id: 1277, username: 'alex', action: 'action_approved', target_type: 'service', target_id: 'prometheus', detail: 'Approved retention policy expansion (30d → 90d)', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(16 * 3600_000) },
    { id: 1276, username: 'flowai', action: 'ai_action_proposed', target_type: 'service', target_id: 'prometheus', detail: 'Suggested increasing TSDB retention window for 30-day capacity models', ip_address: '127.0.0.1', severity: 'info', created_at: isoAgo(17 * 3600_000) },
    { id: 1275, username: 'alex', action: 'peer_link_confirmed', target_type: 'cluster', target_id: 'peer-orion', detail: 'Verified comparison code and established WireGuard mesh link to orion.example.com', ip_address: '198.51.100.14', severity: 'info', created_at: isoAgo(26 * 3600_000) },
    { id: 1274, username: 'system', action: 'system_backup_completed', target_type: 'backup', target_id: 'atlas-snapshot-20261125', detail: 'Encrypted SQLite + config archive verified (1.81 GiB)', ip_address: '127.0.0.1', severity: 'info', created_at: isoAgo(30 * 3600_000) },
    { id: 1273, username: 'alex', action: 'user_totp_verified', target_type: 'auth', target_id: 'user:1', detail: 'Verified TOTP hardware authenticator enrollment and stored recovery digest', ip_address: '198.51.100.14', severity: 'warning', created_at: isoAgo(44 * 3600_000) },
  ];

  return {
    nowMs,
    isoAgo,
    makeTelemetryHistory,
    makeDailyTransfer,
    capacityHistory30d,
    marketplaceApps,
    servicesMap,
    peersSnapshot,
    transcodeConfig,
    streamingDashboard,
    mcbrowserEntries,
    flowAiThreads,
    networkStatus,
    ingressConfigs,
    auditLogs,
    user: {
      id: 1,
      username: 'alex',
      email: 'alex@example.com',
      avatar_url: buildAvatarDataUri(),
      role: 'admin',
      is_oauth: false,
      totp_enabled: true,
      created_at: isoAgo(180 * 86_400_000),
    },
    settings: {
      aiModel: 'gemini-4-carbon',
      localProvider: 'ollama',
      localModel: 'llama3.2:latest',
      systemPrompt: 'You are FlowAI, the AetherFlow v4.0.0 infrastructure diagnostics copilot.',
      language: 'en',
      timezone: 'UTC',
      updateChannel: 'stable',
      defaultDashboard: 'overview',
      setupCompleted: true,
      baseDomain: 'atlas.example.com',
      geminiApiKey: '****',
      anthropicApiKey: '****',
      openaiApiKey: '****',
      ollamaEndpoint: 'http://127.0.0.1:11434',
      lmStudioEndpoint: '',
      anthropicEndpoint: '',
    },
    hardware: {
      cpu: {
        model: 'AMD EPYC 7543P 32-Core Processor',
        cores: 32,
        threads: 64,
        frequency_mhz: 3200,
      },
      memory: {
        type: 'DDR4 ECC 3200 MT/s',
        total_bytes: 128 * 1024 ** 3,
        total_gb: 128,
        banks: 4,
      },
      gpus: [
        { name: 'NVIDIA RTX 4000 SFF Ada Generation', product: 'RTX 4000 SFF Ada (20 GB)', vendor: 'NVIDIA' },
        { name: 'Intel Arc Pro A40', product: 'Arc Pro A40 (6 GB · AV1 QSV)', vendor: 'Intel' },
      ],
      network: [
        { name: 'enp5s0', mac: '02:42:ac:11:00:10', vendor: 'Mellanox Technologies', product: 'ConnectX-5 25GbE SFP28' },
        { name: 'eth0', mac: '02:42:ac:11:00:11', vendor: 'Intel Corporation', product: 'X550T 10GbE Management' },
        { name: 'wg0', mac: '00:00:00:00:00:00', vendor: 'WireGuard', product: 'Kernel VPN Tunnel (51820/UDP)' },
      ],
      storage: [
        { model: 'Samsung PM9A3 2TB NVMe (RAID-1)', size_bytes: 2 * 1024 ** 4 },
        { model: 'Seagate Exos X20 48TB ZFS RaidZ2', size_bytes: 48 * 1024 ** 4 },
        { model: 'WD Ultrastar DC HC550 12TB Vault', size_bytes: 12 * 1024 ** 4 },
      ],
    },
    metrics: {
      cpu_usage: 34.2,
      cpu_freq_mhz: 3185.0,
      load_average: [1.84, 1.62, 1.48],
      per_core_cpu: [
        38.4, 31.2, 44.1, 29.5, 35.8, 27.4, 41.0, 33.6,
        24.9, 36.2, 30.8, 42.7, 28.1, 31.9, 39.4, 34.0,
      ],
      memory: {
        used_bytes: Math.round(48.6 * 1024 ** 3),
        total_bytes: 128 * 1024 ** 3,
        available_bytes: Math.round(79.4 * 1024 ** 3),
        used: 48.6,
        total: 128.0,
      },
      swap: {
        used_bytes: Math.round(0.42 * 1024 ** 3),
        total_bytes: 16 * 1024 ** 3,
        used: 0.42,
        total: 16.0,
      },
      network: {
        rx_bps: Math.round(84.6 * 1_048_576),
        tx_bps: Math.round(31.2 * 1_048_576),
        down: '84.6MB/s',
        up: '31.2MB/s',
        interfaces: [
          { name: 'enp5s0', rx_bps: Math.round(71.4 * 1_048_576), tx_bps: Math.round(24.8 * 1_048_576) },
          { name: 'wg0', rx_bps: Math.round(13.2 * 1_048_576), tx_bps: Math.round(6.4 * 1_048_576) },
        ],
      },
      total_net_bytes: {
        rx: Math.round(14.8 * 1024 ** 4),
        tx: Math.round(9.2 * 1024 ** 4),
      },
      disk_io: {
        read_bytes_sec: Math.round(142.8 * 1_048_576),
        write_bytes_sec: Math.round(58.4 * 1_048_576),
      },
      disk_partitions: [
        { mount_point: '/', device: '/dev/md0 (nvme0n1)', fs_type: 'ext4', used_gb: 118.4, total_gb: 500.0, used_pct: 23.7 },
        { mount_point: '/mnt/media', device: 'tank/media', fs_type: 'zfs', used_gb: 28400.0, total_gb: 48000.0, used_pct: 59.2 },
        { mount_point: '/mnt/nvme-cache', device: '/dev/nvme1n1p1', fs_type: 'xfs', used_gb: 412.0, total_gb: 2000.0, used_pct: 20.6 },
        { mount_point: '/mnt/backups', device: 'vault/snapshots', fs_type: 'zfs', used_gb: 5100.0, total_gb: 12000.0, used_pct: 42.5 },
      ],
      gpus: [
        {
          name: 'NVIDIA RTX 4000 SFF Ada Generation',
          usage_pct: 42.5,
          temperature_c: 54,
          vram_used_mb: 7420,
          vram_total_mb: 20480,
        },
        {
          name: 'Intel Arc Pro A40 (AV1 / QuickSync)',
          usage_pct: 19.2,
          temperature_c: 42,
          vram_used_mb: 1420,
          vram_total_mb: 6144,
        },
      ],
      uptime: '42d 11h 18m',
      processes: [
        { pid: 4102, name: 'af-transcode (NVENC)', cpu: 11.8, mem: 3.1, user: 'jellyfin' },
        { pid: 2218, name: 'jellyfin', cpu: 8.6, mem: 4.4, user: 'jellyfin' },
        { pid: 3104, name: 'qbittorrent-nox', cpu: 4.5, mem: 3.3, user: 'aetherflow' },
        { pid: 2490, name: 'plexmediaserver', cpu: 3.1, mem: 2.9, user: 'plex' },
        { pid: 1042, name: 'aetherflow-api', cpu: 1.4, mem: 0.4, user: 'aetherflow' },
        { pid: 1844, name: 'sonarr', cpu: 1.2, mem: 0.8, user: 'sonarr' },
        { pid: 1620, name: 'prometheus', cpu: 1.1, mem: 1.0, user: 'prometheus' },
        { pid: 1902, name: 'radarr', cpu: 0.9, mem: 0.7, user: 'radarr' },
      ],
    },
    topology: {
      nodes: [
        { id: 'aetherflow-api', status: 'running', group: 'core', details: 'Rust control plane · v4.0.0' },
        { id: 'aetherflow-runner', status: 'running', group: 'core', details: 'Privileged socket daemon' },
        { id: 'af-transcode-worker', status: 'running', group: 'cluster', details: 'Distributed FFmpeg dispatcher' },
        { id: 'jellyfin', status: 'running', group: 'media', details: '12.4.0 · 2 active streams' },
        { id: 'plex', status: 'running', group: 'media', details: '1.41.5 · 1 active stream' },
        { id: 'sonarr', status: 'running', group: 'arr', details: '4.0.12 · TV automation' },
        { id: 'radarr', status: 'running', group: 'arr', details: '5.19.3 · Movie automation' },
        { id: 'prowlarr', status: 'running', group: 'arr', details: '1.31.2 · Indexer proxy' },
        { id: 'qbittorrent', status: 'running', group: 'downloads', details: '5.0.4 · WireGuard routed' },
        { id: 'grafana', status: 'running', group: 'observability', details: '11.5.1 · Dashboards' },
        { id: 'prometheus', status: 'running', group: 'observability', details: '3.2.1 · Metrics store' },
      ],
      links: [
        { source: 'aetherflow-api', target: 'aetherflow-runner' },
        { source: 'aetherflow-api', target: 'af-transcode-worker' },
        { source: 'aetherflow-api', target: 'jellyfin' },
        { source: 'aetherflow-api', target: 'plex' },
        { source: 'jellyfin', target: 'af-transcode-worker' },
        { source: 'sonarr', target: 'prowlarr' },
        { source: 'radarr', target: 'prowlarr' },
        { source: 'sonarr', target: 'qbittorrent' },
        { source: 'radarr', target: 'qbittorrent' },
        { source: 'grafana', target: 'prometheus' },
        { source: 'prometheus', target: 'aetherflow-api' },
      ],
    },
    predictions: {
      cpu_trend: 'stable',
      memory_trend: 'stable',
      disk_io_trend: 'increasing',
      network_trend: 'stable',
      predicted_bottleneck: 'Media ZFS pool projected at 65% in ~90 days',
      confidence_score: '0.94',
      trend_summary:
        'Compute, memory, and 25GbE network headroom remain well within nominal envelopes across the 30-day rolling baseline. Offloaded NVENC transcoding on vega.example.com absorbs evening peak load smoothly.',
      warnings: [],
      recommendations: [
        'Keep vega.example.com transcode weight at 100 for evening 4K HEVC peak smoothing.',
      ],
    },
    pendingActions: [
      {
        id: 414,
        action: 'restart_service:jellyfin:systemd',
        status: 'pending',
        source: 'operator',
        reason: 'Apply updated VAAPI/NVENC render group permissions after driver refresh.',
        risk_level: 'high',
        classification: 'HIGH',
        target: 'jellyfin.service',
        parameters: { service: 'jellyfin', manager: 'systemd', grace_seconds: 30 },
        payload: { service: 'jellyfin', manager: 'systemd', grace_seconds: 30 },
        created_at: isoAgo(9 * 60_000),
      },
      {
        id: 413,
        action: 'sync_ingress_tls',
        status: 'pending',
        source: 'scheduler',
        reason: 'Refresh SAN certificate bundle across 5 published atlas.example.com subdomains.',
        risk_level: 'medium',
        classification: 'MEDIUM',
        target: 'nginx-ingress',
        parameters: { domains: 5, provider: 'certbot', renew_window_days: 30 },
        payload: { domains: 5, provider: 'certbot', renew_window_days: 30 },
        created_at: isoAgo(14 * 60_000),
      },
      {
        id: 412,
        action: 'prune_transcode_cache',
        status: 'pending',
        source: 'flowai',
        reason: 'Reclaim 68.4 GB of expired HLS segments older than 48 hours on /mnt/nvme-cache.',
        risk_level: 'low',
        classification: 'LOW',
        target: '/mnt/nvme-cache/transcodes',
        parameters: { path: '/mnt/nvme-cache/transcodes', older_than_hours: 48, estimated_reclaim_gb: 68.4 },
        payload: { path: '/mnt/nvme-cache/transcodes', older_than_hours: 48, estimated_reclaim_gb: 68.4 },
        created_at: isoAgo(18 * 60_000),
      },
      {
        id: 411,
        action: 'update_package',
        status: 'pending',
        source: 'scheduler',
        reason: 'Apply verified Sonarr 4.0.12 → 4.0.14 update after checksum and unit check.',
        risk_level: 'low',
        classification: 'LOW',
        target: 'sonarr',
        parameters: { package: 'sonarr', from_version: '4.0.12', to_version: '4.0.14' },
        payload: { package: 'sonarr', from_version: '4.0.12', to_version: '4.0.14' },
        created_at: isoAgo(2 * 3600_000),
      },
    ],
    resolvedActions: [
      {
        id: 409,
        action: 'align_transcode_worker',
        status: 'executed',
        source: 'flowai',
        reason: 'Aligned jellyfin-ffmpeg8 8.1.3-1-trixie on nova.example.com and verified path parity.',
        risk_level: 'medium',
        classification: 'MEDIUM',
        target: 'nova.example.com',
        job_unit: 'aetherflow-action-409.service',
        resolved_by: 'alex',
        resolved_at: isoAgo(8 * 3600_000),
        execution_log: 'jellyfin-ffmpeg8 8.1.3-1-trixie installed; parity check passed in 14 ms.',
        created_at: isoAgo(9 * 3600_000),
      },
      {
        id: 406,
        action: 'purge_retired_archive',
        status: 'rejected',
        source: 'scheduler',
        reason: 'Remove archived pre-v4 backup snapshot outside 30-day retention policy.',
        risk_level: 'medium',
        classification: 'MEDIUM',
        target: '/mnt/backups/pre-v4',
        resolved_by: 'maya',
        resolved_at: isoAgo(26 * 3600_000),
        created_at: isoAgo(27 * 3600_000),
      },
    ],
    fileshareFiles: [
      { name: 'Movies', size: 0, modTime: isoAgo(2 * 3600_000), extension: '', isDir: true },
      { name: 'Series', size: 0, modTime: isoAgo(5 * 3600_000), extension: '', isDir: true },
      { name: 'Music-FLAC', size: 0, modTime: isoAgo(19 * 3600_000), extension: '', isDir: true },
      { name: 'Backups', size: 0, modTime: isoAgo(7 * 3600_000), extension: '', isDir: true },
      { name: 'ISOs', size: 0, modTime: isoAgo(4 * 86_400_000), extension: '', isDir: true },
      { name: 'Interstellar.Horizon.2025.2160p.HEVC.mkv', size: 32_480_192_512, modTime: isoAgo(90 * 60_000), extension: 'mkv', isDir: false },
      { name: 'Orbital.Drift.S02E07.1080p.AV1.mkv', size: 4_820_418_560, modTime: isoAgo(3 * 3600_000), extension: 'mkv', isDir: false },
      { name: 'atlas-backup-2026-11-25.tar.zst', size: 1_942_310_912, modTime: isoAgo(7 * 3600_000), extension: 'zst', isDir: false },
      { name: 'cluster-inventory-2026-11.csv', size: 148_920, modTime: isoAgo(16 * 3600_000), extension: 'csv', isDir: false },
      { name: 'wireguard-mesh-notes.md', size: 14_320, modTime: isoAgo(2 * 86_400_000), extension: 'md', isDir: false },
    ],
    fileshareShares: [
      {
        id: 'shr-atlas-01',
        path: 'Documents/runbook-peer-failover.md',
        name: 'runbook-peer-failover.md',
        is_directory: false,
        password_required: true,
        expires_at: new Date(nowMs + 7 * 86_400_000).toISOString(),
        allow_download: true,
        created_at: isoAgo(2 * 86_400_000),
        url: 'https://atlas.example.com/s/af-runbook-74c2',
      },
      {
        id: 'shr-atlas-02',
        path: 'Media/Stills',
        name: 'Stills',
        is_directory: true,
        password_required: false,
        expires_at: new Date(nowMs + 14 * 86_400_000).toISOString(),
        allow_download: true,
        created_at: isoAgo(5 * 86_400_000),
        url: 'https://atlas.example.com/s/af-stills-91e8',
      },
      {
        id: 'shr-atlas-03',
        path: 'Backups/atlas-snapshot-20261125.tar.zst',
        name: 'atlas-snapshot-20261125.tar.zst',
        is_directory: false,
        password_required: true,
        expires_at: new Date(nowMs + 3 * 86_400_000).toISOString(),
        allow_download: true,
        created_at: isoAgo(6 * 3600_000),
        url: 'https://atlas.example.com/s/af-snap-38b5',
      },
    ],
    blueprints: [
      { app_name: 'jellyseerr', config_applied: true, blueprint: { app_name: 'jellyseerr' } },
      { app_name: 'prowlarr', config_applied: true, blueprint: { app_name: 'prowlarr' } },
      { app_name: 'qbittorrent', config_applied: true, blueprint: { app_name: 'qbittorrent' } },
      { app_name: 'sabnzbd', config_applied: true, blueprint: { app_name: 'sabnzbd' } },
      { app_name: 'sonarr', config_applied: true, blueprint: { app_name: 'sonarr' } },
      { app_name: 'radarr', config_applied: true, blueprint: { app_name: 'radarr' } },
      { app_name: 'bazarr', config_applied: true, blueprint: { app_name: 'bazarr' } },
      { app_name: 'jellyfin', config_applied: true, blueprint: { app_name: 'jellyfin' } },
      { app_name: 'plex', config_applied: true, blueprint: { app_name: 'plex' } },
    ],
    mediaflowQueue: [
      {
        id: 805,
        filePath: '/srv/media/series/Orbital Drift/Season 02/Orbital.Drift.S02E08.2160p.REMUX.mkv',
        status: 'PROCESSING',
        originalCodec: 'h264',
        originalSize: Math.round(18.4 * 1024 ** 3),
        newCodec: 'av1_nvenc',
        newSize: Math.round(6.2 * 1024 ** 3),
        sourceFingerprint: '9f4a21c8e704b3d1a55e88c9012f3a18',
        identityBound: true,
        createdAt: isoAgo(22 * 60_000),
      },
      {
        id: 804,
        filePath: '/srv/media/movies/Interstellar Horizon (2025)/Interstellar.Horizon.2025.2160p.BluRay.mkv',
        status: 'PENDING_APPROVAL',
        originalCodec: 'hevc',
        originalSize: Math.round(54.2 * 1024 ** 3),
        newCodec: 'av1_nvenc',
        newSize: Math.round(22.8 * 1024 ** 3),
        sourceFingerprint: '4c81e0b2a9d37610f218c44e9b2d7a05',
        identityBound: true,
        createdAt: isoAgo(58 * 60_000),
      },
      {
        id: 803,
        filePath: '/srv/media/movies/Glass Archive (2024)/Glass.Archive.2024.1080p.AVC.mkv',
        status: 'PENDING_APPROVAL',
        originalCodec: 'h264',
        originalSize: Math.round(14.6 * 1024 ** 3),
        newCodec: 'hevc_nvenc',
        newSize: Math.round(5.9 * 1024 ** 3),
        sourceFingerprint: '7e29a4f610c84b3e5d71f92a38c0e411',
        identityBound: true,
        createdAt: isoAgo(2 * 3600_000),
      },
      {
        id: 802,
        filePath: '/srv/media/series/Deep Relay/Season 01/Deep.Relay.S01E10.1080p.REMUX.mkv',
        status: 'COMPLETED',
        originalCodec: 'h264',
        originalSize: Math.round(42.0 * 1024 ** 3),
        newCodec: 'av1_nvenc',
        newSize: Math.round(15.1 * 1024 ** 3),
        sourceFingerprint: '1b62d9e483a7c502e41f88a09c3b6d22',
        identityBound: true,
        createdAt: isoAgo(7 * 3600_000),
      },
      {
        id: 801,
        filePath: '/srv/media/movies/Midnight Nocturne (2024)/Midnight.Nocturne.2024.2160p.mkv',
        status: 'COMPLETED',
        originalCodec: 'hevc',
        originalSize: Math.round(38.8 * 1024 ** 3),
        newCodec: 'av1_nvenc',
        newSize: Math.round(16.4 * 1024 ** 3),
        sourceFingerprint: '5a07c3f921d8b460a1e93c74f28d5b90',
        identityBound: true,
        createdAt: isoAgo(14 * 3600_000),
      },
    ],
    users: [
      { id: 1, username: 'alex', email: 'alex@example.com', role: 'admin', totp_enabled: true, is_oauth: false, google_id: '', created_at: isoAgo(120 * 86_400_000) },
      { id: 2, username: 'maya', email: 'maya@example.com', role: 'admin', totp_enabled: true, is_oauth: true, google_id: 'oidc-maya-02', created_at: isoAgo(98 * 86_400_000) },
      { id: 3, username: 'sam', email: 'sam@example.com', role: 'user', totp_enabled: true, is_oauth: false, google_id: '', created_at: isoAgo(74 * 86_400_000) },
      { id: 4, username: 'jordan', email: 'jordan@example.com', role: 'user', totp_enabled: false, is_oauth: true, google_id: 'oidc-jordan-04', created_at: isoAgo(52 * 86_400_000) },
      { id: 5, username: 'elena', email: 'elena@example.com', role: 'user', totp_enabled: true, is_oauth: false, google_id: '', created_at: isoAgo(31 * 86_400_000) },
      { id: 6, username: 'devon', email: 'devon@example.com', role: 'user', totp_enabled: false, is_oauth: false, google_id: '', created_at: isoAgo(14 * 86_400_000) },
    ],
    notifications: [
      { id: 5, title: 'Peer cluster healthy', message: 'All 3 peer links (nova, vega, orion) synchronized with sub-20ms RTT.', level: 'success', read: false, created_at: isoAgo(12 * 60_000) },
      { id: 4, title: 'FlowAI proposal queued', message: 'Reclaim 68.4 GB of stale HLS cache on /mnt/nvme-cache awaiting approval (#412).', level: 'info', read: false, created_at: isoAgo(18 * 60_000) },
      { id: 3, title: 'Package update available', message: 'Sonarr 4.0.14 and Audiobookshelf 2.20.0 verified in catalog.', level: 'warning', read: true, created_at: isoAgo(2 * 3600_000) },
      { id: 2, title: 'Nightly database snapshot verified', message: 'atlas-db-20261125-0300.sqlite.zst passed SHA-256 checksum audit.', level: 'success', read: true, created_at: isoAgo(6 * 3600_000) },
      { id: 1, title: 'Distributed transcode completed', message: 'vega.example.com finished NVENC job tc-9834 with 0 errors.', level: 'info', read: true, created_at: isoAgo(9 * 3600_000) },
    ],
    notificationChannels: [
      { id: 1, name: 'Ops Discord (#atlas-alerts)', type: 'discord', enabled: true, config: { webhook_url: 'https://hooks.example.com/discord/atlas-ops' } },
      { id: 2, name: 'On-Call Telegram Bot', type: 'telegram', enabled: true, config: { chat_id: '-100192837465' } },
      { id: 3, name: 'Gotify Homelab Push', type: 'gotify', enabled: true, config: { webhook_url: 'https://push.atlas.example.com/message' } },
    ],
    notificationRules: [
      { id: 1, name: 'Core service health guard', condition_type: 'service_down', condition_value: 'jellyfin,aetherflow-runner', level: 'critical', enabled: true },
      { id: 2, name: 'Media pool capacity alert', condition_type: 'disk_usage', condition_value: '85%', level: 'warning', enabled: true },
      { id: 3, name: 'Sustained CPU saturation', condition_type: 'cpu_usage', condition_value: '90% (5m)', level: 'warning', enabled: true },
      { id: 4, name: 'ECC memory pressure', condition_type: 'memory_usage', condition_value: '88%', level: 'critical', enabled: true },
    ],
    quotas: [
      { user_id: 1, username: 'alex', quota_bytes: 4 * 1024 ** 4, used_bytes: Math.round(1.84 * 1024 ** 4), soft_limit_bytes: Math.round(3.6 * 1024 ** 4), configured: true, status: 'active', source: 'runner', grace_status: null, updated_at: isoAgo(5 * 60_000) },
      { user_id: 2, username: 'maya', quota_bytes: 4 * 1024 ** 4, used_bytes: Math.round(2.42 * 1024 ** 4), soft_limit_bytes: Math.round(3.6 * 1024 ** 4), configured: true, status: 'active', source: 'runner', grace_status: null, updated_at: isoAgo(5 * 60_000) },
      { user_id: 3, username: 'sam', quota_bytes: 2 * 1024 ** 4, used_bytes: Math.round(1.68 * 1024 ** 4), soft_limit_bytes: Math.round(1.6 * 1024 ** 4), configured: true, status: 'warning', source: 'runner', grace_status: '6d remaining', updated_at: isoAgo(5 * 60_000) },
      { user_id: 4, username: 'jordan', quota_bytes: 2 * 1024 ** 4, used_bytes: Math.round(0.88 * 1024 ** 4), soft_limit_bytes: Math.round(1.8 * 1024 ** 4), configured: true, status: 'active', source: 'runner', grace_status: null, updated_at: isoAgo(5 * 60_000) },
      { user_id: 5, username: 'elena', quota_bytes: 2 * 1024 ** 4, used_bytes: Math.round(0.62 * 1024 ** 4), soft_limit_bytes: Math.round(1.8 * 1024 ** 4), configured: true, status: 'active', source: 'runner', grace_status: null, updated_at: isoAgo(5 * 60_000) },
      { user_id: 6, username: 'devon', quota_bytes: 1 * 1024 ** 4, used_bytes: Math.round(0.34 * 1024 ** 4), soft_limit_bytes: Math.round(0.85 * 1024 ** 4), configured: true, status: 'active', source: 'runner', grace_status: null, updated_at: isoAgo(5 * 60_000) },
    ],
    backups: [
      {
        id: 'bkp-20261125-0300',
        filename: 'aetherflow-db-20261125-0300.sqlite.zst',
        size: 48_234_496,
        checksum: 'c4e91f8b2a7d604e3f91b5c8a2d4e7f01a8b3c5d6e7f8a9b0c1d2e3f4a5b6c7d',
        timestamp: isoAgo(6 * 3600_000),
      },
      {
        id: 'bkp-20261124-0300',
        filename: 'aetherflow-db-20261124-0300.sqlite.zst',
        size: 47_812_096,
        checksum: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
        timestamp: isoAgo(30 * 3600_000),
      },
      {
        id: 'bkp-20261123-0300',
        filename: 'aetherflow-db-20261123-0300.sqlite.zst',
        size: 47_104_512,
        checksum: '7f8e9d0c1b2a39485766554433221100ffeeddccbbaa99887766554433221100',
        timestamp: isoAgo(54 * 3600_000),
      },
    ],
    backupWindow: {
      mode: 'smart',
      optimal_window: {
        optimal_hour: 3,
        day_of_week: 'Daily',
        timezone: 'UTC',
        duration_mins: 18,
        confidence: 0.96,
        reasoning: 'Lowest 30-day streaming concurrency (0 active streams) and minimal ZFS scrub I/O between 03:00 and 04:00 UTC.',
      },
      next_backup_at: new Date(nowMs + 18 * 3600_000).toISOString(),
    },
  };
}

async function installMocks(page, fixtures, unmockedLog, options = {}) {
  const theme = options.theme === 'light' ? 'light' : 'dark';
  const json = (route, payload, status = 200) =>
    route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(payload),
    });

  // Seed theme, expanded desktop sidebar, FlowAI sessions, and visual polish styles.
  await page.addInitScript(({ threads, themeMode }) => {
    window.localStorage.setItem('aetherflow-theme', themeMode);
    window.localStorage.setItem('aetherflow-language', 'en');
    window.localStorage.setItem('aetherflow-sidebar-pinned', 'true');
    window.sessionStorage.setItem('aetherflow-ai-sessions:1', JSON.stringify(threads));
    const installStyle = () => {
      if (document.head && !document.head.querySelector('style[data-af-shot-polish]')) {
        const style = document.createElement('style');
        style.setAttribute('data-af-shot-polish', 'true');
        style.textContent = `
          * { caret-color: transparent !important; }
          html { scroll-behavior: auto !important; }
        `;
        document.head.appendChild(style);
      }
    };
    if (document.head) installStyle();
    else window.addEventListener('DOMContentLoaded', installStyle, { once: true });
  }, { threads: fixtures.flowAiThreads, themeMode: theme });

  // Keep WebSocket open so the header status pill displays "API Connected" (emerald).
  await page.routeWebSocket(/\/api\/v1\/auth\/ws/, (ws) => {
    ws.onMessage((message) => {
      try {
        const parsed = JSON.parse(String(message));
        if (parsed?.type === 'PING' || parsed?.type === 'ping') {
          ws.send(JSON.stringify({ type: 'PONG' }));
        }
      } catch {
        // Ignore non-JSON heartbeat frames.
      }
    });
  });

  // Catch-all registered first (LIFO: specific routes below take precedence).
  await page.route('**/api/**', async (route) => {
    const reqUrl = new URL(route.request().url());
    unmockedLog.push(`${route.request().method()} ${reqUrl.pathname}${reqUrl.search}`);
    await json(route, {});
  });

  await page.route('**/health/ready', (route) =>
    json(route, { service: 'aetherflow-api', status: 'ready', database: 'ok' }),
  );
  await page.route(/\/api(\/v1)?\/auth\/ready/, (route) =>
    json(route, { service: 'aetherflow-api', status: 'ready', database: 'ok' }),
  );
  await page.route(/\/api(\/v1)?(\/public)?\/csrf-token/, (route) =>
    json(route, { csrf_token: 'mock-csrf-token' }),
  );
  await page.route(/\/api(\/v1)?(\/public)?\/auth\/setup\/check/, (route) =>
    json(route, { setupRequired: false }),
  );
  await page.route(/\/api(\/v1)?(\/auth)?\/session(?:\?.*)?$/, (route) =>
    json(route, fixtures.user),
  );
  await page.route(/\/api\/v1\/auth\/ws\/ticket(?:\?.*)?$/, (route) =>
    json(route, { ticket: 'mock-ws-ticket-atlas' }),
  );
  await page.route(/\/api\/v1\/auth\/profile\/avatar(?:\?.*)?$/, (route) =>
    route.fulfill({ status: 200, contentType: 'image/svg+xml', body: buildAvatarSvg() }),
  );

  // Settings & System Updates
  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/settings(?:\?.*)?$/, (route) =>
    json(route, fixtures.settings),
  );
  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/system\/update\/status(?:\?.*)?$/, (route) =>
    json(route, { state: 'idle', status: 'idle', phase: '', operationId: '', error: '' }),
  );
  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/system\/update\/check(?:\?.*)?$/, (route) =>
    json(route, {
      updateAvailable: false,
      currentVersion: 'v4.0.0',
      latestVersion: 'v4.0.0',
      message: 'AetherFlow v4.0.0 is up to date (Sigstore provenance verified).',
      url: 'https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0',
    }),
  );

  // Telemetry, Hardware, Topology & Capacity Predictions
  await page.route(/\/api(\/v1)?(\/auth)?\/system\/metrics\/history(?:\?.*)?$/, (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get('aggregate') === 'daily_transfer') {
      return json(route, fixtures.makeDailyTransfer(url.searchParams.get('days')));
    }
    return json(route, fixtures.makeTelemetryHistory(url.searchParams.get('window') || '5m'));
  });
  await page.route(/\/api(\/v1)?(\/auth)?\/system\/metrics(?:\?.*)?$/, (route) =>
    json(route, fixtures.metrics),
  );
  await page.route(/\/api(\/v1)?(\/auth)?\/system\/hardware(?:\?.*)?$/, (route) =>
    json(route, fixtures.hardware),
  );
  await page.route(/\/api(\/v1)?(\/auth)?\/system\/topology(?:\?.*)?$/, (route) =>
    json(route, fixtures.topology),
  );
  await page.route(/\/api\/v1\/admin\/ai\/predictions\/history(?:\?.*)?$/, (route) =>
    json(route, fixtures.capacityHistory30d),
  );
  await page.route(/\/api\/v1\/admin\/ai\/predictions(?:\?.*)?$/, (route) =>
    json(route, fixtures.predictions),
  );

  // Services & Marketplace & Plugins
  await page.route(/\/api(\/v1)?\/(auth|admin)\/services(?:\?.*)?$/, (route) =>
    json(route, fixtures.servicesMap),
  );
  await page.route(/\/api(\/v1)?(\/(public|auth|admin))?\/marketplace(?:\?.*)?$/, (route) =>
    json(route, fixtures.marketplaceApps),
  );
  await page.route(/\/api(\/v1)?(\/auth)?\/plugins(?:\?.*)?$/, (route) => json(route, []));

  // Notifications & Pending Approvals
  await page.route(/\/api(\/v1)?(\/auth)?\/notifications(?:\?.*)?$/, (route) =>
    json(route, fixtures.notifications),
  );
  await page.route(/\/api(\/v1)?\/admin\/notifications\/channels(?:\?.*)?$/, (route) =>
    json(route, { channels: fixtures.notificationChannels }),
  );
  await page.route(/\/api(\/v1)?\/admin\/notifications\/rules(?:\?.*)?$/, (route) =>
    json(route, { rules: fixtures.notificationRules }),
  );
  await page.route(/\/api(\/v1)?(\/admin)?\/actions\/pending(?:\?.*)?$/, (route) => {
    const url = new URL(route.request().url());
    const status = (url.searchParams.get('status') || 'pending').toLowerCase();
    const limit = Number(url.searchParams.get('limit') || '50');
    let list = fixtures.pendingActions;
    if (status === 'approved') {
      list = fixtures.resolvedActions.filter((a) => a.status === 'executed' || a.status === 'approved');
    } else if (status === 'rejected') {
      list = fixtures.resolvedActions.filter((a) => a.status === 'rejected');
    } else if (status === 'all') {
      list = [...fixtures.pendingActions, ...fixtures.resolvedActions];
    }
    return json(route, {
      total: list.length,
      count: list.length,
      actions: list.slice(0, Math.max(1, limit)),
    });
  });
  await page.route(/\/api(\/v1)?\/admin\/actions\/(\d+)\/(approve|reject)(?:\?.*)?$/, (route) => {
    const m = new URL(route.request().url()).pathname.match(/\/actions\/(\d+)\/(approve|reject)/);
    const id = Number(m?.[1]);
    const verb = m?.[2];
    const base = [...fixtures.pendingActions, ...fixtures.resolvedActions].find((a) => a.id === id)
      || fixtures.pendingActions[0];
    const updated = {
      ...base,
      status: verb === 'approve' ? 'executed' : 'rejected',
      resolved_by: 'alex',
      resolved_at: fixtures.isoAgo(1_000),
      job_unit: verb === 'approve' ? `aetherflow-action-${id}.service` : '',
      execution_log: verb === 'approve' ? 'Action executed cleanly by aetherflow-runner.' : '',
    };
    return json(route, { action: updated });
  });
  await page.route(/\/api(\/v1)?\/admin\/actions\/(\d+)(?:\?.*)?$/, (route) => {
    const m = new URL(route.request().url()).pathname.match(/\/actions\/(\d+)/);
    const id = Number(m?.[1]);
    const found = [...fixtures.pendingActions, ...fixtures.resolvedActions].find((a) => a.id === id)
      || fixtures.pendingActions[0];
    return json(route, { action: found });
  });

  // FileShare, MediaFlow, Users, Quotas, Backups
  await page.route(/\/api(\/v1)?\/auth\/fileshare(?:\?.*)?$/, (route) => {
    const url = new URL(route.request().url());
    return json(route, { path: url.searchParams.get('path') || '/', files: fixtures.fileshareFiles });
  });
  await page.route(/\/api(\/v1)?\/auth\/fs(?:\?.*)?$/, (route) => {
    const url = new URL(route.request().url());
    return json(route, {
      path: url.searchParams.get('path') || '/mnt',
      entries: [
        { name: 'media', is_dir: true },
        { name: 'nvme-cache', is_dir: true },
        { name: 'backups', is_dir: true },
        { name: 'af-peers', is_dir: true },
      ],
    });
  });
  await page.route(/\/api(\/v1)?\/auth\/mcbrowser\/shares(?:\?.*)?$/, (route) =>
    json(route, { shares: fixtures.fileshareShares }),
  );
  await page.route(/\/api(\/v1)?\/auth\/blueprints(?:\?.*)?$/, (route) =>
    json(route, { blueprints: fixtures.blueprints }),
  );
  await page.route(/\/api(\/v1)?\/admin\/mediaflow\/queue(?:\?.*)?$/, (route) =>
    json(route, fixtures.mediaflowQueue),
  );
  await page.route(/\/api(\/v1)?\/admin\/users(?:\?.*)?$/, (route) =>
    json(route, fixtures.users),
  );
  await page.route(/\/api(\/v1)?\/admin\/quotas(?:\?.*)?$/, (route) =>
    json(route, fixtures.quotas),
  );
  await page.route(/\/api(\/v1)?\/admin\/backup\/list(?:\?.*)?$/, (route) =>
    json(route, fixtures.backups),
  );
  await page.route(/\/api(\/v1)?\/admin\/ai\/backup\/optimal-window(?:\?.*)?$/, (route) =>
    json(route, fixtures.backupWindow),
  );

  // Peer Clustering + Distributed Transcoding
  await page.route(/\/api\/v1\/admin\/peers\/transcode(?:\?.*)?$/, (route) =>
    json(route, fixtures.transcodeConfig),
  );
  await page.route(/\/api\/v1\/admin\/peers(?:\?.*)?$/, (route) =>
    json(route, fixtures.peersSnapshot),
  );

  // Streaming + Custom Poster Artwork
  const posters = {
    'art-horizon': buildPosterSvg('Interstellar', '4K HDR · HEVC · 7.1', '#1e1b4b', '#0891b2', '4K HDR'),
    'art-meridian': buildPosterSvg('Orbital Drift', 'S2 E7 · NVENC', '#3b0764', '#4f46e5', '1080p'),
    'art-nocturne': buildPosterSvg('Midnight', 'FLAC 24-bit · Lossless', '#064e3b', '#0f172a', 'FLAC'),
  };
  await page.route(/\/api\/v1\/auth\/streaming\/artwork\/([^?]+)/, (route) => {
    const m = new URL(route.request().url()).pathname.match(/\/artwork\/([^/]+)/);
    const svg = posters[m?.[1]] || posters['art-horizon'];
    return route.fulfill({ status: 200, contentType: 'image/svg+xml', body: svg });
  });
  await page.route(/\/api\/v1\/auth\/streaming\/dashboard(?:\?.*)?$/, (route) =>
    json(route, fixtures.streamingDashboard),
  );
  await page.route(/\/api\/v1\/auth\/streaming\/patterns(?:\?.*)?$/, (route) =>
    json(route, { activity: { timeseries: [] }, concurrency: { buckets: [] } }),
  );
  await page.route(/\/api\/v1\/auth\/streaming\/drilldown(?:\?.*)?$/, (route) =>
    json(route, { cohortDistinctPlays: 418, cohortDistinctUsers: 6, cohortDistinctItems: 142 }),
  );

  // McBrowser
  await page.route(/\/api\/v1\/auth\/mcbrowser\/entries(?:\?.*)?$/, (route) =>
    json(route, { path: '', entries: fixtures.mcbrowserEntries }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/usage(?:\?.*)?$/, (route) =>
    json(route, {
      used_bytes: Math.round(1.84 * 1024 ** 4),
      quota_bytes: 4 * 1024 ** 4,
      status: 'ok',
    }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/policy(?:\/1)?(?:\?.*)?$/, (route) =>
    json(route, {
      user_id: 1,
      scope: 'private',
      permissions: {
        read: true,
        create: true,
        modify: true,
        delete: true,
        download: true,
        share: true,
        archive: true,
        extract: true,
      },
      rules: [],
    }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/preferences(?:\?.*)?$/, (route) =>
    json(route, {
      view: 'list',
      sort: 'name',
      direction: 'asc',
      show_hidden: false,
      single_click: false,
      natural_sort: true,
      redirect_after_copy_move: false,
      date_format: false,
      editor_theme: 'dracula',
      locale: 'en',
    }),
  );

  // Network & Ingress & Diagnostics
  await page.route(/\/api\/v1\/admin\/network\/status(?:\?.*)?$/, (route) =>
    json(route, fixtures.networkStatus),
  );
  await page.route(/\/api\/v1\/admin\/network\/diagnostics(?:\?.*)?$/, (route) =>
    json(route, {
      checks: [
        { name: 'WireGuard kernel module', ok: true, detail: 'wg0 up · 51820/UDP bound' },
        { name: 'IPv4/IPv6 forwarding', ok: true, detail: 'net.ipv4.ip_forward=1, net.ipv6.conf.all.forwarding=1' },
        { name: 'Tailscale daemon & MagicDNS', ok: true, detail: 'Running · atlas-mesh.ts.net reachable' },
        { name: 'Subdomain TLS SAN sync', ok: true, detail: '5/5 routes valid · expires in 74 days' },
      ],
      logs: [
        '[atlas] wg0: listening on UDP 51820 (4 active peers, 0 handshake failures)',
        '[atlas] tailscaled: connected to DERP(fra), direct peer links active for nova, vega',
        '[atlas] ingress: certbot SAN bundle matches jellyfin/grafana/vault/cloud/speed.atlas.example.com',
      ].join('\n'),
    }),
  );
  await page.route(/\/api\/v1\/admin\/ingress\/configs(?:\?.*)?$/, (route) =>
    json(route, fixtures.ingressConfigs),
  );

  // Security / Profile / Sessions / Personal Quota
  await page.route(/\/api\/v1\/auth\/sessions(?:\?.*)?$/, (route) =>
    json(route, {
      sessions: [
        {
          jti: 'sess-fam-9a41f0c2',
          ip_address: '198.51.100.14',
          user_agent: 'Chromium 136 · Debian Linux (Workstation)',
          last_active: fixtures.isoAgo(20_000),
          expires_at: new Date(fixtures.nowMs + 7 * 86_400_000).toISOString(),
          is_current: true,
        },
        {
          jti: 'sess-fam-6c18e3b7',
          ip_address: '198.51.100.28',
          user_agent: 'Safari 18 · macOS Sequoia (Studio Laptop)',
          last_active: fixtures.isoAgo(42 * 60_000),
          expires_at: new Date(fixtures.nowMs + 6 * 86_400_000).toISOString(),
          is_current: false,
        },
        {
          jti: 'sess-fam-3d92a7e5',
          ip_address: '203.0.113.88',
          user_agent: 'Firefox 138 · Mobile WireGuard Tunnel',
          last_active: fixtures.isoAgo(4 * 3600_000),
          expires_at: new Date(fixtures.nowMs + 5 * 86_400_000).toISOString(),
          is_current: false,
        },
      ],
    }),
  );
  await page.route(/\/api\/v1\/auth\/user\/quota(?:\?.*)?$/, (route) =>
    json(route, {
      user_id: 1,
      username: 'alex',
      quota_bytes: 4 * 1024 ** 4,
      used_bytes: Math.round(1.84 * 1024 ** 4),
      available_bytes: Math.round(2.16 * 1024 ** 4),
      usage_pct: 46.0,
      configured: true,
      status: 'active',
      source: 'runner',
      updated_at: fixtures.isoAgo(300_000),
    }),
  );

  // Audit Trail
  await page.route(/\/api\/v1\/admin\/audit-log(?:\?.*)?$/, (route) =>
    json(route, {
      total: 1284,
      logs: fixtures.auditLogs,
      items: fixtures.auditLogs,
    }),
  );
}

async function waitForSettle(page) {
  await page.evaluate(async () => {
    if (document.fonts && document.fonts.ready) {
      await document.fonts.ready;
    }
    const imgs = Array.from(document.querySelectorAll('img'));
    await Promise.all(
      imgs.map((img) => {
        if (img.complete) return Promise.resolve();
        return new Promise((resolve) => {
          img.addEventListener('load', resolve, { once: true });
          img.addEventListener('error', resolve, { once: true });
          setTimeout(resolve, 2500);
        });
      }),
    );
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
  await page.waitForTimeout(450);
}

const SHOTS = [
  {
    name: 'overview',
    url: '/?tab=overview',
    ready: async (page) => {
      await page.getByRole('heading', { name: 'Overview', exact: true }).waitFor({ timeout: 20_000 });
      await page.locator('.af-chart svg').first().waitFor({ timeout: 15_000 });
      await page.getByText('API Connected').waitFor({ timeout: 10_000 }).catch(() => {});
    },
  },
  {
    name: 'inbox',
    url: '/?tab=inbox',
    ready: async (page) => {
      await page.getByText('restart_service:jellyfin:systemd').first().waitFor({ timeout: 20_000 });
      await page.getByText('prune_transcode_cache').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'services',
    url: '/?tab=services',
    ready: async (page) => {
      await page.getByRole('heading', { name: 'Services', exact: true }).waitFor({ timeout: 20_000 });
      await page.getByText('AetherFlow API').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'marketplace',
    url: '/?tab=marketplace',
    ready: async (page) => {
      await page.getByRole('heading', { name: /Marketplace/i }).first().waitFor({ timeout: 20_000 });
      await page.getByRole('heading', { name: 'Jellyfin', exact: true }).waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'mcbrowser',
    url: '/?tab=mcbrowser',
    ready: async (page) => {
      await page.getByText('atlas-cluster-policy.toml').first().waitFor({ timeout: 20_000 });
    },
  },
  {
    name: 'fileshare',
    url: '/?tab=fileshare',
    ready: async (page) => {
      await page.getByText('Interstellar.Horizon.2025.2160p.HEVC.mkv').first().waitFor({ timeout: 20_000 });
    },
  },
  {
    name: 'streaming',
    url: '/?tab=streaming',
    ready: async (page) => {
      await page.getByText('Interstellar Horizon').first().waitFor({ timeout: 20_000 });
      await page.getByText('Distribution & Trends').waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'mediaflow',
    url: '/?tab=mediaflow',
    ready: async (page) => {
      await page.getByText('Jellyseerr').first().waitFor({ timeout: 20_000 });
      await page.getByText('Orbital.Drift.S02E08.2160p.REMUX.mkv').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'flowai',
    url: '/?tab=ai',
    ready: async (page) => {
      await page.getByText('HUMAN APPROVAL REQUIRED').first().waitFor({ timeout: 20_000 });
    },
  },
  {
    name: 'network',
    url: '/?tab=network',
    ready: async (page) => {
      await page.getByText('alex-workstation').first().waitFor({ timeout: 20_000 });
      await page.getByText('atlas-mesh.ts.net').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'cluster',
    url: '/?tab=cluster',
    ready: async (page) => {
      const main = page.locator('#main-content .af-tab-content');
      await main.getByText('nova.example.com').first().waitFor({ timeout: 20_000 });
      await main.getByText('vega.example.com').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'users',
    url: '/?tab=users',
    ready: async (page) => {
      await page.getByText('maya@example.com').first().waitFor({ timeout: 20_000 });
      await page.getByText('elena@example.com').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'audit',
    url: '/?tab=audit',
    ready: async (page) => {
      await page.getByText('1284').first().waitFor({ timeout: 20_000 });
      await page.getByText('action_approved').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'settings',
    url: '/?tab=settings',
    ready: async (page) => {
      await page.getByRole('heading', { name: 'Settings', exact: true }).waitFor({ timeout: 20_000 });
      await page.getByText('atlas.example.com').or(page.locator('input[value="atlas.example.com"]')).first().waitFor({ timeout: 15_000 }).catch(() => {});
    },
  },
  {
    name: 'notifications',
    url: '/?tab=notifications',
    ready: async (page) => {
      await page.getByText('Ops Discord (#atlas-alerts)').first().waitFor({ timeout: 20_000 });
      await page.getByText('Core service health guard').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'quotas',
    url: '/?tab=quotas',
    ready: async (page) => {
      const main = page.locator('#main-content .af-tab-content');
      await main.getByText('maya').first().waitFor({ timeout: 20_000 });
      await main.getByText('sam').first().waitFor({ timeout: 15_000 });
    },
  },
  {
    name: 'security',
    url: '/?tab=settings',
    ready: async (page) => {
      await page.getByRole('heading', { name: 'Settings', exact: true }).waitFor({ timeout: 20_000 });
      await page.getByRole('tab', { name: /Security/i }).click();
      await page.getByText('TOTP enabled').waitFor({ timeout: 15_000 });
      await page.getByText('sess-fam-9a41f0c2').first().waitFor({ timeout: 15_000 });
    },
  },
];

function commandExists(cmd) {
  return spawnSync('which', [cmd], { stdio: 'ignore' }).status === 0;
}

function optimizePng(filePath) {
  if (commandExists('oxipng')) {
    spawnSync('oxipng', ['-o', '4', '--strip', 'safe', '-q', filePath], { stdio: 'inherit' });
    if (fs.statSync(filePath).size <= 1_450_000) return 'oxipng';
  }
  if (commandExists('pngquant')) {
    const tmp = `${filePath}.opt.png`;
    const res = spawnSync('pngquant', ['--quality=85-98', '--speed', '1', '--force', '--output', tmp, filePath]);
    if (res.status === 0 && fs.existsSync(tmp) && fs.statSync(tmp).size < fs.statSync(filePath).size) {
      fs.renameSync(tmp, filePath);
      return 'pngquant';
    }
    fs.rmSync(tmp, { force: true });
  }
  if (commandExists('convert')) {
    const tmp = `${filePath}.opt.png`;
    // Smooth Floyd-Steinberg 256-color palette PNG8 keeps 1440p dark obsidian
    // gradients visually crisp while shrinking 3+ MiB captures to ~500-850 KiB.
    const res = spawnSync('convert', [
      filePath,
      '-strip',
      '-dither', 'FloydSteinberg',
      '-colors', '256',
      '-define', 'png:compression-level=9',
      '-define', 'png:compression-filter=5',
      `PNG8:${tmp}`,
    ]);
    if (res.status === 0 && fs.existsSync(tmp) && fs.statSync(tmp).size < fs.statSync(filePath).size) {
      fs.renameSync(tmp, filePath);
      return 'imagemagick-png8';
    }
    fs.rmSync(tmp, { force: true });
  }
  return 'none';
}

function createSocialCrop(overviewPath, socialPath, optimize) {
  if (!fs.existsSync(overviewPath)) return false;
  if (!commandExists('convert')) {
    throw new Error('ImageMagick `convert` is required to generate social-crop.png (1280x640).');
  }
  execFileSync('convert', [
    overviewPath,
    '-crop', '2560x1280+0+0',
    '+repage',
    '-filter', 'Lanczos',
    '-resize', `${SOCIAL_CROP.width}x${SOCIAL_CROP.height}!`,
    '-strip',
    '-define', 'png:compression-level=9',
    '-define', 'png:compression-filter=5',
    '-define', 'png:compression-strategy=1',
    socialPath,
  ]);
  if (optimize) optimizePng(socialPath);
  return true;
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.guides) {
    const guideScript = path.join(__dirname, 'capture_guides.mjs');
    const guideArgs = [guideScript];
    if (opts.dist) guideArgs.push('--dist', opts.dist);
    if (opts.release) guideArgs.push('--release', opts.release);
    if (!opts.optimize) guideArgs.push('--no-optimize');
    if (opts.keepTemp) guideArgs.push('--keep-temp');
    if (opts.guidesFilter) guideArgs.push('--guides', opts.guidesFilter);
    const res = spawnSync(process.execPath, guideArgs, { stdio: 'inherit' });
    if (res.status !== 0) {
      process.exit(res.status ?? 1);
    }
    return;
  }

  const { chromium } = loadPlaywright();
  fs.mkdirSync(opts.out, { recursive: true });

  const { distDir, tempDir } = resolveWebDist(opts);
  const { server, baseUrl } = await startStaticServer(distDir);
  const fixtures = buildFixtures();
  const selectedShots = opts.tabs
    ? SHOTS.filter((s) => opts.tabs.includes(s.name))
    : SHOTS;

  if (selectedShots.length === 0) {
    throw new Error(`No matching shots for --tabs. Valid names: ${SHOTS.map((s) => s.name).join(', ')}`);
  }

  const themes = opts.theme === 'both' ? ['dark', 'light'] : [opts.theme];
  let browser;
  const unmockedLog = [];
  const consoleErrors = [];
  const results = [];

  try {
    browser = await chromium.launch({ headless: true });

    for (const theme of themes) {
      const themeOut = path.join(opts.out, theme);
      fs.mkdirSync(themeOut, { recursive: true });

      const context = await browser.newContext({
        viewport: VIEWPORT,
        deviceScaleFactor: 1,
        colorScheme: theme,
        reducedMotion: 'no-preference',
        serviceWorkers: 'block',
      });

      const page = await context.newPage();
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(`[${theme}] ${msg.text()}`);
        }
      });
      page.on('pageerror', (err) => {
        consoleErrors.push(`[${theme}] PAGEERROR: ${err.message}`);
      });

      await installMocks(page, fixtures, unmockedLog, { theme });

      for (const shot of selectedShots) {
        const targetUrl = `${baseUrl}${shot.url}`;
        await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
        await page.locator(`html[data-theme="${theme}"]`).waitFor({ timeout: 15_000 });
        await shot.ready(page);
        await waitForSettle(page);
        // Scroll main dashboard container to top to guarantee consistent framing.
        await page.evaluate(() => {
          const main = document.querySelector('#main-content');
          if (main) main.scrollTop = 0;
          window.scrollTo(0, 0);
        });
        await page.waitForTimeout(150);

        const outPath = path.join(themeOut, `${shot.name}.png`);
        await page.screenshot({ path: outPath, type: 'png', fullPage: false });
        const optimizer = opts.optimize ? optimizePng(outPath) : 'skipped';
        const bytes = fs.statSync(outPath).size;
        results.push({ name: `${theme}/${shot.name}.png`, path: outPath, bytes, optimizer });
        console.log(`Captured ${theme}/${shot.name}.png (${(bytes / 1024).toFixed(1)} KiB, opt=${optimizer})`);
      }

      await context.close();
    }

    const darkOverviewPath = path.join(opts.out, 'dark', 'overview.png');
    if (
      fs.existsSync(darkOverviewPath)
      && themes.includes('dark')
      && (!opts.tabs || opts.tabs.includes('overview') || opts.tabs.includes('social-crop'))
    ) {
      const socialPath = path.join(opts.out, 'social-crop.png');
      createSocialCrop(darkOverviewPath, socialPath, opts.optimize);
      const bytes = fs.statSync(socialPath).size;
      results.push({ name: 'social-crop.png', path: socialPath, bytes, optimizer: 'imagemagick' });
      console.log(`Generated social-crop.png (${(bytes / 1024).toFixed(1)} KiB, 1280x640)`);
    }
  } finally {
    if (browser) await browser.close();
    await new Promise((resolve) => server.close(resolve));
    if (tempDir && !opts.keepTemp) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  console.log('\n--- Capture Summary ---');
  for (const r of results) {
    console.log(`  ${r.name.padEnd(26)} ${(r.bytes / 1024).toFixed(1).padStart(8)} KiB  ${r.path}`);
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

export {
  REPO_ROOT,
  VIEWPORT,
  SHOTS,
  loadPlaywright,
  resolveWebDist,
  startStaticServer,
  buildFixtures,
  installMocks,
  waitForSettle,
  optimizePng,
  commandExists,
};

const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
