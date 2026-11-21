import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { expect, test, type Page, type Route } from '@playwright/test';

const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'AetherFlowE2E!2026';
const MEMBER_USER = process.env.E2E_MEMBER_USER || 'live-member';

function completedTelemetryHistory(page: Page, window?: string) {
  return page.waitForResponse(async response => {
    const url = new URL(response.url());
    if (url.pathname !== '/api/v1/auth/system/metrics/history' || !url.searchParams.has('window') || !response.ok()
      || (window !== undefined && url.searchParams.get('window') !== window)) return false;
    // A WebSocket revalidation can supersede a read after its headers arrive.
    // Keep waiting for a complete body; the caller still asserts its contents.
    return await response.finished() === null;
  });
}

async function mutationHeaders(page: Page): Promise<Record<string, string>> {
  const response = await page.request.get('/api/v1/public/csrf-token', { timeout: 10_000 });
  expect(response.ok()).toBeTruthy();
  const { csrf_token: token } = await response.json();
  expect(typeof token).toBe('string');
  expect(token.length).toBeGreaterThan(0);
  return {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-CSRF-Token': token,
  };
}

// The real backend intentionally exposes no registration or admin create-user route.
// Seed only the runner's disposable database, then use its real login/session APIs.
function provisionOrdinaryUser(username: string): number {
  const databasePath = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  expect(databasePath, 'Run this live matrix through scripts/run_embedded_e2e.sh --playwright').toBeTruthy();
  const id = execFileSync('python3', ['-c', `
import pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
if database.parent.name != 'data' or not database.parent.parent.name.startswith('aetherflow-embedded-e2e.'):
    raise SystemExit('Refusing to provision a user outside the isolated embedded E2E database')
with sqlite3.connect(database, timeout=15) as connection:
    row = connection.execute('SELECT id FROM users WHERE username = ? AND role = ?', (sys.argv[2], 'user')).fetchone()
    if not row:
        # The comprehensive scenario deletes this account during its cleanup.
        # Recreate the isolated fixture for subsequent browser tests.
        existing = connection.execute('SELECT role FROM users WHERE username = ?', (sys.argv[2],)).fetchone()
        if existing:
            raise SystemExit('The ordinary-user fixture username belongs to a different role')
        admin = connection.execute('SELECT password_hash FROM users WHERE username = ? AND role = ?', (sys.argv[3], 'admin')).fetchone()
        if not admin or not admin[0]:
            raise SystemExit('The ordinary-user fixture requires an isolated administrator password')
        created = connection.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,'user')", (sys.argv[2], admin[0]))
        row = (created.lastrowid,)
    print(row[0])
`, databasePath!, username, ADMIN_USER], { encoding: 'utf8' }).trim();
  expect(id).toMatch(/^\d+$/);
  console.log(`LIVE_MEMBER_FIXTURE: ${username} id=${id} database=${databasePath}`);
  return Number(id);
}

function seedFreshTelemetryHistory(): void {
  const databasePath = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  expect(databasePath, 'Run this live matrix through scripts/run_embedded_e2e.sh --playwright').toBeTruthy();
  execFileSync('python3', ['-B', '-c', `
import datetime, pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
if database.parent.name != 'data' or not database.parent.parent.name.startswith('aetherflow-embedded-e2e.'):
    raise SystemExit('Refusing to seed telemetry outside the isolated embedded E2E database')
now = datetime.datetime.now(datetime.timezone.utc)
rows = [
    ((now - datetime.timedelta(seconds=10 * offset)).strftime('%Y-%m-%d %H:%M:%S'),
     20 + offset, 2 + offset / 10, 8, offset * 1024, offset * 2048)
    for offset in range(12, 0, -1)
]
with sqlite3.connect(database, timeout=15) as connection:
    connection.executemany(
        'INSERT INTO metrics_history '
        '(timestamp, cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        rows,
    )
`, databasePath!], { encoding: 'utf8' });
}

// This scenario verifies persisted editor state. Applying an OS filesystem quota
// requires the privileged runner, which the host-safe live matrix disables.
function provisionPersistedQuota(userId: number, bytes: number): void {
  const databasePath = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  expect(databasePath, 'Run this live matrix through scripts/run_embedded_e2e.sh --playwright').toBeTruthy();
  execFileSync('python3', ['-c', `
import pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
if database.parent.name != 'data' or not database.parent.parent.name.startswith('aetherflow-embedded-e2e.'):
    raise SystemExit('Refusing to provision a quota outside the isolated embedded E2E database')
with sqlite3.connect(database, timeout=15) as connection:
    account = connection.execute('SELECT username FROM users WHERE id = ? AND role = ?', (int(sys.argv[2]), 'admin')).fetchone()
    if not account:
        raise SystemExit('The quota fixture requires the isolated administrator account')
    connection.execute("INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, updated_at) VALUES (?, ?, ?, 0, 'active', 'manual', CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, status = 'active', source = 'manual', updated_at = CURRENT_TIMESTAMP", (int(sys.argv[2]), account[0], int(sys.argv[3])))
`, databasePath!, String(userId), String(bytes)], { encoding: 'utf8' });
}

function approvalHistoryFixture(marker: string, operation: 'seed' | 'cleanup'): void {
  const databasePath = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  expect(databasePath, 'The approval fixture requires the isolated embedded database').toBeTruthy();
  execFileSync('python3', ['-c', `
import pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
if database.parent.name != 'data' or not database.parent.parent.name.startswith('aetherflow-embedded-e2e.'):
    raise SystemExit('Refusing to change approvals outside the isolated embedded E2E database')
with sqlite3.connect(database, timeout=15) as connection:
    marker = sys.argv[2]
    if sys.argv[3] == 'seed':
        connection.execute("INSERT INTO pending_actions (source, action, reason, status, created_at) VALUES (?, ?, ?, 'pending', '2000-01-01 00:00:00')", (marker, marker + ' pending', 'Older approval awaiting review'))
        connection.executemany("INSERT INTO pending_actions (source, action, reason, status, created_at) VALUES (?, ?, ?, 'executed', CURRENT_TIMESTAMP)", [(marker, marker + ' history ' + str(index), 'Completed history fixture') for index in range(502)])
    else:
        connection.execute('DELETE FROM pending_actions WHERE source = ?', (marker,))
`, databasePath!, marker, operation], { encoding: 'utf8' });
}

function notificationFixture(marker: string, operation: 'seed' | 'cleanup'): void {
  const databasePath = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  expect(databasePath, 'The notification fixture requires the isolated embedded database').toBeTruthy();
  execFileSync('python3', ['-c', `
import pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
if database.parent.name != 'data' or not database.parent.parent.name.startswith('aetherflow-embedded-e2e.'):
    raise SystemExit('Refusing to change notifications outside the isolated embedded E2E database')
with sqlite3.connect(database, timeout=15) as connection:
    if sys.argv[3] == 'seed':
        account = connection.execute('SELECT id FROM users WHERE username = ? AND role = ?', (sys.argv[4], 'admin')).fetchone()
        if not account:
            raise SystemExit('The notification fixture requires the isolated administrator account')
        connection.execute("INSERT INTO notifications (user_id, level, title, message, read) VALUES (?, 'warning', ?, 'Localized severity fixture', 0)", (account[0], sys.argv[2]))
    else:
        connection.execute('DELETE FROM notifications WHERE title = ?', (sys.argv[2],))
`, databasePath!, marker, operation, ADMIN_USER], { encoding: 'utf8' });
}

function restoreProfileEmail(userId: number, email: string): void {
  const databasePath = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  expect(databasePath, 'Profile cleanup requires the isolated embedded database').toBeTruthy();
  execFileSync('python3', ['-c', `
import pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
if database.parent.name != 'data' or not database.parent.parent.name.startswith('aetherflow-embedded-e2e.'):
    raise SystemExit('Refusing to restore a profile outside the isolated embedded E2E database')
with sqlite3.connect(database, timeout=15) as connection:
    changed = connection.execute('UPDATE users SET email = ? WHERE id = ? AND username = ?', (sys.argv[3], int(sys.argv[2]), sys.argv[4]))
    if changed.rowcount != 1:
        raise SystemExit('The isolated administrator profile was not found')
`, databasePath!, String(userId), email, ADMIN_USER], { encoding: 'utf8' });
}

function silentWav(): Buffer {
  // 100 ms of valid mono 16-bit PCM at 8 kHz, including the 44-byte RIFF header.
  const samples = 800;
  const wav = Buffer.alloc(44 + samples * 2);
  wav.write('RIFF', 0);
  wav.writeUInt32LE(wav.length - 8, 4);
  wav.write('WAVEfmt ', 8);
  wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(1, 22);
  wav.writeUInt32LE(8000, 24);
  wav.writeUInt32LE(16000, 28);
  wav.writeUInt16LE(2, 32);
  wav.writeUInt16LE(16, 34);
  wav.write('data', 36);
  wav.writeUInt32LE(samples * 2, 40);
  return wav;
}


async function signInLive(page: Page, username = ADMIN_USER): Promise<void> {
  await page.goto('/login', { waitUntil: 'domcontentloaded', timeout: 15_000 });
  await page.locator('input[type="text"]').first().fill(username);
  await page.locator('input[type="password"]').first().fill(ADMIN_PASS);
  const submit = async () => {
    const signedIn = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/public/auth/login'
        && response.request().method() === 'POST'
    );
    await page.locator('button[type="submit"]').first().click();
    return signedIn;
  };
  let response = await submit();
  expect(response.request().postDataJSON()).toEqual({ username, password: ADMIN_PASS });
  if (response.status() === 429) {
    // A full live run shares the real loopback authentication budget.
    const retryAfter = Number(response.headers()['retry-after']);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
    console.log(`LIVE_AUTH_RETRY: honoring the server's ${retryAfter}s Retry-After`);
    await page.waitForTimeout(retryAfter * 1000);
    response = await submit();
  }
  const detail = response.status() === 200 ? `Signed in as ${username}`
    : await response.text().catch(() => `Login response body unavailable for ${username}`);
  console.log(`LIVE_LOGIN_RESULT: ${username} status=${response.status()}`);
  expect(response.status(), detail).toBe(200);
  await expect(page).not.toHaveURL(/\/login/);
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  const onboarding = page.getByRole('heading', { name: 'Welcome to AetherFlow' });
  if (await onboarding.isVisible()) {
    await page.getByRole('button', { name: /Continue/i }).click();
    await page.getByRole('button', { name: /Enter Dashboard/i }).click();
    await expect(onboarding).toHaveCount(0);
  }
}

async function recheckLiveSession(page: Page): Promise<void> {
  const rechecked = page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/v1/auth/session' && response.ok(),
    { timeout: 15_000 }
  );
  // Exercise the recent-login recheck through the live session API.
  await page.evaluate(() => {
    window.dispatchEvent(new Event('af:session-expired'));
  });
  await (await rechecked).finished();
}

async function delayEditorRequest(page: Page, method: 'GET' | 'PUT') {
  const pattern = /\/api\/v1\/auth\/mcbrowser\/(?:content|file)\?/;
  let signalStarted!: () => void;
  let resume!: () => void;
  let signalContinued!: () => void;
  const started = new Promise<void>((resolve) => { signalStarted = resolve; });
  const resumed = new Promise<void>((resolve) => { resume = resolve; });
  const continued = new Promise<void>((resolve) => { signalContinued = resolve; });
  let claimed = false;
  const handler = async (route: Route) => {
    if (claimed || route.request().method() !== method) return route.continue();
    claimed = true;
    signalStarted();
    try {
      await resumed;
      await route.continue();
    } finally {
      signalContinued();
    }
  };
  await page.route(pattern, handler);
  return {
    started,
    resume,
    dispose: async () => {
      resume();
      if (claimed) await continued;
      if (!page.isClosed()) await page.unroute(pattern, handler);
    },
  };
}

// Each test gets a fresh browser context, including an empty service-worker and
// HTTP cache. Count the application URL separately from the lazy worker WASM.
for (const serviceWorkers of ['allow', 'block'] as const) {
  test.describe(`Cold WASM startup (service workers ${serviceWorkers})`, () => {
    test.use({ serviceWorkers });
    test('fetches the main application WASM once', async ({ page }) => {
      const requests: string[] = [];
      const responses: Array<{ url: string; status: number }> = [];
      await page.addInitScript(() => {
        addEventListener('TrunkApplicationStarted', () => performance.mark('af-e2e-app-started'), { once: true });
      });
      page.on('request', (request) => {
        if (new URL(request.url()).pathname.endsWith('.wasm')) requests.push(request.url());
      });
      page.on('response', (response) => {
        if (new URL(response.url()).pathname.endsWith('.wasm')) {
          responses.push({ url: response.url(), status: response.status() });
        }
      });

      await page.goto('/login');
      await expect(page.getByRole('heading', { name: 'Access Nexus', exact: true })).toBeVisible();
      await expect.poll(() => page.evaluate(() => performance.getEntriesByName('af-e2e-app-started').length)).toBe(1);
      const appWasm = await page.locator('meta[name="af-app-wasm-url"]').getAttribute('content');
      expect(appWasm).toBeTruthy();
      const appUrl = new URL(appWasm!, page.url()).href;
      expect(requests.filter((url) => url === appUrl)).toEqual([appUrl]);
      expect(responses.filter((response) => response.url === appUrl)).toEqual([{ url: appUrl, status: 200 }]);
      await expect(page.locator('link[rel~="preload"][as="fetch"][href$=".wasm"]')).toHaveCount(0);

      const resources = await page.evaluate(() => performance.getEntriesByType('resource')
        .map((entry) => {
          const resource = entry as PerformanceResourceTiming;
          return { url: resource.name, initiator: resource.initiatorType,
            transferBytes: resource.transferSize, encodedBytes: resource.encodedBodySize,
            startMs: resource.startTime, responseEndMs: resource.responseEnd, durationMs: resource.duration };
        }).filter((entry) => new URL(entry.url).pathname.endsWith('.wasm')));
      const timing = await page.evaluate(() => ({
        applicationStartedMs: performance.getEntriesByName('af-e2e-app-started')[0].startTime,
        loginHeadingObservedMs: performance.now(),
        navigation: performance.getEntriesByType('navigation').map(entry => {
          const navigation = entry as PerformanceNavigationTiming;
          return { responseEndMs: navigation.responseEnd, domContentLoadedMs: navigation.domContentLoadedEventEnd,
            loadMs: navigation.loadEventEnd };
        }),
      }));
      const applicationTransfers = resources.filter((entry) => entry.url === appUrl);
      expect(applicationTransfers).toHaveLength(1);
      console.log(`COLD_WASM_STARTUP: ${JSON.stringify({ serviceWorkers, timing, applicationTransfers,
        otherWasmTransfers: resources.filter((entry) => entry.url !== appUrl) })}`);
    });
  });
}

test.describe('Real Rust API and external WASM frontend E2E (Zero Mocks)', () => {
  // These real-API cases deliberately delay/reject selected requests to test
  // races. Disable SW interception so page.route observes them in every engine.
  test.use({ serviceWorkers: 'block' });
  test('loads the bundled OpenAPI viewer under its own content policy', async ({ page }) => {
    type ViewerWindow = Window & { viewerPolicyViolations?: string[] };
    await page.addInitScript(() => {
      const violations: string[] = [];
      (window as ViewerWindow).viewerPolicyViolations = violations;
      document.addEventListener('securitypolicyviolation', event => {
        violations.push(`${event.effectiveDirective}: ${event.blockedURI}`);
      });
    });

    await page.goto('/api/v1/public/swagger');
    await expect(page).toHaveURL(/\/api\/v1\/public\/swagger\/index\.html$/);
    await expect(page.locator('#stats-row')).toContainText(/Showing [1-9][0-9]* of/);
    await expect(page.locator('#endpoints-root .tag-section').first()).toBeVisible();
    await page.getByRole('button', { name: 'Raw YAML' }).click();
    await expect(page.getByRole('dialog', { name: 'openapi-v1.yaml' })).toBeVisible();
    await expect(page.locator('#raw-yaml-pre')).toContainText('openapi: 3.1.0');
    expect(await page.evaluate(() => (window as ViewerWindow).viewerPolicyViolations)).toEqual([]);
  });

  test('serves the selected WASM bundle with working workers, CSP, caching and encodings', async ({ page, request }) => {
    test.setTimeout(60_000);
    const selectedDir = process.env.STATIC_DIR;
    expect(selectedDir, 'Run this test through the external asset E2E harness').toBeTruthy();
    const staticDir = realpathSync(selectedDir!);
    const document = await request.get('/', { headers: { 'Accept-Encoding': 'identity' } });
    expect(document.status()).toBe(200);
    expect(document.headers()['content-type']).toMatch(/^text\/html\b/i);
    expect(document.headers()['cache-control']).toContain('no-cache');
    const html = await document.text();
    expect(html).toBe(readFileSync(join(staticDir, 'index.html'), 'utf8'));
    const csp = document.headers()['content-security-policy'] || '';
    expect(csp).toMatch(/(?:^|;)\s*script-src\s+[^;]*'self'[^;]*'wasm-unsafe-eval'/);
    expect(csp).toMatch(/(?:^|;)\s*worker-src\s+[^;]*'self'/);
    expect(csp).not.toContain("'unsafe-inline'");
    expect(csp).not.toContain("'unsafe-eval'");

    const navigationFallback = await request.get('/aetherflow-runtime-navigation-check');
    expect(navigationFallback.status()).toBe(200);
    expect(navigationFallback.headers()['cache-control']).toContain('no-cache');
    expect(await navigationFallback.text()).toBe(html);
    for (const path of [
      '/api/v1/nonexistent-route-check',
      '/ws/nonexistent-route-check',
      '/nonexistent-runtime-check.wasm',
      '/nonexistent-worker-check.js',
    ]) {
      const missing = await request.get(path);
      expect(missing.status(), path).toBe(404);
      expect(missing.headers()['content-type'], path).toMatch(/^application\/json\b/i);
      expect((await missing.json()).error, path).toBeTruthy();
    }

    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Access Nexus', exact: true })).toBeVisible();
    await expect(page.locator('script:not([src])')).toHaveCount(0);
    const bootstrap = await page.locator('script[src]').first().getAttribute('src');
    const appJs = await page.locator('link[rel="modulepreload"][href$=".js"]').first().getAttribute('href');
    const appWasm = await page.locator('meta[name="af-app-wasm-url"]').getAttribute('content');
    const workerLoader = await page.locator('meta[name="af-worker-url"]').getAttribute('content');
    expect(bootstrap && appJs && appWasm && workerLoader).toBeTruthy();

    const loaderResponse = await request.get(workerLoader!);
    expect(loaderResponse.ok()).toBeTruthy();
    const loaderImport = (await loaderResponse.text()).match(/(?:from\s*|import\s*)["']([^"']+\.js)["']/)?.[1];
    expect(loaderImport).toBeTruthy();
    const loaderURL = new URL(workerLoader!, page.url());
    const workerJs = new URL(loaderImport!, loaderURL).pathname;
    const workerResponse = await request.get(workerJs);
    expect(workerResponse.ok()).toBeTruthy();
    const workerWasmReference = (await workerResponse.text()).match(/["']([^"']+\.wasm)["']/)?.[1];
    expect(workerWasmReference).toBeTruthy();
    const workerWasm = new URL(workerWasmReference!, new URL(workerJs, page.url())).pathname;

    let gzipSidecars = 0;
    let brotliSidecars = 0;
    for (const path of [bootstrap!, appJs!, appWasm!, workerLoader!, workerJs, workerWasm]) {
      expect(path).toMatch(/[-_][0-9a-f]{8,}\.(?:js|wasm)$/i);
      const diskFile = realpathSync(join(staticDir, path.replace(/^\//, '')));
      expect(diskFile.startsWith(`${staticDir}/`)).toBe(true);
      const expected = readFileSync(diskFile);
      const identity = await request.get(path, { headers: { 'Accept-Encoding': 'identity' } });
      expect(identity.status(), path).toBe(200);
      expect(identity.headers()['content-type'], path).toMatch(
        path.endsWith('.wasm') ? /^application\/wasm\b/i : /^(?:text|application)\/javascript\b/i,
      );
      expect(identity.headers()['cache-control'], path).toContain('immutable');
      expect(identity.headers()['cache-control'], path).toContain('max-age=31536000');
      expect(identity.headers().vary, path).toMatch(/\baccept-encoding\b/i);
      expect(identity.headers()['content-encoding'], path).toBeUndefined();
      expect(await identity.body(), path).toEqual(expected);

      for (const [encoding, extension] of [['gzip', 'gz'], ['br', 'br']] as const) {
        const sidecarExists = existsSync(`${diskFile}.${extension}`);
        const compressed = await request.get(path, { headers: { 'Accept-Encoding': encoding } });
        expect(compressed.status(), `${path} ${encoding}`).toBe(200);
        expect(compressed.headers()['content-encoding'], `${path} ${encoding}`)
          .toBe(sidecarExists ? encoding : undefined);
        expect(compressed.headers()['content-type']).toBe(identity.headers()['content-type']);
        expect(compressed.headers().vary).toMatch(/\baccept-encoding\b/i);
        // Playwright decompresses response bodies; this verifies the encoded bytes
        // decode to the exact asset selected from the external runtime directory.
        expect(await compressed.body(), `${path} ${encoding}`).toEqual(expected);
        if (sidecarExists && encoding === 'gzip') gzipSidecars += 1;
        if (sidecarExists && encoding === 'br') brotliSidecars += 1;
      }
    }
    expect(gzipSidecars).toBeGreaterThan(0);
    expect(brotliSidecars).toBeGreaterThan(0);
    const rejectedBrotli = await request.get(appWasm!, {
      headers: { 'Accept-Encoding': 'br;q=0, gzip' },
    });
    expect(rejectedBrotli.headers()['content-encoding'])
      .toBe(existsSync(join(staticDir, `${appWasm!.replace(/^\//, '')}.gz`)) ? 'gzip' : undefined);
    const serviceWorker = await request.get('/sw.js');
    expect(serviceWorker.status()).toBe(200);
    expect(serviceWorker.headers()['cache-control']).toContain('no-cache');

    const workerResult = await page.evaluate(async (url) => new Promise((resolve, reject) => {
      const worker = new Worker(url, { type: 'module' });
      const timeout = window.setTimeout(() => {
        worker.terminate();
        reject(new Error('External WASM worker did not respond'));
      }, 10_000);
      worker.onerror = (event) => {
        window.clearTimeout(timeout);
        worker.terminate();
        reject(new Error(`External WASM worker failed: ${event.message}`));
      };
      worker.onmessage = (event) => {
        if (event.data === 'af-worker-ready') {
          const buffer = new TextEncoder().encode('abc').buffer;
          worker.postMessage({ id: 73, type: 'Sha256ChunkTransfer', buffer }, [buffer]);
        } else if (event.data?.id === 73) {
          window.clearTimeout(timeout);
          worker.terminate();
          resolve(event.data.message);
        }
      };
    }), workerLoader!);
    expect(workerResult).toEqual({
      type: 'Hash',
      payload: { hex: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
    });
  });

  test('authenticates with real HttpOnly session cookie, navigates Overview/Marketplace/Settings, hydrates telemetry history, and survives reload/reconnect', async ({
    page,
    request,
    browser,
    browserName,
  }) => {
    test.setTimeout(browserName === 'webkit' ? 420_000 : 240_000);
    page.setDefaultTimeout(15_000);
    await page.addInitScript(() => {
      const sockets: WebSocket[] = [];
      const testWindow = window as Window & { __afAcceptanceSockets?: WebSocket[] };
      testWindow.__afAcceptanceSockets = sockets;
      window.WebSocket = new Proxy(window.WebSocket, {
        construct(NativeSocket, args) {
          const socket = Reflect.construct(NativeSocket, args) as WebSocket;
          sockets.push(socket);
          return socket;
        },
      });
    });
    // 1. Verify backend readiness and setup status directly against the real Rust control plane
    seedFreshTelemetryHistory();
    const readyRes = await request.get('/health/ready');
    expect(readyRes.ok()).toBeTruthy();
    const readyJson = await readyRes.json();
    expect(readyJson.status).toBe('ready');

    const setupCheckRes = await request.get('/api/v1/public/auth/setup/check');
    expect(setupCheckRes.ok()).toBeTruthy();
    const setupCheck = await setupCheckRes.json();

    if (setupCheck.setupRequired) {
      const setupRes = await request.post('/api/v1/public/auth/setup', {
        data: { username: ADMIN_USER, password: ADMIN_PASS },
      });
      expect(setupRes.ok()).toBeTruthy();
    }

    // 2. Perform real UI login without any page.route() mocks
    await page.goto('/login');
    const userField = page.locator('input[type="text"]').first();
    const passField = page.locator('input[type="password"]').first();
    await expect(userField).toBeVisible();
    await userField.fill(ADMIN_USER);
    await passField.fill(ADMIN_PASS);
    const firstSocketPromise = page.waitForEvent('websocket', {
      predicate: (socket) => new URL(socket.url()).pathname === '/api/v1/auth/ws',
    });
    const initialHistoryPromise = completedTelemetryHistory(page);
    const initialSettingsPromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/auth/settings' && response.ok()
    );
    await page.locator('button[type="submit"]').first().click();

    // Verify redirect to dashboard root and real session cookie presence
    await expect(page).toHaveURL(/\/$/);
    const cookies = await page.context().cookies();
    expect(cookies.find((cookie) => cookie.name === 'aetherflow_session')?.httpOnly).toBe(true);
    const firstSocket = await firstSocketPromise;
    const initialHistory = await initialHistoryPromise;
    expect((await initialHistory.json()).length).toBeGreaterThan(1);
    expect(await (await initialSettingsPromise).json()).toBeTruthy();
    await expect(page.getByText('Live Telemetry')).toBeVisible();

    const onboardingHeading = page.getByRole('heading', { name: 'Welcome to AetherFlow' });
    if (await onboardingHeading.isVisible()) {
      await page.getByRole('button', { name: /Continue/i }).click();
      await page.getByRole('button', { name: /Enter Dashboard/i }).click();
      await expect(onboardingHeading).toHaveCount(0);
    }

    // 3. Verify authenticated session & metrics history API directly in browser context
    const sessionCheck = await page.evaluate(async () => {
      const [sessRes, histRes, mktRes, plugRes] = await Promise.all([
        fetch('/api/v1/auth/session', { credentials: 'include' }),
        fetch('/api/v1/auth/system/metrics/history?window=24h&limit=2400&downsample=1&target_points=2400', {
          credentials: 'include',
        }),
        fetch('/api/v1/public/marketplace', { credentials: 'include' }),
        fetch('/api/v1/auth/plugins', { credentials: 'include' }),
      ]);
      return {
        sessStatus: sessRes.status,
        sessUser: await sessRes.json().catch(() => null),
        histStatus: histRes.status,
        histBody: await histRes.json().catch(() => null),
        mktStatus: mktRes.status,
        mktBody: await mktRes.json().catch(() => null),
        plugStatus: plugRes.status,
        plugBody: await plugRes.json().catch(() => null),
      };
    });

    expect(sessionCheck.sessStatus).toBe(200);
    expect(sessionCheck.sessUser?.username).toBe(ADMIN_USER);
    expect(sessionCheck.histStatus).toBe(200);
    expect(Array.isArray(sessionCheck.histBody)).toBeTruthy();
    expect(sessionCheck.mktStatus).toBe(200);
    expect(sessionCheck.plugStatus).toBe(200);
    expect(Array.isArray(sessionCheck.plugBody?.plugins)).toBeTruthy();
    expect(sessionCheck.plugBody.plugins.some((p: { id: string }) => p.id === 'telemetry-inspector')).toBeTruthy();

    // 3b. Verify sandboxed plugin UI headers and scoped plugin token security boundaries against live Rust backend
    const pluginBoundaryCheck = await page.evaluate(async () => {
      const csrfRes = await fetch('/api/v1/public/csrf-token', { credentials: 'include' });
      const csrfPayload = await csrfRes.json().catch(() => ({} as { csrf_token?: string }));
      const csrfToken = csrfPayload.csrf_token || '';
      const jsonHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-Token': csrfToken,
      };
      const stoppedUiRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/ui', { credentials: 'include' });
      const stoppedProxyRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/proxy/status', {
        credentials: 'include',
      });
      const stoppedTokRes = await fetch('/api/v1/admin/plugins/telemetry-inspector/token', {
        method: 'POST',
        credentials: 'include',
        headers: jsonHeaders,
        body: JSON.stringify({ ttl_seconds: 300 }),
      });

      const startRes = await fetch('/api/v1/admin/plugins/telemetry-inspector/control', {
        method: 'POST',
        credentials: 'include',
        headers: jsonHeaders,
        body: JSON.stringify({ action: 'start' }),
      });
      const startBody = await startRes.json().catch(() => ({}));

      const uiRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/ui', { credentials: 'include' });
      const csp = uiRes.headers.get('content-security-policy') || '';
      const xfo = uiRes.headers.get('x-frame-options') || '';
      const uiHtml = await uiRes.text().catch(() => '');

      const proxyRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/proxy/status', {
        credentials: 'include',
      });
      const proxyBody = await proxyRes.json().catch(() => ({}));

      const proxyPolicies = [];
      for (const prefix of [
        '/plugins/telemetry-inspector/proxy',
        '/api/auth/plugins/telemetry-%69nspector/proxy',
        '/api/v1/auth/plugins/telemetry-inspector/proxy',
      ]) {
        for (const suffix of ['status', 'ui', '%75i']) {
          const response = await fetch(`${prefix}/${suffix}`, { credentials: 'include' });
          proxyPolicies.push({
            path: `${prefix}/${suffix}`,
            status: response.status,
            csp: response.headers.get('content-security-policy'),
            xfo: response.headers.get('x-frame-options'),
            contentType: response.headers.get('content-type'),
            cacheControl: response.headers.get('cache-control'),
            pragma: response.headers.get('pragma'),
            expires: response.headers.get('expires'),
            sharedCacheHeaders: ['surrogate-control', 'cdn-cache-control', 'cloudflare-cdn-cache-control']
              .filter(header => response.headers.has(header)),
            body: await response.json(),
          });
        }
      }

      const snapshotRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/proxy/snapshot', {
        credentials: 'include',
      });
      const snapshotBody = await snapshotRes.json().catch(() => ({}));

      const tokRes = await fetch('/api/v1/admin/plugins/telemetry-inspector/token', {
        method: 'POST',
        credentials: 'include',
        headers: jsonHeaders,
        body: JSON.stringify({ ttl_seconds: 300 }),
      });
      const tokBody = await tokRes.json().catch(() => ({}));
      const pluginJwt = tokBody.token || '';

      // Allowed GET /api/v1/auth/system/metrics with plugin token (omit cookies so only Bearer is used)
      const allowedGet = await fetch('/api/v1/auth/system/metrics', {
        method: 'GET',
        credentials: 'omit',
        headers: { Authorization: `Bearer ${pluginJwt}` },
      });
      // Alternate HTTP method (POST) on allowed route must be denied (403)
      const deniedPost = await fetch('/api/v1/auth/system/metrics', {
        method: 'POST',
        credentials: 'omit',
        headers: { Authorization: `Bearer ${pluginJwt}`, 'X-Requested-With': 'XMLHttpRequest' },
      });
      // Unscoped admin endpoint must be denied (403)
      const deniedAdmin = await fetch('/api/v1/admin/users', {
        method: 'GET',
        credentials: 'omit',
        headers: { Authorization: `Bearer ${pluginJwt}` },
      });
      // Session refresh with plugin Bearer token must be denied (401/403)
      const deniedRefresh = await fetch('/api/v1/public/auth/refresh', {
        method: 'POST',
        credentials: 'omit',
        headers: { Authorization: `Bearer ${pluginJwt}`, 'X-Requested-With': 'XMLHttpRequest' },
      });

      const stopRes = await fetch('/api/v1/admin/plugins/telemetry-inspector/control', {
        method: 'POST',
        credentials: 'include',
        headers: jsonHeaders,
        body: JSON.stringify({ action: 'stop' }),
      });
      const stopBody = await stopRes.json().catch(() => ({}));

      const revokedTokenGet = await fetch('/api/v1/auth/system/metrics', {
        method: 'GET',
        credentials: 'omit',
        headers: { Authorization: `Bearer ${pluginJwt}` },
      });
      const stoppedUiAfterRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/ui', {
        credentials: 'include',
      });
      const stoppedProxyAfterRes = await fetch('/api/v1/auth/plugins/telemetry-inspector/proxy/status', {
        credentials: 'include',
      });

      return {
        stoppedUiStatus: stoppedUiRes.status,
        stoppedProxyStatus: stoppedProxyRes.status,
        stoppedTokStatus: stoppedTokRes.status,
        startStatus: startRes.status,
        startedPlugin: startBody.plugin || null,
        uiStatus: uiRes.status,
        csp,
        xfo,
        uiHtml,
        proxyStatus: proxyRes.status,
        proxyBody,
        proxyPolicies,
        snapshotStatus: snapshotRes.status,
        snapshotBody,
        tokStatus: tokRes.status,
        tokenType: tokBody.token_type,
        audience: tokBody.audience,
        allowedGetStatus: allowedGet.status,
        deniedPostStatus: deniedPost.status,
        deniedAdminStatus: deniedAdmin.status,
        deniedRefreshStatus: deniedRefresh.status,
        stopStatus: stopRes.status,
        stoppedPlugin: stopBody.plugin || null,
        revokedTokenStatus: revokedTokenGet.status,
        stoppedUiAfterStatus: stoppedUiAfterRes.status,
        stoppedProxyAfterStatus: stoppedProxyAfterRes.status,
      };
    });

    expect(pluginBoundaryCheck.stoppedUiStatus).toBe(403);
    expect(pluginBoundaryCheck.stoppedProxyStatus).toBe(503);
    expect(pluginBoundaryCheck.stoppedTokStatus).toBe(409);
    expect(pluginBoundaryCheck.startStatus).toBe(200);
    expect(pluginBoundaryCheck.startedPlugin?.enabled).toBe(true);
    expect(pluginBoundaryCheck.startedPlugin?.status).toBe('running');
    expect(pluginBoundaryCheck.startedPlugin?.healthy).toBe(true);
    expect(pluginBoundaryCheck.startedPlugin?.allocated_port).toBeGreaterThanOrEqual(21000);
    expect(pluginBoundaryCheck.startedPlugin?.allocated_port).toBeLessThanOrEqual(21999);
    expect(pluginBoundaryCheck.uiStatus).toBe(200);
    expect(pluginBoundaryCheck.csp).toContain('sandbox allow-scripts');
    expect(pluginBoundaryCheck.xfo).toBe('SAMEORIGIN');
    expect(pluginBoundaryCheck.uiHtml).toContain('Managed Loopback Runtime v1.0.0');
    expect(pluginBoundaryCheck.proxyStatus).toBe(200);
    expect(pluginBoundaryCheck.proxyBody?.status).toBe('ok');
    expect(pluginBoundaryCheck.proxyBody?.plugin_id).toBe('telemetry-inspector');
    expect(pluginBoundaryCheck.proxyBody?.runtime_mode).toBe('managed');
    expect(pluginBoundaryCheck.proxyBody?.listen_port).toBe(pluginBoundaryCheck.startedPlugin?.allocated_port);
    expect(pluginBoundaryCheck.proxyBody?.auth_token_configured).toBe(true);
    expect(pluginBoundaryCheck.proxyBody?.had_cookie_header).toBe(false);
    expect(pluginBoundaryCheck.proxyBody?.had_authorization_header).toBe(false);
    expect(pluginBoundaryCheck.proxyPolicies).toHaveLength(9);
    for (const response of pluginBoundaryCheck.proxyPolicies) {
      expect(response.csp, response.path).toBe("sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
      expect(response.xfo, response.path).toBe('DENY');
      expect(response.contentType, response.path).toContain('application/json');
      expect(response.cacheControl, response.path).toBe('private, no-store');
      expect(response.pragma, response.path).toBe('no-cache');
      expect(response.expires, response.path).toBe('0');
      expect(response.sharedCacheHeaders, response.path).toEqual([]);
      expect(response.status, response.path).toBe(response.path.endsWith('/status') ? 200 : 404);
      if (response.status === 200) {
        expect(response.body.status, response.path).toBe('ok');
        expect(response.body.had_cookie_header, response.path).toBe(false);
        expect(response.body.had_authorization_header, response.path).toBe(false);
      }
    }
    expect(pluginBoundaryCheck.snapshotStatus).toBe(200);
    expect(pluginBoundaryCheck.snapshotBody?.marketplace_status).toBe(200);
    expect(pluginBoundaryCheck.snapshotBody?.metrics_status).toBe(200);
    expect(pluginBoundaryCheck.tokStatus).toBe(200);
    expect(pluginBoundaryCheck.tokenType).toBe('plugin');
    expect(pluginBoundaryCheck.audience).toBe('aetherflow-plugin-api');
    expect(pluginBoundaryCheck.allowedGetStatus).toBe(200);
    expect(pluginBoundaryCheck.deniedPostStatus).toBe(403);
    expect(pluginBoundaryCheck.deniedAdminStatus).toBe(403);
    expect([401, 403]).toContain(pluginBoundaryCheck.deniedRefreshStatus);
    expect(pluginBoundaryCheck.stopStatus).toBe(200);
    expect(pluginBoundaryCheck.stoppedPlugin?.enabled).toBe(false);
    expect(pluginBoundaryCheck.revokedTokenStatus).toBe(401);
    expect(pluginBoundaryCheck.stoppedUiAfterStatus).toBe(403);
    expect(pluginBoundaryCheck.stoppedProxyAfterStatus).toBe(503);

    const windowSelector = page.getByRole('group', { name: 'Telemetry History Window' });
    await expect(windowSelector).toBeVisible();
    const expandedHistoryPromise = completedTelemetryHistory(page, '24h');
    await page.getByTestId('history-window-24h').click();
    expect((await (await expandedHistoryPromise).json()).length).toBeGreaterThan(1);
    await page.getByTestId('history-window-1h').click();
    await page.getByTestId('history-window-5m').click();
    await expect(page.locator('path.recharts-area-curve').first()).toHaveAttribute('d', /\S+/);

    const sidebar = page.locator('aside').first();
    await expect(sidebar).toBeVisible();
    await sidebar.hover();
    await sidebar.getByRole('button', { name: /Marketplace/i }).click();
    await expect(page.getByRole('heading', { name: /AetherMarketplace/i })).toBeVisible();
    await expect(page.getByTestId('installed-plugins-section')).toBeVisible();
    const pluginCard = page.getByTestId('plugin-card-telemetry-inspector');
    await expect(pluginCard).toBeVisible();
    await expect(pluginCard.getByText('Stopped', { exact: true })).toBeVisible();
    await page.getByTestId('toggle-plugin-telemetry-inspector').click();
    await expect(pluginCard.getByText('Healthy', { exact: true })).toBeVisible();
    await page.getByTestId('open-plugin-ui-telemetry-inspector').click();
    const iframe = page.getByTestId('plugin-sandbox-iframe');
    await expect(iframe).toBeVisible();
    await expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');
    await expect(iframe).toHaveAttribute('title', 'Plugin Sandbox: Telemetry Inspector');
    const sandboxFrame = page.frameLocator('[data-testid="plugin-sandbox-iframe"]');
    await expect(sandboxFrame.getByText('Telemetry Inspector', { exact: true }).first()).toBeVisible();
    await expect(sandboxFrame.getByTestId('telemetry-inspector-bundle-badge')).toHaveText('Managed Loopback Runtime v1.0.0');
    await expect(sandboxFrame.getByTestId('telemetry-inspector-bridge-output')).toContainText('"runtime_mode": "managed"');
    await page.getByTestId('close-plugin-sandbox').click();
    await expect(iframe).toHaveCount(0);
    await page.getByTestId('toggle-plugin-telemetry-inspector').click();
    await expect(pluginCard.getByText('Stopped', { exact: true })).toBeVisible();

    await sidebar.hover();
    await sidebar.getByRole('button', { name: /Settings/i }).click();
    await expect(page.getByRole('heading', { name: 'Navigation & Localization' })).toBeVisible();

    seedFreshTelemetryHistory();
    await sidebar.hover();
    await sidebar.getByRole('button', { name: /Overview/i }).click();
    await expect(windowSelector).toBeVisible();
    const reconnectedSocketPromise = page.waitForEvent('websocket', {
      predicate: (socket) => new URL(socket.url()).pathname === '/api/v1/auth/ws',
    });
    const reconnectedHistoryPromise = completedTelemetryHistory(page);
    const closedSocketCount = await page.evaluate(() => {
      const testWindow = window as Window & { __afAcceptanceSockets?: WebSocket[] };
      const liveSockets = (testWindow.__afAcceptanceSockets ?? []).filter((socket) =>
        new URL(socket.url).pathname === '/api/v1/auth/ws' && socket.readyState === WebSocket.OPEN
      );
      liveSockets.forEach((socket) => socket.close(1000, 'Acceptance test transport interruption'));
      return liveSockets.length;
    });
    expect(closedSocketCount).toBe(1);
    // Firefox can report a socket-error notification while processing close().
    // Assert the actual closed state instead of letting the event waiter reject
    // before the browser delivers its close notification.
    await expect.poll(() => firstSocket.isClosed()).toBe(true);
    const reconnectedSocket = await reconnectedSocketPromise;
    const reconnectedFrame = await reconnectedSocket.waitForEvent('framereceived');
    expect(reconnectedFrame.payload).toBeTruthy();
    expect((await (await reconnectedHistoryPromise).json()).length).toBeGreaterThan(1);
    await expect(page.getByText('Live Telemetry')).toBeVisible();

    const reloadedHistoryPromise = completedTelemetryHistory(page);
    await page.reload();
    await expect(page).not.toHaveURL(/\/login/);
    expect((await (await reloadedHistoryPromise).json()).length).toBeGreaterThan(1);
    await expect(windowSelector).toBeVisible();
    await expect(page.getByText('Live Telemetry')).toBeVisible();
    await expect(page.locator('path.recharts-area-curve').first()).toHaveAttribute('d', /\S+/);

    // Use an isolated real file so font/focus coverage never changes an existing README.
    const editorDirectory = `live-editor-${Date.now()}`;
    try {
      const fixture = await page.evaluate(async (directory) => {
        const csrf = await fetch('/api/v1/public/csrf-token', { credentials: 'include' });
        const token = (await csrf.json()).csrf_token;
        const headers = {
          'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest',
          'X-CSRF-Token': token,
        };
        const mkdir = await fetch('/api/v1/auth/mcbrowser/directory', {
          method: 'POST', credentials: 'include', headers, body: JSON.stringify({ path: directory }),
        });
        if (!mkdir.ok) throw new Error(`Editor fixture directory: HTTP ${mkdir.status}`);
        const file = await fetch('/api/v1/auth/mcbrowser/file', {
          method: 'POST', credentials: 'include', headers,
          body: JSON.stringify({ path: `${directory}/README.md`, content: '# AetherFlow\n\nLive editor regression.\n' }),
        });
        return { directory: mkdir.status, file: file.status };
      }, editorDirectory);
      expect([200, 201]).toContain(fixture.directory);
      expect([200, 201]).toContain(fixture.file);
      const fallback = await page.goto('/live-unknown-spa-route?tab=overview');
      expect(fallback?.headers()['content-security-policy']).toMatch(/(?:^|;)\s*style-src 'self'\s*(?:;|$)/);
      await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
      await expect(page).toHaveURL((url) => url.pathname === '/' && url.searchParams.get('tab') === 'overview');
      await page.evaluate(() => history.replaceState(null, '', '/live-unknown-spa-route'));
      await sidebar.getByRole('button', { name: 'Services', exact: true }).click();
      await expect(page).toHaveURL((url) => url.pathname === '/' && url.searchParams.get('tab') === 'services');

      await page.evaluate(() => localStorage.setItem('aetherflow-editor-font-size', '14'));
      await sidebar.getByRole('button', { name: 'McBrowser', exact: true }).click();
      await page.getByRole('button', { name: `Directory ${editorDirectory}`, exact: true }).click();
      await page.getByRole('button', { name: 'File README.md', exact: true }).click();
      const editorDialog = page.getByRole('dialog', { name: 'Code editor', exact: true });
      await expect(editorDialog).toBeVisible();
      const editor = editorDialog.locator('.af-editor-body');
      await expect(editor).toHaveClass(/\baf-editor-fs-14\b/);
      await editorDialog.getByRole('button', { name: 'Increase font size', exact: true }).click();
      await expect(editor).toHaveClass(/\baf-editor-fs-15\b/);
      await expect(editor).toHaveCSS('font-size', '15px');
      await editorDialog.getByRole('button', { name: 'Decrease font size', exact: true }).click();
      await expect(editor).toHaveClass(/\baf-editor-fs-14\b/);
      await expect(editor).toHaveCSS('font-size', '14px');
      await expect(editorDialog.locator('[style]')).toHaveCount(0);
      expect(await editorDialog.innerText()).not.toMatch(/on:(?:click|input|change|keydown|submit)=move\s*\||font\.(?:get|update)\(/);

      const focusable = editorDialog.locator('button:not([disabled]):visible, [href]:visible, input:not([disabled]):visible, select:not([disabled]):visible, textarea:not([disabled]):visible, [tabindex]:not([tabindex="-1"]):visible');
      await focusable.first().focus();
      await page.keyboard.press('Shift+Tab');
      await expect(focusable.last()).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(focusable.first()).toBeFocused();
      await editorDialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
    } finally {
      const cleanupStatus = await page.evaluate(async (directory) => {
        const csrf = await fetch('/api/v1/public/csrf-token', { credentials: 'include' });
        const headers = {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-CSRF-Token': (await csrf.json()).csrf_token,
        };
        const response = await fetch('/api/v1/auth/mcbrowser/delete-recursive', {
          method: 'POST',
          credentials: 'include',
          headers,
          body: JSON.stringify({ path: directory }),
        });
        return response.status;
      }, editorDirectory);
      expect([200, 204, 404]).toContain(cleanupStatus);
    }

    await test.step('a nonzero persisted quota initializes its allocation editor', async () => {
      const userId = sessionCheck.sessUser.id;
      expect(Number(userId)).toBeGreaterThan(0);
      provisionPersistedQuota(Number(userId), 107374182400);
      const persisted = await page.request.get('/api/v1/admin/quotas');
      expect(persisted.ok()).toBeTruthy();
      const { quotas } = await persisted.json();
      expect(Array.isArray(quotas)).toBe(true);
      const quota = quotas.find((row: { user_id: number }) => row.user_id === Number(userId));
      expect(quota).toBeTruthy();
      expect(quota.quota_bytes).toBe(107374182400);
      await page.goto('/?tab=quotas');
      const row = page.locator('[data-quota-row="true"]').filter({
        has: page.getByRole('heading', { name: `${ADMIN_USER} · #${userId}`, exact: true }),
      });
      await expect(row).toContainText(/100(?:[.,]0)?\s*GiB/);
      await expect(row.getByLabel('Allocated disk space', { exact: true })).toHaveValue('107374182400B');
      await page.reload();
      await expect(row.getByLabel('Allocated disk space', { exact: true })).toHaveValue('107374182400B');
    });

    await test.step('settings save preserves an intervening edit back to the original baseline', async () => {
      const settings = await page.request.get('/api/v1/auth/settings');
      expect(settings.ok()).toBeTruthy();
      const initial = await settings.json();
      const baseline = initial.timezone;
      expect(typeof baseline).toBe('string');
      const submitted = baseline === 'Europe/Paris' ? 'UTC' : 'Europe/Paris';
      await page.goto('/?tab=settings');
      const timezone = page.getByLabel('Timezone', { exact: true });
      await expect(timezone).toHaveValue(baseline);
      await timezone.fill(submitted);
      const save = page.getByRole('button', { name: 'Save Settings', exact: true });
      await expect(save).toBeEnabled();
      const savedResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === '/api/v1/admin/settings' && response.request().method() === 'PUT'
      );
      // Both events run in one browser task. The edit is guaranteed to precede any
      // network response, while the real Save handler has already captured its draft.
      await save.evaluate((button, original) => {
        const input = Array.from(document.querySelectorAll<HTMLInputElement>('input'))
          .find((candidate) => candidate.closest('label')?.textContent?.trim() === 'Timezone');
        if (!input) throw new Error('Timezone input is unavailable');
        (button as HTMLButtonElement).click();
        input.value = original;
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }, baseline);
      const firstSave = await savedResponse;
      expect(firstSave.ok()).toBeTruthy();
      expect(firstSave.request().postDataJSON().timezone).toBe(submitted);
      // Waiting for Save to re-enable also waits for the server readback and draft acknowledgement.
      await expect(save).toBeEnabled();
      await expect(timezone).toHaveValue(baseline);
      const firstReadback = await page.request.get('/api/v1/auth/settings');
      expect(firstReadback.ok()).toBeTruthy();
      expect((await firstReadback.json()).timezone).toBe(submitted);
      const secondSave = page.waitForResponse((response) =>
        new URL(response.url()).pathname === '/api/v1/admin/settings' && response.request().method() === 'PUT'
      );
      await save.click();
      expect((await secondSave).ok()).toBeTruthy();
      await expect(save).toBeDisabled();
      await page.reload();
      await expect(timezone).toHaveValue(baseline);
      const finalReadback = await page.request.get('/api/v1/auth/settings');
      expect(finalReadback.ok()).toBeTruthy();
      expect((await finalReadback.json()).timezone).toBe(baseline);
    });

    await test.step('a retained McBrowser queue uploads after a profile session recheck', async () => {
      const filename = `live-retained-upload-${Date.now()}.txt`;
      const content = 'A retained queue survives a same-user session refresh.\n';
      const originalEmail = sessionCheck.sessUser.email || '';
      const updatedEmail = `live-profile-${Date.now()}@example.com`;
      try {
        await page.goto('/?tab=mcbrowser');
        const upload = page.getByLabel('Choose files to upload', { exact: true });
        await expect(upload).toBeAttached();
        const retainedInput = await upload.elementHandle();
        expect(retainedInput).not.toBeNull();
        await sidebar.getByRole('button', { name: 'Settings', exact: true }).click();
        await page.getByRole('tab', { name: 'Security & 2FA', exact: true }).click();
        await page.getByLabel('Email address', { exact: true }).fill(updatedEmail);
        const rechecked = page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/api/v1/auth/session' && response.ok()
        );
        await page.getByRole('button', { name: 'Update profile', exact: true }).click();
        expect((await (await rechecked).json()).email).toBe(updatedEmail);
        await sidebar.getByRole('button', { name: 'McBrowser', exact: true }).click();
        expect(await retainedInput!.evaluate((input) => input.isConnected)).toBe(true);
        const uploaded = page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/api/v1/auth/mcbrowser/upload'
            && response.request().method() === 'PUT'
        );
        await upload.setInputFiles({ name: filename, mimeType: 'text/plain', buffer: Buffer.from(content) });
        expect((await uploaded).ok()).toBeTruthy();
        const queue = page.getByRole('dialog', { name: 'Transfer queue', exact: true });
        await expect(queue).toBeVisible();
        await expect(queue).toContainText(filename);
        await expect(queue.getByText('Completed', { exact: true })).toBeVisible();
        const stored = await page.request.get(`/api/v1/auth/mcbrowser/content?path=${encodeURIComponent(filename)}`);
        expect(stored.ok()).toBeTruthy();
        expect((await stored.json()).content).toBe(content);
        await queue.getByRole('button', { name: 'Close dialog', exact: true }).click();
      } finally {
        // Setup accounts may have an empty email, which the public profile API
        // cannot write. Restore only this isolated fixture row directly.
        restoreProfileEmail(Number(sessionCheck.sessUser.id), originalEmail);
        const headers = await mutationHeaders(page);
        const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', { headers, data: { path: filename } });
        expect([200, 204, 404]).toContain(deleted.status());
      }
    });

    await test.step('a real channel save preserves a name edited while the request is pending', async () => {
      const submitted = `live-channel-${Date.now()}`;
      const newer = `${submitted} edited`;
      const endpoint = '**/api/v1/admin/notifications/channels';
      const delayCreation = async (route: Route) => {
        if (route.request().method() === 'POST') {
          await new Promise<void>((resolve) => setTimeout(resolve, 350));
        }
        await route.continue();
      };
      let channelId: number | undefined;
      await page.route(endpoint, delayCreation);
      try {
        await page.goto('/?tab=notifications');
        await page.getByRole('button', { name: 'Add channel', exact: true }).click();
        const dialog = page.getByRole('dialog', { name: 'Configure delivery channel', exact: true });
        await dialog.getByLabel('Channel name', { exact: true }).fill(submitted);
        await dialog.getByRole('combobox', { name: 'Delivery provider', exact: true }).selectOption('webhook', { timeout: 10_000 });
        await expect(dialog.getByRole('combobox', { name: 'Delivery provider', exact: true })).toHaveValue('webhook');
        await dialog.getByLabel('Delivery URL', { exact: true }).fill('https://example.com/live-alerts');
        await expect(dialog.getByLabel('Delivery URL', { exact: true })).toHaveValue('https://example.com/live-alerts');
        const created = page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/api/v1/admin/notifications/channels'
            && response.request().method() === 'POST', { timeout: 15_000 }
        );
        // Submit and edit in the same browser task so the newer input precedes
        // the real response even on a heavily loaded test host.
        await dialog.getByRole('button', { name: 'Create channel', exact: true }).evaluate((button, name) => {
          const input = button.closest('dialog')?.querySelector<HTMLInputElement>('input[type="text"]');
          if (!input) throw new Error('Channel name input is unavailable');
          (button as HTMLButtonElement).click();
          input.value = name;
          input.dispatchEvent(new Event('input', { bubbles: true }));
        }, newer);
        const response = await created;
        expect([200, 201]).toContain(response.status());
        channelId = Number((await response.json()).id);
        expect(channelId).toBeGreaterThan(0);
        expect(response.request().postDataJSON().name).toBe(submitted);
        await expect(page.getByText('Delivery channel created', { exact: true })).toBeVisible();
        await expect(dialog).toBeVisible();
        await expect(dialog.getByLabel('Channel name', { exact: true })).toHaveValue(newer);
        const channels = await page.request.get('/api/v1/admin/notifications/channels');
        expect(channels.ok()).toBeTruthy();
        expect((await channels.json()).channels.find((channel: { id: number }) => channel.id === channelId)?.name).toBe(submitted);
        await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
      } finally {
        await page.unroute(endpoint, delayCreation);
        if (channelId) {
          const headers = await mutationHeaders(page);
          const deleted = await page.request.delete(`/api/v1/admin/notifications/channels/${channelId}`, { headers });
          expect([200, 204, 404]).toContain(deleted.status());
        }
      }
    });

    await test.step('Unicode fileshare uploads and backup reauthentication reach the real backend', async () => {
      const fixture = process.env.AETHERFLOW_UPLOAD_DIR;
      expect(fixture, 'Fileshare uploads require the isolated upload root').toBeTruthy();
      const fixtureRoot = realpathSync(fixture!);
      expect(basename(fixtureRoot)).toBe('uploads');
      expect(basename(dirname(fixtureRoot))).toMatch(/^aetherflow-embedded-e2e\./);
      // Fileshare paths are rooted inside AETHERFLOW_UPLOAD_DIR, including
      // paths displayed with a leading slash in the browser.
      const directory = `/live-unicode-${Date.now()}/médias`;
      const persistedDirectory = join(fixtureRoot, directory.slice(1));
      const filename = '文档-été.txt';
      const content = '中文文档 · fichier français\n';
      const pageErrors: string[] = [];
      const recordError = (error: Error) => pageErrors.push(error.message);
      page.on('pageerror', recordError);
      mkdirSync(persistedDirectory, { recursive: true });
      try {
        await page.goto('/?tab=fileshare');
        await page.getByLabel('Current directory', { exact: true }).fill(directory);
        const listing = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return url.pathname === '/api/v1/auth/fileshare' && url.searchParams.get('path') === directory;
        });
        await page.getByRole('button', { name: 'Go', exact: true }).click();
        expect((await listing).ok()).toBeTruthy();
        const uploaded = page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/api/v1/admin/fileshare/upload'
            && response.request().method() === 'POST'
        );
        await page.getByLabel('Select file to upload', { exact: true }).setInputFiles({
          name: filename, mimeType: 'text/plain', buffer: Buffer.from(content),
        });
        const response = await uploaded;
        expect(response.status()).toBe(200);
        expect((await response.json()).complete).toBe(true);
        const uploadHeaders = response.request().headers();
        expect(decodeURIComponent(uploadHeaders['x-target-path-encoded'])).toBe(directory);
        expect(decodeURIComponent(uploadHeaders['x-file-name-encoded'])).toBe(filename);
        expect(uploadHeaders['x-target-path']).toBeUndefined();
        expect(uploadHeaders['x-file-name']).toBeUndefined();
        expect(readFileSync(join(persistedDirectory, filename), 'utf8')).toBe(content);

        const headers = await mutationHeaders(page);
        const backups = await page.request.get('/api/v1/admin/backup/list');
        expect(backups.ok()).toBeTruthy();
        const existing = await backups.json();
        let archive = existing[0]?.filename as string | undefined;
        if (!archive) {
          const created = await page.request.post('/api/v1/admin/backup/run', { headers });
          expect(created.ok()).toBeTruthy();
          archive = (await created.json()).filename;
        }
        expect(archive).toBeTruthy();
        // Reload after direct fixture mutations so the browser obtains its own CSRF token.
        await page.goto('/?tab=settings', { waitUntil: 'domcontentloaded' });
        const backupsTab = page.getByRole('tab', { name: 'Backups & Restore', exact: true });
        await backupsTab.press('Enter');
        await expect(backupsTab).toHaveAttribute('aria-selected', 'true');
        await page.getByRole('gridcell', { name: archive!, exact: true }).click();
        const dialog = page.getByRole('dialog', { name: 'Download verified backup', exact: true });
        const password = '密码-échec-été';
        await dialog.getByLabel('Current password', { exact: true }).fill(password);
        const authorized = page.waitForResponse((response) =>
          new URL(response.url()).pathname === `/api/v1/admin/backup/download/${archive}`
            && response.request().method() === 'POST'
        );
        await dialog.getByRole('button', { name: 'Download archive', exact: true }).click();
        const authorization = await authorized;
        expect(authorization.status()).toBe(403);
        expect(authorization.headers()['content-type']).toContain('application/json');
        expect((await authorization.json()).code).toBe('INVALID_CURRENT_PASSWORD');
        expect(authorization.request().postDataJSON()).toEqual({ password });
        expect(authorization.request().headers()['x-reauth-password']).toBeUndefined();
        expect(pageErrors).toEqual([]);
        await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
      } finally {
        page.off('pageerror', recordError);
        rmSync(dirname(persistedDirectory), { recursive: true, force: true });
      }
    });

    await test.step('the approval inbox finds an older pending action beyond executed history', async () => {
      const marker = `live-approval-${Date.now()}`;
      approvalHistoryFixture(marker, 'seed');
      try {
        const pending = await page.request.get('/api/v1/admin/actions/pending?status=pending&limit=50&offset=0');
        expect(pending.ok()).toBeTruthy();
        const pendingBody = await pending.json();
        expect(pendingBody.total).toBeGreaterThanOrEqual(1);
        expect(pendingBody.actions.some((action: { action: string }) => action.action === `${marker} pending`)).toBe(true);
        const loaded = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return url.pathname === '/api/v1/admin/actions/pending' && url.searchParams.get('limit') === '50';
        });
        await page.goto('/?tab=inbox');
        expect(new URL((await loaded).url()).searchParams.get('status')).toBe('pending');
        await expect(page.getByRole('heading', { name: `${marker} pending`, exact: true })).toBeVisible();
        await expect(page.getByText(`${pendingBody.total} matching records`, { exact: true })).toBeVisible();
        const historyPage = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return url.pathname === '/api/v1/admin/actions/pending'
            && url.searchParams.get('status') === 'approved_history' && url.searchParams.get('offset') === '0';
        });
        await page.getByRole('tab', { name: 'Approved / Executed', exact: true }).click();
        const history = await (await historyPage).json();
        expect(history.total).toBeGreaterThanOrEqual(502);
        expect(history.actions).toHaveLength(50);
        const boundary = await page.request.get('/api/v1/admin/actions/pending?status=approved_history&limit=50&offset=500');
        expect(boundary.ok()).toBeTruthy();
        const boundaryBody = await boundary.json();
        expect(boundaryBody.total).toBe(history.total);
        expect(boundaryBody.actions).toHaveLength(Math.min(50, history.total - 500));
        const pagination = page.getByRole('navigation', { name: 'Approval inbox pagination', exact: true });
        const nextPage = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return url.pathname === '/api/v1/admin/actions/pending'
            && url.searchParams.get('status') === 'approved_history' && url.searchParams.get('offset') === '50';
        });
        await pagination.getByRole('button', { name: 'Next', exact: true }).click();
        expect((await nextPage).ok()).toBeTruthy();
        await expect(pagination).toContainText('Page 2 of');
        const resetPage = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return url.pathname === '/api/v1/admin/actions/pending' && url.searchParams.get('status') === 'pending'
            && url.searchParams.get('limit') === '50' && url.searchParams.get('offset') === '0';
        });
        await page.getByRole('tab', { name: 'Pending Approval', exact: true }).click();
        expect((await resetPage).ok()).toBeTruthy();
        await expect(page.getByRole('heading', { name: `${marker} pending`, exact: true })).toBeVisible();
      } finally {
        approvalHistoryFixture(marker, 'cleanup');
      }
    });

    await test.step('French browser detection localizes public login errors and sidebar names', async () => {
      const frenchContext = await browser.newContext({ baseURL: new URL(page.url()).origin, locale: 'fr-FR', serviceWorkers: 'block' });
      try {
        const french = await frenchContext.newPage();
        await french.goto('/login');
        expect(await french.evaluate(() => navigator.language)).toBe('fr-FR');
        const locale = french.locator('select.af-locale-select');
        await expect(locale).toBeVisible();
        await expect(locale).toHaveValue('fr');
        await expect(french.locator('html')).toHaveAttribute('lang', 'fr');
        await french.locator('input[type="text"]').first().fill(ADMIN_USER);
        await french.locator('input[type="password"]').first().fill('invalid-live-password');
        await french.locator('button[type="submit"]').first().click();
        await expect(french.getByRole('alert')).toHaveText('Authentification refusée : identifiants incorrects.');
        await expect(french.getByRole('alert')).not.toContainText('Invalid username or password');
        await french.locator('input[type="password"]').first().fill(ADMIN_PASS);
        await french.locator('button[type="submit"]').first().click();
        await expect(french).not.toHaveURL(/\/login/);
        // The account's server default is English. Select French explicitly
        // for the authenticated navigation's Label-in-Name verification.
        await french.locator('header select.af-locale-select').selectOption('fr');
        await expect(french.locator('html')).toHaveAttribute('lang', 'fr');
        const settings = french.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Paramètres', exact: true });
        await expect(settings).toBeVisible();
        await expect(settings).toHaveAccessibleName('Paramètres');
        await expect(settings).toHaveText('Paramètres');
      } finally {
        await frenchContext.close();
      }
    });

    await test.step('an ordinary user is clamped out of quotas and FlowAI calls chat exclusively', async () => {
      const username = MEMBER_USER;
      const userId = provisionOrdinaryUser(username);
      const memberContext = await browser.newContext({ baseURL: new URL(page.url()).origin, serviceWorkers: 'block' });
      let primaryError: unknown;
      try {
        const member = await memberContext.newPage();
        member.setDefaultTimeout(15_000);
        await member.goto('/login', { waitUntil: 'domcontentloaded' });
        await member.locator('input[type="text"]').first().fill(username);
        await member.locator('input[type="password"]').first().fill(ADMIN_PASS);
        const signedIn = member.waitForResponse((response) =>
          new URL(response.url()).pathname === '/api/v1/public/auth/login'
            && response.request().method() === 'POST'
        );
        await member.locator('button[type="submit"]').first().click();
        const loginResponse = await signedIn;
        expect(loginResponse.request().postDataJSON()).toEqual({ username, password: ADMIN_PASS });
        expect(loginResponse.status()).toBe(200);
        await expect(member).not.toHaveURL(/\/login/);
        const session = await member.request.get('/api/v1/auth/session');
        expect(session.ok()).toBeTruthy();
        expect((await session.json()).role).toBe('user');
        const denied = await member.request.get('/api/v1/admin/quotas');
        expect(denied.status()).toBe(403);
        // Let the login redirect render before starting another document navigation.
        await expect(member.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
        // The role clamp can normalize the URL before the document's load event.
        const quotaNavigation = await member.goto('/?tab=quotas', { waitUntil: 'commit' });
        expect(quotaNavigation?.status()).toBe(200);
        await expect(member).toHaveURL((url) => url.pathname === '/' && !url.searchParams.has('tab'));
        await expect(member.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

        const aiRequests: string[] = [];
        member.on('request', (request) => {
          const path = new URL(request.url()).pathname;
          if (path.startsWith('/api/v1/auth/ai/')) aiRequests.push(path);
        });
        await member.goto('/?tab=ai', { waitUntil: 'domcontentloaded' });
        const prompt = 'Reply with a brief greeting for the ordinary-user live route test.';
        await member.getByRole('textbox', { name: 'Message FlowAI', exact: true }).fill(prompt);
        const chat = member.waitForResponse((response) =>
          new URL(response.url()).pathname === '/api/v1/auth/ai/chat' && response.request().method() === 'POST',
          { timeout: 30_000 }
        );
        await member.getByRole('button', { name: 'Send', exact: true }).click();
        const reply = await chat;
        // A disposable server may have no inference provider configured; authorization and routing still apply.
        expect([401, 403, 404]).not.toContain(reply.status());
        expect(reply.request().postDataJSON().message).toBe(prompt);
        expect(reply.request().postDataJSON()).not.toHaveProperty('metrics_snapshot');
        expect(aiRequests).toContain('/api/v1/auth/ai/chat');
        expect(aiRequests.filter((path) => path === '/api/v1/auth/ai/support')).toHaveLength(0);
      } catch (error) {
        primaryError = error;
        throw error;
      } finally {
        try {
          await memberContext.close();
          const removed = await page.request.delete(`/api/v1/admin/users/${userId}`, {
            headers: await mutationHeaders(page),
            timeout: 10_000,
          });
          expect([200, 204]).toContain(removed.status());
        } catch (cleanupError) {
          if (!primaryError) throw cleanupError;
        }
      }
    });

    await test.step('unauthenticated consent denial never follows an unregistered external callback', async () => {
      const origin = new URL(page.url()).origin;
      const anonymousContext = await browser.newContext({ baseURL: origin, serviceWorkers: 'block' });
      try {
        const consent = await anonymousContext.newPage();
        const externalNavigations: string[] = [];
        consent.on('framenavigated', (frame) => {
          if (frame === consent.mainFrame() && new URL(frame.url()).host === 'attacker.example') {
            externalNavigations.push(frame.url());
          }
        });
        await consent.goto('/oauth/consent?client_id=unregistered-e2e-client&redirect_uri=https%3A%2F%2Fattacker.example%2Fphish&response_type=code&scope=openid&state=probe1');
        await consent.getByRole('button', { name: 'Deny Access', exact: true }).click();
        await expect(consent.getByRole('alert')).toContainText('Authorization denied.');
        expect(new URL(consent.url()).host).toBe(new URL(origin).host);
        expect(new URL(consent.url()).hostname).toBe('127.0.0.1');
        expect(externalNavigations).toHaveLength(0);
      } finally {
        await anonymousContext.close();
      }
    });

    await test.step('streaming status tokens and French public errors are localized live', async () => {
      const dashboard = page.waitForResponse((response) =>
        new URL(response.url()).pathname === '/api/v1/auth/streaming/dashboard' && response.ok()
      );
      await page.goto('/?tab=streaming');
      const live = await (await dashboard).json();
      expect(live.servers.length).toBeGreaterThan(0);
      await expect(page.getByRole('heading', { name: 'Streaming Intelligence', exact: true })).toBeVisible();
      for (const server of live.servers as { name: string; status: string }[]) {
        await expect(page.getByRole('heading', { name: server.name, exact: true }).first()).toBeVisible();
        if (server.status === 'coming_soon') {
          await expect(page.getByText('Coming soon', { exact: true }).first()).toBeVisible();
        }
      }
      await expect(page.locator('body')).not.toContainText('coming_soon');

      const frenchContext = await browser.newContext({ baseURL: new URL(page.url()).origin, serviceWorkers: 'block' });
      try {
        await frenchContext.addInitScript(() => localStorage.setItem('aetherflow-language', 'fr'));
        const consent = await frenchContext.newPage();
        await consent.goto('/oauth/consent');
        await expect(consent.getByRole('alert')).toHaveText('Identifiant client de l’application manquant');
        await expect(consent.getByRole('alert')).not.toContainText('Missing application client ID');
      } finally {
        await frenchContext.close();
      }
    });
  });


  test('cross-tab account changes unmount the private editor and listing', async ({ page, context }) => {
    test.setTimeout(180_000);
    const memberUsername = `${MEMBER_USER}-switch`;
    provisionOrdinaryUser(memberUsername);
    await signInLive(page);
    const filename = `live-private-account-${Date.now()}.txt`;
    const secret = `Private administrator editor content ${filename}`;
    const probe = 'admin-only-cross-epoch-probe';
    const uploadPattern = '**/api/v1/auth/mcbrowser/upload?*';
    let releaseUpload!: () => void;
    let uploadStarted!: () => void;
    let uploadHandled!: () => void;
    const released = new Promise<void>((resolve) => { releaseUpload = resolve; });
    const started = new Promise<void>((resolve) => { uploadStarted = resolve; });
    const handled = new Promise<void>((resolve) => { uploadHandled = resolve; });
    let intercepted = false;
    let retryCount = 0;
    const holdUpload = async (route: Route) => {
      if (route.request().method() !== 'PUT'
        || new URL(route.request().url()).searchParams.get('path') !== probe) return route.continue();
      if (intercepted) {
        retryCount += 1;
        return route.continue();
      }
      intercepted = true;
      uploadStarted();
      try {
        await released;
        await route.fulfill({
          status: 403, contentType: 'application/json',
          body: JSON.stringify({ code: 'CSRF_INVALID', error: 'Invalid CSRF token' }),
        });
      } catch (error) {
        // Session invalidation may already have aborted the browser request.
        if (!route.request().failure()) throw error;
      } finally {
        uploadHandled();
      }
    };
    await page.route(uploadPattern, holdUpload);
    const second = await context.newPage();
    try {
      const headers = await mutationHeaders(page);
      const created = await page.request.post('/api/v1/auth/mcbrowser/file', {
        headers, data: { path: filename, content: secret },
      });
      expect(created.ok()).toBeTruthy();
      await page.goto('/?tab=mcbrowser');
      const privateRow = page.getByRole('button', { name: `File ${filename}`, exact: true });
      await expect(privateRow).toBeVisible();
      const retainedRow = await privateRow.elementHandle();
      await privateRow.click();
      const editor = page.getByRole('dialog', { name: 'Code editor', exact: true });
      await expect(editor.getByRole('textbox', { name: 'Editor text', exact: true })).toHaveValue(secret);
      const retainedEditor = await editor.elementHandle();
      await page.getByLabel('Choose files to upload', { exact: true }).setInputFiles({
        name: probe, mimeType: 'text/plain', buffer: Buffer.from('Administrator-only mutation fixture'),
      });
      await started;
      const memberSession = page.waitForResponse(
        async (response) => new URL(response.url()).pathname === '/api/v1/auth/session' && response.ok()
          && (await response.json()).username === memberUsername,
        { timeout: 120_000 }
      );
      void memberSession.catch(() => {});
      await signInLive(second, memberUsername);
      // Login's real BroadcastChannel/storage notification rechecks the first page.
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await memberSession;
      releaseUpload();
      await handled;
      await expect(editor).toHaveCount(0);
      await expect(privateRow).toHaveCount(0);
      expect(await retainedEditor!.evaluate((element) => element.isConnected)).toBe(false);
      expect(await retainedRow!.evaluate((element) => element.isConnected)).toBe(false);
      await expect(page.locator('main')).not.toContainText(secret);
      expect(await page.locator('textarea').evaluateAll((inputs) => inputs.some((input) => input instanceof HTMLTextAreaElement && input.value.includes('Private administrator editor content')))).toBe(false);
      const currentSession = await page.request.get('/api/v1/auth/session');
      expect((await currentSession.json()).role).toBe('user');
      const memberListing = await page.request.get('/api/v1/auth/mcbrowser/entries?path=');
      expect(memberListing.ok()).toBeTruthy();
      expect(await memberListing.text()).not.toContain(filename);
      expect(await memberListing.json()).toEqual(expect.objectContaining({
        entries: expect.not.arrayContaining([expect.objectContaining({ name: probe })]),
      }));
      await page.waitForLoadState('networkidle');
      expect(retryCount).toBe(0);
      const verifiedListing = await page.request.get('/api/v1/auth/mcbrowser/entries?path=');
      expect(verifiedListing.ok()).toBeTruthy();
      expect(await verifiedListing.text()).not.toContain(probe);
    } finally {
      releaseUpload();
      await page.unroute(uploadPattern, holdUpload);
      if (intercepted) await handled;
      const cleanupSession = await page.request.get('/api/v1/auth/session');
      if (cleanupSession.ok() && (await cleanupSession.json()).username === memberUsername) {
        const memberHeaders = await mutationHeaders(page);
        const removedProbe = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', {
          headers: memberHeaders, data: { path: probe },
        });
        expect([200, 204, 404]).toContain(removedProbe.status());
      }
      await second.close();
      await page.keyboard.press('Escape');
      await signInLive(page);
      const headers = await mutationHeaders(page);
      const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', { headers, data: { path: filename } });
      expect([200, 204, 404]).toContain(deleted.status());
    }
  });

  test('a public WAV share loads a blob audio preview under production CSP', async ({ page, browser }) => {
    test.setTimeout(65_000);
    await signInLive(page);
    const directory = `live-public-audio-${Date.now()}`;
    const path = `${directory}/silence.wav`;
    let shareId: string | undefined;
    const previewContext = await browser.newContext({ baseURL: new URL(page.url()).origin, serviceWorkers: 'block' });
    try {
      const headers = await mutationHeaders(page);
      const mkdir = await page.request.post('/api/v1/auth/mcbrowser/directory', { headers, data: { path: directory } });
      expect([200, 201]).toContain(mkdir.status());
      const upload = await page.request.put(`/api/v1/auth/mcbrowser/upload?path=${encodeURIComponent(path)}`, {
        headers: { ...headers, 'Content-Type': 'audio/wav' }, data: silentWav(),
      });
      expect(upload.status()).toBe(201);
      expect((await upload.json()).success).toBe(true);
      const created = await page.request.post('/api/v1/auth/mcbrowser/shares', {
        headers, data: { path, allow_download: true },
      });
      expect(created.status()).toBe(201);
      const share = (await created.json()).share;
      shareId = share.id;
      const url = new URL(share.url, page.url());
      const token = url.searchParams.get('token');
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const preview = await previewContext.newPage();
      await preview.addInitScript(() => {
        const target = window as Window & { __afCspViolations?: string[] };
        target.__afCspViolations = [];
        document.addEventListener('securitypolicyviolation', (event) => {
          target.__afCspViolations!.push(`${event.violatedDirective}: ${event.blockedURI}`);
        });
      });
      const response = await preview.goto(`/share?token=${token}`);
      expect(response?.ok()).toBeTruthy();
      expect(response?.headers()['content-security-policy']).toMatch(/(?:^|;)\s*media-src\s+[^;]*'self'[^;]*blob:/);
      const downloaded = preview.waitForResponse((response) =>
        new URL(response.url()).pathname === `/api/v1/public/mcbrowser/shares/${token}/download`
      );
      await preview.getByRole('button', { name: 'Preview', exact: true }).click();
      const attachment = await downloaded;
      expect(attachment.ok()).toBeTruthy();
      expect(attachment.headers()['content-type']).toBe('application/octet-stream');
      expect(attachment.headers()['content-disposition']).toMatch(/^attachment;/);
      expect(attachment.headers()['x-content-type-options']).toBe('nosniff');
      const audio = preview.locator('audio');
      await expect(audio).toBeVisible();
      await expect(audio).toHaveAttribute('src', /^blob:/);
      await expect.poll(() => audio.evaluate((element: HTMLAudioElement) => element.readyState)).toBeGreaterThanOrEqual(1);
      expect(await audio.evaluate((element: HTMLAudioElement) => element.duration)).toBeGreaterThan(0);
      expect(await preview.evaluate(() => (window as Window & { __afCspViolations?: string[] }).__afCspViolations)).toEqual([]);
      expect((await previewContext.cookies()).some((cookie) => cookie.name === 'aetherflow_session')).toBe(false);
    } finally {
      await previewContext.close();
      const headers = await mutationHeaders(page);
      if (shareId) {
        const revoked = await page.request.delete(`/api/v1/auth/mcbrowser/shares/${shareId}`, { headers });
        expect([200, 204, 404]).toContain(revoked.status());
      }
      const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', { headers, data: { path: directory } });
      expect([200, 204, 404]).toContain(deleted.status());
    }
  });

  test('same-account session rechecks preserve pending editor loads and saves', async ({ page }) => {
    test.setTimeout(90_000);
    // Keep the browser inside the recent-login window while the server handles
    // real session and file requests and browser timers continue to run.
    await page.clock.setFixedTime(new Date());
    await signInLive(page);
    const filename = `live-editor-session-${Date.now()}.txt`;
    const original = 'Editor load remains authorized across a same-account recheck.\n';
    let primaryError: unknown;
    try {
      const headers = await mutationHeaders(page);
      expect((await page.request.post('/api/v1/auth/mcbrowser/file', {
        headers, data: { path: filename, content: original },
      })).ok()).toBeTruthy();
      await page.goto('/?tab=mcbrowser');
      const fileRow = page.getByRole('button', { name: `File ${filename}`, exact: true });
      const load = await delayEditorRequest(page, 'GET');
      const dialog = page.getByRole('dialog', { name: 'Code editor', exact: true });
      const editor = dialog.getByRole('textbox', { name: 'Editor text', exact: true });
      try {
        await fileRow.click();
        await load.started;
        await expect(dialog).toBeVisible();
        const retained = await dialog.elementHandle();
        await recheckLiveSession(page);
        load.resume();
        await expect(editor).toHaveValue(original);
        await expect(editor).toBeEditable();
        expect(await retained!.evaluate((element) => element.isConnected)).toBe(true);
      } finally { await load.dispose(); }

      const draft = `${original}Saved after a session recheck.\n`;
      await editor.fill(draft);
      const save = await delayEditorRequest(page, 'PUT');
      try {
        await dialog.getByRole('button', { name: 'Save', exact: true }).last().click();
        await save.started;
        await expect(editor).not.toBeEditable();
        await recheckLiveSession(page);
        save.resume();
        await expect(editor).toBeEditable();
        const stored = await page.request.get(`/api/v1/auth/mcbrowser/content?path=${encodeURIComponent(filename)}`);
        expect(stored.ok()).toBeTruthy();
        expect((await stored.json()).content).toBe(draft);
      } finally { await save.dispose(); }

      const finalDraft = `${draft}The editor can save again.\n`;
      await editor.fill(finalDraft);
      const savedAgain = page.waitForResponse((response) =>
        /\/api\/v1\/auth\/mcbrowser\/(?:content|file)$/.test(new URL(response.url()).pathname)
          && response.request().method() === 'PUT',
        { timeout: 15_000 }
      );
      const saveAgain = dialog.getByRole('button', { name: 'Save', exact: true }).last();
      await expect(saveAgain).toBeEnabled();
      await saveAgain.press('Enter');
      expect((await savedAgain).ok()).toBeTruthy();
      await expect(editor).toBeEditable();
      const stored = await page.request.get(`/api/v1/auth/mcbrowser/content?path=${encodeURIComponent(filename)}`);
      expect((await stored.json()).content).toBe(finalDraft);
    } catch (error) {
      primaryError = error;
      throw error;
    } finally {
      try {
        const headers = await mutationHeaders(page);
        const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', {
          headers,
          data: { path: filename },
          timeout: 10_000,
        });
        expect([200, 204, 404]).toContain(deleted.status());
      } catch (cleanupError) {
        if (!primaryError) throw cleanupError;
      }
    }
  });

  test('French Streaming and Fileshare children localize after a live locale switch', async ({ page }) => {
    test.setTimeout(120_000);
    await signInLive(page);
    const directory = `live-french-audit-${Date.now()}`;
    const notification = `live-french-notification-${Date.now()}`;
    try {
      notificationFixture(notification, 'seed');
      const headers = await mutationHeaders(page);
      expect((await page.request.post('/api/v1/auth/mcbrowser/directory', { headers, data: { path: directory } })).ok()).toBeTruthy();
      // Real completed uploads make the audit page truncate without mocking a response.
      for (let index = 0; index < 101; index += 1) {
        const upload = await page.request.put(`/api/v1/auth/mcbrowser/upload?path=${encodeURIComponent(`${directory}/${index}.txt`)}`, {
          headers: { ...headers, 'Content-Type': 'application/octet-stream' }, data: Buffer.from('Locale audit fixture.\n'),
        });
        expect(upload.ok()).toBeTruthy();
      }
      await page.goto('/?tab=streaming');
      await expect(page.getByRole('heading', { name: 'Streaming Intelligence', exact: true })).toBeVisible();
      await page.locator('header select.af-locale-select').selectOption('fr');
      const main = page.locator('main');
      await expect(main.getByRole('heading', { name: 'Jellyfin', exact: true })).toBeVisible();
      await expect(main.getByRole('heading', { name: 'Gelée', exact: true })).toHaveCount(0);
      await expect(main.getByText('Non configuré', { exact: true }).first()).toBeVisible();
      await expect(main.getByText(/Non enregistré/).first()).toBeVisible();
      await expect(main).not.toContainText('Unrecorded');
      await expect(main).not.toContainText('Share policy');
      await expect(main).not.toContainText('Showing the latest 100 events');
      await page.goto('/?tab=fileshare');
      await expect(page.getByRole('tab', { name: 'Politique de partage', exact: true })).toBeVisible();
      await page.getByRole('tab', { name: 'Politique de partage', exact: true }).click();
      await expect(main.getByRole('heading', { name: 'Politique de partage', exact: true })).toBeVisible();
      await page.getByRole('tab', { name: 'Journal d’audit', exact: true }).click();
      await expect(main.getByText('Affichage des 100 derniers événements', { exact: true })).toBeVisible();
      for (const english of ['Unrecorded', 'Share policy', 'Showing the latest 100 events']) {
        await expect(main).not.toContainText(english);
      }
      await page.goto('/?tab=notifications');
      const row = page.getByRole('grid', { name: 'Notifications récentes', exact: true })
        .getByRole('row').filter({ hasText: notification });
      await expect(row).toBeVisible();
      await expect(row.getByRole('gridcell', { name: 'Avertissement', exact: true })).toBeVisible();
      await expect(row.getByRole('gridcell', { name: 'Non lu', exact: true })).toBeVisible();
      await expect(row.getByRole('gridcell', { name: 'warning', exact: true })).toHaveCount(0);
    } finally {
      notificationFixture(notification, 'cleanup');
      const headers = await mutationHeaders(page);
      const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', { headers, data: { path: directory } });
      expect([200, 204, 404]).toContain(deleted.status());
    }
  });
});

test.describe('Real persisted profile and backup workflows', () => {
  test('persists automatic backup controls and keeps avatar changes scoped to the signed-in account', async ({ page, browser }) => {
    test.setTimeout(180_000);
    await signInLive(page);
    const profile = await (await page.request.get('/api/v1/auth/session')).json();
    const original = await (await page.request.get('/api/v1/admin/ai/backup/optimal-window')).json();
    const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==', 'base64');
    const uri = `data:image/png;base64,${pixel.toString('base64')}`;
    const member = `${MEMBER_USER}-avatar`;
    provisionOrdinaryUser(member);
    const memberContext = await browser.newContext({ baseURL: new URL(page.url()).origin, serviceWorkers: 'block' });
    try {
      await page.goto('/?tab=settings');
      await page.getByRole('tab', { name: 'Backups & Restore', exact: true }).click();
      const schedule = page.getByRole('region', { name: 'Automatic backup schedule', exact: true });
      if (original.mode === 'smart') {
        await schedule.getByRole('button', { name: 'Disable automatic backups', exact: true }).click();
        await expect(schedule).toContainText('Schedule mode: Manual');
      }
      await schedule.getByRole('button', { name: 'Enable automatic backups', exact: true }).click();
      await expect(schedule).toContainText('Schedule mode: Smart');
      const scheduled = await (await page.request.get('/api/v1/admin/ai/backup/optimal-window')).json();
      expect(scheduled).toEqual(expect.objectContaining({ mode: 'smart', running: true }));
      expect(scheduled.next_backup_at).toBeTruthy();
      await page.reload();
      await page.getByRole('tab', { name: 'Backups & Restore', exact: true }).click();
      await expect(schedule).toContainText('Schedule mode: Smart');
      await schedule.getByRole('button', { name: 'Disable automatic backups', exact: true }).click();
      await expect(schedule).toContainText('Schedule mode: Manual');
      expect(await (await page.request.get('/api/v1/admin/ai/backup/optimal-window')).json()).toEqual(expect.objectContaining({ mode: 'manual', running: false }));

      await page.getByRole('tab', { name: 'Security & 2FA', exact: true }).click();
      await page.getByLabel('Upload avatar', { exact: true }).setInputFiles({ name: 'profile.png', mimeType: 'image/png', buffer: pixel });
      const avatar = page.getByRole('img', { name: 'Profile avatar', exact: true });
      await expect(avatar).toHaveAttribute('src', uri);
      await expect.poll(() => avatar.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBe(1);
      expect((await (await page.request.get('/api/v1/auth/session')).json()).avatar_url).toBe(uri);
      await page.reload();
      await page.getByRole('tab', { name: 'Security & 2FA', exact: true }).click();
      await expect(avatar).toHaveAttribute('src', uri);

      const memberPage = await memberContext.newPage();
      await signInLive(memberPage, member);
      const otherProfile = await (await memberPage.request.get('/api/v1/auth/session')).json();
      expect(otherProfile.id).not.toBe(profile.id);
      expect(otherProfile.avatar_url || '').toBe('');
      const removed = page.waitForResponse(response =>
        new URL(response.url()).pathname === '/api/v1/auth/profile/avatar' && response.request().method() === 'DELETE');
      await page.getByRole('button', { name: 'Remove avatar', exact: true }).click();
      expect((await removed).ok()).toBeTruthy();
      await expect(page.locator('img[alt="Profile avatar"]')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Remove avatar', exact: true })).toBeDisabled();
      expect((await (await page.request.get('/api/v1/auth/session')).json()).avatar_url || '').toBe('');
      expect((await (await memberPage.request.get('/api/v1/auth/session')).json()).avatar_url || '').toBe('');
    } finally {
      await memberContext.close();
      const headers = await mutationHeaders(page);
      const restored = await page.request.post('/api/v1/admin/ai/backup/schedule', { headers, data: { mode: original.mode } });
      expect(restored.ok()).toBeTruthy();
      const restoredAvatar = profile.avatar_url
        ? await page.request.put('/api/v1/auth/profile/avatar', { headers, data: { avatar: profile.avatar_url } })
        : await page.request.delete('/api/v1/auth/profile/avatar', { headers });
      expect(restoredAvatar.ok()).toBeTruthy();
    }
  });
});

test.describe('Real service-worker cache boundaries', () => {
  test.use({ serviceWorkers: 'allow' });

  test('caches static modules while keeping authenticated JSON and HTML out of caches', async ({ page, context }) => {
    test.setTimeout(120_000);
    await signInLive(page);
    await page.evaluate(async () => { await navigator.serviceWorker.ready; });
    await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const session = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/session', { credentials: 'include', cache: 'no-store' });
      return { status: response.status, username: (await response.json()).username };
    });
    expect(session).toEqual({ status: 200, username: ADMIN_USER });
    const cachedEntries = async () => page.evaluate(async () => {
      const entries = [];
      for (const name of await caches.keys()) {
        const cache = await caches.open(name);
        for (const request of await cache.keys()) {
          const response = await cache.match(request);
          entries.push({ path: new URL(request.url).pathname, type: response?.headers.get('content-type') || '' });
        }
      }
      return entries;
    });
    await expect.poll(async () => (await cachedEntries()).some((entry) => entry.path.endsWith('.wasm'))).toBe(true);
    const entries = await cachedEntries();
    expect(entries.some((entry) => /^\/(?:api|ws)(?:\/|$)/.test(entry.path))).toBe(false);
    expect(entries.some((entry) => entry.type.toLowerCase().includes('text/html'))).toBe(false);
    await context.clearCookies();
    await page.reload();
    await expect(page).toHaveURL(/\/login(?:\?|$)/);
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toHaveCount(0);
  });
});
