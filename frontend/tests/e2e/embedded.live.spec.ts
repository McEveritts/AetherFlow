import { expect, test } from '@playwright/test';

const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'AetherFlowE2E!2026';

test.describe('Real Embedded Single-Binary Full-Stack E2E (Zero Mocks)', () => {
  test('authenticates with real HttpOnly session cookie, navigates Overview/Marketplace/Settings, hydrates telemetry history, and survives reload/reconnect', async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);
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
    const initialHistoryPromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/auth/system/metrics/history' && response.ok()
    );
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
    const expandedHistoryPromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === '/api/v1/auth/system/metrics/history' &&
        url.searchParams.get('window') === '24h' && response.ok();
    });
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

    await sidebar.hover();
    await sidebar.getByRole('button', { name: /Overview/i }).click();
    await expect(windowSelector).toBeVisible();
    const closedSocketPromise = firstSocket.waitForEvent('close');
    const reconnectedSocketPromise = page.waitForEvent('websocket', {
      predicate: (socket) => new URL(socket.url()).pathname === '/api/v1/auth/ws',
    });
    const reconnectedHistoryPromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/auth/system/metrics/history' && response.ok()
    );
    const closedSocketCount = await page.evaluate(() => {
      const testWindow = window as Window & { __afAcceptanceSockets?: WebSocket[] };
      const liveSockets = (testWindow.__afAcceptanceSockets ?? []).filter((socket) =>
        new URL(socket.url).pathname === '/api/v1/auth/ws' && socket.readyState === WebSocket.OPEN
      );
      liveSockets.forEach((socket) => socket.close(1000, 'Acceptance test transport interruption'));
      return liveSockets.length;
    });
    expect(closedSocketCount).toBe(1);
    await closedSocketPromise;
    const reconnectedSocket = await reconnectedSocketPromise;
    const reconnectedFrame = await reconnectedSocket.waitForEvent('framereceived');
    expect(reconnectedFrame.payload).toBeTruthy();
    expect((await (await reconnectedHistoryPromise).json()).length).toBeGreaterThan(1);
    await expect(page.getByText('Live Telemetry')).toBeVisible();

    const reloadedHistoryPromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/auth/system/metrics/history' && response.ok()
    );
    await page.reload();
    await expect(page).not.toHaveURL(/\/login/);
    expect((await (await reloadedHistoryPromise).json()).length).toBeGreaterThan(1);
    await expect(windowSelector).toBeVisible();
    await expect(page.getByText('Live Telemetry')).toBeVisible();
    await expect(page.locator('path.recharts-area-curve').first()).toHaveAttribute('d', /\S+/);
  });
});
