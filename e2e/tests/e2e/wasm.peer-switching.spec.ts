import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const PEERS_API = '/api/v1/admin/peers';
const WG_KEY = Buffer.alloc(32, 9).toString('base64');

type AccessLevel = 'none' | 'read' | 'write';
interface AccessMap {
  services: AccessLevel;
  marketplace: AccessLevel;
  settings: AccessLevel;
  files: AccessLevel;
  users: AccessLevel;
  network: AccessLevel;
  updates: AccessLevel;
  transcoding: AccessLevel;
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function fullAccess(overrides: Partial<AccessMap> = {}): AccessMap {
  return {
    services: 'write',
    marketplace: 'write',
    settings: 'write',
    files: 'write',
    users: 'write',
    network: 'write',
    updates: 'write',
    transcoding: 'write',
    ...overrides,
  };
}

function makePeer(options: {
  id: string;
  name: string;
  state?: 'active' | 'down' | 'pending' | 'revoked';
  compatibility?: 'compatible' | 'limited' | 'incompatible' | 'unknown' | 'full';
  missingCapabilities?: string[];
  outboundAccess?: Partial<AccessMap> | null;
}) {
  const access = options.outboundAccess === null ? null : fullAccess(options.outboundAccess);
  return {
    id: options.id,
    name: options.name,
    wg_pubkey: WG_KEY,
    tunnel_ip: '10.231.0.21',
    endpoint: '192.0.2.21',
    wg_port: 51821,
    state: options.state ?? 'active',
    peer_version: '4.0.0',
    peer_protocol: 1,
    capabilities: ['links', 'grants', 'proxy.http.v1', 'proxy.ws.logs.v1', 'proxy.ws.telemetry.v1'],
    compatibility: options.compatibility ?? 'compatible',
    missing_capabilities: options.missingCapabilities ?? [],
    rtt_ms: 9,
    high_latency: false,
    last_ok_at: new Date().toISOString(),
    last_error: null,
    consecutive_failures: 0,
    pending_attempt_id: null,
    pending_expires_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    grants: {
      inbound: null,
      outbound: access
        ? {
            id: `grant-${options.id}`,
            run_as_user_id: 1,
            access,
            created_by: 'admin',
            created_at: new Date().toISOString(),
          }
        : null,
    },
    exports: [],
    mounts: [],
    transcode_worker: null,
  };
}

function peerSnapshot(peers: Array<ReturnType<typeof makePeer>>) {
  return {
    identity: {
      wg_pubkey: WG_KEY,
      tunnel_ip: '10.231.0.10',
      wg_port: 51821,
      listen_port: 51821,
      created_at: new Date().toISOString(),
    },
    local_protocol_version: 1,
    peer_protocol: 1,
    local_capabilities: ['links', 'grants', 'proxy.http.v1', 'proxy.ws.logs.v1', 'proxy.ws.telemetry.v1'],
    capabilities: ['links', 'grants', 'proxy.http.v1', 'proxy.ws.logs.v1', 'proxy.ws.telemetry.v1'],
    rtt_warn_ms: 120,
    peers,
    pairing_windows: [],
    pairing_attempts: [],
    detected_endpoints: [{ address: '192.0.2.20', interface: 'eth0', family: 'ipv4', recommended: true }],
  };
}

async function json(route: Route, body: unknown, status = 200, headers?: Record<string, string>) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers,
    body: JSON.stringify(body),
  });
}

const EXPECTED_ROUTE_ABORT_RE =
  /Route is already handled|Target page, context or browser has been closed|Request failed|aborted|No resource with given identifier|Cannot fulfill/i;

async function fulfillDelayedRoute(
  route: Route,
  body: unknown,
  status = 200,
  headers?: Record<string, string>,
): Promise<'fulfilled' | 'aborted'> {
  try {
    await json(route, body, status, headers);
    return 'fulfilled';
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (EXPECTED_ROUTE_ABORT_RE.test(message)) {
      return 'aborted';
    }
    throw error;
  }
}

async function mountPeerDefaults(page: Page, peerId: string, overrides?: {
  services?: Record<string, unknown>;
  settings?: Record<string, unknown>;
}) {
  const prefix = `/api/v1/peers/${peerId}`;
  await page.route(`**${prefix}/**`, async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (pathname === `${prefix}/auth/settings`) {
      await json(route, overrides?.settings ?? {
        language: 'de',
        timezone: 'Europe/Berlin',
        defaultDashboard: 'settings',
        setupCompleted: true,
      });
      return;
    }
    if (pathname === `${prefix}/auth/services`) {
      await json(route, overrides?.services ?? {
        sonarr: {
          id: 'sonarr',
          name: 'Beta Sonarr',
          status: 'running',
          managed_by: 'systemd',
          process: 'sonarr',
          default_port: 8989,
          active_port: 8989,
          external_access_enabled: false,
        },
      });
      return;
    }
    if (pathname === `${prefix}/auth/system/metrics`) {
      await json(route, {
        cpu_usage: 44.5,
        memory: { used: 24, total: 64 },
        disks: [{ mount_point: '/', used_pct: 60.0 }],
      });
      return;
    }
    if (pathname === `${prefix}/auth/system/metrics/history`) {
      await json(route, { points: [], days: [] });
      return;
    }
    if (pathname === `${prefix}/auth/system/hardware`) {
      await json(route, { cpu: { model: 'Peer Xeon' }, memory: { total_gb: 64 }, storage: [] });
      return;
    }
    if (pathname === `${prefix}/auth/system/topology`) {
      await json(route, { nodes: [], edges: [] });
      return;
    }
    if (pathname === `${prefix}/auth/notifications`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/admin/actions/pending`) {
      await json(route, { count: 0, actions: [] });
      return;
    }
    if (pathname === `${prefix}/admin/ai/predictions`) {
      await json(route, {});
      return;
    }
    if (pathname === `${prefix}/admin/ai/predictions/history`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/auth/plugins`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/admin/marketplace` || pathname === `${prefix}/auth/marketplace`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/admin/services`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/admin/ingress/configs`) {
      await json(route, { configs: [] });
      return;
    }
    if (pathname === `${prefix}/admin/network/status`) {
      await json(route, { platform: 'linux', runner_available: false });
      return;
    }
    if (pathname.endsWith('/system/update/check')) {
      await json(route, { updateAvailable: false, currentVersion: 'v4.0.0', latestVersion: 'v4.0.0' });
      return;
    }
    if (pathname.endsWith('/system/update/status')) {
      await json(route, { state: 'idle', phase: '', operationId: '', error: '' });
      return;
    }
    if (pathname === `${prefix}/auth/mcbrowser/preferences`) {
      await json(route, {
        view: 'list',
        sort: 'name',
        direction: 'asc',
        show_hidden: false,
        single_click: false,
        natural_sort: true,
        redirect_after_copy_move: false,
        date_format: false,
        editor_theme: 'chrome',
        locale: 'en',
      });
      return;
    }
    if (pathname === `${prefix}/auth/mcbrowser/usage`) {
      await json(route, { used_bytes: 1024, quota_bytes: 1048576, status: 'ok' });
      return;
    }
    if (pathname === `${prefix}/auth/mcbrowser/policy` || pathname.startsWith(`${prefix}/auth/mcbrowser/policy/`)) {
      await json(route, {
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
      });
      return;
    }
    if (pathname === `${prefix}/auth/mcbrowser/entries`) {
      await json(route, {
        path: '',
        entries: [
          { name: 'remote-note.txt', path: 'remote-note.txt', kind: 'file', size: 128, modified: '2026-11-23T12:00:00Z' },
        ],
      });
      return;
    }
    if (pathname === `${prefix}/auth/fileshare`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/admin/logs`) {
      await json(route, { entries: [] });
      return;
    }
    if (pathname === `${prefix}/admin/oidc/clients`) {
      await json(route, { clients: [] });
      return;
    }
    if (pathname === `${prefix}/admin/backup/list`) {
      await json(route, []);
      return;
    }
    if (pathname === `${prefix}/admin/ai/backup/optimal-window`) {
      await json(route, { mode: 'manual' });
      return;
    }
    if (pathname === `${prefix}/admin/mediaflow/queue`) {
      await json(route, { items: [], jobs: [] });
      return;
    }
    if (pathname === `${prefix}/admin/mediaflow/config`) {
      await json(route, { enabled: true });
      return;
    }
    if (pathname === `${prefix}/auth/users` || pathname === `${prefix}/admin/users`) {
      await json(route, []);
      return;
    }
    if (method === 'GET') {
      await json(route, {});
      return;
    }
    await json(route, { ok: true });
  });
}

test('switches servers from Cluster and header switcher with persistent accent bar, local-only peers API, and keyboard exit', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [
    makePeer({ id: 'peer-beta', name: 'Beta Media' }),
    makePeer({ id: 'peer-down', name: 'Delta Down', state: 'down' }),
  ];
  const seenPeerPaths: string[] = [];
  await page.route(`**${PEERS_API}`, async (route) => {
    expect(new URL(route.request().url()).pathname).toBe(PEERS_API);
    await json(route, peerSnapshot(peers));
  });
  await mountPeerDefaults(page, 'peer-beta');
  page.on('request', (req) => {
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/api/v1/peers/')) seenPeerPaths.push(p);
  });

  await page.goto('/?tab=cluster');
  await expect(page.getByTestId('active-server-bar')).toHaveCount(0);
  await expect(page.getByTestId('cluster-local-scope-note')).toHaveCount(0);

  const downButton = page.getByTestId('peer-manage-peer-down');
  await expect(downButton).toBeDisabled();
  await expect(downButton).toHaveAttribute('title', /unreachable/i);

  await page.getByTestId('peer-manage-peer-beta').click();

  const bar = page.getByTestId('active-server-bar');
  await expect(bar).toBeVisible();
  await expect(bar).toHaveAttribute('data-server-id', 'peer-beta');
  await expect(bar).toHaveAttribute('data-server-health', 'healthy');
  await expect(bar).toContainText('Managing Beta Media');
  await expect(page.getByTestId('cluster-local-scope-note')).toBeVisible();

  // Remote settings language ('de') and defaultDashboard ('settings') must not override local UI preferences.
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');

  const switcher = page.getByTestId('server-switcher');
  await expect(switcher).toHaveValue('peer-beta');

  // Bar persists across tab navigation and routes requests to /api/v1/peers/peer-beta/...
  await page.getByRole('button', { name: 'Services', exact: true }).first().click();
  await expect(bar).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Beta Sonarr', exact: true })).toBeVisible();
  expect(seenPeerPaths.some((p) => p === '/api/v1/peers/peer-beta/auth/services')).toBe(true);
  expect(seenPeerPaths.some((p) => p.includes('/admin/peers'))).toBe(false);

  await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
  await expect(bar).toBeVisible();

  // Keyboard exit returns to local server.
  const exitButton = page.getByTestId('exit-active-server');
  await exitButton.focus();
  await page.keyboard.press('Enter');
  await expect(bar).toHaveCount(0);
  await expect(switcher).toHaveValue('');

  // Keyboard / select switch back to peer-beta works from header.
  await switcher.focus();
  await switcher.selectOption('peer-beta');
  await expect(bar).toBeVisible();
  await expect(bar).toHaveAttribute('data-server-id', 'peer-beta');
});

test('cancels stale in-flight responses and isolates telemetry WebSockets across rapid server switches', async ({ page }) => {
  await installAetherFlowMocks(page, { enableWS: true });
  const peers = [makePeer({ id: 'peer-beta', name: 'Beta Media' })];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));

  await mountPeerDefaults(page, 'peer-beta', {
    services: {
      beta_svc: { id: 'beta_svc', name: 'Beta Probe', status: 'running', managed_by: 'systemd' },
    },
  });

  let sendLocalWs: ((payload: object) => void) | undefined;
  let sendPeerWs: ((payload: object) => void) | undefined;
  await page.route('**/api/v1/auth/ws/ticket', (route) => json(route, { ticket: 'local-t' }));
  await page.route('**/api/v1/peers/peer-beta/auth/ws/ticket', (route) => json(route, { ticket: 'peer-t' }));
  await page.routeWebSocket(/\/api\/v1\/auth\/ws(?:\?|$)/, (socket) => {
    sendLocalWs = (data) => socket.send(JSON.stringify({ type: 'METRICS_UPDATE', data }));
    socket.onMessage((msg) => {
      if (msg === '{"type":"PING"}') socket.send('{"type":"PONG"}');
    });
  });
  await page.routeWebSocket(/\/api\/v1\/peers\/peer-beta\/auth\/ws(?:\?|$)/, (socket) => {
    sendPeerWs = (data) => socket.send(JSON.stringify({ type: 'METRICS_UPDATE', data }));
    socket.onMessage((msg) => {
      if (msg === '{"type":"PING"}') socket.send('{"type":"PONG"}');
    });
  });

  const localHeld = deferred();
  const releaseLocal = deferred();
  let holdNextLocal = false;
  const delayedLocalState: {
    outcome: 'pending' | 'fulfilled' | 'aborted';
    failed: boolean;
  } = { outcome: 'pending', failed: false };
  page.on('requestfailed', (req) => {
    if (new URL(req.url()).pathname === '/api/v1/auth/services') {
      delayedLocalState.failed = true;
    }
  });
  await page.route('**/api/v1/auth/services', async (route) => {
    if (holdNextLocal) {
      holdNextLocal = false;
      localHeld.resolve();
      await releaseLocal.promise;
      delayedLocalState.outcome = await fulfillDelayedRoute(route, {
        stale_local: { id: 'stale_local', name: 'Stale Local Probe', status: 'running', managed_by: 'systemd' },
      });
      return;
    }
    await json(route, {
      local_svc: { id: 'local_svc', name: 'Local Probe', status: 'running', managed_by: 'systemd' },
    });
  });

  await page.goto('/?tab=services');
  await expect(page.getByRole('heading', { name: 'Local Probe', exact: true })).toBeVisible();
  await expect.poll(() => Boolean(sendLocalWs)).toBe(true);

  holdNextLocal = true;
  await page.getByRole('button', { name: 'Refresh services', exact: true }).click();
  await localHeld.promise;

  // Switch to peer-beta while local services refresh is still in-flight.
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  await expect(page.getByRole('heading', { name: 'Beta Probe', exact: true })).toBeVisible();
  await expect.poll(() => Boolean(sendPeerWs)).toBe(true);

  // Release delayed local HTTP response and emit stale local WS frame -> must not contaminate peer-beta.
  releaseLocal.resolve();
  try {
    sendLocalWs?.({ services: { leaked_ws: { id: 'leaked_ws', name: 'Leaked WS', status: 'failed' } } });
  } catch {
    // Old socket already closed by server switch.
  }

  // Peer WS update applies cleanly to peer-beta.
  sendPeerWs!({
    services: {
      beta_svc: { id: 'beta_svc', name: 'Beta Probe', status: 'stopped', managed_by: 'systemd' },
    },
  });
  await expect(page.getByRole('heading', { name: 'Beta Probe', exact: true })).toBeVisible();
  await expect.poll(() => delayedLocalState.outcome).toMatch(/^(aborted|fulfilled)$/);
  expect(
    delayedLocalState.failed ||
      delayedLocalState.outcome === 'aborted' ||
      delayedLocalState.outcome === 'fulfilled',
  ).toBe(true);
  await expect(page.getByRole('heading', { name: 'Stale Local Probe' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Leaked WS' })).toHaveCount(0);
});

test('retains local session on peer upstream 401/403 and resets active server on local logout', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [makePeer({ id: 'peer-beta', name: 'Beta Media' })];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-beta');

  let auth401Count = 0;
  await page.route('**/api/v1/peers/peer-beta/auth/services', async (route) => {
    auth401Count += 1;
    if (auth401Count === 1) {
      await json(route, { error: 'Peer upstream unauthorized' }, 401, {
        'X-AetherFlow-Proxied-Peer': 'peer-beta',
      });
      return;
    }
    await json(route, { error: 'Unmarked peer 401' }, 401);
  });

  await page.goto('/?tab=services');
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  await expect(page.getByTestId('active-server-bar')).toBeVisible();
  await expect.poll(() => auth401Count).toBeGreaterThanOrEqual(1);

  // Trigger second unmarked 401 (verified via /api/v1/auth/session probe).
  await page.getByRole('button', { name: 'Refresh services', exact: true }).click();
  await expect.poll(() => auth401Count).toBeGreaterThanOrEqual(2);

  // Local dashboard session must remain intact (not redirected to /login).
  await expect(page).not.toHaveURL(/\/login/);
  await expect(page.getByTestId('active-server-bar')).toBeVisible();

  // Signing out locally clears active server selection and returns to login.
  await page.getByTestId('nav-logout').click();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByTestId('active-server-bar')).toHaveCount(0);
});

test('enforces read-only, multi-area, local-only security, OIDC read-only, and unreachable peer degradation', async ({ page }) => {
  await installAetherFlowMocks(page);
  let peerState: 'active' | 'down' = 'active';
  const buildPeers = () => [
    makePeer({
      id: 'peer-limited',
      name: 'Gamma Limited',
      state: peerState,
      compatibility: 'limited',
      missingCapabilities: ['proxy.ws.logs.v1'],
      outboundAccess: {
        services: 'read',
        marketplace: 'write',
        network: 'read',
        files: 'write',
        users: 'none',
        settings: 'write',
        updates: 'read',
        transcoding: 'none',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  await mountPeerDefaults(page, 'peer-limited');
  await page.route('**/api/v1/auth/plugins', (route) =>
    json(route, {
      plugins: [
        {
          id: 'demo-plugin',
          name: 'Demo Plugin',
          version: '1.0.0',
          description: 'Local sandbox test plugin',
          enabled: true,
          healthy: true,
          granted_scopes: ['services:read'],
          capabilities: [],
          ui_html: '<!doctype html><html><body>Plugin UI</body></html>',
        },
      ],
    }),
  );
  await page.route('**/api/v1/peers/peer-limited/auth/blueprints', (route) =>
    json(route, { blueprints: [{ id: 'sonarr', app_name: 'sonarr', name: 'Sonarr' }] }),
  );

  // Open local Plugin Sandbox first, then switch to peer-limited -> sandbox must auto-close and unmount iframe.
  await page.goto('/?tab=marketplace');
  await page.getByTestId('open-plugin-ui-demo-plugin').click();
  await expect(page.getByTestId('close-plugin-sandbox')).toBeVisible();
  await expect(page.locator('iframe')).toHaveCount(1);

  await page.getByTestId('server-switcher').selectOption('peer-limited', { force: true });
  await expect(page.getByTestId('close-plugin-sandbox')).toBeHidden();
  await expect(page.locator('iframe')).toHaveCount(0);

  const bar = page.getByTestId('active-server-bar');
  await expect(bar).toBeVisible();
  await expect(bar).toHaveAttribute('data-server-health', 'limited');
  await expect(bar).toContainText('Limited capabilities');

  // Services read-only disables Start/Stop/Restart with tooltip naming Gamma Limited,
  // and does not fabricate a local-host launch link.
  await page.getByRole('button', { name: 'Services', exact: true }).first().click();
  const card = page.locator('article.af-service-tile').filter({
    has: page.getByRole('heading', { name: 'Beta Sonarr', exact: true }),
  });
  await expect(card).toBeVisible();
  const restartBtn = card.getByRole('button', { name: /^Restart$/i });
  await expect(restartBtn).toBeDisabled();
  await expect(restartBtn).toHaveAttribute('title', /Gamma Limited/);
  await expect(card.getByRole('link', { name: /Open App|Launch/i })).toHaveCount(0);

  // MediaFlow Blueprint Sync requires Marketplace:Write + Network:Write (peer-limited only has Network:Read).
  await page.getByRole('button', { name: 'MediaFlow', exact: true }).first().click();
  const syncBtn = page.getByRole('button', { name: /Sync Zero-Touch configuration/i });
  await expect(syncBtn).toBeDisabled();
  await expect(syncBtn).toHaveAttribute('title', /Gamma Limited/);

  // Settings -> Security hides local password/2FA/sessions and shows local-only notice.
  await page.getByRole('button', { name: 'Settings', exact: true }).first().click();
  await page.getByRole('tab', { name: /Security/i }).click();
  await expect(page.getByTestId('remote-security-local-only')).toBeVisible();
  await expect(page.getByTestId('remote-security-local-only')).toContainText('Gamma Limited');
  await expect(page.getByLabel(/New password/i)).toHaveCount(0);

  // Settings -> OIDC is read-only remotely.
  await page.getByRole('tab', { name: /OIDC/i }).click();
  await expect(page.getByTestId('oidc-remote-readonly-note')).toBeVisible();
  await expect(page.getByRole('button', { name: /Register OIDC Client/i })).toBeDisabled();

  // McBrowser -> Policy requires Files + Users (missing Users shows access note).
  await page.getByRole('button', { name: 'McBrowser', exact: true }).first().click();
  await page.getByRole('tab', { name: /Policy/i }).click();
  await expect(page.getByTestId('mcbrowser-policy-access-note')).toBeVisible();
  await expect(page.getByTestId('mcbrowser-policy-access-note')).toContainText('Gamma Limited');

  // Peer transitions to down on next local peers refresh -> bar reflects Unreachable state.
  peerState = 'down';
  await page.getByRole('button', { name: 'Cluster', exact: true }).first().click();
  await expect(bar).toHaveAttribute('data-server-health', 'unreachable');
  await expect(bar).toContainText('Unreachable');
});

test('destructive confirmation names target server and auto-closes when server switches while open', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [makePeer({ id: 'peer-beta', name: 'Beta Media' })];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-beta');

  let deleteCalls = 0;
  await page.route(/\/api\/v1\/peers\/peer-beta\/auth\/mcbrowser\/(entry|delete-recursive)/, async (route) => {
    deleteCalls += 1;
    await json(route, { deleted: true });
  });

  await page.goto('/?tab=mcbrowser');
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  await expect(page.getByText('remote-note.txt')).toBeVisible();

  // Select remote-note.txt and click Delete -> submit File operation form -> opens ConfirmDialog.
  await page.getByRole('checkbox', { name: /Select visible/i }).check();
  await page.getByRole('button', { name: /^delete$/i }).click();
  const fileOpDialog = page.getByRole('dialog', { name: /File operation/i });
  await expect(fileOpDialog).toBeVisible();
  await fileOpDialog.locator('button[type="submit"]').click();

  const confirmDialog = page.getByRole('dialog', { name: /Permanently delete selected.*Beta Media/i });
  await expect(confirmDialog).toBeVisible();
  await expect(confirmDialog.getByTestId('confirm-target-server')).toBeVisible();
  await expect(confirmDialog.getByTestId('confirm-target-server')).toContainText('Target server: Beta Media');

  // Switch active server via the select element while dialog is open -> dialog must auto-close without deleting.
  await page.getByTestId('server-switcher').selectOption('', { force: true });
  await expect(confirmDialog).toHaveCount(0);
  expect(deleteCalls).toBe(0);
});

test('streams peer live logs over WebSocket and surfaces close code 4403 revocation alert', async ({ page }) => {
  await installAetherFlowMocks(page, { enableWS: true });
  const peers = [makePeer({ id: 'peer-beta', name: 'Beta Media' })];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-beta');

  await page.route('**/api/v1/auth/ws/ticket', (route) => json(route, { ticket: 'local-t' }));
  await page.route('**/api/v1/peers/peer-beta/auth/ws/ticket', (route) => json(route, { ticket: 'peer-logs-ticket' }));
  await page.routeWebSocket(/\/api\/v1\/auth\/ws(?:\?|$)/, () => {});
  await page.routeWebSocket(/\/api\/v1\/peers\/peer-beta\/auth\/ws(?:\?|$)/, () => {});

  const receivedFilters: string[] = [];
  let closeLogsSocket: ((code: number, reason: string) => void) | undefined;
  let sendLogEntry: ((entry: object) => void) | undefined;

  await page.routeWebSocket(/\/api\/v1\/peers\/peer-beta\/auth\/ws\/logs\?ticket=peer-logs-ticket/, (socket) => {
    sendLogEntry = (entry) => socket.send(JSON.stringify({ type: 'LOG_ENTRY', data: entry }));
    closeLogsSocket = (code, reason) => socket.close({ code, reason });
    socket.onMessage((message) => {
      if (typeof message === 'string') receivedFilters.push(message);
    });
  });

  await page.goto('/?tab=services');
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  const card = page.locator('article.af-service-tile').filter({
    has: page.getByRole('heading', { name: 'Beta Sonarr', exact: true }),
  });
  await expect(card).toBeVisible();
  await card.getByRole('button', { name: /^Logs$/i }).click();

  const dialog = page.getByRole('dialog', { name: /Service Logs/i });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId('logs-stream-status')).toContainText('Live stream');
  await expect.poll(() => receivedFilters.length).toBeGreaterThanOrEqual(1);
  expect(JSON.parse(receivedFilters[0])).toMatchObject({ unit: 'sonarr' });

  sendLogEntry!({
    timestamp: '2026-11-23T18:00:00Z',
    unit: 'sonarr',
    level: 'INFO',
    message: 'Peer beta live log line 42',
  });
  await expect(dialog.getByText(/Peer beta live log line 42/)).toBeVisible();

  closeLogsSocket!(4403, 'grant_revoked');
  await expect(dialog.getByTestId('logs-stream-closed')).toBeVisible();
  await expect(dialog.getByTestId('logs-stream-closed')).toContainText('4403');
  await expect(dialog.getByTestId('logs-stream-status')).toContainText('Stream closed');
});

test('validates peer tus upload Location prefix and performs passwordless remote backup step-up', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [makePeer({ id: 'peer-beta', name: 'Beta Media' })];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-beta');

  // Backup download step-up on peer-beta must not prompt for or send local password.
  const backupDownloadBodies: Array<{ body: unknown; reauthHeader: string | undefined }> = [];
  await page.route('**/api/v1/peers/peer-beta/admin/backup/list', (route) =>
    json(route, [
      {
        filename: 'beta-snap-2026.sqlite',
        size: 4096,
        checksum: 'abc123',
        timestamp: '2026-11-23T10:00:00Z',
      },
    ]),
  );
  await page.route('**/api/v1/peers/peer-beta/admin/backup/download/**', async (route) => {
    const req = route.request();
    if (req.method() === 'POST') {
      const headers = await req.allHeaders();
      backupDownloadBodies.push({
        body: req.postDataJSON(),
        reauthHeader: headers['x-reauth-password'],
      });
      await json(route, { token: 'peer-dl-tok' });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/octet-stream', body: 'SQLITE' });
  });

  await page.goto('/?tab=settings');
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  await page.getByRole('tab', { name: /Backups/i }).click();
  await page.getByText('beta-snap-2026.sqlite').click();

  const backupModal = page.getByRole('dialog');
  await expect(backupModal).toBeVisible();
  await expect(backupModal).toContainText('Beta Media');
  await expect(backupModal.getByTestId('remote-backup-stepup-note')).toBeVisible();
  await expect(backupModal.locator('input[type="password"]')).toHaveCount(0);
  await backupModal.getByRole('button', { name: /Download archive/i }).click();
  await expect.poll(() => backupDownloadBodies.length).toBe(1);
  expect(backupDownloadBodies[0].body).toEqual({});
  expect(backupDownloadBodies[0].reauthHeader).toBeUndefined();

  // McBrowser tus upload (> 64 MiB threshold) must reject unprefixed local Location and accept exact peer Location.
  const uploadHex = '0123456789abcdef0123456789abcdef';
  let createCalls = 0;
  let lastUploadLength = '0';
  let lastUploadMetadata = '';
  let currentUploadOffset = 0;
  const localPatchCalls: string[] = [];
  const peerSessionMethods: string[] = [];

  await page.route('**/api/v1/auth/mcbrowser/uploads/**', async (route) => {
    localPatchCalls.push(route.request().url());
    await route.fulfill({ status: 500, body: 'must never patch local upload from peer' });
  });
  await page.route(/\/api\/v1\/peers\/peer-beta\/auth\/mcbrowser\/uploads(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'GET') {
      await json(route, { uploads: [] });
      return;
    }
    const headers = await route.request().allHeaders();
    lastUploadLength = headers['upload-length'] ?? '0';
    lastUploadMetadata = headers['upload-metadata'] ?? '';
    currentUploadOffset = 0;
    createCalls += 1;
    const location =
      createCalls === 1
        ? `/api/v1/auth/mcbrowser/uploads/${uploadHex}`
        : `/api/v1/peers/peer-beta/auth/mcbrowser/uploads/${uploadHex}`;
    await route.fulfill({
      status: 201,
      headers: {
        Location: location,
        'Tus-Resumable': '1.0.0',
      },
      body: '',
    });
  });
  await page.route(`**/api/v1/peers/peer-beta/auth/mcbrowser/uploads/${uploadHex}`, async (route) => {
    const method = route.request().method();
    peerSessionMethods.push(method);
    if (method === 'HEAD') {
      await route.fulfill({
        status: 200,
        headers: {
          'Tus-Resumable': '1.0.0',
          'Upload-Offset': String(currentUploadOffset),
          'Upload-Length': lastUploadLength,
          'Upload-Metadata': lastUploadMetadata,
          'Upload-Status': currentUploadOffset >= Number(lastUploadLength) ? 'completed' : 'uploading',
        },
        body: '',
      });
      return;
    }
    const headers = await route.request().allHeaders();
    const offset = Number(headers['upload-offset'] ?? '0');
    const len = route.request().postDataBuffer()?.length ?? 0;
    currentUploadOffset = offset + len;
    await route.fulfill({
      status: 204,
      headers: {
        'Tus-Resumable': '1.0.0',
        'Upload-Offset': String(currentUploadOffset),
      },
      body: '',
    });
  });

  await page.getByRole('button', { name: 'McBrowser', exact: true }).first().click();
  await expect(page.getByText('remote-note.txt')).toBeVisible();

  const dispatchTusFile = async (filename: string) => {
    await page.evaluate((name) => {
      const input = document.querySelector('input[type="file"][aria-label="Choose files to upload"]') as HTMLInputElement | null;
      if (!input) throw new Error('McBrowser file input missing');
      const chunk = new Uint8Array(1024 * 1024);
      const parts: BlobPart[] = [];
      for (let i = 0; i < 64; i += 1) parts.push(chunk);
      parts.push(new Uint8Array(17));
      const file = new File(parts, name, { type: 'application/octet-stream' });
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }, filename);
  };

  // Upload 1: server returns spoofed local Location -> rejected, zero HEAD/PATCH to local or peer session.
  await dispatchTusFile('spoof-tus.bin');
  await expect.poll(() => createCalls).toBe(1);
  await expect(page.getByText(/rejected|session URL|upload location|invalid/i).first()).toBeVisible();
  expect(localPatchCalls).toEqual([]);
  expect(peerSessionMethods).toEqual([]);

  // Upload 2: server returns matching peer Location -> HEAD + PATCH succeed on peer prefix.
  await dispatchTusFile('valid-tus.bin');
  await expect.poll(() => peerSessionMethods.includes('PATCH'), { timeout: 15_000 }).toBe(true);
  expect(peerSessionMethods).toContain('HEAD');
  expect(peerSessionMethods).toContain('PATCH');
  expect(localPatchCalls).toEqual([]);
});

test('gates switcher eligibility and active peer health across compatibility, grants capability, link state, and grant status', async ({ page }) => {
  await installAetherFlowMocks(page);
  let dynamicPeer = makePeer({ id: 'peer-compat', name: 'Alpha Peer', compatibility: 'compatible' });
  const buildPeers = () => [
    dynamicPeer,
    makePeer({
      id: 'peer-limited-ok',
      name: 'Limited Logs Peer',
      compatibility: 'limited',
      missingCapabilities: ['proxy.ws.logs.v1'],
    }),
    makePeer({
      id: 'peer-limited-nogrants',
      name: 'Limited No Grants',
      compatibility: 'limited',
      missingCapabilities: ['grants'],
    }),
    makePeer({ id: 'peer-unknown', name: 'Unknown Compat', compatibility: 'unknown' }),
    makePeer({ id: 'peer-incompat', name: 'Incompatible Peer', compatibility: 'incompatible' }),
    makePeer({ id: 'peer-nogrant', name: 'No Grant Peer', outboundAccess: null }),
    makePeer({ id: 'peer-revoked', name: 'Revoked Peer', state: 'revoked' }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  await mountPeerDefaults(page, 'peer-compat');
  await mountPeerDefaults(page, 'peer-limited-ok');

  await page.goto('/?tab=cluster');

  await expect(page.getByTestId('peer-manage-peer-compat')).toBeEnabled();
  await expect(page.getByTestId('peer-manage-peer-limited-ok')).toBeEnabled();

  for (const id of ['peer-limited-nogrants', 'peer-unknown', 'peer-incompat']) {
    const btn = page.getByTestId(`peer-manage-${id}`);
    await expect(btn).toBeDisabled();
    await expect(btn).toHaveAttribute('title', /incompatible/i);
  }
  await expect(page.getByTestId('peer-manage-peer-nogrant')).toBeDisabled();
  await expect(page.getByTestId('peer-manage-peer-nogrant')).toHaveAttribute('title', /permission|grant/i);
  await expect(page.getByTestId('peer-manage-peer-revoked')).toBeDisabled();
  await expect(page.getByTestId('peer-manage-peer-revoked')).toHaveAttribute('title', /revoked/i);

  // Switcher option list only offers eligible peers (compatible + limited with grants).
  const switcherValues = await page
    .getByTestId('server-switcher')
    .locator('option')
    .evaluateAll((opts) => opts.map((o) => (o as HTMLOptionElement).value));
  expect(switcherValues).toContain('peer-compat');
  expect(switcherValues).toContain('peer-limited-ok');
  expect(switcherValues).not.toContain('peer-limited-nogrants');
  expect(switcherValues).not.toContain('peer-unknown');
  expect(switcherValues).not.toContain('peer-incompat');
  expect(switcherValues).not.toContain('peer-nogrant');
  expect(switcherValues).not.toContain('peer-revoked');

  // Activate compatible peer and verify live active-peer health degradation across states.
  await page.getByTestId('peer-manage-peer-compat').click();
  const bar = page.getByTestId('active-server-bar');
  await expect(bar).toHaveAttribute('data-server-health', 'healthy');

  const triggerPeerRefresh = async () => {
    await page.getByRole('button', { name: 'Services', exact: true }).first().click();
    await page.getByRole('button', { name: 'Cluster', exact: true }).first().click();
  };

  dynamicPeer = makePeer({ id: 'peer-compat', name: 'Alpha Peer', compatibility: 'unknown' });
  await triggerPeerRefresh();
  await expect(bar).toHaveAttribute('data-server-health', 'incompatible');

  dynamicPeer = makePeer({
    id: 'peer-compat',
    name: 'Alpha Peer',
    compatibility: 'limited',
    missingCapabilities: ['grants'],
  });
  await triggerPeerRefresh();
  await expect(bar).toHaveAttribute('data-server-health', 'incompatible');

  dynamicPeer = makePeer({ id: 'peer-compat', name: 'Alpha Peer', compatibility: 'incompatible' });
  await triggerPeerRefresh();
  await expect(bar).toHaveAttribute('data-server-health', 'incompatible');

  dynamicPeer = makePeer({
    id: 'peer-compat',
    name: 'Alpha Peer',
    compatibility: 'compatible',
    outboundAccess: null,
  });
  await triggerPeerRefresh();
  await expect(bar).toHaveAttribute('data-server-health', 'no-grant');

  dynamicPeer = makePeer({ id: 'peer-compat', name: 'Alpha Peer', state: 'revoked' });
  await triggerPeerRefresh();
  await expect(bar).toHaveAttribute('data-server-health', 'revoked');
});

test('disposes server-owned tabs, aborts/fences active loaders and drawers on switch, and preserves local Cluster state', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [makePeer({ id: 'peer-beta', name: 'Beta Media' })];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-beta');

  // 1. Cluster local pairing modal state survives server switch (TabRouter keeps Cluster un-keyed).
  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: /Pair with a server/i }).click();
  const pairNameInput = page.locator('#cluster-pair-name');
  await expect(pairNameInput).toBeVisible();
  await pairNameInput.fill('local-pairing-draft');
  await page.getByTestId('server-switcher').selectOption('peer-beta', { force: true });
  await expect(page.getByTestId('active-server-bar')).toHaveAttribute('data-server-id', 'peer-beta');
  await expect(pairNameInput).toBeVisible();
  await expect(pairNameInput).toHaveValue('local-pairing-draft');
  await page.getByTestId('server-switcher').selectOption('', { force: true });
  await expect(pairNameInput).toHaveValue('local-pairing-draft');
  await page.keyboard.press('Escape');

  // 2. Overview CapacityPredictions: delayed local analyze must not commit onto peer-beta.
  const capHeld = deferred();
  const releaseCap = deferred();
  let capOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/admin/ai/predictions/analyze', async (route) => {
    capHeld.resolve();
    await releaseCap.promise;
    capOutcome = await fulfillDelayedRoute(route, {
      trend_summary: 'LOCAL_STALE_CAPACITY_SUMMARY',
      predicted_bottleneck: 'CPU',
      confidence_score: 0.99,
    });
  });
  await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
  await page.getByRole('button', { name: /Analyze capacity/i }).click();
  await capHeld.promise;
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  releaseCap.resolve();
  await expect.poll(() => capOutcome).not.toBe('pending');
  await expect(page.getByText('LOCAL_STALE_CAPACITY_SUMMARY')).toHaveCount(0);

  // Switch back to local for Streaming CanonicalHistory + export test.
  await page.getByTestId('server-switcher').selectOption('');

  // 3. Streaming CanonicalHistory: delayed local history reload & export never commit on peer-beta.
  const histExportHeld = deferred();
  const releaseHistExport = deferred();
  let histExportOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/auth\/streaming\/history(?:\?.*)?$/, (route) =>
    json(route, {
      items: [
        {
          startedAt: '2026-11-23T10:00:00Z',
          itemName: 'Local Movie Alpha',
          userName: 'local-viewer',
          provider: 'jellyfin',
          itemType: 'Movie',
          playMethod: 'DirectPlay',
          watchedSecs: 3600,
          provenance: 'observed_session',
          policyStatus: 'included',
        },
      ],
      counts: { matchingRecords: 1, availableRecords: 1, confirmedPlays: 1, watchTimeSecs: 3600, undatedRecords: 0 },
      scope: { snapshotToken: 'local-snap-1', asOf: '2026-11-23T10:00:00Z', expiresAt: '2026-11-23T11:00:00Z', permissionScope: 'admin', dateSemantics: 'UTC' },
    }),
  );
  await page.route(/\/api\/v1\/auth\/streaming\/history\/export(?:\?.*)?$/, async (route) => {
    histExportHeld.resolve();
    await releaseHistExport.promise;
    histExportOutcome = await fulfillDelayedRoute(route, 'header\nlocal-row\n', 409);
  });
  await page.route(/\/api\/v1\/peers\/peer-beta\/auth\/streaming\/dashboard(?:\?.*)?$/, (route) =>
    json(route, { servers: [], activeSessions: [], liveSummary: {}, analytics: {} }),
  );
  await page.route(/\/api\/v1\/peers\/peer-beta\/auth\/streaming\/history(?:\?.*)?$/, (route) =>
    json(route, {
      items: [
        {
          startedAt: '2026-11-23T12:00:00Z',
          itemName: 'Remote Movie Beta',
          userName: 'beta-viewer',
          provider: 'jellyfin',
          itemType: 'Movie',
          playMethod: 'DirectPlay',
          watchedSecs: 1800,
          provenance: 'observed_session',
          policyStatus: 'included',
        },
      ],
      counts: { matchingRecords: 1, availableRecords: 1, confirmedPlays: 1, watchTimeSecs: 1800, undatedRecords: 0 },
      scope: { snapshotToken: 'beta-snap-1', asOf: '2026-11-23T12:00:00Z', expiresAt: '2026-11-23T13:00:00Z', permissionScope: 'admin', dateSemantics: 'UTC' },
    }),
  );
  await page.route(/\/api\/v1\/peers\/peer-beta\/auth\/streaming\/(patterns|drilldown)(?:\?.*)?$/, (route) =>
    json(route, { activity: { timeseries: [] }, concurrency: { buckets: [] }, cohortDistinctPlays: 1, cohortDistinctUsers: 1, cohortDistinctItems: 1 }),
  );

  await page.getByRole('button', { name: 'Streaming', exact: true }).first().click();
  await page.getByRole('tab', { name: 'Canonical playback history', exact: true }).click();
  await expect(page.getByText('Local Movie Alpha')).toBeVisible();
  await page.getByRole('button', { name: /Export CSV/i }).click();
  await histExportHeld.promise;
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  await page.getByRole('tab', { name: 'Canonical playback history', exact: true }).click();
  await expect(page.getByText('Remote Movie Beta')).toBeVisible();
  releaseHistExport.resolve();
  await expect.poll(() => histExportOutcome).not.toBe('pending');
  await expect(page.getByText('Local Movie Alpha')).toHaveCount(0);
  await expect(page.getByText(/Snapshot expired/i)).toHaveCount(0);

  // 4. Network Diagnostics: switch while manual diagnostics read is in flight.
  await page.getByTestId('server-switcher').selectOption('');
  const diagHeld = deferred();
  const releaseDiag = deferred();
  let diagOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/admin\/network\/diagnostics(?:\?.*)?$/, async (route) => {
    diagHeld.resolve();
    await releaseDiag.promise;
    diagOutcome = await fulfillDelayedRoute(route, {
      checks: [{ name: 'LOCAL_STALE_DIAG', ok: true, detail: 'stale' }],
      logs: 'LOCAL_STALE_DIAG_LOG',
    });
  });
  await page.getByRole('button', { name: 'Network', exact: true }).first().click();
  await page.getByRole('button', { name: /Run diagnostics/i }).click();
  await diagHeld.promise;
  await page.getByTestId('server-switcher').selectOption('peer-beta');
  releaseDiag.resolve();
  await expect.poll(() => diagOutcome).not.toBe('pending');
  await expect(page.getByText('LOCAL_STALE_DIAG')).toHaveCount(0);
  await expect(page.getByText('LOCAL_STALE_DIAG_LOG')).toHaveCount(0);

  // 5. ApprovalInbox detail: switch while detail GET is in flight closes modal and ignores late payload.
  await page.getByTestId('server-switcher').selectOption('');
  const inboxHeld = deferred();
  const releaseInbox = deferred();
  let inboxOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/admin\/actions\/pending(?:\?.*)?$/, (route) =>
    json(route, {
      total: 1,
      count: 1,
      actions: [
        {
          id: 101,
          action: 'restart_service:sonarr',
          status: 'pending',
          source: 'flowai',
          reason: 'Local pending action',
          risk_level: 'MEDIUM',
          created_at: '2026-11-23T10:00:00Z',
        },
      ],
    }),
  );
  await page.route('**/api/v1/admin/actions/101', async (route) => {
    inboxHeld.resolve();
    await releaseInbox.promise;
    inboxOutcome = await fulfillDelayedRoute(route, {
      action: {
        id: 101,
        action: 'restart_service:sonarr',
        status: 'pending',
        source: 'flowai',
        reason: 'LOCAL_STALE_INBOX_DETAIL',
        risk_level: 'MEDIUM',
      },
    });
  });
  await page.getByRole('button', { name: 'Approval Inbox', exact: true }).first().click();
  await page.getByRole('button', { name: /Inspect action/i }).first().click();
  await inboxHeld.promise;
  await expect(page.getByRole('dialog', { name: /Action details/i })).toBeVisible();
  await page.getByTestId('server-switcher').selectOption('peer-beta', { force: true });
  await expect(page.getByRole('dialog', { name: /Action details/i })).toHaveCount(0);
  releaseInbox.resolve();
  await expect.poll(() => inboxOutcome).not.toBe('pending');
  await expect(page.getByText('LOCAL_STALE_INBOX_DETAIL')).toHaveCount(0);

  // 6. Audit details / log drawer: switch while action detail GET is in flight closes drawer and ignores late payload.
  await page.getByTestId('server-switcher').selectOption('');
  const auditHeld = deferred();
  const releaseAudit = deferred();
  let auditOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/admin\/audit-log(?:\?.*)?$/, (route) =>
    json(route, {
      total: 1,
      entries: [
        {
          id: 1,
          username: 'admin',
          action: 'action_approve',
          target_type: 'pending_action',
          target_id: '202',
          detail: 'Local audit event',
          ip_address: '127.0.0.1',
          created_at: '2026-11-23T10:00:00Z',
        },
      ],
    }),
  );
  await page.route(/\/api\/v1\/peers\/peer-beta\/admin\/audit-log(?:\?.*)?$/, (route) =>
    json(route, { total: 0, entries: [] }),
  );
  await page.route('**/api/v1/admin/actions/202', async (route) => {
    auditHeld.resolve();
    await releaseAudit.promise;
    auditOutcome = await fulfillDelayedRoute(route, {
      action: { id: 202, reason: 'LOCAL_STALE_AUDIT_DETAIL', status: 'executed' },
    });
  });
  await page.getByRole('button', { name: 'Audit Trail', exact: true }).first().click();
  await page.getByText('Local audit event').click();
  await auditHeld.promise;
  await expect(page.getByRole('dialog', { name: /Audit event details/i })).toBeVisible();
  await page.getByTestId('server-switcher').selectOption('peer-beta', { force: true });
  await expect(page.getByRole('dialog', { name: /Audit event details/i })).toHaveCount(0);
  releaseAudit.resolve();
  await expect.poll(() => auditOutcome).not.toBe('pending');
  await expect(page.getByText('LOCAL_STALE_AUDIT_DETAIL')).toHaveCount(0);
});

test('uses validated remote public origin for Fileshare and McBrowser shares and blocks local-origin fallback', async ({ page }) => {
  await installAetherFlowMocks(page);
  const SHARE_TOKEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm0123';
  const peers = [
    makePeer({ id: 'peer-origin', name: 'Beta Public' }),
    makePeer({ id: 'peer-noorigin', name: 'Gamma Private' }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-origin', {
    settings: { baseDomain: 'beta-public.example.com', setupCompleted: true },
  });
  await mountPeerDefaults(page, 'peer-noorigin', {
    settings: { baseDomain: '', setupCompleted: true },
  });

  const localSharePosts: string[] = [];
  const noOriginSharePosts: string[] = [];
  await page.route(/\/api\/v1\/auth\/fileshare(?:\?.*)?$/, async (route) => {
    const parsed = new URL(route.request().url());
    if (route.request().method() !== 'GET' || parsed.pathname !== '/api/v1/auth/fileshare') {
      await route.fallback();
      return;
    }
    await json(route, []);
  });
  await page.route(/\/api\/v1\/auth\/mcbrowser\/shares(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      localSharePosts.push(route.request().url());
      await json(route, {
        share: {
          id: 'local-sh-1',
          path: 'local-file.txt',
          url: `/share?token=${SHARE_TOKEN}`,
          allow_download: true,
          password_required: false,
          created_at: '2026-11-23T12:00:00Z',
        },
      });
      return;
    }
    await json(route, { shares: [] });
  });
  await page.route(/\/api\/v1\/peers\/peer-origin\/auth\/mcbrowser\/shares(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await json(route, {
        share: {
          id: 'beta-sh-1',
          path: 'remote-note.txt',
          url: `/share?token=${SHARE_TOKEN}`,
          allow_download: true,
          password_required: false,
          created_at: '2026-11-23T12:00:00Z',
        },
      });
      return;
    }
    await json(route, { shares: [] });
  });
  await page.route(/\/api\/v1\/peers\/peer-noorigin\/auth\/mcbrowser\/shares(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      noOriginSharePosts.push(route.request().url());
    }
    await json(route, { shares: [] });
  });

  // 1. Remote server with validated public baseDomain: Fileshare + McBrowser generate remote HTTPS link & QR.
  await page.goto('/?tab=fileshare');
  await page.getByTestId('server-switcher').selectOption('peer-origin');
  await page.getByRole('tab', { name: /Public Share Links/i }).click();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toHaveCount(0);
  await page.getByRole('button', { name: /^Create share$/i }).click();
  const createDialog = page.getByRole('dialog', { name: /Create public share/i });
  await createDialog.getByLabel(/File or folder path/i).fill('remote-note.txt');
  await createDialog.getByRole('button', { name: /^Create share$/i }).click();
  const expectedRemoteUrl = `https://beta-public.example.com/share?token=${SHARE_TOKEN}`;
  await expect(createDialog.getByLabel(/Share URL/i)).toHaveValue(expectedRemoteUrl);
  await expect(createDialog.getByRole('link', { name: /Open share preview/i })).toHaveAttribute('href', expectedRemoteUrl);
  await expect(createDialog.locator('svg')).toBeVisible();
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: 'McBrowser', exact: true }).first().click();
  await expect(page.getByText('remote-note.txt')).toBeVisible();
  await page.getByRole('checkbox', { name: /Select visible/i }).check();
  await page.getByRole('button', { name: /^Share…$/i }).click();
  const mcShareDialog = page.getByRole('dialog', { name: /Create public share/i });
  await mcShareDialog.getByRole('button', { name: /^Create share$/i }).click();
  await expect(mcShareDialog.getByLabel(/Share URL/i)).toHaveValue(expectedRemoteUrl);
  await expect(mcShareDialog.getByRole('link', { name: /Open share preview/i })).toHaveAttribute('href', expectedRemoteUrl);
  await page.keyboard.press('Escape');
  expect(localSharePosts).toEqual([]);

  // 2. Remote server without public origin: both McBrowser and Fileshare gate share creation with localized guidance.
  await page.getByTestId('server-switcher').selectOption('peer-noorigin');
  await expect(page.getByText('remote-note.txt')).toBeVisible();
  await page.getByRole('checkbox', { name: /Select visible/i }).check();
  const mcShareBtn = page.getByRole('button', { name: /^Share…$/i });
  await expect(mcShareBtn).toBeDisabled();
  await expect(mcShareBtn).toHaveAttribute('title', /Gamma Private/);

  await page.getByRole('button', { name: 'File Share', exact: true }).first().click();
  await page.getByRole('tab', { name: /Public Share Links/i }).click();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toBeVisible();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toContainText('Gamma Private');
  await expect(page.getByRole('button', { name: /^Create share$/i })).toBeDisabled();
  expect(noOriginSharePosts).toEqual([]);
  expect(localSharePosts).toEqual([]);

  // 3. Local server preserves local origin share links.
  await page.getByTestId('server-switcher').selectOption('');
  await page.getByRole('tab', { name: /Public Share Links/i }).click();
  await page.getByRole('button', { name: /^Create share$/i }).click();
  const localDialog = page.getByRole('dialog', { name: /Create public share/i });
  await localDialog.getByLabel(/File or folder path/i).fill('local-file.txt');
  await localDialog.getByRole('button', { name: /^Create share$/i }).click();
  const localOrigin = new URL(page.url()).origin;
  await expect(localDialog.getByLabel(/Share URL/i)).toHaveValue(`${localOrigin}/share?token=${SHARE_TOKEN}`);
  expect(localSharePosts.length).toBe(1);
});

test('enforces least-privilege settings and network fetches, McBrowser checksums write scope, server-aware MediaFlow launch URLs, and local-only Users self-edit protection', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [
    makePeer({
      id: 'peer-least',
      name: 'Least Priv Peer',
      outboundAccess: {
        services: 'none',
        settings: 'none',
        network: 'read',
        files: 'read',
        users: 'write',
        marketplace: 'none',
        updates: 'none',
        transcoding: 'none',
      },
    }),
    makePeer({
      id: 'peer-media',
      name: 'Media Launch Peer',
      outboundAccess: {
        services: 'read',
        settings: 'read',
        network: 'read',
        files: 'read',
        users: 'read',
        marketplace: 'read',
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));

  const leastPaths: string[] = [];
  page.on('request', (req) => {
    const pathname = new URL(req.url()).pathname;
    if (pathname.startsWith('/api/v1/peers/peer-least/')) {
      leastPaths.push(pathname);
    }
  });

  await mountPeerDefaults(page, 'peer-least');
  await page.route('**/api/v1/peers/peer-least/admin/users', (route) =>
    json(route, [
      { id: 1, username: 'admin', email: 'remote-admin@peer.test', role: 'admin', totp_enabled: false, is_oauth: false },
      { id: 2, username: 'ops', email: 'remote-ops@peer.test', role: 'admin', totp_enabled: false, is_oauth: false },
    ]),
  );
  await page.route('**/api/v1/admin/users', (route) =>
    json(route, [
      { id: 1, username: 'admin', email: 'local-admin@example.com', role: 'admin', totp_enabled: false, is_oauth: false },
      { id: 2, username: 'bob', email: 'bob@example.com', role: 'admin', totp_enabled: false, is_oauth: false },
    ]),
  );
  await mountPeerDefaults(page, 'peer-media', {
    settings: { baseDomain: 'media-peer.example.com', setupCompleted: true },
    services: {
      sonarr: {
        id: 'sonarr',
        name: 'Sonarr',
        status: 'running',
        installed: true,
        launch_url: 'http://localhost:8989/sonarr',
      },
      radarr: {
        id: 'radarr',
        name: 'Radarr',
        status: 'running',
        installed: true,
        local_domain: 'radarr.aether.local',
        external_access_enabled: false,
      },
      jellyfin: {
        id: 'jellyfin',
        name: 'Jellyfin',
        status: 'running',
        installed: true,
        public_domain: 'jellyfin.media-peer.example.com',
        external_access_enabled: true,
        tls_enabled: true,
      },
    },
  });

  await page.goto('/?tab=overview');
  await page.getByTestId('server-switcher').selectOption('peer-least');
  await expect(page.getByTestId('active-server-bar')).toHaveAttribute('data-server-id', 'peer-least');

  // Overview CapacityPredictions buttons disabled without Settings:Write, and prediction GETs skipped without Settings:Read.
  await expect(page.getByRole('button', { name: /Analyze capacity/i })).toBeDisabled();
  await expect(page.getByRole('button', { name: /Analyze bandwidth/i })).toBeDisabled();

  // Network ExternalAccessSettings reads ingress configs (Network:Read) but skips settings (Settings:None) & admin/services (Services:None).
  await page.getByRole('button', { name: 'Network', exact: true }).first().click();
  await expect.poll(() => leastPaths.includes('/api/v1/peers/peer-least/admin/ingress/configs')).toBe(true);
  expect(leastPaths.some((p) => p.endsWith('/auth/settings'))).toBe(false);
  expect(leastPaths.some((p) => p.endsWith('/admin/services'))).toBe(false);
  expect(leastPaths.some((p) => p.endsWith('/admin/ai/predictions'))).toBe(false);
  expect(leastPaths.some((p) => p.endsWith('/admin/ai/predictions/history'))).toBe(false);

  // McBrowser checksums requires Files:Write (peer-least has Files:Read), while Info uses Files:Read.
  await page.getByRole('button', { name: 'McBrowser', exact: true }).first().click();
  await expect(page.getByText('remote-note.txt')).toBeVisible();
  await page.getByRole('checkbox', { name: /Select visible/i }).check();
  await expect(page.getByRole('button', { name: /^Info$/i })).toBeEnabled();
  const checksumBtn = page.getByRole('button', { name: /^Checksums$/i });
  await expect(checksumBtn).toBeDisabled();
  await expect(checksumBtn).toHaveAttribute('title', /Least Priv Peer/);

  // Users self-edit protection compares local operator only on local server (not remote user id=1/username='admin').
  await page.getByRole('button', { name: 'Users', exact: true }).first().click();
  await page.getByText('remote-admin@peer.test').click();
  const userDrawer = page.getByRole('dialog', { name: /Manage user/i });
  await expect(userDrawer).toBeVisible();
  await expect(userDrawer.getByText(/Your own account cannot be demoted or deleted here/i)).toHaveCount(0);
  await expect(userDrawer.getByRole('button', { name: /Update role/i })).toBeVisible();
  await expect(userDrawer.getByRole('button', { name: /Delete User/i })).toBeEnabled();
  await page.keyboard.press('Escape');

  await page.getByTestId('server-switcher').selectOption('');
  await page.getByText('local-admin@example.com').click();
  await expect(userDrawer).toBeVisible();
  await expect(userDrawer.getByText(/Your own account cannot be demoted or deleted here/i)).toBeVisible();
  await page.keyboard.press('Escape');

  // MediaFlow launch URLs are server-aware: remote hides localhost/aether.local fallbacks and renders validated public URL.
  await page.getByTestId('server-switcher').selectOption('peer-media');
  await page.getByRole('button', { name: 'MediaFlow', exact: true }).first().click();
  const sonarrCard = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Sonarr', exact: true }) });
  const radarrCard = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Radarr', exact: true }) });
  const jellyfinCard = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Jellyfin', exact: true }) });
  await expect(sonarrCard).toBeVisible();
  await expect(radarrCard).toBeVisible();
  await expect(jellyfinCard).toBeVisible();
  await expect(sonarrCard.getByRole('link', { name: /^Launch$/i })).toHaveCount(0);
  await expect(radarrCard.getByRole('link', { name: /^Launch$/i })).toHaveCount(0);
  await expect(jellyfinCard.getByRole('link', { name: /^Launch$/i })).toHaveAttribute(
    'href',
    'https://jellyfin.media-peer.example.com',
  );
});

test('gates disconnect fallback services polling by grant, resets McBrowser preview href on switch, and keeps local avatar local', async ({ page }) => {
  await installAetherFlowMocks(page, { enableWS: false });
  const ONE_PX_PNG = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    'base64',
  );
  await page.route(/\/api(\/v1)?(\/auth)?\/session/, (route) =>
    json(route, {
      id: 1,
      username: 'admin',
      email: 'admin@example.com',
      avatar_url: '/api/v1/auth/profile/avatar',
      role: 'admin',
      is_oauth: false,
    }),
  );
  await page.route('**/api/v1/auth/profile/avatar', (route) =>
    route.fulfill({ status: 200, contentType: 'image/png', body: ONE_PX_PNG }),
  );

  const peers = [
    makePeer({
      id: 'peer-nosvc',
      name: 'No Services Peer',
      outboundAccess: {
        services: 'none',
        files: 'write',
        settings: 'read',
        marketplace: 'none',
        users: 'none',
        network: 'none',
        updates: 'none',
        transcoding: 'none',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));

  const peerAvatarCalls: string[] = [];
  const peerServicesCalls: string[] = [];
  const peerMetricsCalls: string[] = [];
  page.on('request', (req) => {
    const pathname = new URL(req.url()).pathname;
    if (pathname.includes('/auth/profile/avatar') && pathname.startsWith('/api/v1/peers/')) {
      peerAvatarCalls.push(pathname);
    }
    if (pathname === '/api/v1/peers/peer-nosvc/auth/services') {
      peerServicesCalls.push(pathname);
    }
    if (pathname === '/api/v1/peers/peer-nosvc/auth/system/metrics') {
      peerMetricsCalls.push(pathname);
    }
  });

  await mountPeerDefaults(page, 'peer-nosvc');
  await page.route(/\/api\/v1\/peers\/peer-nosvc\/auth\/mcbrowser\/entries(?:\?.*)?$/, (route) =>
    json(route, {
      path: '',
      entries: [
        { name: 'remote-shot.png', path: 'remote-shot.png', kind: 'file', size: 256, modified: '2026-11-23T12:00:00Z' },
      ],
    }),
  );
  await page.route(/\/api\/v1\/peers\/peer-nosvc\/auth\/mcbrowser\/preview\//, (route) =>
    route.fulfill({ status: 200, contentType: 'image/png', body: ONE_PX_PNG }),
  );
  await page.route('**/api/v1/peers/peer-nosvc/auth/mcbrowser/media**', (route) =>
    route.fulfill({ status: 200, contentType: 'image/png', body: ONE_PX_PNG }),
  );
  await page.route('**/api/v1/peers/peer-nosvc/auth/mcbrowser/media-info**', (route) =>
    json(route, { content_type: 'image/png', size: 256 }),
  );
  await page.route('**/api/v1/auth/mcbrowser/usage', (route) =>
    json(route, { used_bytes: 512, quota_bytes: 1048576, status: 'ok' }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/policy(?:\/.*)?$/, (route) =>
    json(route, {
      user_id: 1,
      scope: 'private',
      permissions: { read: true, create: true, modify: true, delete: true, download: true, share: true, archive: true, extract: true },
      rules: [],
    }),
  );
  await page.route('**/api/v1/auth/mcbrowser/entries**', (route) =>
    json(route, {
      path: '',
      entries: [
        { name: 'local-shot.png', path: 'local-shot.png', kind: 'file', size: 128, modified: '2026-11-23T12:00:00Z' },
      ],
    }),
  );
  await page.route('**/api/v1/auth/mcbrowser/preview/**', (route) =>
    route.fulfill({ status: 200, contentType: 'image/png', body: ONE_PX_PNG }),
  );
  await page.route('**/api/v1/auth/mcbrowser/media**', (route) =>
    route.fulfill({ status: 200, contentType: 'image/png', body: ONE_PX_PNG }),
  );
  await page.route('**/api/v1/auth/mcbrowser/media-info**', (route) =>
    json(route, { content_type: 'image/png', size: 128 }),
  );

  await page.goto('/?tab=mcbrowser');
  const headerAvatar = page.locator('header img[src="/api/v1/auth/profile/avatar"]');
  await expect(headerAvatar).toBeVisible();

  // Switch to peer-nosvc (WS disabled -> immediate fallback polling): metrics polls (initial + fallback), services never polls, avatar stays local.
  await page.getByTestId('server-switcher').selectOption('peer-nosvc');
  await expect.poll(() => peerMetricsCalls.length, { timeout: 10_000 }).toBeGreaterThanOrEqual(2);
  expect(peerServicesCalls).toEqual([]);
  await expect(headerAvatar).toBeVisible();
  expect(peerAvatarCalls).toEqual([]);

  // Open remote McBrowser media preview, verify download href points to peer-nosvc, then switch back to local -> modal closes and local preview binds to local href.
  await page.getByRole('button', { name: /remote-shot\.png/i }).click();
  const previewDialog = page.getByRole('dialog', { name: /Media preview/i });
  await expect(previewDialog).toBeVisible();
  await expect(previewDialog.getByRole('link', { name: /Download original/i })).toHaveAttribute(
    'href',
    '/api/v1/peers/peer-nosvc/auth/mcbrowser/download?path=remote-shot.png',
  );

  await page.getByTestId('server-switcher').selectOption('', { force: true });
  await expect(previewDialog).toHaveCount(0);
  await page.getByRole('button', { name: /local-shot\.png/i }).click();
  await expect(previewDialog).toBeVisible();
  await expect(previewDialog.getByRole('link', { name: /Download original/i })).toHaveAttribute(
    'href',
    '/api/v1/auth/mcbrowser/download?path=local-shot.png',
  );
  expect(peerAvatarCalls).toEqual([]);
});

test('clears stale peer Settings on revisit and live grant revocation, re-fetches on re-grant, and clears Services on grant loss', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);
  const SHARE_TOKEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm0123';
  let settingsGrant: AccessLevel = 'write';
  let servicesGrant: AccessLevel = 'read';
  let peerBaseDomain = 'origin-v1.example.com';
  let holdNextSettingsGet = false;
  let heldSettings = deferred();
  let releaseSettings = deferred();
  let peerServicesCallsAfterRevoke = 0;
  let servicesRevoked = false;

  const buildPeers = () => [
    makePeer({
      id: 'peer-dyn',
      name: 'Dynamic Origin Peer',
      outboundAccess: {
        services: servicesGrant,
        settings: settingsGrant,
        files: 'write',
        marketplace: 'read',
        users: 'read',
        network: 'read',
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  await page.route(/\/api\/v1\/auth\/fileshare(?:\?.*)?$/, async (route) => {
    const parsed = new URL(route.request().url());
    if (route.request().method() !== 'GET' || parsed.pathname !== '/api/v1/auth/fileshare') {
      await route.fallback();
      return;
    }
    await json(route, []);
  });
  await page.route(/\/api\/v1\/auth\/mcbrowser\/shares(?:\?.*)?$/, (route) => json(route, { shares: [] }));
  await mountPeerDefaults(page, 'peer-dyn');
  await page.route('**/api/v1/peers/peer-dyn/auth/settings', async (route) => {
    if (holdNextSettingsGet) {
      holdNextSettingsGet = false;
      heldSettings.resolve();
      await releaseSettings.promise;
      await fulfillDelayedRoute(route, {
        baseDomain: peerBaseDomain,
        setupCompleted: true,
        language: 'en',
        timezone: 'UTC',
        defaultDashboard: 'overview',
        updateChannel: 'stable',
      });
      return;
    }
    await json(route, {
      baseDomain: peerBaseDomain,
      setupCompleted: true,
      language: 'en',
      timezone: 'UTC',
      defaultDashboard: 'overview',
      updateChannel: 'stable',
    });
  });
  await page.route('**/api/v1/peers/peer-dyn/auth/services', async (route) => {
    if (servicesRevoked) {
      peerServicesCallsAfterRevoke += 1;
    }
    await json(route, {
      alpha: {
        id: 'alpha',
        name: 'Alpha Peer Service',
        status: 'running',
        managed_by: 'systemd',
      },
    });
  });
  await page.route(/\/api\/v1\/peers\/peer-dyn\/auth\/mcbrowser\/shares(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await json(route, {
        share: {
          id: 'dyn-sh-1',
          path: 'report.txt',
          url: `/share?token=${SHARE_TOKEN}`,
          allow_download: true,
          password_required: false,
          created_at: '2026-11-23T12:00:00Z',
        },
      });
      return;
    }
    await json(route, { shares: [] });
  });

  // 1. Initial visit uses origin-v1.
  await page.goto('/?tab=fileshare');
  await page.getByTestId('server-switcher').selectOption('peer-dyn');
  await page.getByRole('tab', { name: /Public Share Links/i }).click();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toHaveCount(0);
  await page.getByRole('button', { name: /^Create share$/i }).click();
  const dialog = page.getByRole('dialog', { name: /Create public share/i });
  await dialog.getByLabel(/File or folder path/i).fill('report.txt');
  await dialog.getByRole('button', { name: /^Create share$/i }).click();
  await expect(dialog.getByLabel(/Share URL/i)).toHaveValue(`https://origin-v1.example.com/share?token=${SHARE_TOKEN}`);
  await page.keyboard.press('Escape');

  // 2. Revisit peer-dyn after remote public origin is cleared -> stale origin-v1 must NOT survive.
  await page.getByTestId('server-switcher').selectOption('');
  peerBaseDomain = '';
  await page.getByTestId('server-switcher').selectOption('peer-dyn');
  await page.getByRole('tab', { name: /Public Share Links/i }).click();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toBeVisible();
  await expect(page.getByRole('button', { name: /^Create share$/i })).toBeDisabled();

  // 3. Revisit peer-dyn after origin changes to origin-v2 -> fresh authorized settings take effect.
  await page.getByTestId('server-switcher').selectOption('');
  peerBaseDomain = 'origin-v2.example.com';
  await page.getByTestId('server-switcher').selectOption('peer-dyn');
  await page.getByRole('tab', { name: /Public Share Links/i }).click();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toHaveCount(0);
  await page.getByRole('button', { name: /^Create share$/i }).click();
  await dialog.getByLabel(/File or folder path/i).fill('report.txt');
  await dialog.getByRole('button', { name: /^Create share$/i }).click();
  await expect(dialog.getByLabel(/Share URL/i)).toHaveValue(`https://origin-v2.example.com/share?token=${SHARE_TOKEN}`);
  await page.keyboard.press('Escape');

  // 4. Live revocation of Settings read immediately clears origin & disables sharing.
  settingsGrant = 'none';
  await page.clock.fastForward('00:16');
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toBeVisible();
  await expect(page.getByRole('button', { name: /^Create share$/i })).toBeDisabled();

  // 5. Live re-grant of Settings read does NOT restore stale origin-v2 before fresh authorized GET resolves.
  peerBaseDomain = 'origin-v3.example.com';
  heldSettings = deferred();
  releaseSettings = deferred();
  holdNextSettingsGet = true;
  settingsGrant = 'write';
  await page.clock.fastForward('00:16');
  await heldSettings.promise;
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toBeVisible();
  await expect(page.getByRole('button', { name: /^Create share$/i })).toBeDisabled();
  releaseSettings.resolve();
  await expect(page.getByTestId('fileshare-remote-origin-notice')).toHaveCount(0);
  await page.getByRole('button', { name: /^Create share$/i }).click();
  await dialog.getByLabel(/File or folder path/i).fill('report.txt');
  await dialog.getByRole('button', { name: /^Create share$/i }).click();
  await expect(dialog.getByLabel(/Share URL/i)).toHaveValue(`https://origin-v3.example.com/share?token=${SHARE_TOKEN}`);
  await page.keyboard.press('Escape');

  // 6. Live revocation of Services read clears displayed services and emits no further unauthorized reads.
  await page.getByRole('button', { name: 'Services', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'Alpha Peer Service', exact: true })).toBeVisible();
  servicesGrant = 'none';
  await page.clock.fastForward('00:16');
  await expect(page.getByRole('heading', { name: 'Alpha Peer Service', exact: true })).toHaveCount(0);
  peerServicesCallsAfterRevoke = 0;
  servicesRevoked = true;
  await page.clock.fastForward('00:35');
  expect(peerServicesCallsAfterRevoke).toBe(0);
});

test('keeps remote McBrowser PolicyAdmin empty without local-ID auto-load, clears on grant loss, and enforces unified remote launch rules', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);
  let usersGrant: AccessLevel = 'write';
  const buildPeers = () => [
    makePeer({
      id: 'peer-pol',
      name: 'Policy & Launch Peer',
      outboundAccess: {
        files: 'write',
        users: usersGrant,
        services: 'read',
        marketplace: 'read',
        settings: 'read',
        network: 'read',
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));

  const remotePolicyGets: string[] = [];
  await page.route(/\/api\/v1\/auth\/mcbrowser\/usage(?:\?.*)?$/, (route) =>
    json(route, { used_bytes: 512, quota_bytes: 1048576, status: 'ok' }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/entries(?:\?.*)?$/, (route) =>
    json(route, { path: '', entries: [] }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/policy(?:\/(\d+))?$/, async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname.endsWith('/1')) {
      await json(route, {
        user_id: 1,
        scope: 'local-admin-scope',
        permissions: { read: true, create: true, rename: true, modify: true, delete: true, share: true, download: true, execute: false },
        rules: [],
      });
      return;
    }
    await json(route, {
      user_id: 1,
      scope: 'local-root',
      permissions: { read: true, create: true, rename: true, modify: true, delete: true, share: true, download: true, execute: false },
      rules: [],
    });
  });

  await mountPeerDefaults(page, 'peer-pol', {
    settings: { baseDomain: 'launch-peer.example.com', setupCompleted: true },
    services: {
      jellyfin: {
        id: 'jellyfin',
        name: 'Jellyfin',
        status: 'running',
        installed: true,
        launch_url: 'https://jellyfin.launch-peer.example.com',
        public_domain: 'jellyfin.launch-peer.example.com',
        external_access_enabled: true,
        tls_enabled: true,
        launch_scope: 'public',
      },
      sonarr: {
        id: 'sonarr',
        name: 'Sonarr',
        status: 'running',
        installed: true,
        launch_url: 'http://192.168.1.50:8989/sonarr',
        launch_scope: 'lan',
      },
      radarr: {
        id: 'radarr',
        name: 'Radarr',
        status: 'running',
        installed: true,
        launch_url: 'https://radarr.aether.local',
        launch_scope: 'internal',
      },
      bazarr: {
        id: 'bazarr',
        name: 'Bazarr',
        status: 'running',
        installed: true,
        launch_url: 'https://localhost:6767',
        public_domain: 'localhost',
        external_access_enabled: true,
        tls_enabled: true,
        launch_scope: 'public',
      },
      lidarr: {
        id: 'lidarr',
        name: 'Lidarr',
        status: 'running',
        installed: true,
        launch_url: 'https://intranet/lidarr',
        launch_scope: 'network',
      },
    },
  });
  await page.route(/\/api\/v1\/peers\/peer-pol\/(public|admin|auth)\/marketplace(?:\?.*)?$/, (route) =>
    json(route, [
      {
        id: 'jellyfin',
        name: 'Jellyfin',
        desc: 'Public media server',
        category: 'Media',
        status: 'installed',
        launch_url: 'https://jellyfin.launch-peer.example.com',
        public_domain: 'jellyfin.launch-peer.example.com',
        external_access_enabled: true,
        tls_enabled: true,
        launch_scope: 'public',
        inventory_known: true,
        inventory_authenticated: true,
      },
      {
        id: 'sonarr',
        name: 'Sonarr',
        desc: 'LAN-only automation',
        category: 'Media',
        status: 'installed',
        launch_url: 'http://192.168.1.50:8989/sonarr',
        launch_scope: 'lan',
        inventory_known: true,
        inventory_authenticated: true,
      },
      {
        id: 'radarr',
        name: 'Radarr',
        desc: 'Internal mDNS app',
        category: 'Media',
        status: 'installed',
        launch_url: 'https://radarr.aether.local',
        launch_scope: 'internal',
        inventory_known: true,
        inventory_authenticated: true,
      },
    ]),
  );
  await page.route(/\/api\/v1\/peers\/peer-pol\/auth\/mcbrowser\/policy\/(\d+)$/, async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    remotePolicyGets.push(pathname);
    if (pathname.endsWith('/42')) {
      await json(route, {
        user_id: 42,
        scope: 'peer-team-beta',
        permissions: { read: true, create: true, rename: true, modify: true, delete: false, share: false, download: true, execute: false },
        rules: [],
      });
      return;
    }
    await json(route, { error: 'Not found' }, 404);
  });

  // 1. Local McBrowser PolicyAdmin preserves self-ID default ("1") and auto-load.
  await page.goto('/?tab=mcbrowser');
  await page.getByRole('tab', { name: /Storage Policy/i }).click();
  await expect(page.getByLabel(/Target user ID/i)).toHaveValue('1');
  await expect(page.getByLabel(/Storage scope/i)).toHaveValue('local-admin-scope');

  // 2. Remote McBrowser PolicyAdmin starts empty and NEVER auto-loads /policy/1.
  await page.getByTestId('server-switcher').selectOption('peer-pol');
  await page.getByRole('tab', { name: /Storage Policy/i }).click();
  await expect(page.getByLabel(/Target user ID/i)).toHaveValue('');
  await expect(page.getByLabel(/Storage scope/i)).toHaveCount(0);
  expect(remotePolicyGets).toEqual([]);

  // Explicit peer target ID loads cleanly, and live Users grant revocation clears loaded policy immediately.
  await page.getByLabel(/Target user ID/i).fill('42');
  await page.getByRole('button', { name: /Load \/ refresh policy/i }).click();
  await expect(page.getByLabel(/Storage scope/i)).toHaveValue('peer-team-beta');
  expect(remotePolicyGets).toEqual(['/api/v1/peers/peer-pol/auth/mcbrowser/policy/42']);

  usersGrant = 'none';
  await page.clock.fastForward('00:16');
  await expect(page.getByLabel(/Storage scope/i)).toHaveCount(0);
  await expect(page.getByTestId('mcbrowser-policy-access-note')).toBeVisible();

  // 3. Shared remote launch policy across Services, Marketplace, and MediaFlow.
  await page.getByRole('button', { name: 'Services', exact: true }).first().click();
  const svcJellyfin = page.locator('article.af-service-tile').filter({ has: page.getByRole('heading', { name: 'Jellyfin', exact: true }) });
  const svcSonarr = page.locator('article.af-service-tile').filter({ has: page.getByRole('heading', { name: 'Sonarr', exact: true }) });
  const svcRadarr = page.locator('article.af-service-tile').filter({ has: page.getByRole('heading', { name: 'Radarr', exact: true }) });
  const svcBazarr = page.locator('article.af-service-tile').filter({ has: page.getByRole('heading', { name: 'Bazarr', exact: true }) });
  const svcLidarr = page.locator('article.af-service-tile').filter({ has: page.getByRole('heading', { name: 'Lidarr', exact: true }) });
  await expect(svcJellyfin.getByRole('link', { name: /Open App|Launch/i })).toHaveAttribute('href', 'https://jellyfin.launch-peer.example.com');
  await expect(svcSonarr.getByRole('link', { name: /Open App|Launch/i })).toHaveCount(0);
  await expect(svcRadarr.getByRole('link', { name: /Open App|Launch/i })).toHaveCount(0);
  await expect(svcBazarr.getByRole('link', { name: /Open App|Launch/i })).toHaveCount(0);
  await expect(svcLidarr.getByRole('link', { name: /Open App|Launch/i })).toHaveCount(0);

  await page.getByRole('button', { name: 'Marketplace', exact: true }).first().click();
  const mktJellyfin = page.locator('article[aria-label="Jellyfin application"]');
  const mktSonarr = page.locator('article[aria-label="Sonarr application"]');
  const mktRadarr = page.locator('article[aria-label="Radarr application"]');
  await expect(mktJellyfin).toBeVisible();
  await expect(mktJellyfin.getByRole('link', { name: /Open|Launch/i })).toHaveAttribute('href', 'https://jellyfin.launch-peer.example.com');
  await expect(mktSonarr.getByRole('link', { name: /Open|Launch/i })).toHaveCount(0);
  await expect(mktRadarr.getByRole('link', { name: /Open|Launch/i })).toHaveCount(0);

  await page.getByRole('button', { name: 'MediaFlow', exact: true }).first().click();
  const mfJellyfin = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Jellyfin', exact: true }) });
  const mfSonarr = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Sonarr', exact: true }) });
  const mfRadarr = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Radarr', exact: true }) });
  const mfBazarr = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Bazarr', exact: true }) });
  const mfLidarr = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Lidarr', exact: true }) });
  await expect(mfJellyfin.getByRole('link', { name: /^Launch$/i })).toHaveAttribute('href', 'https://jellyfin.launch-peer.example.com');
  await expect(mfSonarr.getByRole('link', { name: /^Launch$/i })).toHaveCount(0);
  await expect(mfRadarr.getByRole('link', { name: /^Launch$/i })).toHaveCount(0);
  await expect(mfBazarr.getByRole('link', { name: /^Launch$/i })).toHaveCount(0);
  await expect(mfLidarr.getByRole('link', { name: /^Launch$/i })).toHaveCount(0);
});

test('handles live grant revocation, Write-to-Read-to-Write busy release, and same-user role demotion/promotion without logout', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);
  let currentRole: 'admin' | 'user' = 'admin';
  let servicesGrant: AccessLevel = 'write';
  let settingsGrant: AccessLevel = 'write';

  await page.route(/\/api(\/v1)?(\/auth)?\/session/, (route) =>
    json(route, {
      id: 1,
      username: 'admin',
      email: 'admin@example.com',
      avatar_url: '',
      role: currentRole,
      is_oauth: false,
    }),
  );
  await page.route('**/api/v1/auth/profile', (route) =>
    json(route, { message: 'Account updated' }),
  );
  await page.route('**/api/v1/auth/sessions', (route) =>
    json(route, { sessions: [] }),
  );
  await page.route('**/api/v1/auth/user/quota', (route) =>
    json(route, { quota_bytes: 0, used_bytes: 0, configured: false }),
  );

  const buildPeers = () => [
    makePeer({
      id: 'peer-live',
      name: 'Live Transition Peer',
      outboundAccess: {
        services: servicesGrant,
        settings: settingsGrant,
        network: 'write',
        files: 'read',
        users: 'read',
        marketplace: 'read',
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  await mountPeerDefaults(page, 'peer-live');

  const analyzeHeld = deferred();
  const releaseAnalyze = deferred();
  let analyzeOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-live/admin/ai/bandwidth/analyze', async (route) => {
    analyzeHeld.resolve();
    await releaseAnalyze.promise;
    analyzeOutcome = await fulfillDelayedRoute(route, {
      reasoning: 'STALE_DOWNGRADED_BANDWIDTH',
      recommended_download_kbps: 1024,
      recommended_upload_kbps: 512,
    });
  });

  // 1. Open remote Service Logs modal, then revoke Services read -> modal auto-closes.
  await page.goto('/?tab=services');
  await page.getByTestId('server-switcher').selectOption('peer-live');
  const card = page.locator('article.af-service-tile').filter({
    has: page.getByRole('heading', { name: 'Beta Sonarr', exact: true }),
  });
  await expect(card).toBeVisible();
  await card.getByRole('button', { name: /^Logs$/i }).click();
  await expect(page.getByRole('dialog', { name: /Service Logs/i })).toBeVisible();
  servicesGrant = 'none';
  await page.clock.fastForward('00:16');
  await expect(page.getByRole('dialog', { name: /Service Logs/i })).toHaveCount(0);

  // 2. Write -> Read -> Write while Overview Analyze bandwidth is in flight must NOT strand button busy and must drop stale completion.
  servicesGrant = 'read';
  await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
  const analyzeBtn = page.getByRole('button', { name: /Analyze bandwidth/i });
  await expect(analyzeBtn).toBeEnabled();
  await analyzeBtn.click();
  await analyzeHeld.promise;
  await expect(analyzeBtn).toBeDisabled();

  settingsGrant = 'read';
  await page.clock.fastForward('00:16');
  await expect(analyzeBtn).toBeDisabled();

  settingsGrant = 'write';
  await page.clock.fastForward('00:16');
  await expect(analyzeBtn).toBeEnabled();

  releaseAnalyze.resolve();
  await expect.poll(() => analyzeOutcome).not.toBe('pending');
  await expect(page.getByText('STALE_DOWNGRADED_BANDWIDTH')).toHaveCount(0);

  // 3. Same-user role demotion (while already on local) & promotion reset role-scoped UI without logout.
  await page.getByTestId('server-switcher').selectOption('');
  await page.getByRole('button', { name: 'Settings', exact: true }).first().click();
  await page.getByRole('tab', { name: /Security/i }).click();
  await expect(page.getByTestId('server-switcher')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Cluster', exact: true }).first()).toBeVisible();

  currentRole = 'user';
  await page.getByLabel(/Email address/i).fill('demoted@example.com');
  await page.getByRole('button', { name: /Update profile/i }).click();
  await expect(page).not.toHaveURL(/\/login/);
  await expect(page.getByTestId('server-switcher')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Cluster', exact: true })).toHaveCount(0);

  // Role demotion remounted AuthenticatedShell cleanly; reopen Security subtab to trigger promotion.
  await page.getByRole('tab', { name: /Security/i }).click();
  currentRole = 'admin';
  await page.getByLabel(/Email address/i).fill('promoted@example.com');
  await page.getByRole('button', { name: /Update profile/i }).click();
  await expect(page).not.toHaveURL(/\/login/);
  await expect(page.getByRole('button', { name: 'Cluster', exact: true }).first()).toBeVisible();
  await expect(page.getByTestId('server-switcher')).toBeVisible();
});

test('gates secondary reads across MediaFlow, Marketplace plugins, Streaming Administration, Settings/Updates/Metadata, Audit action detail, and FlowAI', async ({ page }) => {
  await installAetherFlowMocks(page);
  const peers = [
    makePeer({
      id: 'peer-partial',
      name: 'Partial Grant Peer',
      outboundAccess: {
        services: 'none',
        marketplace: 'read',
        settings: 'read',
        files: 'none',
        users: 'none',
        network: 'none',
        updates: 'none',
        transcoding: 'none',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(peers)));
  await mountPeerDefaults(page, 'peer-partial');
  await page.route(/\/api\/v1\/peers\/peer-partial\/admin\/audit-log(?:\?.*)?$/, (route) =>
    json(route, {
      total: 1,
      entries: [
        {
          id: 9,
          username: 'peer-admin',
          action: 'action_approve',
          target_type: 'pending_action',
          target_id: '505',
          detail: 'Partial peer audit entry',
          ip_address: '10.231.0.21',
          created_at: '2026-11-23T11:00:00Z',
        },
      ],
    }),
  );
  await page.route('**/api/v1/peers/peer-partial/auth/blueprints', (route) =>
    json(route, { blueprints: [] }),
  );
  await page.route('**/api/v1/peers/peer-partial/admin/streaming/policies', (route) =>
    json(route, { minimumWatchSecs: 30, reconnectWindowSecs: 120, excludedUsers: [], excludedLibraries: [] }),
  );
  await page.route('**/api/v1/peers/peer-partial/admin/ai/metadata/status', (route) =>
    json(route, { scanning: false, done: 0, total: 0, progress: 0 }),
  );
  await page.route('**/api/v1/peers/peer-partial/admin/ai/metadata/results', (route) =>
    json(route, []),
  );
  await page.route(/\/api\/v1\/admin\/audit-log(?:\?.*)?$/, (route) =>
    json(route, { total: 0, entries: [] }),
  );

  const partialPaths: string[] = [];
  page.on('request', (req) => {
    const pathname = new URL(req.url()).pathname;
    if (pathname.startsWith('/api/v1/peers/peer-partial/')) {
      partialPaths.push(pathname);
    }
  });

  await page.goto('/?tab=overview');
  await page.getByTestId('server-switcher').selectOption('peer-partial');
  await expect(page.getByTestId('active-server-bar')).toHaveAttribute('data-server-id', 'peer-partial');

  // 1. MediaFlow: Marketplace:Read allows blueprints; Services:None & Transcoding:None block services/queue/config/stream.
  await page.getByRole('button', { name: 'MediaFlow', exact: true }).first().click();
  await expect.poll(() => partialPaths.includes('/api/v1/peers/peer-partial/auth/blueprints')).toBe(true);

  // 2. Marketplace: Marketplace:Read allows catalog; Services:None blocks /auth/plugins.
  await page.getByRole('button', { name: 'Marketplace', exact: true }).first().click();
  await expect.poll(() =>
    partialPaths.some(
      (p) =>
        p.endsWith('/public/marketplace')
        || p.endsWith('/admin/marketplace')
        || p.endsWith('/auth/marketplace'),
    ),
  ).toBe(true);

  // 3. Streaming -> History administration: Settings:Read allows policies; Services:None & Users:None block dashboard/imports/user-links.
  await page.getByRole('button', { name: 'Streaming', exact: true }).first().click();
  await page.getByRole('tab', { name: /History administration/i }).click();
  await expect.poll(() => partialPaths.includes('/api/v1/peers/peer-partial/admin/streaming/policies')).toBe(true);

  // 4. Settings -> General (Updates:None & Network:None skip update/check, update/status, network/status) & Metadata (Files:None disables Browse Directories and skips /auth/fs).
  await page.getByRole('button', { name: 'Settings', exact: true }).first().click();
  await page.getByRole('tab', { name: /Metadata/i }).click();
  await expect.poll(() => partialPaths.includes('/api/v1/peers/peer-partial/admin/ai/metadata/status')).toBe(true);
  await expect(page.getByRole('button', { name: /Browse Directories/i })).toBeDisabled();

  // 5. Audit Trail: Settings:Read loads audit log, clicking pending_action row does NOT fetch /admin/actions/505 when Services:None.
  await page.getByRole('button', { name: 'Audit Trail', exact: true }).first().click();
  await page.getByText('Partial peer audit entry').click();
  const auditDrawer = page.getByRole('dialog', { name: /Audit event details/i });
  await expect(auditDrawer).toBeVisible();
  await expect(auditDrawer.getByText(/Partial Grant Peer/)).toBeVisible();
  await page.keyboard.press('Escape');

  // 6. FlowAI: Services:None skips /admin/actions/pending.
  await page.getByRole('button', { name: 'FlowAI', exact: true }).first().click();
  await expect(page.getByTestId('active-server-bar')).toHaveAttribute('data-server-id', 'peer-partial');

  // Verify ZERO unauthorized secondary requests were sent to peer-partial.
  const forbiddenSuffixes = [
    '/auth/services',
    '/auth/plugins',
    '/admin/mediaflow/queue',
    '/admin/mediaflow/config',
    '/auth/mediaflow/stream',
    '/auth/streaming/dashboard',
    '/auth/streaming/history',
    '/auth/streaming/patterns',
    '/auth/streaming/drilldown',
    '/admin/streaming/imports/status',
    '/admin/streaming/user-links',
    '/auth/system/update/check',
    '/auth/system/update/status',
    '/admin/network/status',
    '/auth/sessions',
    '/auth/user/quota',
    '/auth/fs',
    '/admin/actions/505',
    '/admin/actions/pending',
  ];
  for (const suffix of forbiddenSuffixes) {
    expect(
      partialPaths.filter((p) => p.endsWith(suffix)),
      `Unexpected unauthorized peer request ending with ${suffix}`,
    ).toEqual([]);
  }
});

test('fences in-flight McBrowser batch actions and overwrite GET/PUT across Files Write-to-Read-to-Write while preserving read-only info', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);

  let filesGrant: AccessLevel = 'write';
  const buildPeers = () => [
    makePeer({
      id: 'peer-files',
      name: 'Files Transition Peer',
      outboundAccess: {
        files: filesGrant,
        services: 'read',
        marketplace: 'read',
        settings: 'read',
        users: 'read',
        network: 'read',
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  const syncPeers = async () => {
    const response = page.waitForResponse((r) => new URL(r.url()).pathname === PEERS_API);
    await page.clock.fastForward('00:16');
    await response;
  };
  await mountPeerDefaults(page, 'peer-files', {
    settings: { language: 'en', timezone: 'UTC', defaultDashboard: 'mcbrowser', setupCompleted: true },
  });

  const fullPerms = {
    read: true,
    create: true,
    rename: true,
    modify: true,
    delete: true,
    share: true,
    download: true,
    execute: true,
  };
  await page.route(/\/api\/v1\/peers\/peer-files\/auth\/mcbrowser\/policy(?:\?.*)?$/, (route) =>
    json(route, { user_id: 1, scope: 'peer-root', permissions: fullPerms, rules: [] }),
  );
  await page.route(/\/api\/v1\/peers\/peer-files\/auth\/mcbrowser\/entries(?:\?.*)?$/, (route) =>
    json(route, {
      path: '',
      entries: [
        { name: 'alpha.txt', path: 'alpha.txt', kind: 'file', size: 24, modified: '2026-11-23T10:00:00Z' },
        { name: 'beta.txt', path: 'beta.txt', kind: 'file', size: 18, modified: '2026-11-23T10:00:00Z' },
      ],
    }),
  );

  // 1. Multi-target batch delete: hold 1st DELETE, downgrade Files Write -> Read -> Write, verify 2nd target never dispatches.
  const deletedPaths: string[] = [];
  const firstDeleteHeld = deferred();
  const releaseFirstDelete = deferred();
  let firstDeleteOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/peers\/peer-files\/auth\/mcbrowser\/entry(?:\?.*)?$/, async (route) => {
    const targetPath = new URL(route.request().url()).searchParams.get('path') ?? '';
    deletedPaths.push(targetPath);
    if (deletedPaths.length === 1) {
      firstDeleteHeld.resolve();
      await releaseFirstDelete.promise;
      firstDeleteOutcome = await fulfillDelayedRoute(route, { deleted: targetPath });
      return;
    }
    await json(route, { deleted: targetPath });
  });

  // 2. Intentionally read-only "info" (GET /info): stays valid across Files Write -> Read.
  const infoHeld = deferred();
  const releaseInfo = deferred();
  let infoCalls = 0;
  await page.route(/\/api\/v1\/peers\/peer-files\/auth\/mcbrowser\/info(?:\?.*)?$/, async (route) => {
    infoCalls += 1;
    infoHeld.resolve();
    await releaseInfo.promise;
    await fulfillDelayedRoute(route, {
      path: 'alpha.txt',
      kind: 'file',
      size: 24,
      sha256: 'INFO_READONLY_OK',
    });
  });

  // 3. Editor overwrite GET/PUT: first PUT returns 412 conflict; overwrite GET is held across Files Write -> Read -> Write and must NEVER dispatch PUT.
  let contentGetCalls = 0;
  let contentPutCalls = 0;
  const overwriteGetHeld = deferred();
  const releaseOverwriteGet = deferred();
  let overwriteGetOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/peers\/peer-files\/auth\/mcbrowser\/content(?:\?.*)?$/, async (route) => {
    const method = route.request().method();
    if (method === 'GET') {
      contentGetCalls += 1;
      if (contentGetCalls === 1) {
        await json(
          route,
          { path: 'alpha.txt', content: 'original content', etag: '"v1"' },
          200,
          { etag: '"v1"' },
        );
        return;
      }
      overwriteGetHeld.resolve();
      await releaseOverwriteGet.promise;
      overwriteGetOutcome = await fulfillDelayedRoute(
        route,
        { path: 'alpha.txt', content: 'server changed content', etag: '"v2"' },
        200,
        { etag: '"v2"' },
      );
      return;
    }
    contentPutCalls += 1;
    if (contentPutCalls === 1) {
      await json(route, { error: 'ETag mismatch' }, 412);
      return;
    }
    await json(route, { path: 'alpha.txt', etag: '"v3"' }, 200, { etag: '"v3"' });
  });

  await page.goto('/?tab=mcbrowser');
  await page.getByTestId('server-switcher').selectOption('peer-files');
  await expect(page.getByText('alpha.txt')).toBeVisible();
  await expect(page.getByText('beta.txt')).toBeVisible();

  // --- Scenario 1: Batch delete interrupted on Files Write -> Read -> Write ---
  await page.getByLabel('Select visible').check();
  await page.getByRole('button', { name: /^Delete$/i }).click();
  const actionDialog = page.getByRole('dialog', { name: 'File operation' });
  await expect(actionDialog).toBeVisible();
  await actionDialog.getByRole('button', { name: /Review deletion/i }).click();
  await page.getByRole('dialog', { name: /Permanently delete selected entries/i })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();

  await firstDeleteHeld.promise;
  expect(deletedPaths).toHaveLength(1);

  filesGrant = 'read';
  await syncPeers();
  await expect(page.getByRole('dialog', { name: /Permanently delete selected entries/i })).toHaveCount(0);
  await expect(actionDialog).toHaveCount(0);

  filesGrant = 'write';
  await syncPeers();
  await expect(page.getByRole('button', { name: /^Delete$/i })).toBeEnabled();

  releaseFirstDelete.resolve();
  await expect.poll(() => firstDeleteOutcome).not.toBe('pending');
  expect(deletedPaths).toHaveLength(1);
  await expect(page.getByText('File operation completed')).toHaveCount(0);

  // --- Scenario 2: Read-only "info" action survives Files Write -> Read ---
  await page.getByLabel('Select visible').uncheck();
  await page.getByRole('checkbox', { name: 'Select alpha.txt', exact: true }).check();
  await page.getByRole('button', { name: /^Info$/i }).click();
  await expect(actionDialog).toBeVisible();
  await actionDialog.getByRole('button', { name: 'Run operation', exact: true }).click();
  await infoHeld.promise;
  expect(infoCalls).toBe(1);

  filesGrant = 'read';
  await syncPeers();
  // Intentionally read-only info modal stays open and active on Write -> Read.
  await expect(actionDialog).toBeVisible();

  releaseInfo.resolve();
  await expect(page.getByText('File operation completed')).toBeVisible();
  await expect(page.getByRole('tabpanel', { name: 'Workspace' }).getByText('INFO_READONLY_OK')).toBeVisible();

  // Restore Files:Write for Scenario 3.
  filesGrant = 'write';
  await syncPeers();

  // --- Scenario 3: Editor overwrite GET/PUT fenced across Files Write -> Read -> Write ---
  await page.getByRole('button', { name: /alpha\.txt/ }).click();
  const editorDialog = page.getByRole('dialog', { name: 'Code editor' });
  await expect(editorDialog).toBeVisible();
  const editorTextarea = editorDialog.getByLabel('Editor text');
  await editorTextarea.fill('modified draft content');
  await editorDialog.getByRole('button', { name: 'Save', exact: true }).click();
  await expect.poll(() => contentPutCalls).toBe(1);
  await expect(editorDialog.getByRole('button', { name: 'Overwrite with my draft…', exact: true })).toBeVisible();

  await editorDialog.getByRole('button', { name: 'Overwrite with my draft…', exact: true }).click();
  await page.getByRole('dialog', { name: 'Replace server content?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await overwriteGetHeld.promise;

  filesGrant = 'read';
  await syncPeers();
  // Editor stays open read-only with draft intact, saving busy released.
  await expect(editorDialog).toBeVisible();
  await expect(editorTextarea).toHaveValue('modified draft content');
  await expect(editorDialog.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();
  await expect(editorDialog.getByRole('button', { name: 'Reload file', exact: true })).toBeEnabled();

  filesGrant = 'write';
  await syncPeers();
  await expect(editorDialog.getByRole('button', { name: 'Save', exact: true })).toBeEnabled();

  releaseOverwriteGet.resolve();
  await expect.poll(() => overwriteGetOutcome).not.toBe('pending');
  // Stale overwrite GET MUST NOT dispatch a PUT.
  expect(contentPutCalls).toBe(1);

  // Fresh save after re-grant succeeds cleanly (proving busy was not stranded).
  await editorDialog.getByRole('button', { name: 'Save', exact: true }).click();
  await expect.poll(() => contentPutCalls).toBe(2);
  await expect(editorDialog.getByText('Saved', { exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(editorDialog).toHaveCount(0);
});

test('aborts and invalidates chunked McBrowser TUS uploads across Files Write-to-Read-to-Write without follow-up chunk or reconciliation requests', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);

  let filesGrant: AccessLevel = 'write';
  const buildPeers = () => [
    makePeer({
      id: 'peer-tus',
      name: 'TUS Transition Peer',
      outboundAccess: {
        files: filesGrant,
        services: 'read',
        marketplace: 'read',
        settings: 'read',
        users: 'read',
        network: 'read',
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  const syncPeers = async () => {
    const response = page.waitForResponse((r) => new URL(r.url()).pathname === PEERS_API);
    await page.clock.fastForward('00:16');
    await response;
  };
  await mountPeerDefaults(page, 'peer-tus', {
    settings: { language: 'en', timezone: 'UTC', defaultDashboard: 'mcbrowser', setupCompleted: true },
  });
  await page.route(/\/api\/v1\/peers\/peer-tus\/auth\/mcbrowser\/policy(?:\?.*)?$/, (route) =>
    json(route, {
      user_id: 1,
      scope: 'peer-root',
      permissions: { read: true, create: true, rename: true, modify: true, delete: true, share: true, download: true, execute: true },
      rules: [],
    }),
  );
  await page.route(/\/api\/v1\/peers\/peer-tus\/auth\/mcbrowser\/entries(?:\?.*)?$/, (route) =>
    json(route, {
      path: '',
      entries: [
        { name: 'alpha.txt', path: 'alpha.txt', kind: 'file', size: 24, modified: '2026-11-23T10:00:00Z' },
        { name: 'beta.txt', path: 'beta.txt', kind: 'file', size: 18, modified: '2026-11-23T10:00:00Z' },
      ],
    }),
  );

  const uploadHex = 'fedcba9876543210fedcba9876543210';
  let tusLength = '0';
  let tusMetadata = '';
  const tusSessionMethods: string[] = [];
  const firstPatchHeld = deferred();
  const releaseFirstPatch = deferred();
  await page.route(/\/api\/v1\/peers\/peer-tus\/auth\/mcbrowser\/uploads(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'GET') {
      await json(route, { uploads: [] });
      return;
    }
    const headers = await route.request().allHeaders();
    tusLength = headers['upload-length'] ?? '0';
    tusMetadata = headers['upload-metadata'] ?? '';
    await route.fulfill({
      status: 201,
      headers: {
        Location: `/api/v1/peers/peer-tus/auth/mcbrowser/uploads/${uploadHex}`,
        'Tus-Resumable': '1.0.0',
      },
      body: '',
    });
  });
  await page.route(`**/api/v1/peers/peer-tus/auth/mcbrowser/uploads/${uploadHex}`, async (route) => {
    const method = route.request().method();
    tusSessionMethods.push(method);
    if (method === 'HEAD') {
      await route.fulfill({
        status: 200,
        headers: {
          'Tus-Resumable': '1.0.0',
          'Upload-Offset': '0',
          'Upload-Length': tusLength,
          'Upload-Metadata': tusMetadata,
          'Upload-Status': 'uploading',
        },
        body: '',
      });
      return;
    }
    if (method === 'PATCH' && tusSessionMethods.filter((m) => m === 'PATCH').length === 1) {
      firstPatchHeld.resolve();
      await releaseFirstPatch.promise;
      await fulfillDelayedRoute(
        route,
        {},
        204,
        { 'Tus-Resumable': '1.0.0', 'Upload-Offset': String(4 * 1024 * 1024) },
      );
      return;
    }
    await route.fulfill({ status: 204, headers: { 'Tus-Resumable': '1.0.0' }, body: '' });
  });

  await page.goto('/?tab=mcbrowser');
  await page.getByTestId('server-switcher').selectOption('peer-tus');
  await expect(page.getByText('alpha.txt')).toBeVisible();
  await expect(page.getByText('beta.txt')).toBeVisible();

  // Warm up the WASM worker before advancing the fake clock so WebKit's worker
  // boot timeout cannot fire while fast-forwarding the 15s peer poll interval.
  const filterInput = page.getByPlaceholder('Instant filter (worker powered)');
  await filterInput.fill('alpha');
  await expect(page.getByText('beta.txt')).toHaveCount(0);
  await filterInput.fill('');
  await expect(page.getByText('beta.txt')).toBeVisible();

  await page.evaluate(() => {
    const input = document.querySelector('input[type="file"][aria-label="Choose files to upload"]') as HTMLInputElement | null;
    if (!input) throw new Error('McBrowser file input missing');
    const chunk = new Uint8Array(1024 * 1024);
    const parts: BlobPart[] = [];
    for (let i = 0; i < 64; i += 1) parts.push(chunk);
    parts.push(new Uint8Array(17));
    const file = new File(parts, 'large-fence.bin', { type: 'application/octet-stream' });
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });

  await firstPatchHeld.promise;
  expect(tusSessionMethods).toEqual(['HEAD', 'PATCH']);

  filesGrant = 'read';
  await syncPeers();
  await expect(page.getByRole('dialog', { name: 'Transfer queue' }).getByText('Cancelled', { exact: true })).toBeVisible();

  filesGrant = 'write';
  await syncPeers();
  releaseFirstPatch.resolve();
  await page.clock.fastForward('00:02');
  // No follow-up chunk PATCH, reconciliation HEAD, or DELETE may fire for the invalidated transfer.
  expect(tusSessionMethods).toEqual(['HEAD', 'PATCH']);
  await expect(page.getByRole('dialog', { name: 'Transfer queue' }).getByText('Cancelled', { exact: true })).toBeVisible();
});

test('fences cross-area Inbox, Services updates, Marketplace plugins, Network Tailscale, Streaming portability/live, Settings AI test, and FlowAI mutations on live grant transitions', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);

  let servicesGrant: AccessLevel = 'write';
  let marketplaceGrant: AccessLevel = 'write';
  let settingsGrant: AccessLevel = 'write';
  let networkGrant: AccessLevel = 'write';

  const buildPeers = () => [
    makePeer({
      id: 'peer-xarea',
      name: 'Cross-Area Peer',
      outboundAccess: {
        services: servicesGrant,
        marketplace: marketplaceGrant,
        settings: settingsGrant,
        files: 'read',
        users: 'read',
        network: networkGrant,
        updates: 'read',
        transcoding: 'read',
      },
    }),
  ];
  await page.route(`**${PEERS_API}`, (route) => json(route, peerSnapshot(buildPeers())));
  const syncPeers = async () => {
    const response = page.waitForResponse((r) => new URL(r.url()).pathname === PEERS_API);
    await page.clock.fastForward('00:16');
    await response;
  };
  await mountPeerDefaults(page, 'peer-xarea', {
    settings: { language: 'en', timezone: 'UTC', defaultDashboard: 'inbox', setupCompleted: true },
  });

  // --- Route mocks for peer-xarea ---
  const pendingAction = {
    id: 77,
    action: 'restart:sonarr',
    classification: 'high',
    risk_level: 'HIGH',
    status: 'pending',
    source: 'flowai',
    reason: 'Peer restart test action',
    created_at: '2026-11-23T12:00:00Z',
  };
  await page.route(/\/api\/v1\/peers\/peer-xarea\/admin\/actions(?:\?.*)?$/, (route) =>
    json(route, { total: 1, actions: [pendingAction] }),
  );
  await page.route(/\/api\/v1\/peers\/peer-xarea\/admin\/actions\/pending(?:\?.*)?$/, (route) =>
    json(route, { total: 1, count: 1, actions: [pendingAction] }),
  );
  await page.route('**/api/v1/peers/peer-xarea/admin/actions/77', (route) =>
    json(route, pendingAction),
  );
  const approveHeld = deferred();
  const releaseApprove = deferred();
  let approveOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-xarea/admin/actions/77/approve', async (route) => {
    approveHeld.resolve();
    await releaseApprove.promise;
    approveOutcome = await fulfillDelayedRoute(route, {
      message: 'STALE_ACTION_APPROVED',
      action: { ...pendingAction, status: 'executed' },
    });
  });

  const checkUpdatesHeld = deferred();
  const releaseCheckUpdates = deferred();
  let checkUpdatesOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-xarea/admin/packages/updates/check', async (route) => {
    checkUpdatesHeld.resolve();
    await releaseCheckUpdates.promise;
    checkUpdatesOutcome = await fulfillDelayedRoute(route, { updates_available: 9 });
  });

  await page.route('**/api/v1/peers/peer-xarea/auth/plugins', (route) =>
    json(route, {
      plugins: [
        {
          id: 'demo-plugin',
          name: 'Demo Plugin',
          version: '1.0.0',
          description: 'Cross-area plugin toggle test',
          enabled: false,
          healthy: true,
          granted_scopes: [],
        },
      ],
    }),
  );
  const pluginToggleHeld = deferred();
  const releasePluginToggle = deferred();
  let pluginToggleOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-xarea/admin/plugins/demo-plugin/control', async (route) => {
    pluginToggleHeld.resolve();
    await releasePluginToggle.promise;
    pluginToggleOutcome = await fulfillDelayedRoute(route, { message: 'STALE_PLUGIN_STARTED' });
  });

  await page.route(/\/api\/v1\/peers\/peer-xarea\/auth\/streaming\/dashboard(?:\?.*)?$/, (route) =>
    json(route, {
      servers: [
        {
          provider: 'jellyfin',
          name: 'Peer Jellyfin',
          status: 'connected',
          serverId: 'jf-peer-1',
          version: '10.10.0',
          url: 'https://jf.peer.example',
          enabled: true,
        },
      ],
      liveSummary: { activeSessions: 0, isDemoMode: false },
      sessions: [],
      analytics: { recentHistory: [] },
    }),
  );
  await page.route('**/api/v1/peers/peer-xarea/admin/streaming/policies', (route) =>
    json(route, { minimumWatchSecs: 30, reconnectWindowSecs: 120, excludedUsers: [], excludedLibraries: [] }),
  );
  await page.route('**/api/v1/peers/peer-xarea/admin/streaming/imports/status', (route) =>
    json(route, { jobs: [] }),
  );
  await page.route('**/api/v1/peers/peer-xarea/admin/streaming/user-links', (route) =>
    json(route, { links: [] }),
  );
  const exportHeld = deferred();
  const releaseExport = deferred();
  let exportOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-xarea/admin/streaming/portability/export', async (route) => {
    exportHeld.resolve();
    await releaseExport.promise;
    exportOutcome = await fulfillDelayedRoute(route, {
      manifest: { format: 'aetherflow.streaming-history', version: 1 },
      data: { history: [] },
    });
  });

  const testAiHeld = deferred();
  const releaseTestAi = deferred();
  let testAiOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-xarea/admin/settings/test-ai', async (route) => {
    testAiHeld.resolve();
    await releaseTestAi.promise;
    testAiOutcome = await fulfillDelayedRoute(route, { message: 'STALE_PROVIDER_CONNECTED' });
  });

  const chatHeld = deferred();
  const releaseChat = deferred();
  let chatOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route(/\/api\/v1\/peers\/peer-xarea\/auth\/ai\/(chat|support)$/, async (route) => {
    chatHeld.resolve();
    await releaseChat.promise;
    chatOutcome = await fulfillDelayedRoute(route, { reply: 'STALE_AI_REPLY' });
  });

  const tsConnectHeld = deferred();
  const releaseTsConnect = deferred();
  let tsConnectOutcome: 'pending' | 'fulfilled' | 'aborted' = 'pending';
  await page.route('**/api/v1/peers/peer-xarea/admin/network/tailscale/connect', async (route) => {
    tsConnectHeld.resolve();
    await releaseTsConnect.promise;
    tsConnectOutcome = await fulfillDelayedRoute(route, {
      auth_url: 'https://login.tailscale.com/a/stale-ts-auth',
      message: 'STALE_TS_CONNECT',
    });
  });

  // --- 1. Inbox ActionDetailModal: Services Write -> Read -> Write ---
  await page.goto('/?tab=inbox');
  await page.getByTestId('server-switcher').selectOption('peer-xarea');
  await expect(page.getByText('restart:sonarr')).toBeVisible();
  await page.getByRole('button', { name: 'Inspect action', exact: true }).click();
  const detailModal = page.getByRole('dialog', { name: /Action details/i });
  await expect(detailModal).toBeVisible();
  await detailModal.getByRole('button', { name: /Approve & Execute/i }).click();
  await page.getByRole('dialog', { name: /Approve and execute high-risk action/i })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await approveHeld.promise;

  servicesGrant = 'read';
  await syncPeers();
  // Confirm closes, busy releases, read-only detail modal stays open.
  await expect(page.getByRole('dialog', { name: /Approve and execute high-risk action/i })).toHaveCount(0);
  await expect(detailModal).toBeVisible();
  await expect(detailModal.getByRole('button', { name: /Approve & Execute/i })).toBeDisabled();
  await expect(detailModal.getByRole('button', { name: /Approve & Execute/i })).toHaveAttribute('title', /.+/);

  servicesGrant = 'write';
  await syncPeers();
  await expect(detailModal.getByRole('button', { name: /Approve & Execute/i })).toBeEnabled();

  releaseApprove.resolve();
  await expect.poll(() => approveOutcome).not.toBe('pending');
  await expect(page.getByText('STALE_ACTION_APPROVED')).toHaveCount(0);
  await page.keyboard.press('Escape');

  // --- 2. Services cross-area Check updates: Marketplace Write -> Read -> Write keeps Services Write intact ---
  await page.getByRole('button', { name: 'Services', exact: true }).first().click();
  const svcCard = page.locator('article.af-service-tile').filter({
    has: page.getByRole('heading', { name: 'Beta Sonarr', exact: true }),
  });
  await expect(svcCard).toBeVisible();
  const checkUpdatesBtn = page.getByRole('button', { name: 'Check updates', exact: true });
  await expect(checkUpdatesBtn).toBeEnabled();
  await checkUpdatesBtn.click();
  await checkUpdatesHeld.promise;

  marketplaceGrant = 'read';
  await syncPeers();
  await expect(checkUpdatesBtn).toBeDisabled();
  await expect(checkUpdatesBtn).toHaveAttribute('title', /.+/);
  // Separately authorized Services:Write remains enabled.
  await expect(svcCard.getByRole('button', { name: 'Restart', exact: true })).toBeEnabled();

  marketplaceGrant = 'write';
  await syncPeers();
  await expect(checkUpdatesBtn).toBeEnabled();

  releaseCheckUpdates.resolve();
  await expect.poll(() => checkUpdatesOutcome).not.toBe('pending');
  await expect(page.getByText('9 application updates available.')).toHaveCount(0);

  // --- 3. Marketplace cross-area PluginCatalog toggle: Services Write -> Read -> Write ---
  await page.getByRole('button', { name: 'Marketplace', exact: true }).first().click();
  const pluginToggleBtn = page.getByTestId('toggle-plugin-demo-plugin');
  await expect(pluginToggleBtn).toBeEnabled();
  await pluginToggleBtn.click();
  await pluginToggleHeld.promise;

  servicesGrant = 'read';
  await syncPeers();
  await expect(pluginToggleBtn).toBeDisabled();
  await expect(pluginToggleBtn).toHaveAttribute('title', /.+/);

  servicesGrant = 'write';
  await syncPeers();
  await expect(pluginToggleBtn).toBeEnabled();

  releasePluginToggle.resolve();
  await expect.poll(() => pluginToggleOutcome).not.toBe('pending');
  await expect(page.getByText('STALE_PLUGIN_STARTED')).toHaveCount(0);

  // --- 4. Streaming ProviderCards Connection & identity gate + HistoryPortability export abort ---
  settingsGrant = 'read';
  await syncPeers();
  await page.getByRole('button', { name: 'Streaming', exact: true }).first().click();
  const connBtn = page.getByRole('button', { name: 'Connection & identity', exact: true });
  await expect(connBtn).toBeVisible();
  await expect(connBtn).toBeDisabled();
  await expect(connBtn).toHaveAttribute('title', /.+/);

  settingsGrant = 'write';
  await syncPeers();
  await expect(connBtn).toBeEnabled();

  await page.getByRole('tab', { name: /History administration/i }).click();
  await page.getByText('Portable archive export / restore', { exact: true }).click();
  const exportBtn = page.getByRole('button', { name: 'Export native JSON archive', exact: true });
  await expect(exportBtn).toBeEnabled();
  await exportBtn.click();
  await exportHeld.promise;

  settingsGrant = 'read';
  await syncPeers();
  await expect(exportBtn).toBeDisabled();
  await expect(exportBtn).toHaveAttribute('title', /.+/);

  settingsGrant = 'write';
  await syncPeers();
  await expect(exportBtn).toBeEnabled();

  releaseExport.resolve();
  await expect.poll(() => exportOutcome).not.toBe('pending');
  await expect(page.getByText('Native JSON archive exported.')).toHaveCount(0);

  // --- 5. Settings ProviderSettings Test API: Settings Write -> Read -> Write ---
  await page.getByRole('button', { name: 'Settings', exact: true }).first().click();
  await page.getByRole('tab', { name: /FlowAI Providers/i }).click();
  const testApiBtn = page.getByRole('button', { name: 'Test API', exact: true });
  await expect(testApiBtn).toBeEnabled();
  await testApiBtn.click();
  await testAiHeld.promise;

  settingsGrant = 'read';
  await syncPeers();
  await expect(testApiBtn).toBeDisabled();
  await expect(testApiBtn).toHaveAttribute('title', /.+/);

  settingsGrant = 'write';
  await syncPeers();
  await expect(testApiBtn).toBeEnabled();

  releaseTestAi.resolve();
  await expect.poll(() => testAiOutcome).not.toBe('pending');
  await expect(page.getByText('STALE_PROVIDER_CONNECTED')).toHaveCount(0);

  // --- 6. FlowAI AiChatTab Send: Settings Write -> Read -> Write rolls back optimistic turn and drops stale reply ---
  await page.getByRole('button', { name: 'FlowAI', exact: true }).first().click();
  const composer = page.getByLabel('Message FlowAI');
  const sendBtn = page.getByRole('button', { name: 'Send', exact: true });
  const chatLog = page.getByRole('log', { name: 'FlowAI conversation' });
  await composer.fill('Check cluster health');
  await sendBtn.click();
  await chatHeld.promise;
  await expect(chatLog.getByText('Check cluster health')).toBeVisible();
  await expect(page.getByText('FlowAI is analyzing…')).toBeVisible();

  settingsGrant = 'read';
  await syncPeers();
  // Optimistic turn rolled back and busy cleared immediately on Settings:Write loss.
  await expect(page.getByText('FlowAI is analyzing…')).toHaveCount(0);
  await expect(chatLog.getByText('Check cluster health')).toHaveCount(0);

  settingsGrant = 'write';
  await syncPeers();
  await composer.fill('Fresh prompt');
  await expect(sendBtn).toBeEnabled();

  releaseChat.resolve();
  await expect.poll(() => chatOutcome).not.toBe('pending');
  await expect(page.getByText('STALE_AI_REPLY')).toHaveCount(0);

  // --- 7. Network Tailscale connect: Network Write -> Read -> Write releases busy and drops stale auth URL/toast ---
  await page.getByRole('button', { name: 'Network', exact: true }).first().click();
  const tsConnectBtn = page.getByRole('button', { name: 'Up / Interactive login', exact: true });
  await expect(tsConnectBtn).toBeEnabled();
  await tsConnectBtn.click();
  await tsConnectHeld.promise;

  networkGrant = 'read';
  await syncPeers();
  await expect(tsConnectBtn).toBeDisabled();
  await expect(tsConnectBtn).toHaveAttribute('title', /.+/);

  networkGrant = 'write';
  await syncPeers();
  await expect(tsConnectBtn).toBeEnabled();

  releaseTsConnect.resolve();
  await expect.poll(() => tsConnectOutcome).not.toBe('pending');
  await expect(page.getByText('https://login.tailscale.com/a/stale-ts-auth')).toHaveCount(0);
  await expect(page.getByText('STALE_TS_CONNECT')).toHaveCount(0);
});

test('P6 ingress certificate sync fences its second request on Network downgrade', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);
  let settings: AccessLevel = 'write';
  let network: AccessLevel = 'write';
  const id = 'ingress-race';
  const prefix = `/api/v1/peers/${id}`;
  await page.route(`**${PEERS_API}`, (route) =>
    json(route, peerSnapshot([makePeer({ id, name: 'Ingress peer', outboundAccess: { settings, network } })])),
  );
  await mountPeerDefaults(page, id);
  const configs = { configs: [{ appName: 'sonarr', publicDomain: 'sonarr.example.com', tlsEnabled: true }] };
  const waiting = deferred();
  const release = deferred();
  const completed = deferred();
  let holdNextRead = false;
  await page.route(`**${prefix}/admin/ingress/configs`, async (route) => {
    if (holdNextRead) {
      holdNextRead = false;
      waiting.resolve();
      await release.promise;
      await fulfillDelayedRoute(route, configs);
      completed.resolve();
      return;
    }
    await json(route, configs);
  });
  let writes = 0;
  await page.route(`**${prefix}/admin/ingress/apps/sonarr`, async (route) => {
    expect(route.request().method()).toBe('PUT');
    writes += 1;
    await json(route, { ok: true });
  });

  await page.goto('/?tab=cluster');
  await page.getByTestId('server-switcher').selectOption(id);
  await page.getByRole('button', { name: 'Network', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'sonarr', exact: true })).toBeVisible();
  const sync = page.getByRole('button', { name: /Sync Let's Encrypt SANs/ });
  const domain = page.getByLabel('Server base domain');
  holdNextRead = true;
  await sync.click();
  await waiting.promise;
  await expect(sync).toBeDisabled();

  settings = 'read';
  await page.clock.fastForward('00:16');
  await expect(domain).toBeDisabled();
  await expect(sync).toBeDisabled();

  network = 'read';
  await page.clock.fastForward('00:16');
  await expect(sync).toHaveAttribute('title', /network/i);
  release.resolve();
  await completed.promise;

  network = 'write';
  await page.clock.fastForward('00:16');
  await expect(sync).toBeEnabled();
  await sync.click();
  await expect(page.getByText("Let's Encrypt SAN synchronization requested", { exact: true })).toBeVisible();
  expect(writes).toBe(1);
});

test('P6 provider connection clears its draft and ignores stale completion on Settings downgrade', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page);
  const id = 'connection-race';
  const prefix = `/api/v1/peers/${id}`;
  let settings: AccessLevel = 'write';
  await page.route(`**${PEERS_API}`, (route) =>
    json(route, peerSnapshot([makePeer({ id, name: 'Streaming peer', outboundAccess: { settings } })])),
  );
  await mountPeerDefaults(page, id);
  await page.route(new RegExp(`${prefix}/auth/streaming/dashboard(?:\\?|$)`), (route) =>
    json(route, { servers: [{ provider: 'jellyfin', name: 'Remote Jellyfin', url: 'https://stream.example.com', enabled: true }] }),
  );

  const staleStarted = deferred();
  const releaseStale = deferred();
  const staleFinished = deferred();
  const currentStarted = deferred();
  const releaseCurrent = deferred();
  let writes = 0;
  await page.route(`**${prefix}/admin/streaming/servers/jellyfin`, async (route) => {
    expect(route.request().method()).toBe('PUT');
    writes += 1;
    if (writes === 1) {
      staleStarted.resolve();
      await releaseStale.promise;
      await fulfillDelayedRoute(route, { ok: true, message: 'Stale provider response' });
      staleFinished.resolve();
      return;
    }
    currentStarted.resolve();
    await releaseCurrent.promise;
    await json(route, { ok: true, message: 'Current provider response' });
  });

  await page.goto('/?tab=cluster');
  await page.getByTestId('server-switcher').selectOption(id);
  await page.getByRole('button', { name: 'Streaming', exact: true }).first().click();
  const open = page.getByRole('button', { name: 'Connection & identity', exact: true });
  const dialog = page.getByRole('dialog', { name: /Streaming server connection/ });
  const save = dialog.getByRole('button', { name: 'Save connection', exact: true });
  await open.click();
  await dialog.locator('input[type="password"]').fill('temporary-fixture-value');
  await save.click();
  await staleStarted.promise;
  settings = 'read';
  await page.clock.fastForward('00:16');
  await expect(dialog).toBeHidden();

  settings = 'write';
  await page.clock.fastForward('00:16');
  await open.click();
  await expect(dialog.locator('input[type="password"]')).toHaveValue('');
  await save.click();
  await currentStarted.promise;
  releaseStale.resolve();
  await staleFinished.promise;
  await expect(dialog).toBeVisible();
  await expect(save).toBeDisabled();
  await expect(page.getByText('Stale provider response', { exact: true })).toHaveCount(0);
  releaseCurrent.resolve();
  await expect(page.getByText('Current provider response', { exact: true })).toBeVisible();
  await expect(dialog).toBeHidden();
  expect(writes).toBe(2);
});
