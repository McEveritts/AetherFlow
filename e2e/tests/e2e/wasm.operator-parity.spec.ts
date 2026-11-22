import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const json = (route: Route, value: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(value),
  });

const ONE_BY_ONE_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64',
);

const VALID_RESTART_UNIT =
  'aetherflow-self-update-restart-aetherflow-api-1234567890abcdef1234567890abcdef.service';
const FAIL_RESTART_UNIT =
  'aetherflow-self-update-restart-aetherflow-api-abcdef1234567890abcdef1234567890.service';
const TIMEOUT_RESTART_UNIT =
  'aetherflow-self-update-restart-aetherflow-api-fedcba9876543210fedcba9876543210.service';

const mockOperatorServices = async (page: Page) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await page.route('**/api/v1/auth/services', route =>
    json(route, {
      sonarr: {
        id: 'sonarr',
        name: 'Sonarr',
        slug: 'sonarr',
        status: 'running',
        installed_version: '4.0.0',
        latest_version: '4.0.2',
        update_available: true,
        update_url: 'https://github.com/Sonarr/Sonarr/releases/tag/v4.0.2',
        default_port: 8989,
        active_port: 18989,
        managed_by: 'systemd',
        process: 'sonarr',
        components: [
          { unit: 'sonarr.service', status: 'running', role: 'required' },
          { unit: 'sonarr-worker.service', status: 'running', role: 'worker' },
        ],
      },
      bazarr: {
        id: 'bazarr',
        name: 'Bazarr',
        slug: 'bazarr',
        status: 'stopped',
        default_port: 6767,
        managed_by: 'systemd',
        process: 'bazarr',
        last_job: {
          action: 'install',
          status: 'failed',
          sanitized_summary: 'Dependency checksum mismatch',
        },
      },
    }),
  );
};

const captureServiceControls = async (page: Page) => {
  const calls: Array<{ service: string; action: string }> = [];
  await page.route('**/api/v1/admin/services/*/control', async route => {
    const url = new URL(route.request().url());
    const service = url.pathname.split('/').slice(-2)[0];
    const body = route.request().postDataJSON() as { action: string };
    calls.push({ service, action: body.action });
    await json(route, { message: 'ok' });
  });
  return calls;
};

test.describe('WASM operator parity workflows', () => {
  test('persists core restart receipts across reload and confirms job and readiness before completion', async ({ page }) => {
    await page.clock.install();
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, preserveStorage: true });

    const jobUnit = VALID_RESTART_UNIT;
    let statusChecks = 0;
    let readyChecks = 0;
    let jobComplete = false;
    let apiReady = false;

    await page.route('**/api/v1/auth/services', route =>
      json(route, {
        'aetherflow-api': {
          id: 'aetherflow-api',
          name: 'AetherFlow API',
          slug: 'aetherflow-api',
          status: 'running',
          managed_by: 'systemd',
          process: 'aetherflow-api',
        },
      }),
    );

    await page.route('**/api/v1/admin/services/*/control', route =>
      json(route, {
        status: 'accepted',
        service: 'aetherflow-api',
        action: 'restart',
        job_unit: jobUnit,
      }, 202),
    );

    await page.route('**/api/v1/admin/services/restart/status?*', route => {
      statusChecks += 1;
      const url = new URL(route.request().url());
      expect(url.searchParams.get('job_unit')).toBe(jobUnit);
      if (statusChecks === 1) {
        return json(route, { error: 'temporary API loss' }, 503);
      }
      if (!jobComplete) {
        return json(route, {
          job_unit: jobUnit,
          completed: false,
          success: false,
          status: 'running',
          state: 'running',
        });
      }
      return json(route, {
        job_unit: jobUnit,
        completed: true,
        success: true,
        status: 'succeeded',
        state: 'complete',
      });
    });

    await page.route('**/api/v1/auth/ready', route => {
      readyChecks += 1;
      if (!apiReady) {
        return json(route, { service: 'aetherflow-api', status: 'not_ready', database: 'unreachable' }, 503);
      }
      return json(route, { service: 'aetherflow-api', status: 'ready', database: 'ok' });
    });

    await page.goto('/?tab=services');
    await page.getByRole('button', { name: 'Restart', exact: true }).first().click();

    await expect(page.getByText(new RegExp(jobUnit))).toBeVisible();
    await page.clock.fastForward('00:02');
    await expect.poll(() => statusChecks).toBeGreaterThanOrEqual(1);

    // Verify receipt was persisted to localStorage and survives reload.
    const savedReceipts = await page.evaluate(() =>
      window.localStorage.getItem('af-core-restart-receipts'),
    );
    expect(savedReceipts).toContain(jobUnit);
    await page.reload();
    await expect(page.getByText(new RegExp(jobUnit))).toBeVisible();

    jobComplete = true;
    await page.clock.fastForward('00:02');
    await expect.poll(() => readyChecks).toBeGreaterThanOrEqual(1);
    await expect(page.getByText(/API readiness confirmed/)).toHaveCount(0);

    apiReady = true;
    await page.clock.fastForward('00:02');
    await expect(page.getByText(/service activation and API readiness confirmed/).first()).toBeVisible();
  });

  test('reports core restart job failure and timeout accurately', async ({ page }) => {
    await page.clock.install();
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

    await page.route('**/api/v1/auth/services', route =>
      json(route, {
        'aetherflow-api': {
          id: 'aetherflow-api',
          name: 'AetherFlow API',
          slug: 'aetherflow-api',
          status: 'running',
          managed_by: 'systemd',
          process: 'aetherflow-api',
        },
      }),
    );

    let nextUnit = FAIL_RESTART_UNIT;
    await page.route('**/api/v1/admin/services/*/control', route =>
      json(route, { status: 'accepted', service: 'aetherflow-api', action: 'restart', job_unit: nextUnit }, 202),
    );
    await page.route('**/api/v1/admin/services/restart/status?*', route => {
      const unit = new URL(route.request().url()).searchParams.get('job_unit');
      if (unit === FAIL_RESTART_UNIT) {
        return json(route, {
          job_unit: FAIL_RESTART_UNIT,
          completed: true,
          success: false,
          status: 'failed',
          state: 'failed',
          error: 'System update failed; inspect authenticated updater diagnostics',
        });
      }
      return json(route, { job_unit: unit, completed: false, success: false, status: 'running', state: 'running' });
    });

    await page.goto('/?tab=services');
    await page.getByRole('button', { name: 'Restart', exact: true }).first().click();
    await expect(page.getByText(FAIL_RESTART_UNIT, { exact: false }).first()).toBeVisible();
    await page.clock.fastForward('00:02');
    await expect(
      page.getByRole('alert').filter({ hasText: /System update failed; inspect authenticated updater diagnostics/ }).first(),
    ).toBeVisible();

    nextUnit = TIMEOUT_RESTART_UNIT;
    await page.getByRole('button', { name: 'Restart', exact: true }).first().click();
    await expect(page.getByText(TIMEOUT_RESTART_UNIT, { exact: false }).first()).toBeVisible();
    await page.clock.fastForward('03:05');
    await expect(page.getByRole('alert').filter({ hasText: /restart outcome or readiness could not be confirmed/ }).first()).toBeVisible();
  });

  test('exposes confirmed Tailscale node logout with error handling', async ({ page }) => {
    const unmocked: string[] = [];
    await page.route('**/api/**', route => {
      unmocked.push(route.request().method() + ' ' + new URL(route.request().url()).pathname);
      return json(route, { message: 'Missing Network test fixture' }, 599);
    });
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let logoutCalls = 0;
    let shouldFail = true;

    await page.route('**/api/v1/admin/network/diagnostics?*', route =>
      json(route, { checks: [], logs: '' }),
    );
    await page.route('**/api/v1/admin/ingress/configs', route => json(route, {}));
    await page.route('**/api/v1/admin/services', route => json(route, {}));
    await page.route('**/api/v1/admin/network/status', route =>
      json(route, {
        platform: 'linux',
        runner_available: true,
        checked_at: '2026-11-19T05:00:00Z',
        wireguard: { listen_port: '51820', addresses: [], public_key: 'pk', peers: [] },
        tailscale: {
          state: 'running',
          backend_state: 'Running',
          service_state: 'active',
          tailnet_name: 'example.ts.net',
          magic_dns: true,
          self: { tailscale_ip: '100.64.0.10', dns_name: 'node.example.ts.net' },
          peers: [],
        },
      }),
    );

    await page.route('**/api/v1/admin/network/tailscale/logout', route => {
      logoutCalls += 1;
      if (shouldFail) {
        shouldFail = false;
        return json(route, { message: 'Tailscale runner unavailable' }, 503);
      }
      return json(route, { message: 'Logged out from Tailscale.' });
    });

    await page.goto('/?tab=network');
    await page.getByRole('button', { name: 'Logout', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Log out Tailscale node?' });
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(logoutCalls).toBe(0);

    await page.getByRole('button', { name: 'Logout', exact: true }).click();
    await dialog.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect.poll(() => logoutCalls).toBe(1);
    await expect(page.locator('#main-content').getByRole('alert').filter({ hasText: 'Tailscale runner unavailable' })).toBeVisible();
    await expect(page.locator('.af-toast').filter({ hasText: 'Tailscale runner unavailable' })).toBeVisible();

    await page.getByRole('button', { name: 'Logout', exact: true }).click();
    await dialog.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect.poll(() => logoutCalls).toBe(2);
    await expect(page.getByText('Logged out from Tailscale.')).toBeVisible();
    expect(unmocked).toEqual([]);
  });

  test('shows personal storage quota to ordinary users in Profile without admin tabs', async ({ page }) => {
    await installAetherFlowMocks(page, {
      authenticated: true,
      setupRequired: false,
      userRole: 'user',
    });

    await page.route('**/api/v1/auth/user/quota', route =>
      json(route, {
        user_id: 2,
        username: 'alice',
        quota_bytes: 10 * 1024 * 1024 * 1024,
        used_bytes: 2 * 1024 * 1024 * 1024,
        available_bytes: 8 * 1024 * 1024 * 1024,
        usage_pct: 20.0,
        configured: true,
        status: 'active',
        source: 'runner',
        updated_at: '2026-11-19T05:00:00Z',
        usedGB: 2.0,
        totalGB: 10.0,
        percentage: 20.0,
      }),
    );

    await page.goto('/?tab=settings');
    await page.getByRole('tab', { name: 'Security & 2FA', exact: true }).click();
    const region = page.getByRole('region', { name: 'Account Storage Quota' });
    await expect(region).toBeVisible();
    await expect(region).toContainText('2.0 GiB used');
    await expect(region).toContainText('10.0 GiB');
    await expect(region.getByRole('progressbar', { name: 'Storage quota used' })).toHaveAttribute('aria-valuenow', '20');
  });

  test('renders scoped streaming artwork only when unambiguous and enforces typed confirmation on demo controls', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let isDemoMode = false;
    const demoActions: string[] = [];
    const artworkRequests: string[] = [];
    const dashboardUrls: string[] = [];

    await page.route('**/api/v1/auth/streaming/artwork/**', route => {
      artworkRequests.push(route.request().url());
      return route.fulfill({
        status: 200,
        contentType: 'image/png',
        body: ONE_BY_ONE_PNG,
      });
    });

    await page.route('**/api/v1/auth/streaming/dashboard?*', route => {
      dashboardUrls.push(route.request().url());
      return json(route, {
        servers: [
          {
            provider: 'jellyfin',
            name: 'Jellyfin A',
            status: isDemoMode ? 'demo' : 'unconfigured',
            serverId: 'srv-1',
          },
          {
            provider: 'emby',
            name: 'Emby A',
            status: 'unconfigured',
            serverId: 'emby-1',
          },
          {
            provider: 'emby',
            name: 'Emby B',
            status: 'unconfigured',
            serverId: 'emby-2',
          },
        ],
        liveSummary: {
          activeStreams: 3,
          directPlayCount: 3,
          directStreamCount: 0,
          transcodeCount: 0,
          totalBandwidthMbps: 12.5,
          isDemoMode,
        },
        activeSessions: [
          {
            provider: 'jellyfin',
            sessionId: 'sess-1',
            serverName: 'Jellyfin A',
            itemName: 'Unambiguous Film',
            itemType: 'Movie',
            userName: 'viewer',
            hasArtwork: true,
            artworkItemId: 'item-42',
            playMethod: 'DirectPlay',
            state: 'playing',
            progressPct: 40,
            positionSecs: 600,
            durationSecs: 1500,
          },
          {
            provider: 'emby',
            sessionId: 'sess-2',
            serverName: 'Emby',
            itemName: 'Ambiguous Show',
            itemType: 'Episode',
            userName: 'viewer',
            hasArtwork: true,
            artworkItemId: 'item-99',
            playMethod: 'DirectPlay',
            state: 'playing',
            progressPct: 10,
            positionSecs: 60,
            durationSecs: 600,
          },
          {
            provider: 'emby',
            sessionId: 'sess-3',
            serverId: 'emby-2',
            serverName: 'Emby B',
            itemName: 'Explicit Emby Film',
            itemType: 'Movie',
            userName: 'viewer',
            hasArtwork: true,
            artworkItemId: 'item-100',
            playMethod: 'DirectPlay',
            state: 'playing',
            progressPct: 15,
            positionSecs: 90,
            durationSecs: 600,
          },
        ],
        updatedAt: '2026-11-19T05:00:00Z',
        analytics: { recentHistory: [], historicalEstimates: [] },
      });
    });

    await page.route('**/api/v1/admin/streaming/demo', async route => {
      const body = route.request().postDataJSON() as { action: string };
      demoActions.push(body.action);
      isDemoMode = body.action === 'seed';
      await json(route, { demoMode: isDemoMode, message: isDemoMode ? 'Loaded' : 'Cleared' });
    });

    await page.goto('/?tab=streaming');
    await expect(page.getByRole('img', { name: 'Unambiguous Film' })).toHaveAttribute(
      'src',
      '/api/v1/auth/streaming/artwork/item-42?provider=jellyfin&serverId=srv-1',
    );
    await expect(page.getByRole('img', { name: 'Artwork unavailable for Ambiguous Show' })).toBeVisible();
    await expect(page.getByRole('img', { name: 'Explicit Emby Film' })).toHaveAttribute(
      'src',
      '/api/v1/auth/streaming/artwork/item-100?provider=emby&serverId=emby-2',
    );
    await expect(page.getByText('viewer · Movie · playing')).toHaveCount(2);
    await expect(page.getByText(/·\s*·\s*S\s*E\s*·/)).toHaveCount(0);
    await expect.poll(() => artworkRequests.some(url => url.includes('item-42?provider=jellyfin&serverId=srv-1'))).toBe(true);
    expect(artworkRequests.some(url => url.includes('item-99'))).toBe(false);

    // Filter controls update the dashboard query parameters cleanly.
    await page.getByLabel('Play method').selectOption('Transcode');
    await page.getByLabel('Media type').selectOption('Movie');
    await expect.poll(() => dashboardUrls.some(url => url.includes('playMethod=Transcode') && url.includes('mediaType=Movie'))).toBe(true);

    await page.getByRole('button', { name: 'Load Demo Telemetry', exact: true }).click();
    const seedModal = page.getByRole('dialog', { name: 'Load streaming demo telemetry?' });
    const confirmSeed = seedModal.getByRole('button', { name: 'Confirm', exact: true });
    await expect(confirmSeed).toBeDisabled();
    await seedModal.getByRole('textbox').fill('SEED');
    await expect(confirmSeed).toBeEnabled();
    await confirmSeed.click();
    await expect.poll(() => demoActions).toEqual(['seed']);

    await page.getByRole('button', { name: 'Clear Demo Data', exact: true }).click();
    const clearModal = page.getByRole('dialog', { name: 'Clear streaming demo telemetry?' });
    await clearModal.getByRole('textbox').fill('CLEAR');
    await clearModal.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect.poll(() => demoActions).toEqual(['seed', 'clear']);
  });

  test('blocks DemoTelemetryBanner submission when provider connects, dashboard read fails, or demo mode changes while modal is open', async ({ page }) => {
    await page.clock.install();
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

    let mode: 'unconfigured' | 'connected_emby' | 'error' | 'demo_already_active' = 'unconfigured';
    let demoPosts = 0;

    await page.route('**/api/v1/auth/streaming/dashboard?*', route => {
      if (mode === 'error') {
        return json(route, { message: 'Telemetry backend unavailable' }, 500);
      }
      return json(route, {
        servers: [
          { provider: 'jellyfin', name: 'Jellyfin', status: mode === 'demo_already_active' ? 'demo' : 'unconfigured', serverId: '' },
          { provider: 'emby', name: 'Emby', status: mode === 'connected_emby' ? 'connected' : 'unconfigured', serverId: 'emby-1' },
        ],
        liveSummary: {
          activeStreams: 0,
          directPlayCount: 0,
          directStreamCount: 0,
          transcodeCount: 0,
          totalBandwidthMbps: 0,
          isDemoMode: mode === 'demo_already_active',
        },
        activeSessions: [],
        updatedAt: '2026-11-19T05:00:00Z',
        analytics: { recentHistory: [], historicalEstimates: [] },
      });
    });

    await page.route('**/api/v1/admin/streaming/demo', route => {
      demoPosts += 1;
      return json(route, { demoMode: true });
    });

    await page.goto('/?tab=streaming');
    await page.getByRole('button', { name: 'Load Demo Telemetry', exact: true }).click();
    const modal = page.getByRole('dialog', { name: 'Load streaming demo telemetry?' });
    await modal.getByRole('textbox').fill('SEED');
    const confirm = modal.getByRole('button', { name: 'Confirm', exact: true });
    await expect(confirm).toBeEnabled();

    // 1) A real Emby provider connects while modal is open.
    mode = 'connected_emby';
    await page.clock.fastForward('00:06');
    await expect(modal.getByRole('alert')).toContainText(/live Jellyfin or Emby provider is connected/i);
    await expect(confirm).toBeDisabled();

    // 2) Dashboard read fails while modal is open.
    mode = 'error';
    await page.clock.fastForward('00:06');
    await expect(modal.getByRole('alert')).toContainText(/unavailable or failed to refresh/i);
    await expect(confirm).toBeDisabled();

    // 3) Demo mode flips to active while seed modal is open.
    mode = 'demo_already_active';
    await page.clock.fastForward('00:06');
    await expect(modal.getByRole('alert')).toContainText(/already active/i);
    await expect(confirm).toBeDisabled();

    expect(demoPosts).toBe(0);
  });

  test('retained Marketplace data requires the exact package ID before purge', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const app = {
      id: 'rclone', name: 'Rclone', desc: 'Cloud sync', category: 'Cloud',
      status: 'uninstalled', inventory_known: true, inventory_authenticated: true,
      retained_data_present: true,
    };
    let purgeRequests = 0;
    await page.route(/\/api\/v1\/(?:public|auth)\/marketplace$/, route =>
      json(route, [{ ...app, retained_data_present: purgeRequests === 0 }]),
    );
    await page.route('**/api/v1/admin/packages/rclone/uninstall?*', route => {
      expect(route.request().method()).toBe('POST');
      expect(new URL(route.request().url()).searchParams.get('purge')).toBe('true');
      purgeRequests += 1;
      return json(route, { job_id: 'purge-retained-fixture', status: 'uninstalling' }, 202);
    });

    await page.goto('/?tab=marketplace');
    await expect(page.getByRole('button', { name: 'Install', exact: true })).toBeEnabled();
    const purge = page.getByRole('button', { name: 'Purge retained data', exact: true });
    await purge.click();
    const dialog = page.getByRole('dialog', { name: 'Purge retained data for Rclone' });
    const confirm = dialog.getByRole('button', { name: 'Confirm', exact: true });
    await expect(confirm).toBeDisabled();
    const packageId = dialog.getByRole('textbox', { name: 'Package ID to confirm data purge' });
    await packageId.fill('RClone');
    await expect(confirm).toBeDisabled();
    expect(purgeRequests).toBe(0);
    await packageId.fill('rclone');
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect.poll(() => purgeRequests).toBe(1);
    await expect(purge).toHaveCount(0);
  });

  test('never fabricates baseDomain Open App links for headless or loopback-only services in Services and Marketplace', async ({ page, baseURL }) => {
    const localOrigin = baseURL ?? 'http://127.0.0.1:18763';
    const localHost = new URL(localOrigin).hostname;

    await page.route('https://panel.example.com/**', async route => {
      const target = new URL(route.request().url());
      if (target.pathname.startsWith('/api/')) {
        return route.fallback();
      }
      // Start a new asset request so Firefox uses the fixture server's Host header.
      const response = await page.request.get(new URL(target.pathname + target.search, localOrigin).href);
      return route.fulfill({ response });
    });

    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

    await page.route(/\/api(\/v1)?(\/(auth|admin))?\/settings/, route =>
      json(route, {
        baseDomain: 'apps.example.com',
        language: 'en',
        timezone: 'UTC',
        setupCompleted: true,
      }),
    );

    await page.route('**/api/v1/auth/services', route =>
      json(route, {
        fail2ban: {
          id: 'fail2ban',
          name: 'Fail2Ban',
          slug: 'fail2ban',
          status: 'running',
          default_port: 0,
          managed_by: 'systemd',
          process: 'fail2ban',
        },
        'aetherflow-runner': {
          id: 'aetherflow-runner',
          name: 'AetherFlow Runner',
          slug: 'aetherflow-runner',
          status: 'running',
          default_port: 0,
          managed_by: 'systemd',
          process: 'aetherflow-runner',
        },
        rutorrent: {
          id: 'rutorrent',
          name: 'ruTorrent',
          slug: 'rutorrent',
          status: 'running',
          default_port: 8087,
          active_port: 8087,
          bind_scope: 'loopback',
          external_access_enabled: false,
          managed_by: 'systemd',
          process: 'rutorrent',
        },
        sonarr: {
          id: 'sonarr',
          name: 'Sonarr',
          slug: 'sonarr',
          status: 'running',
          default_port: 8989,
          active_port: 8989,
          external_access_enabled: true,
          public_domain: 'sonarr.apps.example.com',
          tls_enabled: true,
          managed_by: 'systemd',
          process: 'sonarr',
        },
      }),
    );

    await page.route(/\/api(\/v1)?(\/(public|auth|admin))?\/marketplace/, route =>
      json(route, [
        {
          id: 'fail2ban',
          name: 'Fail2Ban',
          desc: 'Intrusion prevention daemon.',
          category: 'Monitoring & Security',
          status: 'installed',
          default_port: 0,
          inventory_known: true,
          inventory_authenticated: true,
        },
        {
          id: 'rutorrent',
          name: 'ruTorrent',
          desc: 'Loopback torrent UI.',
          category: 'Download Clients',
          status: 'installed',
          default_port: 8087,
          active_port: 8087,
          bind_scope: 'loopback',
          external_access_enabled: false,
          inventory_known: true,
          inventory_authenticated: true,
        },
        {
          id: 'sonarr',
          name: 'Sonarr',
          desc: 'TV automation.',
          category: 'Arr Stack',
          status: 'installed',
          default_port: 8989,
          active_port: 8989,
          external_access_enabled: true,
          public_domain: 'sonarr.apps.example.com',
          tls_enabled: true,
          inventory_known: true,
          inventory_authenticated: true,
        },
      ]),
    );

    // Local loopback origin: headless services have no Open App link, loopback-only ruTorrent opens locally, and Sonarr uses baseDomain.
    await page.goto('/?tab=services');
    await expect(page.getByRole('link', { name: 'Open App' })).toHaveCount(2);
    await expect(page.locator('article').filter({ hasText: 'Fail2Ban' }).getByRole('link', { name: 'Open App' })).toHaveCount(0);
    await expect(page.locator('article').filter({ hasText: 'AetherFlow Runner' }).getByRole('link', { name: 'Open App' })).toHaveCount(0);
    await expect(page.locator('article').filter({ hasText: 'ruTorrent' }).getByRole('link', { name: 'Open App' })).toHaveAttribute('href', `http://${localHost}:8087`);
    await expect(page.locator('article').filter({ hasText: 'Sonarr' }).getByRole('link', { name: 'Open App' })).toHaveAttribute('href', 'https://sonarr.apps.example.com');

    await page.goto('/?tab=marketplace');
    await expect(page.getByRole('link', { name: 'Open App' })).toHaveCount(2);
    await expect(page.locator('article').filter({ hasText: 'Fail2Ban' }).getByRole('link', { name: 'Open App' })).toHaveCount(0);
    await expect(page.locator('article').filter({ hasText: 'ruTorrent' }).getByRole('link', { name: 'Open App' })).toHaveAttribute('href', `http://${localHost}:8087`);
    await expect(page.locator('article').filter({ hasText: 'Sonarr' }).getByRole('link', { name: 'Open App' })).toHaveAttribute('href', 'https://sonarr.apps.example.com');

    // Remote origin: loopback-only ruTorrent must NOT open remotely or fabricate https://rutorrent.apps.example.com.
    await page.goto('https://panel.example.com/?tab=services');
    await expect(page.getByRole('heading', { name: 'Sonarr', exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('link', { name: 'Open App' })).toHaveCount(1);
    await expect(page.locator('article').filter({ hasText: 'ruTorrent' }).getByRole('link', { name: 'Open App' })).toHaveCount(0);
    await expect(page.locator('article').filter({ hasText: 'Sonarr' }).getByRole('link', { name: 'Open App' })).toHaveAttribute('href', 'https://sonarr.apps.example.com');

    await page.goto('https://panel.example.com/?tab=marketplace');
    await expect(page.getByRole('heading', { name: 'Sonarr', exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('link', { name: 'Open App' })).toHaveCount(1);
    await expect(page.locator('article').filter({ hasText: 'ruTorrent' }).getByRole('link', { name: 'Open App' })).toHaveCount(0);
    await expect(page.locator('article').filter({ hasText: 'Sonarr' }).getByRole('link', { name: 'Open App' })).toHaveAttribute('href', 'https://sonarr.apps.example.com');
  });

  test('checks for service updates and requests the displayed target version', async ({ page }) => {
    await mockOperatorServices(page);
    const updatePayloads: unknown[] = [];

    await page.route('**/api/v1/admin/packages/updates/check', route =>
      json(route, { updates_available: 1, updates: [{ package_id: 'sonarr', update_available: true }] }),
    );
    await page.route('**/api/v1/admin/packages/sonarr/update', async route => {
      updatePayloads.push(route.request().postDataJSON());
      await json(route, { status: 'accepted', job_id: 'job-upd-1' }, 202);
    });
    await page.goto('/?tab=services');
    await expect(page.getByText('def :8989')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Update v4.0.2' })).toHaveAttribute(
      'href',
      'https://github.com/Sonarr/Sonarr/releases/tag/v4.0.2',
    );

    await page.getByRole('button', { name: 'Check updates', exact: true }).click();
    await expect(page.locator('.af-toast').filter({ hasText: '1 application updates available.' })).toBeVisible();

    await page.getByRole('button', { name: 'Update Sonarr', exact: true }).click();
    await expect.poll(() => updatePayloads).toEqual([{ expected_target_version: '4.0.2' }]);
  });

  test('requires confirmation before stopping a service', async ({ page }) => {
    await mockOperatorServices(page);
    const controlCalls = await captureServiceControls(page);
    await page.goto('/?tab=services');

    const sonarrStop = page.locator('article', { hasText: 'Sonarr' }).getByRole('button', { name: 'Stop', exact: true });
    await sonarrStop.click();
    const stopDialog = page.getByRole('dialog', { name: 'Stop Sonarr?' });
    await expect(stopDialog).toBeVisible();
    await stopDialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(controlCalls).toHaveLength(0);

    await sonarrStop.click();
    await page.getByRole('dialog', { name: 'Stop Sonarr?' }).getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect.poll(() => controlCalls).toContainEqual({ service: 'sonarr', action: 'stop' });
  });

  test('requires confirmation to start a service after a failed install', async ({ page }) => {
    await mockOperatorServices(page);
    const controlCalls = await captureServiceControls(page);
    await page.goto('/?tab=services');
    await expect(page.getByText('Dependency checksum mismatch')).toBeVisible();

    await page.locator('article', { hasText: 'Bazarr' }).getByRole('button', { name: 'Start', exact: true }).click();
    const startGuard = page.getByRole('dialog', { name: 'Start Bazarr after failed install?' });
    await expect(startGuard).toBeVisible();
    await startGuard.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect.poll(() => controlCalls).toContainEqual({ service: 'bazarr', action: 'start' });
  });

  test('opens component logs and reviews a FlowAI Auto-Debug proposal', async ({ page }) => {
    await mockOperatorServices(page);
    const aiSupportBodies: unknown[] = [];

    await page.route('**/api/v1/admin/logs?*', route =>
      json(route, {
        logs: [
          { timestamp: '2026-11-19T06:00:00Z', level: 'ERROR', message: 'Database locked in sonarr-worker' },
        ],
      }),
    );
    await page.route('**/api/v1/auth/ai/support', async route => {
      aiSupportBodies.push(route.request().postDataJSON());
      await json(route, {
        reply: 'SQLite WAL lock contention detected.',
        proposed_action: {
          title: 'Restart sonarr-worker.service',
          description: 'Recycle worker unit to clear lock.',
        },
      });
    });

    await page.goto('/?tab=services');
    await page.locator('article', { hasText: 'Sonarr' }).locator('ul').getByRole('button', { name: 'Logs', exact: true }).nth(1).click();
    const logsModal = page.getByRole('dialog', { name: 'Service Logs' });
    await expect(logsModal).toBeVisible();
    await expect(logsModal.getByLabel('Journal unit')).toHaveValue('sonarr-worker.service');
    await logsModal.getByRole('button', { name: 'AI Auto-Debug', exact: true }).click();
    await expect.poll(() => aiSupportBodies.length).toBe(1);
    expect(aiSupportBodies[0]).toMatchObject({ context_mode: 'logs' });
    await expect(logsModal.getByText('SQLite WAL lock contention detected.')).toBeVisible();
    await logsModal.getByRole('button', { name: 'Review Proposed Remediation', exact: true }).click();
    const remediationDialog = page.getByRole('dialog', { name: 'Remediation proposed' });
    await expect(remediationDialog).toBeVisible();
    await remediationDialog.getByRole('button', { name: 'Acknowledge', exact: true }).click();
  });

  test('provides structured policy and user-link controls in Streaming History administration', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const policyUpdates: unknown[] = [];
    const linkDeletes: unknown[] = [];

    await page.route('**/api/v1/auth/streaming/dashboard?*', route =>
      json(route, {
        servers: [{ provider: 'jellyfin', name: 'Jellyfin', status: 'connected', serverId: 'srv-1' }],
        liveSummary: { activeStreams: 0, isDemoMode: false },
        activeSessions: [],
        updatedAt: '2026-11-19T05:00:00Z',
        analytics: { recentHistory: [], historicalEstimates: [] },
      }),
    );
    await page.route('**/api/v1/admin/streaming/imports/status', route =>
      json(route, { maxBatchEvents: 500, checkpoints: [], capabilities: [] }),
    );
    await page.route('**/api/v1/admin/streaming/policies', async route => {
      if (route.request().method() === 'PUT') {
        policyUpdates.push(route.request().postDataJSON());
        return json(route, { ok: true });
      }
      return json(route, {
        minimumWatchSecs: 30,
        reconnectWindowSecs: 120,
        excludedUsers: [],
        excludedLibraries: [],
      });
    });
    await page.route('**/api/v1/admin/streaming/user-links', async route => {
      if (route.request().method() === 'DELETE') {
        linkDeletes.push(route.request().postDataJSON());
        return json(route, { links: [] });
      }
      return json(route, {
        links: [
          { afUserId: 2, afUsername: 'alice', provider: 'jellyfin', serverId: 'srv-1', providerUserId: 'jf-u2' },
        ],
      });
    });

    await page.goto('/?tab=streaming');
    await page.getByRole('tab', { name: 'History administration', exact: true }).click();

    await page.getByText('Tracking policy and exclusions', { exact: true }).click();
    await page.getByLabel('Minimum Watch (secs)').fill('60');
    await page.getByRole('button', { name: 'Save Tracking Policy', exact: true }).click();
    const policyReview = page.getByRole('dialog', { name: 'Review exact administrative request' });
    await policyReview.getByRole('button', { name: 'Apply reviewed change', exact: true }).click();
    await expect.poll(() => policyUpdates).toEqual([
      { minimumWatchSecs: 60, reconnectWindowSecs: 120, excludedUsers: [], excludedLibraries: [] },
    ]);

    await page.getByText('Explicit provider user bindings', { exact: true }).click();
    await expect(page.getByText('#2 (alice)')).toBeVisible();
    await page.getByRole('button', { name: 'Delete binding for #2 (alice)' }).click();
    await page.getByRole('dialog', { name: 'Review exact administrative request' })
      .getByRole('button', { name: 'Apply reviewed change', exact: true })
      .click();
    await expect.poll(() => linkDeletes).toEqual([
      { afUserId: 2, provider: 'jellyfin', serverId: 'srv-1', providerUserId: 'jf-u2' },
    ]);
  });

  test('syncs Jellyfin summaries with a different import server selected', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const syncRequests: string[] = [];

    await page.route('**/api/v1/auth/streaming/dashboard?*', route =>
      json(route, {
        servers: [
          { provider: 'jellyfin', name: 'Jellyfin', status: 'connected', serverId: 'srv-jf' },
          { provider: 'emby', name: 'Emby', status: 'connected', serverId: 'srv-emby' },
        ],
        liveSummary: { activeStreams: 0, isDemoMode: false },
        activeSessions: [],
        analytics: { recentHistory: [], historicalEstimates: [] },
      }),
    );
    await page.route('**/api/v1/admin/streaming/imports/status', route =>
      json(route, { maxBatchEvents: 500, checkpoints: [], capabilities: [] }),
    );
    await page.route('**/api/v1/admin/streaming/servers/*/sync', route => {
      syncRequests.push(new URL(route.request().url()).pathname);
      return json(route, { imported: 2, complete: true });
    });

    await page.goto('/?tab=streaming');
    await page.getByRole('tab', { name: 'History administration', exact: true }).click();
    await page.getByText('Jellystat / Tautulli / JSON event import', { exact: true }).click();
    const importServer = page.getByLabel('Bind to verified server');
    await importServer.selectOption('emby:srv-emby');
    await page.getByRole('button', { name: 'Sync Jellyfin item summaries & metadata' }).click();

    await expect(page.getByText(/Synchronized 2 item summaries/)).toBeVisible();
    expect(syncRequests).toEqual(['/api/v1/admin/streaming/servers/jellyfin/sync']);
    await expect(importServer).toHaveValue('emby:srv-emby');
  });

  test('renders Audit KPI counters and contextual pending_action / service log drilldowns', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

    await page.route('**/api/v1/admin/audit-log?*', route =>
      json(route, {
        total: 3,
        entries: [
          {
            id: 1,
            username: 'admin',
            action: 'action_approve',
            target_type: 'pending_action',
            target_id: '77',
            detail: 'Approved action 77',
            ip_address: '127.0.0.1',
            severity: 'info',
            created_at: '2026-11-19T05:00:00Z',
          },
          {
            id: 2,
            username: 'flowai',
            action: 'ai_action_proposed',
            target_type: 'pending_action',
            target_id: '78',
            detail: 'AI proposal 78',
            ip_address: '127.0.0.1',
            severity: 'warning',
            created_at: '2026-11-19T05:01:00Z',
          },
          {
            id: 3,
            username: 'admin',
            action: 'service_restart',
            target_type: 'service',
            target_id: 'sonarr',
            detail: 'Restarted sonarr',
            ip_address: '127.0.0.1',
            severity: 'info',
            created_at: '2026-11-19T05:02:00Z',
          },
        ],
      }),
    );
    await page.route('**/api/v1/admin/actions/77', route =>
      json(route, { id: 77, action: 'restart:sonarr', risk_level: 'medium', status: 'executed' }),
    );
    await page.route('**/api/v1/admin/logs?*', route =>
      json(route, {
        logs: [{ timestamp: '2026-11-19T05:02:01Z', level: 'INFO', message: 'Sonarr started cleanly' }],
      }),
    );

    await page.goto('/?tab=audit');
    const summary = page.getByRole('region', { name: 'Audit summary' });
    await expect(summary).toContainText('Total Events');
    await expect(summary).toContainText('3');
    await expect(summary).toContainText('Operator Approvals');
    await expect(summary).toContainText('AI Proposed');
    await expect(summary).toContainText('System & Auth');

    await page.getByRole('row', { name: /Approved action 77/ }).click();
    const auditDrawer = page.getByRole('dialog', { name: 'Audit event details' });
    await expect(auditDrawer.getByText('Linked approval action')).toBeVisible();
    await expect(auditDrawer.getByText('restart:sonarr')).toBeVisible();
    await auditDrawer.getByRole('button', { name: 'Close dialog', exact: true }).click();

    await page.getByRole('row', { name: /Restarted sonarr/ }).click();
    await auditDrawer.getByRole('button', { name: 'Open service logs', exact: true }).click();
    const logsModal = page.getByRole('dialog', { name: 'Service Logs' });
    await expect(logsModal).toBeVisible();
    await expect(logsModal.getByText('Sonarr started cleanly')).toBeVisible();
  });

  test('deep-links Services and Marketplace External access shortcuts to targeted Network ingress rows', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

    await page.route('**/api/v1/auth/services', route =>
      json(route, {
        'aetherflow-api': {
          id: 'aetherflow-api',
          name: 'AetherFlow API',
          slug: 'aetherflow-api',
          status: 'running',
          managed_by: 'systemd',
          default_port: 8080,
          active_port: 8080,
        },
        fail2ban: {
          id: 'fail2ban',
          name: 'Fail2Ban',
          slug: 'fail2ban',
          status: 'running',
          managed_by: 'systemd',
          default_port: 0,
        },
        sonarr: {
          id: 'sonarr',
          name: 'Sonarr',
          slug: 'sonarr',
          status: 'running',
          managed_by: 'systemd',
          default_port: 8989,
          active_port: 8989,
        },
        radarr: {
          id: 'radarr',
          name: 'Radarr',
          slug: 'radarr',
          status: 'running',
          managed_by: 'systemd',
          default_port: 7878,
          active_port: 7878,
        },
      }),
    );

    await page.route(/\/api(\/v1)?(\/(public|auth|admin))?\/marketplace/, route =>
      json(route, [
        {
          id: 'fail2ban',
          name: 'Fail2Ban',
          desc: 'Intrusion prevention daemon.',
          category: 'Monitoring & Security',
          status: 'installed',
          default_port: 0,
          inventory_known: true,
          inventory_authenticated: true,
        },
        {
          id: 'sonarr',
          name: 'Sonarr',
          desc: 'TV automation.',
          category: 'Arr Stack',
          status: 'installed',
          default_port: 8989,
          active_port: 8989,
          external_access_enabled: true,
          public_domain: 'sonarr.apps.example.com',
          tls_enabled: true,
          inventory_known: true,
          inventory_authenticated: true,
        },
        {
          id: 'radarr',
          name: 'Radarr',
          desc: 'Movie automation.',
          category: 'Arr Stack',
          status: 'installed',
          default_port: 7878,
          active_port: 7878,
          inventory_known: true,
          inventory_authenticated: true,
        },
      ]),
    );

    await page.route('**/api/v1/admin/network/status', route =>
      json(route, { platform: 'linux', interfaces: [], wireguard: { available: false }, tailscale: { installed: false } }),
    );
    await page.route('**/api/v1/admin/services', route =>
      json(route, { services: [{ id: 'apache2', name: 'apache2', status: 'running' }] }),
    );
    await page.route('**/api/v1/admin/ingress/configs', route =>
      json(route, {
        configs: [
          { appName: 'sonarr', listenPort: 8989, externalAccessEnabled: true, publicDomain: 'sonarr.example.com', tlsEnabled: true },
          { appName: 'radarr', listenPort: 7878, externalAccessEnabled: false, publicDomain: '', tlsEnabled: false },
        ],
      }),
    );

    await page.goto('/?tab=services');
    await expect(page.getByRole('button', { name: 'External access', exact: true })).toHaveCount(2);
    await page.locator('article').filter({ hasText: 'Sonarr' }).getByRole('button', { name: 'External access', exact: true }).click();

    await expect(page.getByText('Focused application: sonarr')).toBeVisible();
    const ingressTable = page.getByRole('table', { name: 'Application external access' });
    await expect(ingressTable.getByRole('heading', { name: 'sonarr' })).toBeVisible();
    await expect(ingressTable.getByRole('heading', { name: 'radarr' })).toHaveCount(0);

    await page.getByRole('button', { name: 'Show all applications', exact: true }).click();
    await expect(ingressTable.getByRole('heading', { name: 'radarr' })).toBeVisible();

    await page.goto('/?tab=marketplace');
    await expect(page.getByRole('button', { name: 'External access', exact: true })).toHaveCount(2);
    await page.locator('article').filter({ hasText: 'Radarr' }).getByRole('button', { name: 'External access', exact: true }).click();

    await expect(page.getByText('Focused application: radarr')).toBeVisible();
    await expect(ingressTable.getByRole('heading', { name: 'radarr' })).toBeVisible();
    await expect(ingressTable.getByRole('heading', { name: 'sonarr' })).toHaveCount(0);
  });

  test('renders Streaming distribution charts and updates analytics when Play method and Media type filters change', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const dashboardUrls: string[] = [];

    await page.route('**/api/v1/auth/streaming/dashboard?*', route => {
      const url = new URL(route.request().url());
      dashboardUrls.push(url.search);
      const playMethod = url.searchParams.get('playMethod') ?? 'all';
      const mediaType = url.searchParams.get('mediaType') ?? 'all';
      const filtered = playMethod === 'Transcode' && mediaType === 'Movie';
      return json(route, {
        servers: [{ provider: 'jellyfin', name: 'Jellyfin A', status: 'connected', serverId: 'srv-1' }],
        liveSummary: {
          activeStreams: 1,
          directPlayCount: 1,
          directStreamCount: 0,
          transcodeCount: 0,
          totalBandwidthMbps: 10.0,
          isDemoMode: false,
        },
        activeSessions: [],
        analytics: filtered
          ? {
              windowDays: 30,
              totalPlays: 4,
              totalWatchTimeSecs: 7200,
              totalDataUsedBytes: 4294967296,
              uniqueUsers: 1,
              uniqueTitles: 2,
              avgCompletionPct: 88.0,
              peakBandwidthMbps: 18.4,
              streamTypes: {
                directPlayCount: 0,
                directPlayPct: 0.0,
                directStreamCount: 0,
                directStreamPct: 0.0,
                transcodeCount: 4,
                transcodePct: 100.0,
              },
              mediaTypeBreakdown: [{ label: 'Movie', count: 4, pct: 100.0, watchTimeSecs: 7200, dataUsedBytes: 4294967296 }],
              resolutionBreakdown: [{ label: '1080p', count: 4, pct: 100.0, watchTimeSecs: 7200, dataUsedBytes: 4294967296 }],
              codecBreakdown: [{ label: 'h264', count: 4, pct: 100.0, watchTimeSecs: 7200, dataUsedBytes: 4294967296 }],
              timeSeriesGranularity: 'daily',
              timeSeries: [
                { date: '2026-11-18', plays: 4, watchTimeSecs: 7200, dataUsedBytes: 4294967296, peakBandwidthMbps: 18.4, directPlayCount: 0, directStreamCount: 0, transcodeCount: 4 },
              ],
              topUsers: [
                { userId: 'u2', userName: 'bob', provider: 'jellyfin', totalPlays: 4, totalWatchSecs: 7200, totalDataBytes: 4294967296 },
              ],
              topTitles: [
                { itemId: 'm2', itemName: 'Arrival', videoResolution: '1080p', videoCodec: 'h264', totalPlays: 4, totalDataBytes: 4294967296 },
              ],
              recentHistory: [],
              historicalEstimates: [],
            }
          : {
              windowDays: 30,
              totalPlays: 12,
              totalWatchTimeSecs: 14400,
              totalDataUsedBytes: 8589934592,
              uniqueUsers: 2,
              uniqueTitles: 4,
              avgCompletionPct: 91.5,
              peakBandwidthMbps: 34.2,
              streamTypes: {
                directPlayCount: 7,
                directPlayPct: 58.3,
                directStreamCount: 2,
                directStreamPct: 16.7,
                transcodeCount: 3,
                transcodePct: 25.0,
              },
              mediaTypeBreakdown: [
                { label: 'Movie', count: 8, pct: 66.7, watchTimeSecs: 10800, dataUsedBytes: 6442450944 },
                { label: 'Episode', count: 4, pct: 33.3, watchTimeSecs: 3600, dataUsedBytes: 2147483648 },
              ],
              resolutionBreakdown: [
                { label: '2160p', count: 8, pct: 66.7, watchTimeSecs: 10800, dataUsedBytes: 6442450944 },
              ],
              codecBreakdown: [
                { label: 'hevc', count: 8, pct: 66.7, watchTimeSecs: 10800, dataUsedBytes: 6442450944 },
              ],
              timeSeriesGranularity: 'daily',
              timeSeries: [
                { date: '2026-11-17', plays: 5, watchTimeSecs: 5400, dataUsedBytes: 3221225472, peakBandwidthMbps: 22.0, directPlayCount: 3, directStreamCount: 1, transcodeCount: 1 },
                { date: '2026-11-18', plays: 7, watchTimeSecs: 9000, dataUsedBytes: 5368709120, peakBandwidthMbps: 34.2, directPlayCount: 4, directStreamCount: 1, transcodeCount: 2 },
              ],
              topUsers: [
                { userId: 'u1', userName: 'alice', provider: 'jellyfin', totalPlays: 8, totalWatchSecs: 10800, totalDataBytes: 6442450944 },
              ],
              topTitles: [
                { itemId: 'm1', itemName: 'Blade Runner 2049', videoResolution: '2160p', videoCodec: 'hevc', totalPlays: 6, totalDataBytes: 5368709120 },
              ],
              recentHistory: [],
              historicalEstimates: [],
            },
      });
    });

    await page.goto('/?tab=streaming');
    await expect(page.getByText('Distribution & Trends')).toBeVisible();
    const methodRegion = page.getByRole('region', { name: 'Playback method breakdown' });
    await expect(methodRegion).toContainText('Direct Play: 7 (58.3%)');
    await expect(methodRegion.getByRole('img', { name: 'Playback method breakdown' })).toBeVisible();
    const formatRegion = page.getByRole('region', { name: 'Media format distribution' });
    await expect(formatRegion).toContainText('Movie');
    await expect(formatRegion.getByRole('progressbar', { name: 'Movie' })).toHaveAttribute('value', '66.7');
    await expect(page.getByRole('region', { name: 'Resolution distribution' })).toContainText('2160p');
    await expect(page.getByRole('region', { name: 'Source codec distribution' })).toContainText('hevc');
    await expect(page.getByRole('region', { name: 'Top watchers' })).toContainText('alice');
    await expect(page.getByRole('region', { name: 'Top titles' })).toContainText('Blade Runner 2049');

    await page.getByRole('combobox', { name: 'Play method' }).selectOption('Transcode');
    await page.getByRole('combobox', { name: 'Media type' }).selectOption('Movie');

    await expect.poll(() => dashboardUrls.some(s => s.includes('playMethod=Transcode') && s.includes('mediaType=Movie'))).toBe(true);
    await expect(methodRegion).toContainText('Transcode: 4 (100.0%)');
    await expect(page.getByRole('region', { name: 'Resolution distribution' })).toContainText('1080p');
    await expect(page.getByRole('region', { name: 'Source codec distribution' })).toContainText('h264');
    await expect(page.getByRole('region', { name: 'Top watchers' })).toContainText('bob');
    await expect(page.getByRole('region', { name: 'Top titles' })).toContainText('Arrival');
  });
});
