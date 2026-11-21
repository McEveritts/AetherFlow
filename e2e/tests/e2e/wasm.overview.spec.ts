import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

test('applies the displayed bandwidth recommendation explicitly and reports daemon failures', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const applied: unknown[] = [];
  let reject = false;
  await page.route('**/api/v1/admin/ai/bandwidth/analyze', (route) => route.fulfill({ json: {
    reasoning: 'Keep capacity for active streams.', recommended_upload_kbps: 160, recommended_download_kbps: 960,
  } }));
  await page.route('**/api/v1/admin/ai/bandwidth/apply', (route) => {
    applied.push(route.request().postDataJSON());
    return reject ? route.fulfill({
      status: 502, json: { code: 'BAD_GATEWAY', error: 'Torrent daemon rejected RPC request' },
    }) : route.fulfill({ json: { message: 'Limits applied successfully to Torrent engine via RPC' } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Analyze bandwidth', exact: true }).click();
  await expect(page.getByText('RX 960 KiB/s · TX 160 KiB/s', { exact: true })).toBeVisible();
  expect(applied).toEqual([]);
  const apply = page.getByRole('button', { name: 'Apply bandwidth limits', exact: true });
  await apply.click();
  await expect(page.getByRole('status').filter({ hasText: 'Bandwidth limits applied' })).toBeVisible();
  expect(applied).toEqual([{ upload_kbps: 160, download_kbps: 960 }]);

  reject = true;
  await apply.click();
  await expect(page.getByRole('alert').filter({ hasText: 'Torrent daemon rejected RPC request' })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'Bandwidth limits applied' })).toHaveCount(0);
  await expect(apply).toBeEnabled();
  expect(applied).toHaveLength(2);
});

test('does not apply malformed recommendations or expose administrator actions to ordinary users', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let requests = 0;
  await page.route('**/api/v1/admin/ai/bandwidth/analyze', (route) => route.fulfill({ json: {
    reasoning: 'Invalid provider result', recommended_upload_kbps: -1,
  } }));
  await page.route('**/api/v1/admin/ai/bandwidth/apply', (route) => {
    requests += 1;
    return route.fulfill({ json: {} });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Analyze bandwidth', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Apply bandwidth limits', exact: true })).toBeDisabled();
  await expect(page.getByText('Invalid bandwidth recommendation', { exact: true })).toBeVisible();
  expect(requests).toBe(0);

  await page.route('**/api/v1/auth/session', (route) => route.fulfill({ json: {
    id: 2, username: 'member', role: 'user', is_oauth: false,
  } }));
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Analyze bandwidth', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Apply bandwidth limits', exact: true })).toHaveCount(0);
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  test(`keeps quantitative SVG chart labels readable at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    const labels = page.locator('.af-chart svg text');
    await expect(labels.first()).toBeVisible();
    const readSizes = () => labels.evaluateAll((elements) => elements.filter(element => {
      const box = element.getBoundingClientRect();
      return box.width > 0 && box.height > 0;
    }).map((element) => {
      const transform = (element as SVGTextElement).getScreenCTM();
      const scale = transform ? Math.hypot(transform.a, transform.b) : 0;
      return { text: element.textContent, cssPixels: parseFloat(getComputedStyle(element).fontSize) * scale };
    }));
    await expect.poll(async () => {
      const sizes = await readSizes();
      return sizes.length > 0 && sizes.every(size => Number.isFinite(size.cssPixels) && size.cssPixels >= 11.99);
    }).toBe(true);
    const sizes = await readSizes();
    expect(sizes.length).toBeGreaterThan(0);
    for (const size of sizes) expect(size.cssPixels, size.text || 'chart label').toBeGreaterThanOrEqual(11.99);
  });
}

test('draws each returned service link and preserves an isolated service', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const ids = ['Gateway', 'Service A', 'Service B', 'Isolated'];
  const links = [{ source: 'Gateway', target: 'Service A' }, { source: 'Service A', target: 'Service B' }];
  await page.route('**/api/v1/auth/system/topology', route => route.fulfill({ json: {
    nodes: ids.map(id => ({ id, status: 'running' })), links,
  } }));
  await page.goto('/');
  const graph = page.getByRole('group', { name: 'Service topology graph' });
  await expect(graph.locator('line')).toHaveCount(2);
  await expect(graph.getByRole('button', { name: 'Isolated', exact: true })).toBeVisible();
  for (const { source, target } of links) {
    const line = graph.locator(`line[data-source="${source}"][data-target="${target}"]`);
    for (const [name, end] of [[source, 1], [target, 2]] as const) {
      const x = await line.getAttribute(`x${end}`);
      const y = await line.getAttribute(`y${end}`);
      await expect(graph.getByRole('button', { name, exact: true })).toHaveAttribute('transform', `translate(${x},${y})`);
    }
  }
});

test('persists dashboard density and widget visibility across a reload', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, preserveStorage: true });
  await page.goto('/?tab=settings');
  await page.getByLabel('Immersive dashboard layout').check();
  await page.getByLabel('Show GPU telemetry').uncheck();
  await page.getByLabel('Show transfer history').uncheck();
  await page.goto('/?tab=overview');
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: /GPU Accelerators/i })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: /Data Usage History/i })).toHaveCount(0);
  await page.goto('/?tab=settings');
  await expect(page.getByLabel('Immersive dashboard layout')).toBeChecked();
  await expect(page.getByLabel('Show GPU telemetry')).not.toBeChecked();
  await expect(page.getByLabel('Show transfer history')).not.toBeChecked();
});

test('queries aggregated daily transfer and 30-day capacity history endpoints and decodes both responses', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const dailyTransferDays: string[] = [];
  const capacityQueries: string[] = [];

  await page.route(/\/api\/v1\/auth\/system\/metrics\/history(?:\?.*)?$/, async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get('aggregate') === 'daily_transfer') {
      const days = url.searchParams.get('days') || '';
      dailyTransferDays.push(days);
      await route.fulfill({
        json: {
          days: [
            { date: '2026-11-16', downloaded_bytes: 0, uploaded_bytes: 0 },
            { date: '2026-11-18', downloaded_bytes: 2 * 1024 * 1024 * 1024, uploaded_bytes: 512 * 1024 * 1024 },
          ],
          counter_resets: 1,
          invalid_samples: 0,
          conflicting_samples: 0,
          duplicate_samples: 0,
        },
      });
      return;
    }
    await route.fulfill({ json: [] });
  });

  await page.route(/\/api\/v1\/admin\/ai\/predictions\/history(?:\?.*)?$/, async (route) => {
    const url = new URL(route.request().url());
    capacityQueries.push(`${url.searchParams.get('days')}:${url.searchParams.get('aggregate')}`);
    await route.fulfill({
      json: [
        {
          timestamp: '2026-10-21 00:00:00',
          cpu_avg: 22.0,
          mem_used_gb: 16.0,
          mem_total_gb: 64.0,
          disk_read_bps: 4 * 1024 * 1024,
          disk_write_bps: 2 * 1024 * 1024,
          net_rx_bytes: 1_000_000,
          net_tx_bytes: 500_000,
        },
        {
          timestamp: '2026-11-19 00:00:00',
          cpu_avg: 38.0,
          mem_used_gb: 24.0,
          mem_total_gb: 64.0,
          disk_read_bps: 8 * 1024 * 1024,
          disk_write_bps: 3 * 1024 * 1024,
          net_rx_bytes: 101_000_000,
          net_tx_bytes: 50_500_000,
        },
      ],
    });
  });

  await page.goto('/');
  await expect(page.getByText('Coverage: 2 of 30 days observed', { exact: false })).toBeVisible();
  await expect(page.getByText('1 counter resets detected; only post-reset values are counted.', { exact: false })).toBeVisible();
  await expect(page.getByText('2.0 GiB', {exact:true})).toBeVisible();
  await expect(page.getByText('512.0 MiB', {exact:true})).toBeVisible();
  await expect(page.getByTestId('capacity-history-plots').locator('svg')).toHaveCount(4);
  await expect(page.getByText('30d history · 2 samples · 2 days observed', { exact: true })).toBeVisible();
  expect(dailyTransferDays).toContain('30');
  expect(capacityQueries).toContain('30:capacity');

  await page.getByTestId('data-usage-window-7d').click();
  await expect(page.getByText('Coverage: 2 of 7 days observed', { exact: false })).toBeVisible();
  await page.getByTestId('data-usage-window-90d').click();
  await expect(page.getByText('Coverage: 2 of 90 days observed', { exact: false })).toBeVisible();
  expect(dailyTransferDays).toEqual(expect.arrayContaining(['30', '7', '90']));
});

for (const timezoneId of ['UTC', 'Europe/Berlin', 'America/New_York']) {
  test.describe(`disk telemetry in ${timezoneId}`, () => {
    test.use({ timezoneId });
    test('joins SQLite UTC history to both live disk rates across a DST transition', async ({ page }) => {
      await page.clock.setFixedTime(new Date('2026-11-01T06:00:15Z'));
      await installAetherFlowMocks(page, { authenticated: true });
      await page.route('**/api/v1/auth/system/metrics/history?window=*', route => route.fulfill({
        json: [{ timestamp: '2026-11-01 05:59:45', disk_read_bps: 1024, disk_write_bps: 512 }],
      }));
      await page.route('**/api/v1/auth/system/metrics', route => route.fulfill({
        json: { disk_io: {read_bytes_sec: 0, write_bytes_sec: 8192}, cpu_usage: 10 },
      }));
      await page.goto('/?tab=overview&window=1m');
      await page.getByTestId('telemetry-series-disk').click();
      const chart = page.getByRole('img', { name: 'Historical and live system telemetry' });
      await expect(chart.locator('.af-wasm-area-curve')).toHaveAttribute('d', /L/);
      await expect(chart.locator('.af-wasm-secondary-curve')).toHaveAttribute('d', /L/);
      await expect(page.getByTestId('telemetry-coverage-summary')).toContainText('2 samples');
    });
  });
}

test('filters storage partitions with pool summary, triages service exceptions, and navigates via configure and account menu', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await page.route(/\/api(\/v1)?(\/auth)?\/system\/metrics$/, route => route.fulfill({
    json: {
      cpu_usage: 24.5,
      memory: { used: 16, total: 64 },
      network: { down: '4.2MB/s', up: '1.1MB/s' },
      disk_io: { read_bytes_sec: 524288, write_bytes_sec: 262144 },
      disk_partitions: [
        { mount_point: '/', device: '/dev/nvme0n1p2', fs_type: 'ext4', used_gb: 100, total_gb: 400 },
        { mount_point: '/mnt/media', device: '/dev/md0', fs_type: 'xfs', used_gb: 200, total_gb: 1000 },
      ],
    },
  }));
  await page.route(/\/api(\/v1)?(\/auth)?\/services/, route => route.fulfill({
    json: {
      'aetherflow-api': { status: 'running', version: '3.1.0', uptime: '4d', managed_by: 'pm2', process: 'aetherflow-api' },
      sonarr: { status: 'failed', version: '4.0.0', uptime: '0s', managed_by: 'systemd', process: 'sonarr' },
    },
  }));

  await page.goto('/?tab=overview');
  await expect(page.getByTestId('storage-pool-summary')).toContainText('300.0 / 1400.0 GB · 1100.0 GB free');
  await expect(page.getByTestId('storage-partition-row')).toHaveCount(2);

  await page.getByTestId('storage-partition-filter').selectOption('/mnt/media');
  await expect(page.getByTestId('storage-partition-row')).toHaveCount(1);
  await expect(page.getByTestId('storage-pool-summary')).toContainText('200.0 / 1000.0 GB · 800.0 GB free');

  const banner = page.getByTestId('overview-service-exception-banner');
  await expect(banner).toBeVisible();
  await expect(banner).toContainText('1 services require attention');
  await expect(banner).toContainText('sonarr');
  await page.getByTestId('overview-triage-services-button').click();
  await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /Attention/i })).toHaveAttribute('aria-pressed', 'true');

  await page.goto('/?tab=overview');
  await page.getByTestId('overview-configure-button').click();
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'General & Localization', exact: true })).toHaveAttribute('aria-selected', 'true');

  await page.getByTestId('header-account-menu-trigger').click();
  const menu = page.getByTestId('header-account-menu');
  await expect(menu).toBeVisible();
  await page.getByTestId('header-account-profile').click();
  await expect(page.getByRole('tab', { name: 'Security & 2FA', exact: true })).toHaveAttribute('aria-selected', 'true');
});
