import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

for (const initialInventory of [true, false]) {
  test(`Services preserves live status over a delayed ${initialInventory ? 'initial inventory' : 'manual refresh'}`, async ({ page }) => {
    await page.clock.install({ time: new Date('2026-11-17T11:59:00Z') });
    await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, enableWS: true });
    let publish: ((data: object) => void) | undefined;
    await page.route('**/api/v1/auth/ws/ticket', route => route.fulfill({ json: { ticket: 'services-fixture' } }));
    await page.routeWebSocket(/\/api\/v1\/auth\/ws(?:\?|$)/, socket => {
      publish = data => socket.send(JSON.stringify({ type: 'METRICS_UPDATE', data }));
      socket.onMessage(message => {
        if (message === '{"type":"PING"}') socket.send('{"type":"PONG"}');
      });
    });
    const services = (status: string) => ({ snapshot_probe: {
      id: 'snapshot_probe', name: 'Snapshot Probe', status, managed_by: 'systemd',
    } });
    const held = deferred();
    const release = deferred();
    const completed = deferred();
    let hold = false;
    await page.route('**/api/v1/auth/services', async route => {
      if (hold) {
        hold = false;
        held.resolve();
        await release.promise;
        await route.fulfill({ json: services('running') });
        completed.resolve();
      } else {
        await route.fulfill({ json: services('stopped') });
      }
    });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Snapshot Probe', exact: true })).toBeVisible();
    await expect(page.getByText('API Connected', { exact: true })).toBeVisible();
    await expect.poll(() => Boolean(publish)).toBe(true);
    hold = initialInventory;
    await page.getByRole('button', { name: 'Services', exact: true }).first().click();
    const card = page.locator('article.af-service-tile').filter({
      has: page.getByRole('heading', { name: 'Snapshot Probe', exact: true }),
    });
    const refresh = page.getByRole('button', { name: 'Refresh services', exact: true });
    if (!initialInventory) {
      await expect(refresh).toBeEnabled();
      await expect(card.getByText(/^Stopped$/i)).toBeVisible();
      hold = true;
      await refresh.click();
    }
    try {
      await held.promise;
      publish!({ services: services('failed') });
      await expect(card.getByText(/^Failed$/i)).toBeVisible();
    } finally {
      release.resolve();
    }
    await completed.promise;
    await expect(refresh).toBeEnabled();
    await expect(card.getByText(/^Failed$/i)).toBeVisible();
    await expect(card.getByText(/^Running$/i)).toHaveCount(0);
    // A request deliberately started after the live sample may publish new state.
    await refresh.click();
    await expect(card.getByText(/^Stopped$/i)).toBeVisible();
  });
}

for (const liveServices of [false, true]) {
  test(`a delayed shell refresh preserves live metrics and ${liveServices ? 'live' : 'HTTP bootstrap'} services`, async ({ page }) => {
    await page.clock.install({ time: new Date('2026-11-17T11:59:00Z') });
    await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, enableWS: true });
    const metricsReturned = deferred();
    const servicesStarted = deferred();
    const releaseServices = deferred();
    const refreshCompleted = deferred();
    let publish: ((data: object) => void) | undefined;
    await page.route('**/api/v1/auth/ws/ticket', route => route.fulfill({ json: { ticket: 'telemetry-fixture' } }));
    await page.routeWebSocket(/\/api\/v1\/auth\/ws(?:\?|$)/, socket => {
      publish = (data) => socket.send(JSON.stringify({ type: 'METRICS_UPDATE', data }));
      socket.onMessage(message => {
        if (message === '{"type":"PING"}') socket.send('{"type":"PONG"}');
      });
    });
    await page.route('**/api/v1/auth/system/metrics', async route => {
      await route.fulfill({ json: { cpu_usage: 10, memory_usage: 20 } });
      metricsReturned.resolve();
    });
    await page.route('**/api/v1/auth/system/topology', route => route.fulfill({ json: { nodes: [] } }));
    await page.route('**/api/v1/auth/services', async route => {
      servicesStarted.resolve();
      await releaseServices.promise;
      await route.fulfill({ json: { http_probe: { status: 'stopped' } } });
    });
    await page.route('**/api/v1/admin/actions/pending?*', async route => {
      await route.fulfill({ json: { actions: [], total: 0 } });
      refreshCompleted.resolve();
    });
    const cpu = page.getByRole('heading', { name: 'CPU Utilization', exact: true }).locator('..').locator('p').first();
    const topology = page.getByRole('group', { name: 'Service topology graph', exact: true });
    try {
      await page.goto('/');
      await metricsReturned.promise;
      await servicesStarted.promise;
      await expect(page.getByText('API Connected', { exact: true })).toBeVisible();
      await expect.poll(() => Boolean(publish)).toBe(true);
      publish!({ system: { cpu_usage: 90, memory_usage: 80 },
        ...(liveServices ? { services: { live_probe: { status: 'running' } } } : {}) });
      await expect(cpu).toHaveText('90.0%');
      if (liveServices) await expect(topology.getByRole('button', { name: 'Live Probe', exact: true })).toBeVisible();
    } finally {
      releaseServices.resolve();
    }
    // Pending actions are fetched only after the joined HTTP refresh commits.
    await refreshCompleted.promise;
    await page.clock.runFor(50);
    await expect(cpu).toHaveText('90.0%');
    await expect(topology.getByRole('button', {
      name: liveServices ? 'Live Probe' : 'Http Probe', exact: true,
    })).toBeVisible();
    await expect(topology.getByRole('button', {
      name: liveServices ? 'Http Probe' : 'Live Probe', exact: true,
    })).toHaveCount(0);
  });
}
