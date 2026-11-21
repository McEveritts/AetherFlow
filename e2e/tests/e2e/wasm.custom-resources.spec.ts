import { expect, test, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';
import { reads, resetSettledReads, trackReads } from './support/readProbe';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

async function installConnectedMocks(page: Page) {
  await installAetherFlowMocks(page, { enableWS: true });
  await page.route('**/api/v1/auth/ws/ticket', route => route.fulfill({ json: { ticket: 'custom-resource-fixture' } }));
  await page.routeWebSocket(/\/api\/v1\/auth\/ws(?:\?|$)/, socket => {
    socket.onMessage(message => {
      if (message === '{"type":"PING"}') socket.send('{"type":"PONG"}');
    });
  });
}


const historyPath = '/api/v1/auth/streaming/history';
const servicesPath = '/api/v1/auth/services';
const metricsPath = '/api/v1/auth/system/metrics';
const notificationsPath = '/api/v1/auth/notifications';
const settingsPath = '/api/v1/auth/settings';
const pendingPath = '/api/v1/admin/actions/pending';

test('history replaces held filter reads without overlap and aborts the held read on disposal', async ({ page }) => {
  await installConnectedMocks(page);
  await trackReads(page, [historyPath]);
  const release = deferred();
  let sequence = 0;
  await page.route('**/api/v1/auth/streaming/history?*', async route => {
    const number = ++sequence;
    if (number !== 3) await release.promise;
    await route.fulfill({ json: {
      scope: { snapshotToken: `snapshot-${number}`, asOf: '2026-11-17T00:00:00Z', expiresAt: '2026-11-18T00:00:00Z' },
      counts: { matchingRecords: 1, availableRecords: 1, confirmedPlays: 1, watchTimeSecs: 60, undatedRecords: 0 },
      items: [{ id: number, provider: 'jellyfin', itemName: `History record ${number}` }],
      nextCursor: '',
    } }).catch(() => {});
  });
  try {
    await page.goto('/?tab=streaming');
    await page.getByRole('tab', { name: 'Canonical playback history', exact: true }).click();
    await expect.poll(async () => (await reads(page, historyPath)).attempts.length).toBe(1);
    await page.getByLabel('Server provider').selectOption('emby');
    await expect.poll(async () => (await reads(page, historyPath)).attempts.length).toBe(2);
    let state = await reads(page, historyPath);
    expect(state.attempts[0].outcome).toBe('aborted');
    expect(state.attempts[1].url).toContain('provider=emby');
    await page.getByLabel('Server provider').selectOption('jellyfin');
    await expect.poll(async () => (await reads(page, historyPath)).attempts.length).toBe(3);
    const grid = page.getByRole('grid', { name: 'Canonical playback history; worker-backed page search', exact: true });
    await expect(grid.getByText('History record 3', { exact: true })).toBeVisible();
    state = await reads(page, historyPath);
    expect(state.attempts.slice(0, 2).map(attempt => attempt.outcome)).toEqual(['aborted', 'aborted']);
    expect(state.attempts[2].url).toContain('provider=jellyfin');
    expect(state.maximum).toBe(1);
    await page.getByRole('button', { name: 'New snapshot', exact: true }).click();
    await expect.poll(async () => (await reads(page, historyPath)).attempts.length).toBe(4);
    await page.getByRole('tab', { name: 'Active playback sessions', exact: true }).click();
    await expect.poll(async () => (await reads(page, historyPath)).active).toBe(0);
    state = await reads(page, historyPath);
    expect(state.attempts[3].outcome).toBe('aborted');
    expect(state.maximum).toBe(1);
  } finally {
    release.resolve();
  }
});

test('repeated Services disposal aborts held inventories in the same session', async ({ page }) => {
  await installConnectedMocks(page);
  await trackReads(page, [servicesPath]);
  const release = deferred();
  let holdInventory = false;
  await page.route('**/api/v1/auth/services', async route => {
    if (holdInventory) await release.promise;
    await route.fulfill({ json: { probe: { id: 'probe', name: 'Probe', status: 'running' } } }).catch(() => {});
  });
  try {
    await page.goto('/?tab=overview');
    await expect(page.locator('#desktop-sidebar-navigation')).toBeVisible();
    await expect(page.getByText('API Connected', { exact: true })).toBeVisible();
    await resetSettledReads(page, servicesPath);
    holdInventory = true;
    for (let visit = 0; visit < 3; visit += 1) {
      await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Services', exact: true }).click();
      await expect.poll(async () => (await reads(page, servicesPath)).attempts.length).toBe(visit + 1);
      await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Overview', exact: true }).click();
      await expect.poll(async () => (await reads(page, servicesPath)).active).toBe(0);
      const state = await reads(page, servicesPath);
      expect(state.attempts.map(attempt => attempt.outcome)).toEqual(Array(visit + 1).fill('aborted'));
      expect(state.maximum).toBe(1);
    }
  } finally {
    release.resolve();
  }
});

test('shell coalesces slow polls through pending actions, then resumes and aborts on session disposal', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-17T11:59:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installConnectedMocks(page);
  let identity = 1;
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: {
    id: identity, username: identity === 1 ? 'alice' : 'bob', role: 'admin', is_oauth: false,
  } }));
  await trackReads(page, [metricsPath, servicesPath, notificationsPath, settingsPath, pendingPath]);
  const releaseFirstMetrics = deferred();
  const releaseSecondMetrics = deferred();
  const releasePending = deferred();
  let holdMetrics = false;
  let holdPending = false;
  let metricsCount = 0;
  let pendingCount = 0;
  await page.route('**/api/v1/auth/system/metrics', async route => {
    if (holdMetrics) {
      const number = ++metricsCount;
      await (number === 1 ? releaseFirstMetrics.promise : releaseSecondMetrics.promise);
    }
    await route.fulfill({ json: { cpu_usage: 23, memory_usage: 30 } }).catch(() => {});
  });
  await page.route('**/api/v1/auth/settings', route => route.fulfill({ json: { language: 'en', setupCompleted: true } }));
  await page.route('**/api/v1/admin/actions/pending?*', async route => {
    if (holdPending) {
      pendingCount += 1;
      await releasePending.promise;
    }
    await route.fulfill({ json: { total: 0, actions: [] } }).catch(() => {});
  });
  try {
    await page.goto('/?tab=overview');
    await expect(page.locator('#desktop-sidebar-navigation')).toBeVisible();
    await expect(page.getByText('API Connected', { exact: true })).toBeVisible();
    // Observe one committed shell after its bootstrap reads finish. Transient
    // startup mounts are outside this controlled 30-second polling interval.
    for (const path of [metricsPath, servicesPath, notificationsPath, settingsPath, pendingPath]) {
      await resetSettledReads(page, path);
    }
    holdMetrics = true;
    holdPending = true;
    await page.clock.runFor(30_000);
    await expect.poll(async () => (await reads(page, metricsPath)).attempts.length).toBe(1);
    await page.clock.runFor(90_000);
    let metrics = await reads(page, metricsPath);
    expect(metrics.attempts).toHaveLength(1);
    expect(metrics.attempts[0].outcome).toBe('pending');
    expect(metrics.maximum).toBe(1);
    expect((await reads(page, servicesPath)).attempts).toHaveLength(1);
    expect((await reads(page, notificationsPath)).attempts).toHaveLength(1);
    releaseFirstMetrics.resolve();
    await expect.poll(() => pendingCount).toBe(1);
    await expect.poll(async () => (await reads(page, pendingPath)).active).toBe(1);
    await page.clock.runFor(60_000);
    expect((await reads(page, metricsPath)).attempts).toHaveLength(1);
    expect((await reads(page, servicesPath)).attempts).toHaveLength(1);
    expect((await reads(page, notificationsPath)).attempts).toHaveLength(1);
    expect((await reads(page, pendingPath)).attempts).toHaveLength(1);
    releasePending.resolve();
    await expect.poll(async () => (await reads(page, pendingPath)).active).toBe(0);
    await page.clock.runFor(30_000);
    await expect.poll(async () => (await reads(page, metricsPath)).attempts.length).toBe(2);
    metrics = await reads(page, metricsPath);
    expect(metrics.attempts[0].outcome).toBe('finished');
    expect(metrics.attempts[1].outcome).toBe('pending');
    expect(metrics.maximum).toBe(1);
    holdMetrics = false;
    holdPending = false;
    identity = 2;
    await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', { key: 'af_login_sync' })));
    await expect.poll(async () => (await reads(page, metricsPath)).attempts[1].outcome).toBe('aborted');
    await expect(page.getByText('bob', { exact: true }).first()).toBeVisible();
  } finally {
    releaseFirstMetrics.resolve();
    releaseSecondMetrics.resolve();
    releasePending.resolve();
  }
});

const networkStatusPath = '/api/v1/admin/network/status';
const diagnosticsPath = '/api/v1/admin/network/diagnostics';

test('Network replaces held diagnostics on provider and status refresh and cancels on tab exit', async ({ page }) => {
  // Pause the 10s network status poll so exact diagnostics attempt counts observe
  // only explicit provider changes, Refresh network clicks, and tab disposal.
  await page.clock.install({ time: new Date('2026-11-17T11:59:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installConnectedMocks(page);
  await trackReads(page, [diagnosticsPath]);
  const release = deferred();
  let statusReads = 0;
  let diagnosticReads = 0;
  await page.route(`**${networkStatusPath}`, route => route.fulfill({ json: {
    platform: 'linux', runner_available: true, checked_at: `Network status ${++statusReads}`,
  } }));
  await page.route(`**${diagnosticsPath}?*`, async route => {
    const number = ++diagnosticReads;
    if (number !== 3) await release.promise;
    await route.fulfill({ json: { logs: `Diagnostics ${number}` } }).catch(() => {});
  });
  async function outcomes() {
    return (await reads(page, diagnosticsPath)).attempts.map(attempt => attempt.outcome);
  }
  try {
    await Promise.all([
      page.waitForRequest(request => new URL(request.url()).pathname === diagnosticsPath),
      page.goto('/?tab=network'),
    ]);
    await expect.poll(outcomes).toEqual(['pending']);
    await page.getByLabel('VPN diagnostic provider').selectOption('tailscale');
    await expect.poll(outcomes).toEqual(['aborted', 'pending']);
    expect((await reads(page, diagnosticsPath)).attempts[1].url).toContain('provider=tailscale');
    await page.getByRole('button', { name: 'Refresh network', exact: true }).click();
    await expect(page.getByText('Diagnostics 3', { exact: true })).toBeVisible();
    await expect.poll(outcomes).toEqual(['aborted', 'aborted', 'finished']);
    await page.getByLabel('VPN diagnostic provider').selectOption('wireguard');
    await expect.poll(outcomes).toEqual(['aborted', 'aborted', 'finished', 'pending']);
    await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Overview', exact: true }).click();
    await expect.poll(outcomes).toEqual(['aborted', 'aborted', 'finished', 'aborted']);
    expect((await reads(page, diagnosticsPath)).maximum).toBe(1);
  } finally {
    release.resolve();
  }
});
