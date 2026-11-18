import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type Outcome = 'pending' | 'aborted' | 'finished' | 'failed';
type Attempt = { id: string; signal: boolean; outcome: Outcome };
type Probe = { attempts: Attempt[]; active: number; maximum: number };

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

function nodes(prefix: 'old' | 'new') {
  return ['shared', ...Array.from({ length: 5 }, (_, index) => `${prefix}-${index + 2}`)]
    .map((id) => ({ id, hostname: `${prefix}-${id}`, role: 'worker', status: 'online' }));
}

async function installMetricsProbe(page: Page) {
  // Observe the actual signals passed to browser fetch, before Playwright
  // releases any held route. Settled requests no longer count as active.
  await page.addInitScript(() => {
    const state: Probe = { attempts: [], active: 0, maximum: 0 };
    (window as Window & { __clusterMetrics?: Probe }).__clusterMetrics = state;
    const fetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const match = new URL(url, location.href).pathname.match(/\/admin\/cluster\/nodes\/([^/]+)\/metrics$/);
      if (!match) return fetch(input, init);
      const signal = init?.signal;
      const attempt: Attempt = { id: decodeURIComponent(match[1]), signal: Boolean(signal), outcome: 'pending' };
      state.attempts.push(attempt);
      state.active += 1;
      state.maximum = Math.max(state.maximum, state.active);
      const settle = (outcome: Outcome) => {
        if (attempt.outcome === 'pending') {
          attempt.outcome = outcome;
          state.active -= 1;
        }
      };
      if (signal?.aborted) settle('aborted');
      else signal?.addEventListener('abort', () => settle('aborted'), { once: true });
      return fetch(input, init).then((response) => {
        settle('finished');
        return response;
      }, (error: unknown) => {
        settle('failed');
        throw error;
      });
    };
  });
}

async function probe(page: Page): Promise<Probe> {
  return page.evaluate(() => {
    const state = (window as Window & { __clusterMetrics?: Probe }).__clusterMetrics;
    if (!state) throw new Error('Cluster fetch probe was not installed');
    return state;
  });
}

async function browserTurns(page: Page, clockPaused = false) {
  const turns = page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
  if (clockPaused) await page.clock.runFor(50);
  await turns;
}

async function json(route: Route, value: unknown, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
}

async function startCluster(page: Page) {
  await page.goto('/?tab=cluster');
  await expect(page.getByRole('button', { name: 'Refresh topology' })).toBeVisible();
  await expect.poll(async () => (await probe(page)).attempts.length).toBe(4);
}

test('unmount aborts the four held metrics fetches without starting queued nodes', async ({ page }) => {
  // This race covers one collector; a wall-clock poll would create a new one.
  await page.clock.install();
  await page.clock.pauseAt(new Date(Date.now() + 60_000));
  await installAetherFlowMocks(page);
  await installMetricsProbe(page);
  const release = deferred();
  const settled: Promise<void>[] = [];
  await page.route('**/api/v1/admin/cluster/nodes', (route) => json(route, { nodes: nodes('old') }));
  await page.route(/\/api\/v1\/admin\/cluster\/nodes\/[^/]+\/metrics$/, async (route) => {
    const done = deferred();
    settled.push(done.promise);
    try {
      await release.promise;
      await json(route, { metrics: { cpu_usage: 11 } }).catch(() => {});
    } finally {
      done.resolve();
    }
  });

  try {
    await startCluster(page);
    const initial = await probe(page);
    expect(initial.attempts.map((attempt) => attempt.id)).toEqual(['shared', 'old-2', 'old-3', 'old-4']);
    expect(initial.attempts.map((attempt) => attempt.outcome)).toEqual(Array(4).fill('pending'));
    expect(initial.attempts.every((attempt) => attempt.signal)).toBe(true);
    await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Services', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
    await browserTurns(page, true);
    const beforeRelease = await probe(page);
    release.resolve();
    await Promise.all(settled);
    await browserTurns(page, true);
    const afterRelease = await probe(page);
    expect.soft(beforeRelease.attempts.map((attempt) => attempt.outcome)).toEqual(Array(4).fill('aborted'));
    expect.soft(beforeRelease.attempts.every((attempt) => attempt.signal)).toBe(true);
    expect.soft(afterRelease.attempts.map((attempt) => attempt.id)).toEqual(['shared', 'old-2', 'old-3', 'old-4']);
    expect.soft(afterRelease.attempts).toEqual(beforeRelease.attempts);
    expect.soft(afterRelease.active).toBe(0);
    expect(afterRelease.maximum).toBe(4);
  } finally {
    release.resolve();
  }
});

for (const refresh of ['button', 'poll'] as const) {
  test(`a newer topology from ${refresh} cancels the old batch and keeps the four-request bound`, async ({ page }) => {
    // Isolate one refresh even when a slow engine crosses the real ten-second
    // interval. The poll case explicitly advances that interval below.
    await page.clock.install();
    await page.clock.pauseAt(new Date(Date.now() + 60_000));
    await installAetherFlowMocks(page);
    await installMetricsProbe(page);
    const oldRelease = deferred();
    const newReleases = new Map(nodes('new').map(({ id }) => [id, deferred()]));
    const settled: Promise<void>[] = [];
    let lists = 0;
    let sharedRequests = 0;
    await page.route('**/api/v1/admin/cluster/nodes', (route) => {
      lists += 1;
      return json(route, { nodes: nodes(lists === 1 ? 'old' : 'new') });
    });
    await page.route(/\/api\/v1\/admin\/cluster\/nodes\/[^/]+\/metrics$/, async (route) => {
      const id = decodeURIComponent(new URL(route.request().url()).pathname.split('/').at(-2)!);
      const old = id.startsWith('old-') || (id === 'shared' && sharedRequests++ === 0);
      const done = deferred();
      settled.push(done.promise);
      try {
        await (old ? oldRelease.promise : newReleases.get(id)!.promise);
        if (old) {
          await json(route, { metrics: { cpu_usage: 11 } }).catch(() => {});
        } else if (id === 'new-6') {
          await json(route, { error: 'Node telemetry offline' }, 503);
        } else {
          await json(route, { metrics: { cpu_usage: 77 } });
        }
      } finally {
        done.resolve();
      }
    });

    try {
      await startCluster(page);
      if (refresh === 'poll') await page.clock.fastForward(10_000);
      else await page.getByRole('button', { name: 'Refresh topology' }).click();
      await expect.poll(async () => (await probe(page)).attempts.length).toBe(8);
      const switched = await probe(page);
      expect(switched.attempts.slice(0, 4).map((attempt) => attempt.outcome)).toEqual(Array(4).fill('aborted'));
      expect(switched.attempts.slice(4).map((attempt) => attempt.outcome)).toEqual(Array(4).fill('pending'));
      expect(switched.attempts.every((attempt) => attempt.signal)).toBe(true);
      expect(switched.maximum).toBe(4);

      newReleases.get('shared')!.resolve();
      await expect.poll(async () => (await probe(page)).attempts.length).toBe(9);
      newReleases.get('new-2')!.resolve();
      await expect.poll(async () => (await probe(page)).attempts.length).toBe(10);
      for (const release of newReleases.values()) release.resolve();
      const grid = page.getByRole('grid', { name: 'Cluster node telemetry' });
      const sharedRow = grid.getByRole('row').filter({ hasText: 'new-shared' });
      await expect(sharedRow).toContainText('77.0%');
      await expect(grid.getByRole('row').filter({ hasText: 'new-new-6' })).toContainText('Not reported');
      await grid.getByRole('row').filter({ hasText: 'new-new-6' }).click();
      await expect(page.getByRole('dialog', { name: 'Worker telemetry & services' })).toContainText('Node telemetry offline');

      oldRelease.resolve();
      await Promise.all(settled);
      await browserTurns(page, true);
      const complete = await probe(page);
      expect(lists).toBe(2);
      expect(complete.attempts).toHaveLength(10);
      expect(complete.attempts.filter((attempt) => attempt.id.startsWith('old-')).map((attempt) => attempt.id))
        .toEqual(['old-2', 'old-3', 'old-4']);
      expect(complete.attempts.slice(4).map((attempt) => attempt.outcome)).toEqual(Array(6).fill('finished'));
      expect(complete.maximum).toBe(4);
      expect(complete.active).toBe(0);
      await expect(sharedRow).toContainText('77.0%');
    } finally {
      oldRelease.resolve();
      for (const release of newReleases.values()) release.resolve();
    }
  });
}

test('an auth epoch change aborts held administrator metrics and never starts queued requests for the next account', async ({ page }) => {
  // As above, keep the intended account transition separate from topology polls.
  await page.clock.install();
  await page.clock.pauseAt(new Date(Date.now() + 60_000));
  await installAetherFlowMocks(page);
  await installMetricsProbe(page);
  const releaseMetrics = deferred();
  const releaseSession = deferred();
  const sessionStarted = deferred();
  const settled: Promise<void>[] = [];
  let switched = false;
  await page.route('**/api/v1/auth/session', async (route) => {
    if (switched) {
      sessionStarted.resolve();
      await releaseSession.promise;
    }
    await json(route, switched
      ? { id: 2, username: 'bob', role: 'user' }
      : { id: 1, username: 'alice', role: 'admin' }).catch(() => {});
  });
  await page.route('**/api/v1/admin/cluster/nodes', (route) => json(route, { nodes: nodes('old') }));
  await page.route(/\/api\/v1\/admin\/cluster\/nodes\/[^/]+\/metrics$/, async (route) => {
    const done = deferred();
    settled.push(done.promise);
    try {
      await releaseMetrics.promise;
      await json(route, { metrics: { cpu_usage: 11 } }).catch(() => {});
    } finally {
      done.resolve();
    }
  });

  try {
    await startCluster(page);
    switched = true;
    await page.evaluate(() => {
      window.dispatchEvent(new StorageEvent('storage', { key: 'af_login_sync', newValue: 'changed-account' }));
    });
    await sessionStarted.promise;
    await browserTurns(page, true);
    const suspended = await probe(page);
    releaseMetrics.resolve();
    await Promise.all(settled);
    await browserTurns(page, true);
    releaseSession.resolve();
    await expect(page.locator('.af-user-badge')).toHaveText('bob');
    await browserTurns(page, true);
    const final = await probe(page);
    expect(suspended.attempts.map((attempt) => attempt.outcome)).toEqual(Array(4).fill('aborted'));
    expect(final.attempts.map((attempt) => attempt.id)).toEqual(['shared', 'old-2', 'old-3', 'old-4']);
    expect(final.active).toBe(0);
    expect(final.maximum).toBe(4);
    await expect(page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Cluster', exact: true })).toHaveCount(0);
  } finally {
    releaseMetrics.resolve();
    releaseSession.resolve();
  }
});


test('unchanged heartbeat and order polls let a slow bounded metrics batch finish, then refresh again', async ({ page }) => {
  test.setTimeout(90_000);
  await page.clock.install();
  await page.clock.pauseAt(new Date(Date.now() + 60_000));
  await installAetherFlowMocks(page);
  await installMetricsProbe(page);
  const gates: ReturnType<typeof deferred>[] = [];
  let lists = 0;
  const records = Array.from({ length: 24 }, (_, index) => ({
    id: `node-${index + 1}`,
    hostname: `node-${index + 1}`,
    address: `192.0.2.${index + 1}`,
    role: 'worker',
    status: 'online',
  }));
  await page.route('**/api/v1/admin/cluster/nodes', route => {
    lists += 1;
    const refreshed = records.map(node => ({ ...node, last_heartbeat: new Date(Date.now() + lists * 1000).toISOString() }));
    return json(route, { nodes: lists > 1 ? refreshed.reverse() : refreshed });
  });
  await page.route(/\/api\/v1\/admin\/cluster\/nodes\/[^/]+\/metrics$/, async route => {
    const gate = deferred();
    gates.push(gate);
    await gate.promise;
    await json(route, {
      hostname: 'old-observation-hostname',
      last_heartbeat: '2000-01-01T00:00:00Z',
      metrics: { cpu_usage: 42 },
    }).catch(() => {});
  });
  const grid = page.getByRole('grid', { name: 'Cluster node telemetry' });
  try {
    await startCluster(page);
    // Each group of four takes two seconds. All 24 requests need twelve
    // seconds, so the unchanged ten-second topology poll occurs mid-batch.
    for (let group = 0; group < 6; group += 1) {
      await page.clock.runFor(2000);
      await browserTurns(page, true);
      const state = await probe(page);
      expect(state.attempts.some(attempt => attempt.outcome === 'aborted')).toBe(false);
      expect(state.attempts.map(attempt => attempt.id)).toEqual(records.slice(0, (group + 1) * 4).map(node => node.id));
      await expect.poll(() => gates.length).toBe(state.attempts.length);
      gates.slice(-4).forEach(gate => gate.resolve());
      if (group < 5) {
        await expect.poll(async () => (await probe(page)).attempts.length).toBe((group + 2) * 4);
      }
      await browserTurns(page, true);
    }
    expect(lists).toBeGreaterThanOrEqual(2);
    await expect(page.getByText('Telemetry available for 24 / 24 nodes. Totals include reporting nodes only.', { exact: true })).toBeVisible();
    await expect(grid.getByText('42.0%', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('old-observation-hostname', { exact: true })).toHaveCount(0);
    await expect(grid.getByRole('row').filter({ hasText: 'node-24' })).toBeVisible();
    const completed = await probe(page);
    expect(completed.attempts).toHaveLength(24);
    expect(completed.attempts.map(attempt => attempt.outcome)).toEqual(Array(24).fill('finished'));
    expect(completed.active).toBe(0);
    expect(completed.maximum).toBe(4);

    // Coalescing an in-flight batch must not suppress later metric refreshes.
    await page.clock.fastForward(10_000);
    await expect.poll(async () => (await probe(page)).attempts.length).toBe(28);
    const refreshed = await probe(page);
    expect(refreshed.attempts.slice(24).map(attempt => attempt.id)).toEqual(records.slice().reverse().slice(0, 4).map(node => node.id));
    expect(refreshed.maximum).toBe(4);
    await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Services', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
    await browserTurns(page, true);
    const disposed = await probe(page);
    expect(disposed.attempts).toHaveLength(28);
    expect(disposed.attempts.slice(24).map(attempt => attempt.outcome)).toEqual(Array(4).fill('aborted'));
    expect(disposed.active).toBe(0);
  } finally {
    gates.forEach(gate => gate.resolve());
  }
});
