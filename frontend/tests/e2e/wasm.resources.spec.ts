import { expect, test, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type Attempt = { url: string; outcome: 'pending' | 'aborted' | 'finished' | 'failed' };
type ReadProbe = { attempts: Attempt[]; active: number; maximum: number };

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

async function trackReads(page: Page, path: string) {
  await page.addInitScript((path) => {
    const state: ReadProbe = { attempts: [], active: 0, maximum: 0 };
    (window as Window & { __resourceReads?: ReadProbe }).__resourceReads = state;
    const fetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input), location.href);
      if (url.pathname !== path) return fetch(input, init);
      const attempt: Attempt = { url: url.pathname + url.search, outcome: 'pending' };
      state.attempts.push(attempt);
      state.active += 1;
      state.maximum = Math.max(state.maximum, state.active);
      const settle = (outcome: Attempt['outcome']) => {
        if (attempt.outcome !== 'pending') return;
        attempt.outcome = outcome;
        state.active -= 1;
      };
      const signal = init?.signal;
      if (signal?.aborted) settle('aborted');
      else signal?.addEventListener('abort', () => settle('aborted'), { once: true });
      return fetch(input, init).then(response => {
        settle('finished');
        return response;
      }, (error: unknown) => {
        settle('failed');
        throw error;
      });
    };
  }, path);
}

async function reads(page: Page): Promise<ReadProbe> {
  return page.evaluate(() => {
    const state = (window as Window & { __resourceReads?: ReadProbe }).__resourceReads;
    if (!state) throw new Error('Resource read probe not installed');
    return state;
  });
}

test('repeated same-account tab disposal aborts generic reads instead of accumulating obsolete fetches', async ({ page }) => {
  await installAetherFlowMocks(page);
  await trackReads(page, '/api/v1/auth/system/hardware');
  const release = deferred();
  await page.route('**/api/v1/auth/system/hardware', async route => {
    await release.promise;
    await route.fulfill({ json: { cpu: { model: 'Held processor' } } }).catch(() => {});
  });
  try {
    await page.goto('/?tab=overview');
    for (let visit = 0; visit < 4; visit += 1) {
      await expect.poll(async () => (await reads(page)).attempts.length).toBe(visit + 1);
      await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Services', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
      await expect.poll(async () => (await reads(page)).active).toBe(0);
      const disposed = await reads(page);
      expect(disposed.attempts.map(attempt => attempt.outcome)).toEqual(Array(visit + 1).fill('aborted'));
      expect(disposed.maximum).toBe(1);
      if (visit < 3) await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Overview', exact: true }).click();
    }
  } finally {
    release.resolve();
  }
});

test('a superseded notifications read aborts before its explicit refresh starts', async ({ page }) => {
  await installAetherFlowMocks(page);
  await trackReads(page, '/api/v1/admin/notifications/rules');
  const release = deferred();
  let sequence = 0;
  await page.route('**/api/v1/admin/notifications/rules', async route => {
    const number = sequence++;
    if (number === 0) await release.promise;
    await route.fulfill({ json: { rules: [{
      id: 42, name: number === 0 ? 'Obsolete rule' : 'Current rule', condition_type: 'cpu_usage',
      condition_value: '75', level: 'warning', enabled: true,
    }] } }).catch(() => {});
  });
  try {
    await page.goto('/?tab=notifications');
    await expect.poll(async () => (await reads(page)).attempts.length).toBe(1);
    await page.getByRole('button', { name: 'Refresh notifications', exact: true }).click();
    await expect.poll(async () => (await reads(page)).attempts.length).toBe(2);
    const state = await reads(page);
    expect(state.attempts[0].outcome).toBe('aborted');
    expect(state.maximum).toBe(1);
    const grid = page.getByRole('grid', { name: 'Notification alert rules', exact: true });
    await expect(grid.getByText('Current rule', { exact: true })).toBeVisible();
    release.resolve();
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await expect(grid.getByText('Obsolete rule', { exact: true })).toHaveCount(0);
    await expect(grid.getByText('Current rule', { exact: true })).toBeVisible();
  } finally {
    release.resolve();
  }
});

test('changing a generic resource path aborts the previous telemetry window read', async ({ page }) => {
  await installAetherFlowMocks(page);
  await trackReads(page, '/api/v1/auth/system/metrics/history');
  const release = deferred();
  await page.route('**/api/v1/auth/system/metrics/history?**', async route => {
    await release.promise;
    await route.fulfill({ json: { points: [] } }).catch(() => {});
  });
  try {
    await page.goto('/?tab=overview');
    await expect.poll(async () => (await reads(page)).attempts.length).toBe(1);
    await page.getByTestId('history-window-1h').click();
    await expect.poll(async () => (await reads(page)).attempts.length).toBe(2);
    let state = await reads(page);
    expect(state.attempts[0].outcome).toBe('aborted');
    expect(state.attempts[1].url).toContain('window=1h');
    await page.getByTestId('history-window-24h').click();
    await expect.poll(async () => (await reads(page)).attempts.length).toBe(3);
    state = await reads(page);
    expect(state.attempts.slice(0, 2).map(attempt => attempt.outcome)).toEqual(['aborted', 'aborted']);
    expect(state.attempts[2].url).toContain('window=24h');
    expect(state.maximum).toBe(1);
    release.resolve();
    await expect.poll(async () => (await reads(page)).active).toBe(0);
    expect((await reads(page)).attempts[2].outcome).toBe('finished');
  } finally {
    release.resolve();
  }
});
