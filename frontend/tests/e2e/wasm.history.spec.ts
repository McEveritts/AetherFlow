import { readFile } from 'node:fs/promises';
import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

function gate() {
  return { started: deferred(), release: deferred(), finished: deferred() };
}

const json = (route: Route, value: unknown, status = 200) => route.fulfill({
  status, contentType: 'application/json', body: JSON.stringify(value),
});

async function historyFixture(page: Page, sameSnapshot = false) {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const queries: Array<{ params: URLSearchParams; snapshot: string }> = [];
  let sequence = 0;
  let nextHistoryGate: ReturnType<typeof gate> | undefined;
  await page.route('**/api/v1/auth/streaming/history?*', async route => {
    const params = new URL(route.request().url()).searchParams;
    const provider = (params.get('provider') ?? 'all').toLowerCase();
    const media = (params.get('mediaType') ?? 'all').toLowerCase();
    // Match the packaged API's filter contract instead of accepting arbitrary values.
    if (!['all', 'jellyfin', 'emby'].includes(provider)
      || !['all', 'movie', 'episode', 'audio', 'video', 'unknown'].includes(media)) {
      return json(route, { message: 'invalid_history_query' }, 400);
    }
    const number = ++sequence;
    const snapshot = sameSnapshot ? 'snapshot-shared' : `snapshot-${number}`;
    queries.push({ params, snapshot });
    const held = nextHistoryGate;
    nextHistoryGate = undefined;
    if (held) {
      held.started.resolve();
      await held.release.promise;
    }
    try {
      await json(route, {
        scope: { snapshotToken: snapshot, asOf: '2026-11-17T00:00:00Z', expiresAt: '2026-11-18T00:00:00Z' },
        counts: { matchingRecords: 2, availableRecords: 2, confirmedPlays: 2, watchTimeSecs: 7200, undatedRecords: 0 },
        items: [{ id: number, provider: 'jellyfin', serverId: 'server-a', userId: 'user-a', userName: 'Viewer', itemId: 'item-a', itemName: `History record ${number}` }],
        nextCursor: `cursor-${number}`,
      });
    } finally {
      held?.finished.resolve();
    }
  });
  await page.route(/\/api\/v1\/auth\/streaming\/(patterns|drilldown)\?.*/, route => {
    if (new URL(route.request().url()).pathname.endsWith('/patterns')) {
      return json(route, { activity: { timeseries: [] }, concurrency: { buckets: [] } });
    }
    return json(route, { cohortDistinctPlays: 2, cohortDistinctUsers: 1, cohortDistinctItems: 2 });
  });
  return {
    queries,
    holdNextHistory: () => {
      nextHistoryGate = gate();
      return nextHistoryGate;
    },
  };
}

async function openHistory(page: Page) {
  await page.goto('/?tab=streaming');
  await page.getByRole('tab', { name: 'Canonical playback history' }).click();
  await expect(historyGrid(page).getByText('History record 1', { exact: true })).toBeVisible();
}

function historyGrid(page: Page) {
  return page.getByRole('grid', { name: 'Canonical playback history; worker-backed page search', exact: true });
}

function csvButton(page: Page) {
  return page.getByRole('button', { name: 'Export CSV · all matches' });
}

async function settleBrowserTasks(page: Page) {
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}

for (const [transition, status] of [
  ['new filter', 409],
  ['new snapshot', 409],
  ['filter still loading', 409],
  ['new filter', 503],
] as const) {
  test(`ignores a held export ${status === 409 ? 'conflict' : 'error'} after ${transition}`, async ({ page }) => {
    // Reuse the token for a refresh to verify that revision also matters.
    const fixture = await historyFixture(page, transition === 'new snapshot');
    const heldExport = gate();
    const exportQueries: URLSearchParams[] = [];
    await page.route('**/api/v1/auth/streaming/history/export?*', async route => {
      exportQueries.push(new URL(route.request().url()).searchParams);
      heldExport.started.resolve();
      await heldExport.release.promise;
      try {
        await json(route, { message: 'export failed' }, status);
      } finally {
        heldExport.finished.resolve();
      }
    });
    await openHistory(page);
    await csvButton(page).click();
    await heldExport.started.promise;
    const heldHistory = transition === 'filter still loading' ? fixture.holdNextHistory() : undefined;
    try {
      if (transition === 'new snapshot') {
        await page.getByRole('button', { name: 'New snapshot' }).click();
      } else {
        await page.getByLabel('Server provider').selectOption('emby');
      }
      if (heldHistory) {
        await heldHistory.started.promise;
        await expect(page.getByText('Loading history snapshot…')).toBeVisible();
      } else {
        await expect(historyGrid(page).getByText('History record 2', { exact: true })).toBeVisible();
      }
      expect(exportQueries[0].get('snapshot')).toBe(fixture.queries[0].snapshot);
      if (transition === 'new snapshot') {
        expect(fixture.queries[1].snapshot).toBe(fixture.queries[0].snapshot);
      }
      const exportResponse = page.waitForResponse(response =>
        response.url().includes('/streaming/history/export?') && response.status() === status,
      );
      heldExport.release.resolve();
      await heldExport.finished.promise;
      await exportResponse;
      if (heldHistory) {
        // Let the conflict be handled while the newer query has no committed page.
        await settleBrowserTasks(page);
        heldHistory.release.resolve();
        await heldHistory.finished.promise;
      }
      await expect(historyGrid(page).getByText('History record 2', { exact: true })).toBeVisible();
      await expect(csvButton(page)).toBeEnabled();
      await expect(page.getByRole('button', { name: 'Next', exact: true })).toBeEnabled();
      await expect(page.getByText('History snapshot expired or changed. Restart from page one before exporting.')).toHaveCount(0);
      await expect(page.getByText('CSV export failed (HTTP 503).')).toHaveCount(0);
      await expect(page.getByRole('alert').filter({ hasText: 'Analytics snapshot expired or changed' })).toHaveCount(0);
    } finally {
      heldExport.release.resolve();
      heldHistory?.release.resolve();
    }
  });
}

test('invalidates a current export conflict and recovers for CSV and JSON downloads', async ({ page }) => {
  const fixture = await historyFixture(page);
  const exports: URLSearchParams[] = [];
  const csv = 'title,viewer\r\nA,Viewer\r\n';
  await page.route('**/api/v1/auth/streaming/history/export?*', async route => {
    exports.push(new URL(route.request().url()).searchParams);
    expect(route.request().headers().accept).toContain('text/csv');
    if (exports.length === 1) return json(route, { message: 'snapshot expired' }, 409);
    return route.fulfill({ status: 200, contentType: 'text/csv', body: csv });
  });
  await openHistory(page);
  await csvButton(page).click();
  await expect(page.getByText('History snapshot expired or changed. Restart from page one before exporting.')).toBeVisible();
  await expect(page.getByRole('alert').filter({ hasText: 'Analytics snapshot expired or changed' })).toBeVisible();
  await expect(csvButton(page)).toBeDisabled();
  await expect(historyGrid(page).getByText('History record 1', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Restart history snapshot' }).click();
  await expect(historyGrid(page).getByText('History record 2', { exact: true })).toBeVisible();
  await expect(csvButton(page)).toBeEnabled();

  const [csvDownload] = await Promise.all([page.waitForEvent('download'), csvButton(page).click()]);
  expect(csvDownload.suggestedFilename()).toBe('aetherflow-streaming-history.csv');
  expect(await readFile(await csvDownload.path(), 'utf8')).toBe(csv);
  expect(exports.map(params => params.get('snapshot'))).toEqual(fixture.queries.slice(0, 2).map(q => q.snapshot));
  await expect(csvButton(page)).toBeEnabled();
  const [jsonDownload] = await Promise.all([
    page.waitForEvent('download'), page.getByRole('button', { name: 'Export JSON · this page' }).click(),
  ]);
  expect(jsonDownload.suggestedFilename()).toBe('aetherflow-history-page.json');
  const rows = JSON.parse(await readFile(await jsonDownload.path(), 'utf8')) as Array<{ itemName: string }>;
  expect(rows.some(row => row.itemName === 'History record 2')).toBe(true);
  await expect(csvButton(page)).toBeEnabled();
});

test('downloads the requested CSV if its valid response arrives after a filter change', async ({ page }) => {
  const fixture = await historyFixture(page);
  const held = gate();
  let exportedSnapshot = '';
  await page.route('**/api/v1/auth/streaming/history/export?*', async route => {
    exportedSnapshot = new URL(route.request().url()).searchParams.get('snapshot') ?? '';
    held.started.resolve();
    await held.release.promise;
    try {
      await route.fulfill({ status: 200, contentType: 'text/csv', body: 'title\nOriginal snapshot\n' });
    } finally {
      held.finished.resolve();
    }
  });
  await openHistory(page);
  await csvButton(page).click();
  await held.started.promise;
  try {
    await page.getByLabel('Server provider').selectOption('emby');
    await expect(historyGrid(page).getByText('History record 2', { exact: true })).toBeVisible();
    const downloadPromise = page.waitForEvent('download');
    held.release.resolve();
    const download = await downloadPromise;
    expect(await readFile(await download.path(), 'utf8')).toBe('title\nOriginal snapshot\n');
    expect(exportedSnapshot).toBe(fixture.queries[0].snapshot);
    await expect(historyGrid(page).getByText('History record 2', { exact: true })).toBeVisible();
    await expect(csvButton(page)).toBeEnabled();
  } finally {
    held.release.resolve();
  }
});

test('offers only history filters accepted by the packaged API', async ({ page }) => {
  const fixture = await historyFixture(page);
  await openHistory(page);
  const provider = page.getByLabel('Server provider');
  const media = page.getByLabel('Media type');
  expect(await provider.locator('option').evaluateAll(options => options.map(option => (option as HTMLOptionElement).value))).toEqual(['', 'jellyfin', 'emby']);
  expect(await media.locator('option').evaluateAll(options => options.map(option => (option as HTMLOptionElement).value))).toEqual(['', 'Movie', 'Episode', 'Audio', 'Video', 'Unknown']);
  for (const value of ['jellyfin', 'emby', '']) {
    const previous = fixture.queries.length;
    await provider.selectOption(value);
    await expect.poll(() => fixture.queries.length).toBeGreaterThan(previous);
    expect(fixture.queries.at(-1)?.params.get('provider') ?? '').toBe(value);
    await expect(historyGrid(page).getByText(`History record ${fixture.queries.length}`, { exact: true })).toBeVisible();
    await expect(csvButton(page)).toBeEnabled();
  }
  for (const value of ['Movie', 'Episode', 'Audio', 'Video', 'Unknown', '']) {
    const previous = fixture.queries.length;
    await media.selectOption(value);
    await expect.poll(() => fixture.queries.length).toBeGreaterThan(previous);
    expect(fixture.queries.at(-1)?.params.get('mediaType') ?? '').toBe(value);
    await expect(historyGrid(page).getByText(`History record ${fixture.queries.length}`, { exact: true })).toBeVisible();
    await expect(csvButton(page)).toBeEnabled();
  }
  await expect(page.getByText('invalid_history_query')).toHaveCount(0);
});

test('does not download a held CSV blob after the session changes', async ({ page }) => {
  const fixture = await historyFixture(page);
  let identity = 1;
  let sessionReads = 0;
  await page.route('**/api/v1/auth/session', route => {
    sessionReads++;
    return json(route, { id: identity, username: identity === 1 ? 'alice' : 'bob', role: 'admin' });
  });
  await page.route('**/api/v1/auth/streaming/history/export?*', route => route.fulfill({
    status: 200, contentType: 'text/csv', body: 'title\nAlice private data\n',
  }));
  await page.addInitScript(() => {
    const target = window as Window & {
      releaseHistoryBlob?: () => void;
      historyBlobResolved?: boolean;
      historyDownloads?: number;
    };
    target.historyDownloads = 0;
    const click = HTMLElement.prototype.click;
    HTMLElement.prototype.click = function () {
      if (this instanceof HTMLAnchorElement && this.hasAttribute('download')) target.historyDownloads!++;
      click.call(this);
    };
    const blob = Response.prototype.blob;
    Response.prototype.blob = function () {
      if (!this.url.includes('/streaming/history/export?')) return blob.call(this);
      // Finish the real body read before holding delivery. The live body suite
      // covers aborting an incomplete transfer; this case keeps exercising the
      // ownership check for data already buffered before an account change.
      return blob.call(this).then(value => new Promise<Blob>(resolve => {
          target.releaseHistoryBlob = () => {
            resolve(value);
            target.historyBlobResolved = true;
          };
      }));
    };
  });
  await openHistory(page);
  await csvButton(page).click();
  await expect.poll(() => page.evaluate(() => typeof (window as Window & { releaseHistoryBlob?: () => void }).releaseHistoryBlob)).toBe('function');
  const previousReads = sessionReads;
  const previousQueries = fixture.queries.length;
  identity = 2;
  await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', { key: 'af_login_sync' })));
  await expect.poll(() => sessionReads).toBeGreaterThan(previousReads);
  await page.getByRole('tab', { name: 'Canonical playback history' }).click();
  await expect.poll(() => fixture.queries.length).toBeGreaterThan(previousQueries);
  await expect(csvButton(page)).toBeEnabled();
  await page.evaluate(() => (window as Window & { releaseHistoryBlob?: () => void }).releaseHistoryBlob!());
  await expect.poll(() => page.evaluate(() => (window as Window & { historyBlobResolved?: boolean }).historyBlobResolved)).toBe(true);
  await settleBrowserTasks(page);
  expect(await page.evaluate(() => (window as Window & { historyDownloads?: number }).historyDownloads)).toBe(0);
  await expect(csvButton(page)).toBeEnabled();
  await expect(page.getByText('History snapshot expired or changed. Restart from page one before exporting.')).toHaveCount(0);
});

test('does not download a held JSON worker result after leaving history', async ({ page }) => {
  await historyFixture(page);
  await page.addInitScript(() => {
    const target = window as Window & {
      releaseHistoryWorker?: () => void;
      historyWorkerDone?: boolean;
      historyDownloads?: number;
    };
    target.historyDownloads = 0;
    const click = HTMLElement.prototype.click;
    HTMLElement.prototype.click = function () {
      if (this instanceof HTMLAnchorElement && this.hasAttribute('download')) target.historyDownloads!++;
      click.call(this);
    };
    window.Worker = class extends Worker {
      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        const post = this.postMessage.bind(this);
        Object.defineProperty(this, 'postMessage', {
          value: (message: { id?: number; message?: { type?: string } }, transfer?: Transferable[]) => {
            const send = () => transfer ? post(message, transfer) : post(message);
            if (message.message?.type !== 'BuildExportPayload') return send();
            this.addEventListener('message', event => {
              if (event.data.id === message.id) target.historyWorkerDone = true;
            });
            target.releaseHistoryWorker = send;
          },
        });
      }
    };
  });
  await openHistory(page);
  await page.getByRole('button', { name: 'Export JSON · this page' }).click();
  await expect.poll(() => page.evaluate(() => typeof (window as Window & { releaseHistoryWorker?: () => void }).releaseHistoryWorker)).toBe('function');
  await page.getByRole('tab', { name: 'Active playback sessions' }).click();
  await expect(csvButton(page)).toHaveCount(0);
  await page.evaluate(() => (window as Window & { releaseHistoryWorker?: () => void }).releaseHistoryWorker!());
  await expect.poll(() => page.evaluate(() => (window as Window & { historyWorkerDone?: boolean }).historyWorkerDone)).toBe(true);
  await settleBrowserTasks(page);
  expect(await page.evaluate(() => (window as Window & { historyDownloads?: number }).historyDownloads)).toBe(0);
  await page.getByRole('tab', { name: 'Canonical playback history' }).click();
  await expect(csvButton(page)).toBeEnabled();
});
