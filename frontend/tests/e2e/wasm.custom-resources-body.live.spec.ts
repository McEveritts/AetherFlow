import { createServer, request as httpRequest, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import type { Socket } from 'node:net';
import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type CsvWindow = Window & {
  csvBodyStarted?: boolean;
  csvSignalObserved?: boolean;
  csvAborted?: boolean;
  csvDownloads?: number;
};

const exportPath = '/api/v1/auth/streaming/history/export';

// A real same-origin response sends headers and a prefix but holds the body
// tail. This observes connection closure during blob(), not just a delayed
// Promise or a Playwright-fulfilled, already-buffered response.
async function streamedCsv(baseURL: string, csv: string) {
  const upstream = new URL(baseURL);
  if (upstream.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(upstream.hostname)) {
    throw new Error('The embedded test server must be on loopback HTTP');
  }
  const bytes = Buffer.from(csv);
  const prefix = bytes.subarray(0, Math.floor(bytes.length / 2));
  const tail = bytes.subarray(prefix.length);
  const sockets = new Set<Socket>();
  let response: ServerResponse | undefined;
  let requests = 0;
  let closedBeforeTail = false;
  let tailReleased = false;
  let prefixFlushed = false;
  const server = createServer((request, reply) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    if (url.pathname === exportPath) {
      if (request.method !== 'GET' || response || !url.searchParams.get('snapshot')) {
        reply.writeHead(404).end();
        return;
      }
      requests += 1;
      response = reply;
      reply.on('close', () => { if (!tailReleased) closedBeforeTail = true; });
      reply.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Type': 'text/csv',
        'Content-Length': bytes.length,
      });
      reply.write(prefix, () => { prefixFlushed = true; });
      return;
    }
    if (!request.url?.startsWith('/') || request.url.startsWith('//')) {
      reply.writeHead(400).end();
      return;
    }
    const forwarded = httpRequest({
      hostname: upstream.hostname,
      port: upstream.port,
      method: request.method,
      path: request.url,
      headers: { ...request.headers, host: upstream.host },
      agent: false,
    }, upstreamReply => {
      reply.writeHead(upstreamReply.statusCode ?? 502, upstreamReply.headers);
      upstreamReply.pipe(reply);
    });
    forwarded.on('error', () => {
      if (reply.headersSent) reply.destroy();
      else reply.writeHead(502).end();
    });
    reply.on('close', () => { if (!reply.writableFinished) forwarded.destroy(); });
    request.pipe(forwarded);
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing fixture address');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requests: () => requests,
    closedBeforeTail: () => closedBeforeTail,
    prefixFlushed: () => prefixFlushed,
    release: () => {
      if (!response || response.destroyed || tailReleased) throw new Error('Stream is not open');
      tailReleased = true;
      response.end(tail);
    },
    dispose: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    },
  };
}

for (const transition of ['subtab', 'tab', 'account', 'none'] as const) {
  test(`streamed history CSV ${transition === 'none' ? 'completes' : `aborts on ${transition} change`}`, async ({ page, baseURL }) => {
    if (!baseURL) throw new Error('The embedded test server URL is required');
    const csv = 'title,provider\nSynthetic title,jellyfin\n';
    const fixture = await streamedCsv(baseURL, csv);
    const pageErrors: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    try {
      await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
      let identity = 1;
      await page.route('**/api/v1/auth/session', route => route.fulfill({ json: {
        id: identity, username: identity === 1 ? 'alice' : 'bob', role: 'admin', is_oauth: false,
      } }));
      await page.route(url => url.pathname.startsWith('/api/v1/auth/streaming/') && url.pathname !== exportPath,
        route => route.fulfill({ json: new URL(route.request().url()).pathname === '/api/v1/auth/streaming/history'
          ? {
              scope: { snapshotToken: 'snapshot-csv', asOf: '2026-11-17T00:00:00Z', expiresAt: '2026-11-18T00:00:00Z' },
              counts: { matchingRecords: 1, availableRecords: 1, confirmedPlays: 1, watchTimeSecs: 60, undatedRecords: 0 },
              items: [{ id: 1, provider: 'jellyfin', itemName: 'Synthetic title' }], nextCursor: '',
            }
          : {} }));
      await page.addInitScript(() => {
        const target = window as CsvWindow;
        target.csvDownloads = 0;
        const originalFetch = window.fetch.bind(window);
        window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(input instanceof Request ? input.url : String(input), location.href);
          if (url.pathname === '/api/v1/auth/streaming/history/export') {
            const signal = init?.signal;
            target.csvSignalObserved = Boolean(signal);
            if (signal?.aborted) target.csvAborted = true;
            else signal?.addEventListener('abort', () => { target.csvAborted = true; }, { once: true });
          }
          return originalFetch(input, init);
        };
        const blob = Response.prototype.blob;
        Response.prototype.blob = function () {
          if (this.url.includes('/api/v1/auth/streaming/history/export?')) target.csvBodyStarted = true;
          return blob.call(this);
        };
        const click = HTMLElement.prototype.click;
        HTMLElement.prototype.click = function () {
          if (this instanceof HTMLAnchorElement && this.download === 'aetherflow-streaming-history.csv') target.csvDownloads!++;
          click.call(this);
        };
      });
      await page.goto(`${fixture.origin}/?tab=streaming`);
      await page.getByRole('tab', { name: 'Canonical playback history', exact: true }).click();
      const exportButton = page.getByRole('button', { name: 'Export CSV · all matches', exact: true });
      await expect(exportButton).toBeEnabled();
      await exportButton.click();
      await expect.poll(() => fixture.requests()).toBe(1);
      await expect.poll(() => fixture.prefixFlushed()).toBe(true);
      await expect.poll(() => page.evaluate(() => (window as CsvWindow).csvBodyStarted)).toBe(true);
      expect(await page.evaluate(() => (window as CsvWindow).csvSignalObserved)).toBe(true);
      expect(fixture.closedBeforeTail()).toBe(false);

      if (transition === 'subtab') {
        await page.getByRole('tab', { name: 'Active playback sessions', exact: true }).click();
        await expect(exportButton).toHaveCount(0);
      } else if (transition === 'tab') {
        await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Overview', exact: true }).click();
        await expect(exportButton).toHaveCount(0);
      } else if (transition === 'account') {
        identity = 2;
        await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', { key: 'af_login_sync' })));
        await expect(exportButton).toHaveCount(0);
        await expect(page.getByText('bob', { exact: true }).first()).toBeVisible();
      }
      if (transition === 'none') {
        const download = page.waitForEvent('download');
        fixture.release();
        const result = await download;
        expect(result.suggestedFilename()).toBe('aetherflow-streaming-history.csv');
        const path = await result.path();
        expect(path).not.toBeNull();
        expect(await readFile(path!)).toEqual(Buffer.from(csv));
        expect(fixture.closedBeforeTail()).toBe(false);
        expect(await page.evaluate(() => Boolean((window as CsvWindow).csvAborted))).toBe(false);
        await expect(exportButton).toBeEnabled();
      } else {
        await expect.poll(() => page.evaluate(() => (window as CsvWindow).csvAborted)).toBe(true);
        await expect.poll(() => fixture.closedBeforeTail()).toBe(true);
      }
      expect(await page.evaluate(() => (window as CsvWindow).csvDownloads)).toBe(transition === 'none' ? 1 : 0);
      expect(pageErrors).toEqual([]);
    } finally {
      await fixture.dispose();
    }
  });
}
