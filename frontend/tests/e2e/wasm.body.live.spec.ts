import { createServer, request as httpRequest, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import type { Socket } from 'node:net';
import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type BodyWindow = Window & {
  archiveBodyStarted?: boolean;
  archiveDownloads?: number;
};

const exportPath = '/api/v1/admin/streaming/portability/export';

// Serve the export directly on the app's test origin, forwarding other traffic
// to the isolated API. The response is a real stream with a held tail, not a
// Playwright response (or a redirect, which has different abort behavior).
async function streamedArchive(baseURL: string, archive: string) {
  const upstream = new URL(baseURL);
  if (upstream.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(upstream.hostname)) {
    throw new Error('The embedded test server must be on loopback HTTP');
  }
  const bytes = Buffer.from(archive);
  const prefix = bytes.subarray(0, Math.floor(bytes.length / 2));
  const tail = bytes.subarray(prefix.length);
  const sockets = new Set<Socket>();
  let response: ServerResponse | undefined;
  let requests = 0;
  let closedBeforeTail = false;
  let tailReleased = false;
  let prefixFlushed = false;
  const server = createServer((request, reply) => {
    if (request.url === exportPath) {
      if (request.method !== 'GET' || response) {
        reply.writeHead(404).end();
        return;
      }
      requests++;
      response = reply;
      reply.on('close', () => {
        if (!tailReleased) closedBeforeTail = true;
      });
      reply.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json',
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
  test(`streaming archive body ${transition === 'none' ? 'completes' : `aborts on ${transition} change`}`, async ({ page, baseURL }) => {
    if (!baseURL) throw new Error('The embedded test server URL is required');
    const archive = JSON.stringify({ manifest: { format: 'aetherflow.streaming-history' }, data: { private_history: ['synthetic-playback'] } });
    const fixture = await streamedArchive(baseURL, archive);
    const pageErrors: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    try {
      await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
      let identity = 1;
      await page.route('**/api/v1/auth/session', route => route.fulfill({ json: {
        id: identity, username: identity === 1 ? 'alice' : 'bob', role: 'admin', is_oauth: false,
      } }));
      await page.route('**/api/v1/auth/streaming/**', route => route.fulfill({ json: {} }));
      await page.route(url => url.pathname.startsWith('/api/v1/admin/streaming/') && url.pathname !== exportPath,
        route => route.fulfill({ json: {} }));
      await page.addInitScript(() => {
        const target = window as BodyWindow;
        target.archiveDownloads = 0;
        const click = HTMLElement.prototype.click;
        HTMLElement.prototype.click = function () {
          if (this instanceof HTMLAnchorElement && this.download === 'aetherflow-streaming-archive.json') target.archiveDownloads!++;
          click.call(this);
        };
        const blob = Response.prototype.blob;
        Response.prototype.blob = function () {
          if (this.url.endsWith('/api/v1/admin/streaming/portability/export')) target.archiveBodyStarted = true;
          return blob.call(this);
        };
      });
      await page.goto(`${fixture.origin}/?tab=streaming`);
      const administration = page.getByRole('tab', { name: 'History administration', exact: true });
      await administration.click();
      await page.locator('summary').filter({ hasText: /^Portable archive export \/ restore$/ }).click();
      const exportButton = page.getByRole('button', { name: 'Export native JSON archive', exact: true });
      await exportButton.click();
      await expect.poll(() => fixture.requests()).toBe(1);
      await expect.poll(() => fixture.prefixFlushed()).toBe(true);
      await expect.poll(() => page.evaluate(() => (window as BodyWindow).archiveBodyStarted)).toBe(true);
      expect(fixture.closedBeforeTail()).toBe(false);

      if (transition === 'subtab') {
        await page.getByRole('tab', { name: 'Active playback sessions', exact: true }).click();
        await expect(exportButton).toHaveCount(0);
      } else if (transition === 'tab') {
        await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
        await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
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
        expect(result.suggestedFilename()).toBe('aetherflow-streaming-archive.json');
        const path = await result.path();
        expect(path).not.toBeNull();
        const downloaded = await readFile(path!);
        expect(downloaded).toEqual(Buffer.from(archive));
        expect(JSON.parse(downloaded.toString('utf8'))).toEqual(JSON.parse(archive));
        expect(fixture.closedBeforeTail()).toBe(false);
        await expect(exportButton).toBeEnabled();
      } else {
        // This is the server observing the live response connection close while
        // its declared body is still incomplete, not a delayed Blob callback.
        await expect.poll(() => fixture.closedBeforeTail()).toBe(true);
      }
      expect(await page.evaluate(() => (window as BodyWindow).archiveDownloads)).toBe(transition === 'none' ? 1 : 0);
      expect(pageErrors).toEqual([]);
    } finally {
      await fixture.dispose();
    }
  });
}
