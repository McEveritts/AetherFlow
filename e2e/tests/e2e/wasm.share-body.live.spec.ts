import { createHash } from 'node:crypto';
import { createServer, request as httpRequest, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { crc32, deflateSync } from 'node:zlib';
import { expect, test as base, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const token = 'share-body-fixture';
const otherToken = 'share-body-other-fixture';
const sharesPath = '/api/v1/public/mcbrowser/shares';
const downloadPath = `${sharesPath}/${token}/download`;
const mediaLimit = 20 * 1024 * 1024;
const textLimit = 1024 * 1024;

type BodyProbe = {
  bodies: Map<string, {
    consumer: 'reader' | 'blob' | 'text';
    contentLength: string | null;
    stream?: ReadableStream<Uint8Array>;
  }>;
  signals: Map<string, AbortSignal>;
  created: { url: string; blob: Blob }[];
  revoked: string[];
};
type ShareWindow = typeof window & {
  shareBodyProbe: BodyProbe;
  shareBodyOpened: (path: string) => Promise<void>;
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

async function observed<T>(event: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      event,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 8000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function pngChunk(type: string, data: Buffer): Buffer {
  const chunk = Buffer.alloc(data.length + 12);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(chunk.subarray(4, -4)), chunk.length - 4);
  return chunk;
}

function pngBytes(size?: number): Buffer {
  const header = Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]); // 1x1 RGBA
  const chunks = [
    Buffer.from('89504e470d0a1a0a', 'hex'),
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(Buffer.from([0, 0x27, 0xa3, 0xcd, 0xff]))),
  ];
  const end = pngChunk('IEND', Buffer.alloc(0));
  if (size !== undefined) {
    const used = chunks.reduce((sum, chunk) => sum + chunk.length, end.length);
    // An ancillary private chunk allows precise byte counts with a valid PNG.
    chunks.push(pngChunk('paDd', Buffer.alloc(size - used - 12)));
  }
  return Buffer.concat([...chunks, end]);
}

type CloseObservation = { written: number; tailReleased: boolean; finished: boolean };

function heldBody(bytes: Buffer, prefixLength: number, declaredLength?: number) {
  const opened = deferred<void>();
  const closed = deferred<CloseObservation>();
  let response: ServerResponse | undefined;
  let written = 0;
  let prefixFlushed = false;
  let tailReleased = false;
  let close: CloseObservation | undefined;
  return {
    opened,
    closed,
    send(reply: ServerResponse) {
      if (response) {
        reply.writeHead(409).end();
        return;
      }
      response = reply;
      reply.once('close', () => {
        close = { written, tailReleased, finished: reply.writableFinished };
        closed.resolve(close);
      });
      // Match the generic attachment MIME used by canonical share downloads.
      reply.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/octet-stream',
        ...(declaredLength === undefined ? { 'Transfer-Encoding': 'chunked' } : { 'Content-Length': declaredLength }),
      });
      written = prefixLength;
      reply.write(bytes.subarray(0, prefixLength), (error?: Error | null) => {
        prefixFlushed = !error;
      });
    },
    state() {
      return {
        declaredLength: declaredLength ?? null,
        plannedBytes: bytes.length,
        written,
        prefixFlushed,
        tailReleased,
        open: Boolean(response && !response.destroyed && !response.writableFinished && !close),
        close: close ?? null,
      };
    },
    release() {
      if (!response || response.destroyed || tailReleased) throw new Error('Stream is not open');
      tailReleased = true;
      written = bytes.length;
      response.end(bytes.subarray(prefixLength));
    },
  };
}

// MIXED evidence. Share metadata and listings are mocked. The packaged WASM
// page retains its upstream CSP, and body requests go directly to this
// same-origin loopback HTTP server without Playwright interception.
async function startShareFixture(baseURL: string) {
  const upstream = new URL(baseURL);
  if (upstream.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(upstream.hostname)) {
    throw new Error('The embedded test server must be on loopback HTTP');
  }
  const bodies = new Map<string, ReturnType<typeof heldBody>>();
  const redirects = new Map<string, string>();
  const sockets = new Set<Socket>();
  let documentRequests = 0;
  const server = createServer((request, reply) => {
    if (!request.url?.startsWith('/') || request.url.startsWith('//')) {
      reply.writeHead(400).end();
      return;
    }
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === downloadPath) {
      const path = url.searchParams.get('path') ?? '';
      const body = bodies.get(path);
      const target = redirects.get(path);
      if (request.method !== 'GET') reply.writeHead(405).end();
      else if (body) body.send(reply);
      else if (target) {
        reply.writeHead(302, {
          'Cache-Control': 'no-store',
          Location: `${downloadPath}?path=${encodeURIComponent(target)}`,
        }).end();
      } else reply.writeHead(404).end();
      return;
    }
    if (url.pathname === '/share') documentRequests++;
    const forwarded = httpRequest({
      hostname: upstream.hostname === '[::1]' ? '::1' : upstream.hostname,
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
    reply.once('close', () => { if (!reply.writableFinished) forwarded.destroy(); });
    request.pipe(forwarded);
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing fixture address');

  return {
    origin: `http://127.0.0.1:${address.port}`,
    documentRequests: () => documentRequests,
    hold(path: string, bytes: Buffer, prefixLength: number, declaredLength?: number) {
      const body = heldBody(bytes, prefixLength, declaredLength);
      bodies.set(path, body);
      return body;
    },
    redirect(path: string, target: string) { redirects.set(path, target); },
    observeBody(path: string) { bodies.get(path)?.opened.resolve(); },
    state() {
      return {
        listenerPort: address.port,
        documentRequests,
        bodies: Object.fromEntries([...bodies].map(([path, body]) => [path, body.state()])),
      };
    },
    async dispose() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    },
  };
}

type ShareFixture = Awaited<ReturnType<typeof startShareFixture>>;

async function chromiumBodyBytes(page: Page) {
  const session = await page.context().newCDPSession(page);
  const responses = new Map<string, { path: string; status: number; received: number; ended: string | null }>();
  session.on('Network.responseReceived', ({ requestId, response }) => {
    const url = new URL(response.url);
    const path = url.searchParams.get('path');
    if (url.pathname === downloadPath && path) {
      responses.set(requestId, { path, status: response.status, received: 0, ended: null });
    }
  });
  session.on('Network.dataReceived', ({ requestId, dataLength }) => {
    const response = responses.get(requestId);
    if (response) response.received += dataLength;
  });
  session.on('Network.loadingFinished', ({ requestId }) => {
    const response = responses.get(requestId);
    if (response) response.ended = 'finished';
  });
  session.on('Network.loadingFailed', ({ requestId, errorText }) => {
    const response = responses.get(requestId);
    if (response) response.ended = errorText;
  });
  await session.send('Network.enable');
  return () => [...responses.values()];
}

const test = base.extend<{ shareFixture: ShareFixture }>({
  shareFixture: async ({ page, baseURL, browserName }, provide, testInfo) => {
    if (!baseURL) throw new Error('The embedded test server URL is required');
    const fixture = await startShareFixture(baseURL);
    const pageErrors: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    let chromiumBytes: Awaited<ReturnType<typeof chromiumBodyBytes>> | undefined;
    try {
      if (browserName === 'chromium' && process.env.AF_SHARE_BODY_CHROMIUM_DIAGNOSTICS === '1') {
        chromiumBytes = await chromiumBodyBytes(page);
      }
      await page.exposeFunction('shareBodyOpened', (path: string) => fixture.observeBody(path));
      await page.addInitScript(pathname => {
        const target = window as ShareWindow;
        const probe: BodyProbe = { bodies: new Map(), signals: new Map(), created: [], revoked: [] };
        target.shareBodyProbe = probe;
        const filePath = (input: string) => {
          const url = new URL(input, location.href);
          return url.pathname === pathname ? url.searchParams.get('path') : null;
        };
        const fetch = window.fetch.bind(window);
        window.fetch = (input, init) => {
          const path = filePath(input instanceof Request ? input.url : String(input));
          const signal = init?.signal ?? (input instanceof Request ? input.signal : null);
          if (path && signal) probe.signals.set(path, signal);
          return fetch(input, init);
        };
        const observe = (
          response: Response,
          consumer: 'reader' | 'blob' | 'text',
          stream?: ReadableStream<Uint8Array>,
        ) => {
          const path = response.url && filePath(response.url);
          if (!path) return;
          probe.bodies.set(path, { consumer, stream, contentLength: response.headers.get('Content-Length') });
          void target.shareBodyOpened(path);
        };
        const body = Object.getOwnPropertyDescriptor(Response.prototype, 'body')!;
        Object.defineProperty(Response.prototype, 'body', {
          ...body,
          get(this: Response) {
            const stream = body.get!.call(this) as ReadableStream<Uint8Array> | null;
            if (stream) observe(this, 'reader', stream);
            return stream;
          },
        });
        // The negative control reaches the same socket assertion through Fetch's
        // native convenience readers. The new path still checks lock release.
        const blob = Response.prototype.blob;
        Response.prototype.blob = function () {
          observe(this, 'blob');
          return blob.call(this);
        };
        const text = Response.prototype.text;
        Response.prototype.text = function () {
          observe(this, 'text');
          return text.call(this);
        };
        const create = URL.createObjectURL.bind(URL);
        URL.createObjectURL = value => {
          const url = create(value);
          if (value instanceof Blob) probe.created.push({ url, blob: value });
          return url;
        };
        const revoke = URL.revokeObjectURL.bind(URL);
        URL.revokeObjectURL = url => {
          probe.revoked.push(url);
          revoke(url);
        };
      }, downloadPath);
      await provide(fixture);
      expect(pageErrors).toEqual([]);
    } finally {
      try {
        const server = fixture.state();
        const browser = await page.evaluate(() => {
          const probe = (window as ShareWindow).shareBodyProbe;
          return {
            bodies: Object.fromEntries([...probe.bodies].map(([path, body]) => [path, {
              consumer: body.consumer,
              contentLength: body.contentLength,
              locked: body.stream?.locked ?? null,
            }])),
            aborted: Object.fromEntries([...probe.signals].map(([path, signal]) => [path, signal.aborted])),
            created: probe.created.map(({ blob }) => ({ size: blob.size, type: blob.type })),
            alert: document.querySelector('[role=alert]')?.textContent ?? null,
            status: document.querySelector('[role=status]')?.textContent ?? null,
          };
        }).catch(error => ({ measurementError: String(error) }));
        await testInfo.attach('share-streams-before-fixture-cleanup', {
          body: JSON.stringify({ server, browser, pageErrors, chromiumTransport: chromiumBytes?.() }, null, 2),
          contentType: 'application/json',
        });
      } finally {
        await fixture.dispose();
      }
    }
  },
});

async function openShare(page: Page, fixture: ShareFixture, files: string[]) {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
  const share = `${sharesPath}/${token}`;
  const other = `${sharesPath}/${otherToken}`;
  await page.route(url => [share, other, `${share}/entries`].includes(url.pathname), route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/entries')) {
      const path = url.searchParams.get('path') ?? '';
      const entries = files.flatMap(file => {
        const parts = file.split('/');
        const name = parts.pop();
        return parts.join('/') === path ? [{ name, path: file, is_directory: false }] : [];
      });
      return route.fulfill({ json: {
        path,
        entries: path ? entries : [...entries, { name: 'docs', path: 'docs', is_directory: true }],
      } });
    }
    return route.fulfill({ json: {
      name: url.pathname === share ? 'Stream fixture share' : 'Alternate share',
      is_directory: url.pathname === share,
      allow_download: true,
      password_required: false,
    } });
  });
  const response = await page.goto(`${fixture.origin}/share?token=${token}`);
  const policy = response?.headers()['content-security-policy'];
  expect(policy).toMatch(/(?:^|;)\s*script-src 'self' 'wasm-unsafe-eval';/);
  expect(policy).toMatch(/(?:^|;)\s*connect-src 'self'(?: [^;]+)?;/);
  expect(policy).toMatch(/(?:^|;)\s*img-src [^;]*\bblob:/);
}

const fileRow = (page: Page, name: string) => page.getByRole('button', { name, exact: false });
const image = (page: Page) => page.locator('main img[src^="blob:"]');
const waitClose = (body: ReturnType<typeof heldBody>) => observed(body.closed.promise, 'server response close');

async function waitBody(page: Page, path: string, body: ReturnType<typeof heldBody>, length: number | null) {
  await observed(body.opened.promise, `the browser stream for ${path}`);
  const state = await page.evaluate(path => {
    const entry = (window as ShareWindow).shareBodyProbe.bodies.get(path);
    return { consumer: entry?.consumer, locked: entry?.stream?.locked, contentLength: entry?.contentLength };
  }, path);
  expect(state.contentLength).toBe(length === null ? null : String(length));
  if (state.consumer === 'reader') expect(state.locked).toBe(true);
}

async function expectUnlocked(page: Page, path: string) {
  expect(await page.evaluate(path => (window as ShareWindow).shareBodyProbe.bodies.get(path)?.stream?.locked, path))
    .toBe(false);
}

async function expectNoPreview(page: Page) {
  await expect(image(page)).toHaveCount(0);
  await expect(page.locator('main pre')).toHaveCount(0);
  expect(await page.evaluate(() => (window as ShareWindow).shareBodyProbe.created.length)).toBe(0);
}

async function expectPng(page: Page, expected: Buffer): Promise<string> {
  const preview = image(page);
  await expect(preview).toBeVisible();
  await expect(preview).toHaveJSProperty('naturalWidth', 1);
  const identity = await preview.evaluate(async element => {
    const target = window as ShareWindow;
    const url = (element as HTMLImageElement).src;
    const blob = target.shareBodyProbe.created.find(entry => entry.url === url)!.blob;
    const hash = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
    return { url, size: blob.size, type: blob.type, hash: Array.from(new Uint8Array(hash)) };
  });
  const { url, ...blob } = identity;
  expect(blob).toEqual({
    size: expected.length,
    type: 'image/png',
    hash: Array.from(createHash('sha256').update(expected).digest()),
  });
  return url;
}

async function expectRevoked(page: Page, url: string) {
  expect(await page.evaluate(() => (window as ShareWindow).shareBodyProbe.revoked)).toContain(url);
}

test('replacement closes a direct pending preview and the completed control preserves PNG bytes', async ({ page, shareFixture }) => {
  const png = pngBytes();
  const old = shareFixture.hold('pending.png', png, 16, png.length);
  const next = shareFixture.hold('complete.png', png, 16, png.length);
  await openShare(page, shareFixture, ['pending.png', 'complete.png']);
  await fileRow(page, 'pending.png').click();
  await waitBody(page, 'pending.png', old, png.length);
  await fileRow(page, 'complete.png').click();
  await waitBody(page, 'complete.png', next, png.length);

  next.release();
  await expectPng(page, png);
  expect(await waitClose(next)).toEqual({ written: png.length, tailReleased: true, finished: true });
  expect(await page.evaluate(() => {
    const probe = (window as ShareWindow).shareBodyProbe;
    return { allocations: probe.created.length, completedAborted: probe.signals.get('complete.png')?.aborted };
  })).toEqual({ allocations: 1, completedAborted: false });
  expect(await waitClose(old)).toEqual({ written: 16, tailReleased: false, finished: false });
  await expectUnlocked(page, 'pending.png');
  await expectUnlocked(page, 'complete.png');
});

test('disposing the share view on same-document token history closes its body and revokes its rendered URL', async ({ page, shareFixture }) => {
  const png = pngBytes();
  const pending = shareFixture.hold('pending.png', png, 16, png.length);
  const completed = shareFixture.hold('complete.png', png, 16, png.length);
  await openShare(page, shareFixture, ['pending.png', 'complete.png']);
  await fileRow(page, 'pending.png').click();
  await waitBody(page, 'pending.png', pending, png.length);
  const documentRoot = await page.evaluateHandle(() => document.documentElement);
  const shareView = await page.locator('main').elementHandle();
  await page.evaluate(token => {
    const current = location.href;
    const previous = new URL(current);
    previous.searchParams.set('token', token);
    history.replaceState(null, '', previous);
    history.pushState(null, '', current);
    history.back();
  }, otherToken);
  await expect(page.getByText('Alternate share', { exact: true })).toBeVisible();
  expect(await shareView!.evaluate(element => element.isConnected)).toBe(false);
  expect(await documentRoot.evaluate(element => element === document.documentElement)).toBe(true);
  expect(shareFixture.documentRequests()).toBe(1);
  expect(await waitClose(pending)).toEqual({ written: 16, tailReleased: false, finished: false });
  await expectUnlocked(page, 'pending.png');
  await expectNoPreview(page);

  await page.evaluate(() => history.forward());
  await fileRow(page, 'complete.png').click();
  await waitBody(page, 'complete.png', completed, png.length);
  completed.release();
  const url = await expectPng(page, png);
  await page.evaluate(() => history.back());
  await expect(page.getByText('Alternate share', { exact: true })).toBeVisible();
  expect(await documentRoot.evaluate(element => element === document.documentElement)).toBe(true);
  expect(shareFixture.documentRequests()).toBe(1);
  await expectRevoked(page, url);
  await expect(image(page)).toHaveCount(0);
});

test('folder changes reset pending previews and revoke a rendered URL after parent navigation', async ({ page, shareFixture }) => {
  const png = pngBytes();
  const pending = shareFixture.hold('pending.png', png, 16, png.length);
  const completed = shareFixture.hold('docs/complete.png', png, 16, png.length);
  await openShare(page, shareFixture, ['pending.png', 'docs/complete.png']);
  await fileRow(page, 'pending.png').click();
  await waitBody(page, 'pending.png', pending, png.length);
  await fileRow(page, 'docs').click();
  await expect(fileRow(page, 'complete.png')).toBeEnabled();
  expect(await waitClose(pending)).toEqual({ written: 16, tailReleased: false, finished: false });
  await expectUnlocked(page, 'pending.png');
  await expectNoPreview(page);

  await fileRow(page, 'complete.png').click();
  await waitBody(page, 'docs/complete.png', completed, png.length);
  completed.release();
  const url = await expectPng(page, png);
  await page.getByRole('button', { name: /Parent/ }).click();
  await expect(fileRow(page, 'pending.png')).toBeEnabled();
  await expect(image(page)).toHaveCount(0);
  await expectRevoked(page, url);
});

for (const type of ['media', 'text'] as const) {
  const media = type === 'media';
  const limit = media ? mediaLimit : textLimit;
  const name = media ? 'limit.png' : 'limit.txt';
  const alert = media ? 'This file is too large to preview. Use Download.' : 'Text preview is limited to 1 MiB.';

  test(`chunked ${type} closes on overflow with the response tail still held`, async ({ page, shareFixture }) => {
    const total = limit + 65536;
    const body = shareFixture.hold(name, media ? pngBytes(total) : Buffer.alloc(total, 0x61), limit + 1);
    await openShare(page, shareFixture, [name]);
    await fileRow(page, name).click();
    await observed(body.opened.promise, `the browser stream for ${name}`);
    expect(await page.evaluate(path => (window as ShareWindow).shareBodyProbe.bodies.get(path)?.contentLength, name))
      .toBeNull();
    expect(await waitClose(body)).toEqual({ written: limit + 1, tailReleased: false, finished: false });
    await expect(page.getByRole('alert')).toHaveText(alert);
    await expectUnlocked(page, name);
    await expectNoPreview(page);
  });

  test(`chunked ${type} at the exact limit completes with original bytes`, async ({ page, shareFixture }) => {
    const suffix = Buffer.from('λ🙂 original text\n');
    const bytes = media ? pngBytes(limit) : Buffer.concat([Buffer.alloc(limit - suffix.length, 0x61), suffix]);
    // Hold in the middle of a multibyte UTF-8 character for the text case.
    const body = shareFixture.hold(name, bytes, media ? 16 : limit - suffix.length + 1);
    await openShare(page, shareFixture, [name]);
    await fileRow(page, name).click();
    await waitBody(page, name, body, null);
    body.release();
    if (media) {
      await expectPng(page, bytes);
    } else {
      const preview = page.locator('main pre');
      await expect(preview).toBeVisible();
      expect(await preview.evaluate(async element => {
        const bytes = new TextEncoder().encode(element.textContent!);
        return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
      })).toEqual(Array.from(createHash('sha256').update(bytes).digest()));
    }
    expect(await waitClose(body)).toEqual({ written: limit, tailReleased: true, finished: true });
    await expectUnlocked(page, name);
  });
}

test('an oversized declared length closes before the browser opens a body reader', async ({ page, shareFixture }) => {
  const png = pngBytes(mediaLimit + 1);
  const body = shareFixture.hold('declared.png', png, 16, png.length);
  await openShare(page, shareFixture, ['declared.png']);
  await fileRow(page, 'declared.png').click();
  await expect(page.getByRole('alert')).toHaveText('This file is too large to preview. Use Download.');
  expect(await waitClose(body)).toEqual({ written: 16, tailReleased: false, finished: false });
  expect(await page.evaluate(() => (window as ShareWindow).shareBodyProbe.bodies.has('declared.png'))).toBe(false);
  await expectNoPreview(page);
});

test('a superseded redirect releases the app reader without asserting redirected server closure', async ({ page, shareFixture }) => {
  const png = pngBytes();
  shareFixture.redirect('redirect.png', 'redirect-target.png');
  const redirected = shareFixture.hold('redirect-target.png', png, 16, png.length);
  const next = shareFixture.hold('complete.png', png, 16, png.length);
  await openShare(page, shareFixture, ['redirect.png', 'complete.png']);
  await fileRow(page, 'redirect.png').click();
  await waitBody(page, 'redirect-target.png', redirected, png.length);
  await fileRow(page, 'complete.png').click();
  await waitBody(page, 'complete.png', next, png.length);
  await expectUnlocked(page, 'redirect-target.png');
  expect(await page.evaluate(() => (window as ShareWindow).shareBodyProbe.signals.get('redirect.png')?.aborted))
    .toBe(true);
  next.release();
  await expectPng(page, png);
  expect(await page.evaluate(() => (window as ShareWindow).shareBodyProbe.created.length)).toBe(1);
  // The upstream browser may keep a redirected connection open after abort.
  // Fixture teardown will close a still-held response. It is not closure proof.
});
