import { createServer, request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, test as base, type Page } from '@playwright/test';

type NetworkGate = {
  origin: string;
  disconnect: () => void;
  seed: (path: string, body: string) => void;
  stopSeeding: () => void;
};

// Preserve real HTTP responses while online; dropping loopback connections lets
// every engine exercise the worker's actual network-failure handling. Browser
// offline emulation does not consistently reach service workers across engines.
const test = base.extend<{ networkGate: NetworkGate; httpCachePage: Page }>({
  // Playwright's ephemeral WebKit context does not retain the HTTP fixture;
  // a separate persistent context exercises its real HTTP cache. CacheStorage
  // is checked in the ordinary page context, where it is available.
  httpCachePage: async ({ page, browserName, playwright }, runFixture, testInfo) => {
    if (browserName !== 'webkit') {
      await runFixture(page);
      return;
    }
    const persistent = await playwright.webkit.launchPersistentContext(
      testInfo.outputPath('webkit-cache-profile'),
      {
        headless: true,
        serviceWorkers: 'allow',
        ...(process.env.PLAYWRIGHT_WEBKIT_EXECUTABLE_PATH
          ? { executablePath: process.env.PLAYWRIGHT_WEBKIT_EXECUTABLE_PATH }
          : {}),
      },
    );
    try {
      await runFixture(await persistent.newPage());
    } finally {
      await persistent.close();
    }
  },
  networkGate: async ({ baseURL }, runFixture) => {
    if (!baseURL) throw new Error('A loopback API base URL is required');
    const upstream = new URL(baseURL);
    if (upstream.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(upstream.hostname)) {
      throw new Error('The cache test forwards only to an isolated loopback API');
    }
    let disconnected = false;
    let fixture: { path: string; body: string } | undefined;
    const server = createServer((incoming, outgoing) => {
      if (disconnected) {
        incoming.socket.destroy();
        return;
      }
      if (fixture && incoming.method === 'GET' && incoming.url === fixture.path) {
        outgoing.writeHead(200, {
          'content-type': 'application/json',
          'cache-control': 'public, max-age=3600',
          'content-length': Buffer.byteLength(fixture.body),
        }).end(fixture.body);
        return;
      }
      const target = new URL(incoming.url || '/', upstream);
      if (target.origin !== upstream.origin) {
        outgoing.writeHead(400).end();
        return;
      }
      const forwarded = httpRequest(target, {
        method: incoming.method,
        headers: { ...incoming.headers, host: upstream.host },
      }, (response) => {
        outgoing.writeHead(response.statusCode || 502, response.headers);
        response.pipe(outgoing);
      });
      forwarded.on('error', () => outgoing.destroy());
      incoming.pipe(forwarded);
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    try {
      const port = (server.address() as AddressInfo).port;
      await runFixture({
        origin: `http://127.0.0.1:${port}`,
        disconnect: () => { disconnected = true; },
        seed: (path, body) => { fixture = { path, body }; },
        stopSeeding: () => { fixture = undefined; },
      });
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
    }
  },
});

test.describe('Live public static and plugin cache boundaries', () => {
  test.use({ serviceWorkers: 'allow' });

  test('removes legacy entries and reaches authorization while retaining public offline assets', async ({ page, httpCachePage, request, networkGate }) => {
    test.setTimeout(90_000);

    // A JSON document provides an origin without launching the app or registering
    // a worker before the legacy cache has been created.
    const manifestDocument = await page.goto(`${networkGate.origin}/manifest.json`);
    expect(manifestDocument?.status()).toBe(200);
    const setup = await page.evaluate(async () => {
      const source = await (await fetch('/sw.js', { cache: 'no-store' })).text();
      const match = source.match(/const CACHE_NAME = '(aetherflow-cache-wasm-v2-([a-f0-9]+))'/);
      if (!match) throw new Error('Expected a published worker with the v2 cache policy');
      const current = match[1];
      const legacy = `aetherflow-cache-wasm-${match[2]}`;
      const fixture = await fetch('/manifest.json', { cache: 'no-store' });
      if (fixture.status !== 200 || fixture.type !== 'basic') throw new Error('Expected a real same-origin public manifest');
      const cache = await caches.open(legacy);
      await cache.put('/plugins/demo/proxy/asset-deadbeef.js', fixture.clone());
      const oldEntries = await cache.keys();
      if (!oldEntries.some((entry) => new URL(entry.url).pathname === '/plugins/demo/proxy/asset-deadbeef.js')) {
        throw new Error('The legacy cache fixture was not stored');
      }
      await caches.open('unrelated-app-cache');
      return { current, legacy, fixture: await fixture.text() };
    });
    expect(JSON.parse(setup.fixture)).toBeTruthy();

    // Prime the browser HTTP cache using only the actual public manifest bytes.
    // The local fixture is switched off before any authorization assertions.
    const httpCachePath = '/plugins/demo/proxy/asset-deadbeef.js';
    if (httpCachePage !== page) await httpCachePage.goto(`${networkGate.origin}/manifest.json`);
    networkGate.seed(httpCachePath, setup.fixture);
    const firstFetch = await httpCachePage.evaluate(async (path) => {
      const response = await fetch(path);
      return { status: response.status, body: await response.text() };
    }, httpCachePath);
    expect(firstFetch).toEqual({ status: 200, body: setup.fixture });
    networkGate.stopSeeding();
    const cachedFetch = await httpCachePage.evaluate(async (path) => {
      const response = await fetch(path);
      return { status: response.status, body: await response.text() };
    }, httpCachePath);
    expect(cachedFetch).toEqual({ status: 200, body: setup.fixture });

    await httpCachePage.evaluate(async () => {
      await navigator.serviceWorker.register('/sw.js');
      await navigator.serviceWorker.ready;
    });
    await expect.poll(() => httpCachePage.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
    const httpCacheBoundary = await httpCachePage.evaluate(async (path) => {
      const response = await fetch(path);
      return { status: response.status, body: await response.text() };
    }, httpCachePath);
    const directHttpCacheBoundary = await request.get(httpCachePath);
    expect(directHttpCacheBoundary.status()).toBe(401);
    expect(httpCacheBoundary.status).toBe(401);
    expect(JSON.parse(httpCacheBoundary.body)).toEqual(await directHttpCacheBoundary.json());

    await page.evaluate(async () => {
      await navigator.serviceWorker.register('/sw.js');
      await navigator.serviceWorker.ready;
    });
    await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
    const activated = await page.evaluate(() => caches.keys());
    expect(activated).toContain(setup.current);
    expect(activated).not.toContain(setup.legacy);
    expect(activated).toContain('unrelated-app-cache');

    const paths = [
      httpCachePath,
      '/plugins/de%6do/proxy/data.json',
      '/api/auth/plugins/de%6do/proxy/asset-deadbeef.wasm',
      '/api/v1/auth/plugins/%64emo/proxy/asset-deadbeef.css',
    ];
    // Serve the same public bytes without Vary so CacheStorage matching tests
    // the plugin URL itself in every browser, including persistent WebKit.
    networkGate.seed('/cache-fixture.json', setup.fixture);
    const seeded = await page.evaluate(async ({ current, paths }) => {
      const cache = await caches.open(current);
      const fixture = await fetch('/cache-fixture.json', { cache: 'no-store' });
      if (fixture.status !== 200 || fixture.type !== 'basic') throw new Error('Expected a basic public fixture');
      for (const path of paths) await cache.put(path, fixture.clone());
      return Promise.all(paths.map(async (path) => (await cache.match(path))?.text()));
    }, { current: setup.current, paths });
    networkGate.stopSeeding();
    expect(seeded).toEqual(paths.map(() => setup.fixture));

    // APIRequestContext does not use the page's service worker. Its direct
    // response is the oracle for the same anonymous request through the worker.
    for (const path of paths) {
      const direct = await request.get(path);
      const throughWorker = await page.evaluate(async (target) => {
        const response = await fetch(target);
        return { status: response.status, type: response.headers.get('content-type'), body: await response.text() };
      }, path);
      expect(direct.status(), path).toBe(401);
      expect(throughWorker.status, path).toBe(direct.status());
      expect(throughWorker.type, path).toContain('application/json');
      expect(JSON.parse(throughWorker.body), path).toEqual(await direct.json());
      expect(throughWorker.body, path).not.toBe(setup.fixture);
    }
    const directHead = await request.head(paths[0]);
    const workerHead = await page.evaluate(async (target) => {
      const response = await fetch(target, { method: 'HEAD' });
      return { status: response.status, body: await response.text() };
    }, paths[0]);
    expect(directHead.status()).toBe(401);
    expect(workerHead).toEqual({ status: 401, body: '' });
    const freshlyCached = await page.evaluate(async ({ current, paths }) => {
      const cache = await caches.open(current);
      for (const path of paths) await cache.delete(path);
      for (const path of paths) await fetch(path);
      return Promise.all(paths.map(async (path) => Boolean(await cache.match(path))));
    }, { current: setup.current, paths });
    expect(freshlyCached).toEqual(paths.map(() => false));

    const publicAssets = await page.evaluate(async (current) => {
      const documentText = await (await fetch('/', { cache: 'no-store' })).text();
      const html = new DOMParser().parseFromString(documentText, 'text/html');
      const wasm = html.querySelector('meta[name="af-app-wasm-url"]')?.getAttribute('content')
        || html.querySelector<HTMLLinkElement>('link[href$=".wasm"]')?.getAttribute('href');
      if (!wasm) throw new Error('The published document has no application WASM reference');
      const cache = await caches.open(current);
      const wasmResponse = await fetch(wasm);
      const imageResponse = await fetch('/img/plex.png');
      const manifestResponse = await fetch('/manifest.json');
      const marketplace = await fetch('/api/v1/public/marketplace');
      const restrictedMarketplace = await fetch('/api/v1/public/marketplace?require_auth=1');
      return {
        wasm,
        statuses: [wasmResponse.status, imageResponse.status, manifestResponse.status, marketplace.status, restrictedMarketplace.status],
        cached: [Boolean(await cache.match(wasm)), Boolean(await cache.match('/img/plex.png')), Boolean(await cache.match('/manifest.json'))],
        marketplaceType: marketplace.headers.get('content-type'),
        marketplaceCached: Boolean(await cache.match('/api/v1/public/marketplace')),
      };
    }, setup.current);
    expect(publicAssets.statuses).toEqual([200, 200, 200, 200, 401]);
    expect(publicAssets.cached).toEqual([true, true, true]);
    expect(publicAssets.marketplaceType).toContain('application/json');
    expect(publicAssets.marketplaceCached).toBe(false);

    networkGate.disconnect();
    const offline = await page.evaluate(async ({ wasm, plugin }) => {
      const status = async (url: string) => {
        try { return (await fetch(url)).status; } catch (error) { return String(error); }
      };
      const staticStatus = await status(wasm);
      const manifestStatus = await status('/manifest.json');
      let pluginReachedNetwork = false;
      try { await fetch(plugin); } catch { pluginReachedNetwork = true; }
      return { staticStatus, manifestStatus, pluginReachedNetwork };
    }, { wasm: publicAssets.wasm, plugin: paths[0] });
    expect(offline).toEqual({ staticStatus: 200, manifestStatus: 200, pluginReachedNetwork: true });
    // A controller on the current document can outlive an unregistered worker.
    // Navigation needs the registration itself to remain active for this scope.
    const navigationWorker = await page.evaluate(async () => {
      const registration = await navigator.serviceWorker.getRegistration();
      return {
        scope: registration?.scope,
        active: registration?.active?.scriptURL,
        activeState: registration?.active?.state,
        controller: navigator.serviceWorker.controller?.scriptURL,
        controllerState: navigator.serviceWorker.controller?.state,
      };
    });
    expect(navigationWorker).toEqual({
      scope: `${networkGate.origin}/`,
      active: `${networkGate.origin}/sw.js`,
      activeState: 'activated',
      controller: `${networkGate.origin}/sw.js`,
      controllerState: 'activated',
    });
    const navigation = await page.goto(`${networkGate.origin}/offline-cache-test`);
    expect(navigation?.status()).toBe(503);
    await expect(page.locator('h1')).toHaveText('Offline');
    console.log(`CACHE_LIVE: legacy=${setup.legacy} removed; browser HTTP and CacheStorage fixtures bypassed; ${paths.length} proxy aliases reached HTTP 401; static and offline controls passed`);
  });
});
