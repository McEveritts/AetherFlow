// Bump the policy version even when the generated index has not changed.  Old
// caches may contain plugin responses admitted by the former suffix matcher.
const CACHE_NAME = 'aetherflow-cache-wasm-v2-__BUILD_HASH__';
const PRECACHE_URLS = ['/favicon.ico'];

function isPluginNamespace(pathname) {
  // Include the top-level route and both authenticated API aliases. Decode
  // defensively so encoded route components cannot select a public policy.
  let path = pathname;
  for (let i = 0; i < 4; i += 1) {
    if (/^\/(?:plugins(?:\/|$)|api\/(?:v1\/)?auth\/plugins(?:\/|$))/i.test(path)) return true;
    try {
      const decoded = decodeURIComponent(path);
      if (decoded === path) return false;
      path = decoded;
    } catch {
      return true;
    }
  }
  // Ambiguous multi-encoded paths take the network-only route.
  return true;
}

function isPublishedImmutable(pathname) {
  return /^\/(?:af-bootstrap|af-web-app|af-web-worker(?:_loader)?)-[a-f0-9]{8,}\.js$/i.test(pathname) ||
    /^\/af-web-(?:app|worker)_bg-[a-f0-9]{8,}\.wasm$/i.test(pathname) ||
    /^\/compiled-[a-f0-9]{8,}\.css$/i.test(pathname);
}

function usableStaticResponse(response, jsonOnly = false) {
  const contentType = response && (response.headers.get('content-type') || '').toLowerCase();
  return response && response.status === 200 && response.type === 'basic' &&
    !contentType.includes('text/html') && (!jsonOnly || contentType.includes('application/json'));
}

async function cacheStaticResponse(cache, request, response, jsonOnly = false) {
  if (usableStaticResponse(response, jsonOnly)) {
    const copy = response.clone();
    await cache.put(request, copy).catch(() => {});
  }
}

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => Promise.all(PRECACHE_URLS.map(async url => {
    const response = await fetch(url, { cache: 'reload' });
    await cacheStaticResponse(cache, url, response);
  }))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key.startsWith('aetherflow-cache-') && key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  // The page fetches the catalog with cache: no-store. Let its network
  // request keep the page's client identity instead of issuing a worker fetch.
  if (url.pathname === '/api/v1/auth/plugins' || url.pathname === '/api/auth/plugins') return;
  if (isPluginNamespace(url.pathname)) {
    // Neither CacheStorage nor a previously cached HTTP response may stand in
    // for the server's authentication and authorization decision.
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }
  if (request.method !== 'GET') return;
  if (url.pathname === '/api' || url.pathname.startsWith('/api/') || url.pathname === '/ws' || url.pathname.startsWith('/ws/') || url.pathname === '/sw.js') return;
  if (url.pathname === '/manifest.json' || /^\/locales\/(de|dk|es|fr|zh)\.json$/.test(url.pathname)) {
    event.respondWith(caches.open(CACHE_NAME).then(async cache => {
      try {
        const response = await fetch(request, { cache: 'no-store' });
        await cacheStaticResponse(cache, request, response, true);
        if (usableStaticResponse(response, true)) return response;
        const cached = await cache.match(request);
        return usableStaticResponse(cached, true) ? cached : response;
      } catch (error) {
        const cached = await cache.match(request);
        if (usableStaticResponse(cached, true)) return cached;
        throw error;
      }
    }));
    return;
  }
  if (request.mode === 'navigate' || (request.headers.get('accept') || '').includes('text/html') || url.pathname === '/' || url.pathname.endsWith('.html')) {
    event.respondWith(fetch(request, {cache: 'no-store'}).catch(() => new Response('<!doctype html><title>AetherFlow Offline</title><h1>Offline</h1><p>Reconnect to open your control plane.</p>', {status: 503, headers: {'Content-Type': 'text/html', 'Cache-Control': 'no-store'}})));
    return;
  }
  if (/^\/img\/[a-z0-9_-]+\.(?:png|svg|jpe?g|webp|gif|ico)$/i.test(url.pathname)) {
    const cache = caches.open(CACHE_NAME);
    const fresh = fetch(request).then(async response => {
      await cacheStaticResponse(await cache, request, response);
      return response;
    });
    event.waitUntil(fresh.then(() => {}, () => {}));
    event.respondWith(cache.then(async cache => {
      const cached = await cache.match(request);
      return usableStaticResponse(cached) ? cached : fresh;
    }));
    return;
  }
  if (isPublishedImmutable(url.pathname)) {
    event.respondWith(caches.open(CACHE_NAME).then(async cache => {
      const cached = await cache.match(request);
      if (usableStaticResponse(cached)) return cached;
      const response = await fetch(request);
      await cacheStaticResponse(cache, request, response);
      return response;
    }));
  }
});
