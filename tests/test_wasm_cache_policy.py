"""Service-worker contract tests; these do not start the API or a browser."""

import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKER = Path(os.environ.get("AETHERFLOW_SW_PATH", ROOT / "frontend-rs/public/sw.js"))
NODE = os.environ.get("NODE", shutil.which("node") or "node")

HARNESS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const worker = fs.readFileSync(process.argv[1], 'utf8').replace('__BUILD_HASH__', 'sameindex');
const testName = process.argv[2];
const origin = 'https://aetherflow.test';
const listeners = {};
const stores = new Map();
const httpCache = new Map();
const calls = [];
let online = true;
let nextResponse;

class BasicResponse {
  constructor(body, { status = 200, type = 'application/json', cache = 'public, max-age=31536000' } = {}) {
    this.body = body;
    this.status = status;
    this.type = 'basic';
    this.headers = new Headers({ 'content-type': type, 'cache-control': cache });
  }
  clone() { return new BasicResponse(this.body, { status: this.status, type: this.headers.get('content-type'), cache: this.headers.get('cache-control') }); }
}
function key(request) { return new URL(typeof request === 'string' ? request : request.url, origin).href; }
const caches = {
  async open(name) {
    if (!stores.has(name)) stores.set(name, new Map());
    const store = stores.get(name);
    return {
      async put(request, response) { store.set(key(request), response); },
      async match(request) { return store.get(key(request)); },
    };
  },
  async keys() { return [...stores.keys()]; },
  async delete(name) { return stores.delete(name); },
};
async function network(request, options = {}) {
  const url = key(request);
  calls.push({ url, method: request.method, cache: options.cache });
  if (!online) throw new Error('offline');
  if (options.cache !== 'no-store' && httpCache.has(url)) return httpCache.get(url).clone();
  return nextResponse.clone();
}
const self = {
  location: { origin },
  addEventListener(name, handler) { listeners[name] = handler; },
  skipWaiting: async () => {},
  clients: { claim: async () => {} },
};
const context = vm.createContext({ self, caches, fetch: network, URL, Headers, Response });
vm.runInContext(worker, context, { filename: process.argv[1] });
const current = vm.runInContext('CACHE_NAME', context);
async function activate() {
  let done;
  listeners.activate({ waitUntil(promise) { done = promise; } });
  await done;
}
async function request(path, options = {}) {
  let result;
  const waits = [];
  listeners.fetch({
    request: { url: new URL(path, origin).href, method: options.method || 'GET',
      mode: options.mode || 'cors', headers: new Headers(options.headers), cache: options.cache || 'default' },
    respondWith(promise) { result = Promise.resolve(promise); },
    waitUntil(promise) { waits.push(promise); },
  });
  if (!result) return undefined;
  const response = await result;
  await Promise.all(waits);
  return response;
}

async function cleanup() {
  assert.equal(current, 'aetherflow-cache-wasm-v2-sameindex');
  for (const name of ['aetherflow-cache-wasm-sameindex', 'aetherflow-cache-legacy', current, 'other-app']) await caches.open(name);
  await activate();
  assert.deepEqual((await caches.keys()).sort(), [current, 'other-app'].sort());
}

async function plugins() {
  const paths = [
    '/plugins/demo/proxy/asset-deadbeef.js',
    '/plugins/de%6do/proxy/ui',
    '/api/auth/plugins/%64emo/proxy/asset-deadbeef.wasm',
    '/api/v1/auth/plugins/demo/proxy/data-deadbeef.css',
    '/%70lugins/demo/proxy/asset-deadbeef.js',
    '/api/%76%31/auth/plugins/demo/proxy/asset-deadbeef.js',
    '/api/v1/auth/plugins/%2564emo/proxy/asset-deadbeef.js',
  ];
  const cache = await caches.open(current);
  for (const [index, path] of paths.entries()) {
    const stale = new BasicResponse('stale cached fixture');
    await cache.put(path, stale);
    httpCache.set(key(path), stale);
    nextResponse = new BasicResponse('network fixture', {
      status: index % 2 ? 401 : 200,
      type: ['application/json', 'text/html', 'application/javascript'][index % 3],
      cache: 'public, max-age=31536000, immutable',
    });
    const headers = index === 1 ? { accept: 'text/html' } : {};
    const response = await request(path, { cache: 'force-cache', headers });
    assert.equal(response.body, 'network fixture', path);
    assert.equal(response.status, nextResponse.status, path);
    assert.equal(calls.at(-1).cache, 'no-store', path);
    assert.equal((await cache.match(path)).body, 'stale cached fixture', path);
  }
  assert.equal(calls.length, paths.length);
  for (const method of ['HEAD', 'POST']) {
    nextResponse = new BasicResponse('network fixture', { status: 401 });
    const response = await request(paths[0], { method, cache: 'force-cache' });
    assert.equal(response.body, 'network fixture', method);
    assert.equal(calls.at(-1).method, method);
    assert.equal(calls.at(-1).cache, 'no-store', method);
  }
}

async function publicAssets() {
  const cache = await caches.open(current);
  nextResponse = new BasicResponse('wasm fixture', { type: 'application/wasm' });
  const wasm = '/af-web-app_bg-deadbeef.wasm';
  assert.equal((await request(wasm)).body, 'wasm fixture');
  assert.equal((await cache.match(wasm)).body, 'wasm fixture');
  online = false;
  assert.equal((await request(wasm)).body, 'wasm fixture');
  online = true;
  for (const path of [
    '/af-bootstrap-deadbeef.js', '/af-web-app-deadbeef.js',
    '/af-web-worker-deadbeef.js', '/af-web-worker_loader-deadbeef.js',
    '/af-web-worker_bg-deadbeef.wasm', '/compiled-deadbeef.css',
  ]) {
    nextResponse = new BasicResponse('published fixture', { type: 'application/octet-stream' });
    assert.equal((await request(path)).body, 'published fixture', path);
    assert.equal((await cache.match(path)).body, 'published fixture', path);
  }
  nextResponse = new BasicResponse('image fixture', { type: 'image/png' });
  assert.equal((await request('/img/plex.png')).body, 'image fixture');
  assert.equal((await cache.match('/img/plex.png')).body, 'image fixture');
  nextResponse = new BasicResponse('manifest fixture', { cache: 'no-cache, no-store, must-revalidate' });
  assert.equal((await request('/manifest.json')).body, 'manifest fixture');
  assert.equal(calls.at(-1).cache, 'no-store');
  online = false;
  assert.equal((await request('/manifest.json')).body, 'manifest fixture');
  const offline = await request('/', { mode: 'navigate' });
  assert.equal(offline.status, 503);
  assert.match(await offline.text(), /Offline/);
  online = true;
  nextResponse = new BasicResponse('not a static asset', { type: 'text/html' });
  await request('/compiled-abcdef12.css');
  assert.equal(await cache.match('/compiled-abcdef12.css'), undefined);
  assert.equal(await request('/unpublished/asset-deadbeef.js'), undefined);
  assert.equal(await request('/api/v1/public/marketplace'), undefined);
  assert.equal(await request('/ws/logs'), undefined);
}

({ cleanup, plugins, publicAssets })[testName]().catch(error => { console.error(error); process.exitCode = 1; });
"""


class ServiceWorkerCachePolicy(unittest.TestCase):
    def run_contract(self, scenario):
        result = subprocess.run(
            [NODE, "-e", HARNESS, str(WORKER), scenario],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_activation_removes_legacy_caches_with_the_same_index_hash(self):
        self.run_contract("cleanup")

    def test_plugin_namespaces_bypass_cache_storage_and_http_cache(self):
        self.run_contract("plugins")

    def test_public_assets_catalog_and_offline_policy_remain_available(self):
        self.run_contract("publicAssets")


if __name__ == "__main__":
    unittest.main()
