import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';

const CHUNK_SIZE = 4 * 1024 * 1024;
const FILE_SIZE = 64 * 1024 * 1024 + 17;
const UPLOADS = '/api/v1/auth/mcbrowser/uploads';

type Failure = 'crash' | 'timeout' | 'native-error';
type Exchange = {
  method: string;
  path: string;
  startedAt: number;
  sentAt?: number;
  responseAt?: number;
  request: Record<string, string | null>;
  body: { length: number; sha256: string } | null;
  response: { status: number; headers: Record<string, string | null> } | null;
  error?: string;
};
type Observation = {
  loss?: {
    mode: Failure; before: number; after: number; at: number; errorAt?: number;
    terminatedAt?: number; workerUrl: string; transferContainsBuffer: boolean;
    errorIsTrusted?: boolean; errorMessage?: string;
  };
  exchanges: Exchange[];
};

// Fail before any request or mutation if this was not launched by the disposable
// loopback harness. Resolving paths checks containment without opening its DB.
async function isolatedCredentials(): Promise<{ username: string; password: string }> {
  expect(process.env.AETHERFLOW_E2E_ISOLATED).toBe('1');
  expect(process.env.PRIVILEGED_RUNNER_ENABLED).toBe('false');
  expect(process.env.AETHERFLOW_DISABLE_BACKGROUND_WORKERS).toBe('1');
  expect(process.env.AETHERFLOW_SKIP_ENV_FILES).toBe('1');
  const database = await realpath(process.env.AETHERFLOW_DB_PATH || '');
  const data = dirname(database);
  const root = dirname(data);
  expect(basename(root)).toMatch(/^aetherflow-embedded-e2e\.[A-Za-z0-9]+$/);
  expect(basename(data)).toBe('data');
  expect(basename(database)).toBe('aetherflow.sqlite');
  expect(await realpath(process.env.AETHERFLOW_FS_ROOT || '')).toBe(join(root, 'fs-root'));
  expect(await realpath(process.env.MCBROWSER_ROOT || '')).toBe(join(root, 'mcbrowser'));
  expect(await realpath(process.env.AETHERFLOW_UPLOAD_DIR || '')).toBe(join(root, 'uploads'));
  expect(await realpath(process.env.AETHERFLOW_ENV_FILE || '')).toBe(join(root, 'aetherflow.env'));
  expect(process.env.BIND_ADDR).toBe('127.0.0.1');
  expect(process.env.PLAYWRIGHT_BASE_URL).toBe(`http://127.0.0.1:${process.env.PORT}`);
  const username = process.env.E2E_ADMIN_USER;
  const password = process.env.E2E_ADMIN_PASS;
  expect(username, 'The harness must supply E2E_ADMIN_USER').toBeTruthy();
  expect(password, 'The harness must supply E2E_ADMIN_PASS').toBeTruthy();
  return { username: username!, password: password! };
}

async function signInLive(page: Page, username: string, password: string): Promise<void> {
  await page.goto('/login', { waitUntil: 'domcontentloaded', timeout: 15_000 });
  await page.locator('input[type="text"]').first().fill(username);
  await page.locator('input[type="password"]').first().fill(password);
  const submit = async () => {
    const response = page.waitForResponse((candidate) =>
      new URL(candidate.url()).pathname === '/api/v1/public/auth/login'
        && candidate.request().method() === 'POST', { timeout: 15_000 });
    await page.locator('button[type="submit"]').first().click();
    return response;
  };
  let response = await submit();
  expect(response.request().postDataJSON()).toEqual({ username, password });
  if (response.status() === 429) {
    const retryAfter = Number(response.headers()['retry-after']);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
    console.log(`LIVE_AUTH_RETRY: honoring the server's ${retryAfter}s Retry-After`);
    // This wait is the server's explicit rate-limit instruction, not a retry
    // backoff chosen by the test or a change to the real auth limit.
    await page.waitForTimeout(retryAfter * 1000);
    response = await submit();
  }
  expect(response.status(), response.status() === 200 ? 'login' : await response.text()).toBe(200);
  await expect(page).not.toHaveURL(/\/login/);
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  const onboarding = page.getByRole('heading', { name: 'Welcome to AetherFlow' });
  if (await onboarding.isVisible()) {
    await page.getByRole('button', { name: /Continue/i }).click();
    await page.getByRole('button', { name: /Enter Dashboard/i }).click();
    await expect(onboarding).toHaveCount(0);
  }
}

// The native-error case changes only the worker loader response, in memory.
// This listener runs before the real worker installs its onmessage handler. It
// consumes exactly the first full chunk, then throws inside the worker global;
// the browser must generate and deliver the Worker's real error event.
const INJECTED_WORKER_ERROR = 'AF_INJECTED_TRANSFERRED_CHUNK_ERROR';
type LoaderInjection = { pathname: string; originalSha256: string };

async function installObservation(page: Page, mode: Failure): Promise<LoaderInjection[]> {
  const injections: LoaderInjection[] = [];
  if (mode === 'native-error') {
    await page.route(/\/af-web-worker_loader[^/?]*\.js(?:\?.*)?$/, async (route) => {
      // Only the first worker receives the fault; respawned workers are normal.
      if (injections.length) return route.continue();
      const response = await route.fetch();
      expect(response.ok()).toBe(true);
      const original = await response.body();
      injections.push({
        pathname: new URL(route.request().url()).pathname,
        originalSha256: createHash('sha256').update(original).digest('hex'),
      });
      const prefix = `self.addEventListener('message', (event) => {
        if (event.data?.type === 'Sha256ChunkTransfer'
            && event.data.buffer instanceof ArrayBuffer
            && event.data.buffer.byteLength === 4 * 1024 * 1024) {
          event.stopImmediatePropagation();
          throw new Error('${INJECTED_WORKER_ERROR}');
        }
      });\n`;
      await route.fulfill({ response, body: Buffer.concat([Buffer.from(prefix), original]) });
    });
  }
  await page.addInitScript((faultMode) => {
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 1 });
    const target = window as unknown as Window & { __liveWorkerObservation: Observation };
    target.__liveWorkerObservation = { exchanges: [] };
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      // Inspect a clone only. The original input and body go to native fetch.
      const request = new Request(input instanceof Request ? input.clone() : input, init);
      const path = new URL(request.url).pathname;
      if (!path.startsWith('/api/v1/auth/mcbrowser/uploads')
          || !['POST', 'HEAD', 'PATCH'].includes(request.method)) {
        return nativeFetch(input, init);
      }
      const headers = (names: string[], source: Headers) => Object.fromEntries(
        names.map((name) => [name, source.get(name)]),
      );
      const exchange: Exchange = {
        method: request.method,
        path,
        startedAt: performance.now(),
        request: headers(['tus-resumable', 'upload-length', 'upload-metadata',
          'upload-offset', 'upload-checksum', 'content-type', 'x-upload-conflict'], request.headers),
        body: null,
        response: null,
      };
      target.__liveWorkerObservation.exchanges.push(exchange);
      try {
        if (request.method === 'PATCH') {
          // WebKit's debugging protocol can omit Blob bodies. This reads a
          // Request clone in the page; it never replaces the application's Blob.
          const bytes = new Uint8Array(await request.clone().arrayBuffer());
          const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
          exchange.body = { length: bytes.length, sha256: btoa(String.fromCharCode(...digest)) };
        }
        exchange.sentAt = performance.now();
        const response = await nativeFetch(input, init);
        exchange.responseAt = performance.now();
        exchange.response = {
          status: response.status,
          headers: headers(['tus-resumable', 'location', 'upload-offset', 'upload-length',
            'upload-metadata', 'upload-status', 'upload-path'], response.headers),
        };
        return response;
      } catch (error) {
        exchange.error = String(error);
        throw error;
      }
    };
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        const post = this.postMessage.bind(this);
        const terminate = this.terminate.bind(this);
        let injectedLoss: Observation['loss'];
        // Registered before the application installs onerror, so this timestamps
        // the actual event before the application's error handler terminates.
        this.addEventListener('error', (event: ErrorEvent) => {
          if (injectedLoss && injectedLoss.errorAt === undefined) {
            injectedLoss.errorAt = performance.now();
            injectedLoss.errorIsTrusted = event.isTrusted;
            injectedLoss.errorMessage = event.message;
          }
        });
        Object.defineProperty(this, 'terminate', {
          value: () => {
            if (injectedLoss && injectedLoss.terminatedAt === undefined) {
              injectedLoss.terminatedAt = performance.now();
            }
            return terminate();
          },
        });
        Object.defineProperty(this, 'postMessage', {
          value: (message: { type?: string; buffer?: ArrayBuffer }, transfer: Transferable[]) => {
            if (message.type !== 'Sha256ChunkTransfer'
                || message.buffer?.byteLength !== 4 * 1024 * 1024
                || target.__liveWorkerObservation.loss) {
              return post(message, transfer);
            }
            const before = message.buffer.byteLength;
            const transferContainsBuffer = transfer.includes(message.buffer);
            post(message, transfer);
            const loss: NonNullable<Observation['loss']> = {
              mode: faultMode, before, after: message.buffer.byteLength, transferContainsBuffer,
              at: performance.now(), workerUrl: new URL(url, location.href).pathname,
            };
            injectedLoss = loss;
            target.__liveWorkerObservation.loss = loss;
            if (faultMode === 'timeout') {
              // Bypass the observed method so only the application's later
              // timeout-driven termination is recorded.
              terminate();
            } else if (faultMode === 'crash') {
              // Dispatch before terminating: WebKit drops synthetic events on
              // terminated Workers. A microtask runs before a worker response
              // can be delivered; the real error handler must terminate it.
              queueMicrotask(() => {
                this.dispatchEvent(new ErrorEvent('error', { message: 'Injected worker crash' }));
              });
            }
          },
        });
      }
    };
  }, mode);
  return injections;
}

function expectTrustedWorkerError(loss: NonNullable<Observation['loss']>): void {
  expect(loss.errorIsTrusted, 'the browser must dispatch the worker error').toBe(true);
}

function decodeMetadata(value: string | null): Record<string, string> {
  expect(value).toBeTruthy();
  return Object.fromEntries(value!.split(',').map((item) => {
    const [key, encoded] = item.trim().split(' ');
    expect(key).toBeTruthy();
    expect(encoded).toBeTruthy();
    return [key, Buffer.from(encoded, 'base64').toString('utf8')];
  }));
}

async function removePublishedFile(page: Page, filename: string, published: boolean): Promise<void> {
  const csrf = await page.request.get('/api/v1/public/csrf-token', { timeout: 15_000 });
  expect(csrf.ok()).toBe(true);
  const { csrf_token: token } = await csrf.json();
  expect(typeof token).toBe('string');
  expect(token.length).toBeGreaterThan(0);
  const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', {
    timeout: 15_000,
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': token },
    data: { path: filename },
  });
  expect(published ? [200, 204] : [200, 204, 404]).toContain(deleted.status());
  if (deleted.ok()) {
    const removed = await page.request.get(
      `/api/v1/auth/mcbrowser/download?path=${encodeURIComponent(filename)}`, { timeout: 15_000 },
    );
    expect(removed.status()).toBe(404);
  }
}

test.describe.configure({ retries: 0 });
for (const failure of ['crash', 'timeout', 'native-error'] as const) {
  test(`live TUS publishes the original file after a detached worker ${failure}`, async ({ page }, testInfo) => {
    test.setTimeout(240_000);
    const credentials = await isolatedCredentials();
    const injections = await installObservation(page, failure);
    const filename = `live-worker-${failure}-${randomBytes(12).toString('hex')}.bin`;
    const fixture = testInfo.outputPath(filename);
    let attemptedUpload = false;
    let published = false;
    let primaryError: unknown;
    const cleanupErrors: unknown[] = [];
    try {
      await mkdir(dirname(fixture), { recursive: true });
      await writeFile(fixture, randomBytes(FILE_SIZE));
      // This on-disk fixture, independently hashed by Node, is the oracle for
      // every chunk and for the final byte-for-byte download comparison.
      const source = await readFile(fixture);
      expect(source.length).toBe(FILE_SIZE);
      const fileHash = createHash('sha256').update(source).digest('hex');
      await signInLive(page, credentials.username, credentials.password);
      await page.goto('/?tab=mcbrowser', { waitUntil: 'domcontentloaded', timeout: 15_000 });
      await expect(page.getByRole('button', { name: 'Upload files', exact: true })).toBeEnabled();
      const workerUrl = await page.locator('meta[name="af-worker-url"]').getAttribute('content');
      expect(workerUrl).toBeTruthy();
      attemptedUpload = true;
      await page.getByLabel('Choose files to upload', { exact: true }).setInputFiles(fixture);
      const queue = page.getByRole('dialog', { name: 'Transfer queue', exact: true });
      await expect(queue).toContainText(filename);
      await expect(queue.getByText('Completed', { exact: true })).toBeVisible({ timeout: 150_000 });
      published = true;

      const observed = await page.evaluate(() =>
        (window as unknown as Window & { __liveWorkerObservation: Observation }).__liveWorkerObservation);
      expect(observed.loss).toBeDefined();
      expect(observed.loss).toMatchObject({
        mode: failure, before: CHUNK_SIZE, after: 0, workerUrl, transferContainsBuffer: true,
      });
      if (failure === 'native-error') {
        expect(injections).toHaveLength(1);
        expect(injections[0].pathname).toBe(workerUrl);
        expect(injections[0].originalSha256).toMatch(/^[0-9a-f]{64}$/);
      } else {
        expect(injections).toHaveLength(0);
      }
      const creates = observed.exchanges.filter((exchange) => exchange.method === 'POST');
      const patches = observed.exchanges.filter((exchange) => exchange.method === 'PATCH');
      const heads = observed.exchanges.filter((exchange) => exchange.method === 'HEAD');
      expect(creates).toHaveLength(1);
      expect(patches).toHaveLength(17);
      expect(heads).toHaveLength(2);
      const create = creates[0];
      expect(create.path).toBe(UPLOADS);
      expect(create.request['tus-resumable']).toBe('1.0.0');
      expect(create.request['upload-length']).toBe(String(FILE_SIZE));
      const metadata = decodeMetadata(create.request['upload-metadata']);
      expect(metadata.path).toBe(filename);
      expect(metadata.fingerprint).toBeTruthy();
      expect(create.response?.status).toBe(201);
      expect(create.response?.headers['tus-resumable']).toBe('1.0.0');
      expect(create.response?.headers['upload-offset']).toBe('0');
      const location = create.response?.headers.location;
      expect(location).toMatch(/^\/api\/v1\/auth\/mcbrowser\/uploads\/[0-9a-f]{32}$/);
      for (const [index, head] of heads.entries()) {
        expect(head.path).toBe(location);
        expect(head.request['tus-resumable']).toBe('1.0.0');
        expect(head.response?.status).toBe(200);
        expect(head.response?.headers['tus-resumable']).toBe('1.0.0');
        expect(head.response?.headers['upload-length']).toBe(String(FILE_SIZE));
        expect(head.response?.headers['upload-offset']).toBe(index === 0 ? '0' : String(FILE_SIZE));
        expect(head.response?.headers['upload-status']).toBe(index === 0 ? 'uploading' : 'completed');
        expect(decodeMetadata(head.response?.headers['upload-metadata'] ?? null)).toMatchObject(metadata);
      }
      expect(heads[1].response?.headers['upload-path']).toBe(filename);
      let offset = 0;
      for (const patch of patches) {
        const end = Math.min(offset + CHUNK_SIZE, source.length);
        const expectedDigest = createHash('sha256').update(source.subarray(offset, end)).digest('base64');
        expect(patch.path).toBe(location);
        expect(patch.request['tus-resumable']).toBe('1.0.0');
        expect(patch.request['content-type']).toBe('application/offset+octet-stream');
        expect(patch.request['upload-offset']).toBe(String(offset));
        expect(patch.request['upload-checksum']).toBe(`sha256 ${expectedDigest}`);
        expect(patch.body).toEqual({ length: end - offset, sha256: expectedDigest });
        expect(patch.response?.status).toBe(204);
        expect(patch.response?.headers['tus-resumable']).toBe('1.0.0');
        expect(patch.response?.headers['upload-offset']).toBe(String(end));
        offset = end;
      }
      expect(offset).toBe(FILE_SIZE);
      if (failure === 'timeout') {
        expect(observed.loss!.errorAt).toBeUndefined();
        expect(observed.loss!.terminatedAt).toBeDefined();
        expect(observed.loss!.terminatedAt! - observed.loss!.at).toBeGreaterThanOrEqual(15_000);
        expect(patches[0].startedAt - observed.loss!.at).toBeGreaterThanOrEqual(15_000);
      } else {
        expect(observed.loss!.errorAt).toBeDefined();
        expect(observed.loss!.errorAt!).toBeGreaterThanOrEqual(observed.loss!.at);
        expect(observed.loss!.terminatedAt).toBeGreaterThanOrEqual(observed.loss!.errorAt!);
        expect(patches[0].startedAt).toBeGreaterThanOrEqual(observed.loss!.terminatedAt!);
        expect(patches[0].sentAt).toBeGreaterThanOrEqual(patches[0].startedAt);
        expect(patches[0].responseAt).toBeGreaterThanOrEqual(patches[0].sentAt!);
        expect(patches[0].responseAt! - observed.loss!.at).toBeLessThan(15_000);
        if (failure === 'native-error') {
          expectTrustedWorkerError(observed.loss!);
          expect(observed.loss!.errorMessage).toContain(INJECTED_WORKER_ERROR);
        } else {
          // Negative control: this very same assertion rejects the page-created
          // ErrorEvent. It must not be accepted as a real worker-origin error.
          expect(observed.loss!.errorIsTrusted).toBe(false);
          expect(() => expectTrustedWorkerError(observed.loss!)).toThrow();
        }
      }
      console.log(`LIVE_WORKER_TIMING: ${JSON.stringify({
        failure, loss: observed.loss, firstPatch: patches[0], injections,
      })}`);
      const download = await page.request.get(
        `/api/v1/auth/mcbrowser/download?path=${encodeURIComponent(filename)}`, { timeout: 60_000 },
      );
      expect(download.status()).toBe(200);
      const downloaded = await download.body();
      expect(downloaded.length).toBe(source.length);
      expect(downloaded.equals(source)).toBe(true);
      expect(createHash('sha256').update(downloaded).digest('hex')).toBe(fileHash);
      console.log(`LIVE_WORKER_UPLOAD: ${failure} bytes=${source.length} chunks=${patches.length} sha256=${fileHash}`);
    } catch (error) {
      primaryError = error;
    } finally {
      // Keep observations in the report even when an assertion fails. Cleanup
      // failures are reported alongside, never in place of the primary failure.
      try {
        const observed = await page.evaluate(() =>
          (window as Window & { __liveWorkerObservation?: Observation }).__liveWorkerObservation);
        if (observed) await testInfo.attach('live-worker-observation', {
          body: Buffer.from(JSON.stringify({ ...observed, injections }, null, 2)), contentType: 'application/json',
        });
      } catch (error) { cleanupErrors.push(error); }
      if (attemptedUpload) {
        try { await removePublishedFile(page, filename, published); } catch (error) { cleanupErrors.push(error); }
      }
      try { await rm(fixture, { force: true }); } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) {
      const details = cleanupErrors.map((error) =>
        error instanceof Error ? error.stack || error.message : String(error)).join('\n\n');
      console.error(`LIVE_WORKER_CLEANUP_FAILURE:\n${details}`);
      if (primaryError === undefined) throw new Error(`Live worker cleanup failed:\n${details}`);
    }
    if (primaryError !== undefined) throw primaryError;
  });
}
