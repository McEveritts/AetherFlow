import { createHash } from 'node:crypto';
import { mkdir, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type WorkerLoss = {
  before: number; after: number; mode: string; at: number;
  errorAt?: number; terminatedAt?: number; firstPatchAt?: number;
};

for (const failure of ['crash', 'timeout'] as const) {
  test(`preserves upload checksums after worker ${failure} detaches its buffer`, async ({ page }, testInfo) => {
    test.setTimeout(90_000);
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.addInitScript((mode) => {
      Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 1 });
      const target = window as Window & {
        __workerLoss?: WorkerLoss;
        __uploadBodies?: { length: number; offset: number; digest: string; unchanged: boolean }[];
      };
      target.__uploadBodies = [];
      const nativeFetch = window.fetch.bind(window);
      window.fetch = async (input, init) => {
        const request = input instanceof Request ? new Request(input.clone(), init) : new Request(input, init);
        if (request.method === 'PATCH' && new URL(request.url).pathname.includes('/mcbrowser/uploads/')) {
          if (target.__workerLoss) target.__workerLoss.firstPatchAt ??= performance.now();
          // WebKit's Playwright protocol omits Blob POST bodies. Observe the
          // actual Request before forwarding it, without replacing its body.
          const bytes = new Uint8Array(await request.clone().arrayBuffer());
          const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
          target.__uploadBodies!.push({
            length: bytes.length, offset: Number(request.headers.get('Upload-Offset')),
            digest: btoa(String.fromCharCode(...digest)), unchanged: bytes.every((byte) => byte === 0xa7),
          });
        }
        return nativeFetch(input, init);
      };
      window.Worker = class extends Worker {
        constructor(url: string | URL, options?: WorkerOptions) {
          super(url, options);
          const post = this.postMessage.bind(this);
          const terminate = this.terminate.bind(this);
          let injectedLoss: WorkerLoss | undefined;
          Object.defineProperty(this, 'terminate', {
            value: () => {
              if (injectedLoss) injectedLoss.terminatedAt ??= performance.now();
              return terminate();
            },
          });
          Object.defineProperty(this, 'postMessage', {
            value: (message: { type?: string; buffer?: ArrayBuffer }, transfer: Transferable[]) => {
              if (message.type !== 'Sha256ChunkTransfer' || message.buffer?.byteLength !== 4 * 1024 * 1024 || target.__workerLoss) {
                return post(message, transfer);
              }
              const before = message.buffer!.byteLength;
              post(message, transfer);
              const loss = { before, after: message.buffer!.byteLength, mode, at: performance.now() } as WorkerLoss;
              target.__workerLoss = injectedLoss = loss;
              if (mode === 'timeout') {
                // Silence the real worker; its later application-driven
                // timeout termination is observed by the wrapper above.
                terminate();
              } else {
                // WebKit drops events dispatched after termination. Deliver
                // the error before a response, then require app termination.
                queueMicrotask(() => {
                  loss.errorAt = performance.now();
                  this.dispatchEvent(new ErrorEvent('error', { message: 'Injected worker crash' }));
                });
              }
            },
          });
        }
      };
    }, failure);

    // Cross the 64 MiB direct-upload boundary so production chooses Tus and
    // hashes real Blob slices through the WASM worker pool.
    const size = 64 * 1024 * 1024 + 17;
    const filename = `worker-${failure}.bin`;
    let offset = 0;
    let metadata = '';
    let chunks = 0;
    await page.route('**/api/v1/auth/mcbrowser/**', async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path.endsWith('/entries')) {
        return route.fulfill({ json: { path: '', entries: [] } });
      }
      if (path.endsWith('/policy')) {
        return route.fulfill({ json: { scope: 'private', permissions: { read: true, create: true, modify: true }, rules: [] } });
      }
      if (path.endsWith('/usage')) {
        return route.fulfill({ json: { used_bytes: 0, quota_bytes: size * 2 } });
      }
      if (path.endsWith('/uploads') && request.method() === 'GET') {
        return route.fulfill({ json: { uploads: [] } });
      }
      if (path.endsWith('/uploads') && request.method() === 'POST') {
        expect(Number(request.headers()['upload-length'])).toBe(size);
        metadata = request.headers()['upload-metadata'];
        return route.fulfill({ status: 201, headers: { Location: '/api/v1/auth/mcbrowser/uploads/0123456789abcdef0123456789abcdef' } });
      }
      if (path.endsWith('/uploads/0123456789abcdef0123456789abcdef')) {
        if (request.method() === 'PATCH') {
          const body = await page.evaluate((index) => (window as Window & {
            __uploadBodies?: { length: number; offset: number; digest: string; unchanged: boolean }[];
          }).__uploadBodies?.[index], chunks);
          expect(body).toBeDefined();
          expect(Number(request.headers()['upload-offset'])).toBe(offset);
          const length = Math.min(4 * 1024 * 1024, size - offset);
          const expectedDigest = createHash('sha256').update(Buffer.alloc(length, 0xa7)).digest('base64');
          expect(body).toEqual({ length, offset, digest: expectedDigest, unchanged: true });
          expect(request.headers()['upload-checksum']).toBe(`sha256 ${expectedDigest}`);
          const bytes = request.postDataBuffer();
          if (bytes) expect(bytes.equals(Buffer.alloc(length, 0xa7))).toBe(true);
          offset += length;
          chunks += 1;
        } else {
          expect(request.method()).toBe('HEAD');
        }
        return route.fulfill({
          status: request.method() === 'HEAD' ? 200 : 204,
          headers: {
            'Tus-Resumable': '1.0.0', 'Upload-Offset': String(offset), 'Upload-Length': String(size),
            'Upload-Metadata': metadata, 'Upload-Status': offset === size ? 'completed' : 'uploading',
            'Upload-Path': filename,
          },
        });
      }
      return route.fulfill({ json: {} });
    });

    const fixture = testInfo.outputPath(filename);
    await mkdir(dirname(fixture), { recursive: true });
    await writeFile(fixture, Buffer.alloc(size, 0xa7));
    try {
      await page.goto('/?tab=mcbrowser');
      await expect(page.getByRole('button', { name: 'Upload files', exact: true })).toBeEnabled();
      await page.getByLabel('Choose files to upload', { exact: true }).setInputFiles(fixture);
      await expect(page.getByText('Completed', { exact: true })).toBeVisible({ timeout: 60_000 });
      expect(offset).toBe(size);
      expect(chunks).toBe(17);
      const loss = await page.evaluate(() => (window as Window & { __workerLoss?: WorkerLoss }).__workerLoss);
      expect(loss).toMatchObject({
        before: 4 * 1024 * 1024, after: 0, mode: failure,
      });
      expect(loss!.terminatedAt).toBeDefined();
      if (failure === 'crash') {
        expect(loss!.errorAt).toBeDefined();
        expect(loss!.terminatedAt!).toBeGreaterThanOrEqual(loss!.errorAt!);
        expect(loss!.firstPatchAt! - loss!.at).toBeLessThan(15_000);
      } else {
        expect(loss!.errorAt).toBeUndefined();
        expect(loss!.firstPatchAt! - loss!.at).toBeGreaterThanOrEqual(15_000);
      }
    } finally {
      await unlink(fixture);
    }
  });
}
