import { randomBytes } from 'node:crypto';
import { mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';

const SIZE = 64 * 1024 * 1024 + 17;
const CHUNK = 4 * 1024 * 1024;
type Observation = {
  held: boolean;
  aborted: boolean;
  discoveries: string[];
  creates: { policy: string; fingerprint: string; location: string | null; status: number }[];
  patches: { path: string; offset: number; status: number; acknowledged: number }[];
};

async function signIn(page: Page) {
  expect(process.env.AETHERFLOW_E2E_ISOLATED).toBe('1');
  expect(process.env.PRIVILEGED_RUNNER_ENABLED).toBe('false');
  expect(process.env.AETHERFLOW_DISABLE_BACKGROUND_WORKERS).toBe('1');
  expect(process.env.AETHERFLOW_SKIP_ENV_FILES).toBe('1');
  const database = await realpath(process.env.AETHERFLOW_DB_PATH || '');
  const root = dirname(dirname(database));
  expect(basename(root)).toMatch(/^aetherflow-embedded-e2e\.[A-Za-z0-9]+$/);
  expect(basename(dirname(database))).toBe('data');
  expect(basename(database)).toBe('aetherflow.sqlite');
  expect(await realpath(process.env.MCBROWSER_ROOT || '')).toBe(join(root, 'mcbrowser'));
  expect(process.env.BIND_ADDR).toBe('127.0.0.1');
  expect(process.env.PLAYWRIGHT_BASE_URL).toBe(`http://127.0.0.1:${process.env.PORT}`);
  expect(process.env.E2E_ADMIN_USER).toBeTruthy();
  expect(process.env.E2E_ADMIN_PASS).toBeTruthy();
  await page.goto('/login');
  await page.locator('input[type="text"]').first().fill(process.env.E2E_ADMIN_USER!);
  await page.locator('input[type="password"]').first().fill(process.env.E2E_ADMIN_PASS!);
  const submit = async () => {
    const result = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/public/auth/login'
        && response.request().method() === 'POST');
    await page.locator('button[type="submit"]').click();
    return result;
  };
  let response = await submit();
  if (response.status() === 429) {
    const delay = Number(response.headers()['retry-after']);
    expect(delay).toBeGreaterThan(0);
    expect(delay).toBeLessThanOrEqual(60);
    await page.waitForTimeout(delay * 1000);
    response = await submit();
  }
  expect(response.status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  const onboarding = page.getByRole('heading', { name: 'Welcome to AetherFlow' });
  if (await onboarding.isVisible()) {
    await page.getByRole('button', { name: /Continue/i }).click();
    await page.getByRole('button', { name: /Enter Dashboard/i }).click();
    await expect(onboarding).toHaveCount(0);
  }
}

async function mutationHeaders(page: Page) {
  const response = await page.request.get('/api/v1/public/csrf-token');
  expect(response.status()).toBe(200);
  const { csrf_token: token } = await response.json();
  expect(typeof token).toBe('string');
  expect(token.length).toBeGreaterThan(0);
  return { 'X-CSRF-Token': token, 'X-Requested-With': 'XMLHttpRequest' };
}

async function observeAndHoldFirstAcknowledgement(page: Page) {
  await page.addInitScript(() => {
    const target = window as Window & { __uploadPolicy?: Observation };
    const observed: Observation = { held: false, aborted: false, discoveries: [], creates: [], patches: [] };
    target.__uploadPolicy = observed;
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const request = new Request(input instanceof Request ? input.clone() : input, init);
      const url = new URL(request.url);
      if (!url.pathname.startsWith('/api/v1/auth/mcbrowser/uploads')) return nativeFetch(input, init);
      if (request.method === 'GET') observed.discoveries.push(url.searchParams.get('fingerprint') ?? '');
      const response = await nativeFetch(input, init);
      if (request.method === 'POST') {
        const entry = request.headers.get('upload-metadata')?.split(',')
          .find((item) => item.trim().startsWith('fingerprint '))?.trim().split(' ')[1];
        observed.creates.push({
          policy: request.headers.get('x-upload-conflict') ?? '', fingerprint: entry ? atob(entry) : '',
          location: response.headers.get('location'), status: response.status,
        });
      }
      if (request.method === 'PATCH') {
        observed.patches.push({ path: url.pathname, offset: Number(request.headers.get('upload-offset')),
          status: response.status, acknowledged: Number(response.headers.get('upload-offset')) });
        if (!observed.held && response.ok) {
          // The real API has durably accepted one chunk. Delay only delivery
          // of that acknowledgement so Pause can abort this pending fetch.
          // Never replace a request body, upload response or server decision.
          const signal = init?.signal ?? request.signal;
          await new Promise<void>((_resolve, reject) => {
            const abort = () => {
              observed.aborted = true;
              reject(new DOMException('Paused acknowledgement', 'AbortError'));
            };
            signal?.addEventListener('abort', abort, { once: true });
            observed.held = true;
            if (signal?.aborted) abort();
          });
        }
      }
      return response;
    };
  });
}

test.describe.configure({ retries: 0 });
for (const policy of ['skip', 'error', 'overwrite'] as const) {
  test(`a paused overwrite session respects a newly queued ${policy} policy`, async ({ page }, testInfo) => {
    test.setTimeout(180_000);
    page.setDefaultTimeout(15_000);
    await signIn(page);
    await observeAndHoldFirstAcknowledgement(page);
    const filename = `policy-${policy}-${randomBytes(10).toString('hex')}.bin`;
    const fixture = testInfo.outputPath(filename);
    const original = Buffer.from('Existing contents must survive Skip or Reject.');
    const headers = await mutationHeaders(page);
    let originalSession: string | undefined;
    let createdTarget = false;
    let primaryError: unknown;
    const cleanupErrors: unknown[] = [];
    try {
      await mkdir(dirname(fixture), { recursive: true });
      await writeFile(fixture, randomBytes(SIZE));
      const created = await page.request.put(`/api/v1/auth/mcbrowser/upload?path=${encodeURIComponent(filename)}`, {
        headers: { ...headers, 'Content-Type': 'application/octet-stream' }, data: original,
      });
      createdTarget = true;
      expect(created.status()).toBe(201);
      await page.goto('/?tab=mcbrowser');
      await page.getByLabel('Large upload conflicts').selectOption('overwrite');
      const choose = page.getByLabel('Choose files to upload', { exact: true });
      await choose.setInputFiles(fixture);
      const queue = page.getByRole('dialog', { name: 'Transfer queue', exact: true });
      const rows = queue.getByText(filename, { exact: true }).locator('..');
      await expect.poll(() => page.evaluate(() =>
        (window as Window & { __uploadPolicy?: Observation }).__uploadPolicy?.held)).toBe(true);
      await rows.first().getByRole('button', { name: 'Pause', exact: true }).click();
      await expect(rows.first().getByText('Paused', { exact: true })).toBeVisible();
      const paused = await page.evaluate(() => (window as Window & { __uploadPolicy?: Observation }).__uploadPolicy!);
      expect(paused.aborted).toBe(true);
      expect(paused.creates).toHaveLength(1);
      expect(paused.patches).toHaveLength(1);
      expect(paused.patches[0]).toMatchObject({ offset: 0, acknowledged: CHUNK, status: 204 });
      originalSession = paused.creates[0].location!;
      expect(originalSession).toMatch(/^\/api\/v1\/auth\/mcbrowser\/uploads\/[0-9a-f]{32}$/);
      const download = () => page.request.get(`/api/v1/auth/mcbrowser/download?path=${encodeURIComponent(filename)}`);
      expect((await (await download()).body()).equals(original)).toBe(true);

      await queue.getByRole('button', { name: 'Close dialog', exact: true }).click();
      await expect(queue).not.toBeVisible();
      await page.getByLabel('Large upload conflicts').selectOption(policy);
      // Clearing permits selecting the identical on-disk File again, with the
      // same size, modification time, contents and target path.
      await choose.setInputFiles([]);
      await choose.setInputFiles(fixture);
      await expect(rows).toHaveCount(2);
      await expect(rows.nth(1).getByText(policy === 'error' ? 'Failed' : 'Completed', { exact: true }))
        .toBeVisible({ timeout: 60_000 });
      await expect(rows.first().getByText('Paused', { exact: true })).toBeVisible();
      const published = await download();
      expect(published.status()).toBe(200);
      const expected = policy === 'overwrite' ? await readFile(fixture) : original;
      expect((await published.body()).equals(expected), 'Published bytes must honor the new job policy').toBe(true);
      const observed = await page.evaluate(() => (window as Window & { __uploadPolicy?: Observation }).__uploadPolicy!);
      expect(observed.discoveries).toHaveLength(2);
      if (policy === 'overwrite') {
        expect(observed.discoveries[1]).toBe(observed.discoveries[0]);
        expect(observed.creates).toHaveLength(1);
        expect(observed.patches).toHaveLength(17);
        expect(observed.patches.map((patch) => patch.offset)).toEqual(
          Array.from({ length: 17 }, (_, index) => index * CHUNK));
        expect(observed.patches.every((patch) => patch.path === originalSession && patch.status === 204)).toBe(true);
      } else {
        expect(observed.discoveries[1]).not.toBe(observed.discoveries[0]);
        expect(observed.creates).toHaveLength(2);
        expect(observed.creates[1]).toMatchObject({ policy, status: policy === 'error' ? 409 : 201 });
        expect(observed.patches).toHaveLength(1);
        const retained = await page.request.head(originalSession, { headers: { 'Tus-Resumable': '1.0.0' } });
        expect(retained.status()).toBe(200);
        expect(retained.headers()['upload-offset']).toBe(String(CHUNK));
        expect(retained.headers()['upload-status']).toBe('uploading');
      }
    } catch (error) {
      primaryError = error;
    } finally {
      try {
        const observed = await page.evaluate(() => (window as Window & { __uploadPolicy?: Observation }).__uploadPolicy);
        if (observed) await testInfo.attach('upload-policy-observation', {
          body: Buffer.from(JSON.stringify(observed, null, 2)), contentType: 'application/json',
        });
      } catch (error) { cleanupErrors.push(error); }
      let cleanupHeaders: Record<string, string> | undefined;
      if (originalSession || createdTarget) {
        try { cleanupHeaders = await mutationHeaders(page); } catch (error) { cleanupErrors.push(error); }
      }
      if (originalSession && policy !== 'overwrite') {
        try {
          if (!cleanupHeaders) throw new Error('Current cleanup CSRF token is unavailable');
          const deleted = await page.request.delete(originalSession, { headers: { ...cleanupHeaders, 'Tus-Resumable': '1.0.0' } });
          if (primaryError === undefined) expect(deleted.status()).toBe(204);
          else expect([204, 409]).toContain(deleted.status());
        } catch (error) { cleanupErrors.push(error); }
      }
      if (createdTarget) {
        try {
          if (!cleanupHeaders) throw new Error('Current cleanup CSRF token is unavailable');
          const deleted = await page.request.post('/api/v1/auth/mcbrowser/delete-recursive', {
            headers: { ...cleanupHeaders, 'Content-Type': 'application/json' }, data: { path: filename },
          });
          expect(deleted.status()).toBe(200);
          const missing = await page.request.get(`/api/v1/auth/mcbrowser/download?path=${encodeURIComponent(filename)}`);
          expect(missing.status()).toBe(404);
        } catch (error) { cleanupErrors.push(error); }
      }
      try { await rm(fixture, { force: true }); } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) {
      const details = cleanupErrors.map((error) =>
        error instanceof Error ? error.stack || error.message : String(error)).join('\n\n');
      console.error(`UPLOAD_POLICY_CLEANUP_FAILURE:\n${details}`);
      if (primaryError === undefined) throw new Error(`Upload policy cleanup failed:\n${details}`);
    }
    if (primaryError !== undefined) throw primaryError;
  });
}
