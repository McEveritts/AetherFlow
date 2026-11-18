import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';
import { reads, trackReads } from './support/readProbe';

const token = 'share-directory-fixture';
const endpoint = `/api/v1/public/mcbrowser/shares/${token}`;

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

function listing(path: string, filename = 'report.txt') {
  const entries = [{ name: filename, path: path ? `${path}/${filename}` : filename, is_directory: false, size: 12 }];
  if (!path) entries.push({ name: 'docs', path: 'docs', is_directory: true, size: 0 });
  return { path, entries };
}

async function installShare(page: Page, entries: (route: Route, path: string) => Promise<void>, allowDownload = true) {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
  const downloads: string[] = [];
  await page.route(`**${endpoint}**`, async route => {
    const url = new URL(route.request().url());
    const path = url.searchParams.get('path') ?? '';
    if (url.pathname.endsWith('/entries')) {
      await entries(route, path);
    } else if (url.pathname.endsWith('/download')) {
      downloads.push(path);
      await route.fulfill({ contentType: 'text/plain', body: `Contents of ${path}` });
    } else {
      await route.fulfill({ json: {
        name: 'Shared documents', is_directory: true, allow_download: allowDownload, password_required: false,
      } });
    }
  });
  return downloads;
}

const report = (page: Page) => page.getByRole('button', { name: /^◇ report\.txt/ });
const docs = (page: Page) => page.getByRole('button', { name: /^▱ docs/ });
const parent = (page: Page) => page.getByRole('button', { name: '↑ Parent', exact: true });
const download = (page: Page) => page.getByRole('link', { name: 'Download', exact: true });

test('entering a shared folder disables old rows until the matching listing commits', async ({ page }) => {
  const started = deferred();
  const release = deferred();
  const downloads = await installShare(page, async (route, path) => {
    if (path === 'docs') {
      started.resolve();
      await release.promise;
    }
    await route.fulfill({ json: listing(path) });
  });
  try {
    await page.goto(`/share?token=${token}`);
    await expect(report(page)).toBeEnabled();
    await report(page).click();
    await expect(page.locator('pre')).toHaveText('Contents of report.txt');
    await docs(page).click();
    await started.promise;
    await expect(page.locator('main ul')).toHaveAttribute('aria-busy', 'true');
    // A queued click on a retained old DOM row cannot reinterpret its filename.
    await report(page).evaluate(button => (button as HTMLButtonElement).click());
    await expect(download(page)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Preview', exact: true })).toBeDisabled();
    await expect(page.locator('pre')).toHaveCount(0);
    await expect(report(page)).toBeDisabled();
    expect(downloads).toEqual(['report.txt']);
    release.resolve();
    await expect(report(page)).toBeEnabled();
    await report(page).click();
    await expect(page.locator('pre')).toHaveText('Contents of docs/report.txt');
    await expect(download(page)).toHaveAttribute('href', `${endpoint}/download?path=docs%2Freport.txt`);
    expect(downloads).toEqual(['report.txt', 'docs/report.txt']);
  } finally {
    release.resolve();
  }
});

test('Parent navigation invalidates the selected file while the root listing is delayed', async ({ page }) => {
  const started = deferred();
  const release = deferred();
  let rootReads = 0;
  const downloads = await installShare(page, async (route, path) => {
    if (!path && ++rootReads === 2) {
      started.resolve();
      await release.promise;
    }
    await route.fulfill({ json: listing(path) });
  });
  try {
    await page.goto(`/share?token=${token}`);
    await docs(page).click();
    await expect(report(page)).toBeEnabled();
    await report(page).click();
    await expect(page.locator('pre')).toHaveText('Contents of docs/report.txt');
    await parent(page).click();
    await started.promise;
    await report(page).evaluate(button => (button as HTMLButtonElement).click());
    await expect(download(page)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Preview', exact: true })).toBeDisabled();
    await expect(page.locator('pre')).toHaveCount(0);
    await expect(report(page)).toBeDisabled();
    expect(downloads).toEqual(['docs/report.txt']);
    release.resolve();
    await expect(report(page)).toBeEnabled();
    await report(page).click();
    await expect(page.locator('pre')).toHaveText('Contents of report.txt');
    expect(downloads).toEqual(['docs/report.txt', 'report.txt']);
  } finally {
    release.resolve();
  }
});

test('directory shares offer no file transfer before selection and after folder changes', async ({ page }) => {
  const downloads = await installShare(page, async (route, path) => {
    await route.fulfill({ json: listing(path) });
  });
  await page.goto(`/share?token=${token}`);
  await expect(report(page)).toBeEnabled();
  const preview = page.getByRole('button', { name: 'Preview', exact: true });
  await expect(preview).toBeDisabled();
  await expect(download(page)).toHaveCount(0);
  await report(page).click();
  await expect(page.locator('pre')).toHaveText('Contents of report.txt');
  await docs(page).click();
  await expect(preview).toBeDisabled();
  await expect(download(page)).toHaveCount(0);
  await expect(page.locator('pre')).toHaveCount(0);
  await expect(report(page)).toBeEnabled();
  expect(downloads).toEqual(['report.txt']);
  await report(page).click();
  await expect(download(page)).toHaveAttribute('href', `${endpoint}/download?path=docs%2Freport.txt`);
});

test('browsing-only directory shares retain folder browsing without download or preview requests', async ({ page }) => {
  const downloads = await installShare(page, async (route, path) => {
    await route.fulfill({ json: listing(path) });
  }, false);
  await page.goto(`/share?token=${token}`);
  await expect(report(page)).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Preview', exact: true })).toHaveCount(0);
  await expect(download(page)).toHaveCount(0);
  await docs(page).click();
  await expect(parent(page)).toBeEnabled();
  await expect(report(page)).toBeDisabled();
  // Programmatic activation of a disabled file row must remain inert too.
  await report(page).evaluate(button => (button as HTMLButtonElement).click());
  await parent(page).click();
  await expect(docs(page)).toBeEnabled();
  expect(downloads).toEqual([]);
});

for (const outcome of ['success', 'error'] as const) {
  test(`a cancelled shared-folder ${outcome} cannot replace a newer visit to the same folder`, async ({ page }) => {
    const entriesPath = `${endpoint}/entries`;
    await trackReads(page, [entriesPath]);
    const started = deferred();
    const settled = deferred();
    const release = deferred();
    let docsReads = 0;
    await installShare(page, async (route, path) => {
      if (path === 'docs' && ++docsReads === 1) {
        started.resolve();
        await release.promise;
        await route.fulfill(outcome === 'error'
          ? { status: 410, json: { error: 'Expired old request' } }
          : { json: listing(path, 'obsolete.txt') }).catch(() => {});
        settled.resolve();
        return;
      }
      await route.fulfill({ json: listing(path, path ? 'café.txt' : 'report.txt') });
    });
    try {
      await page.goto(`/share?token=${token}`);
      await docs(page).click();
      await started.promise;
      await parent(page).click();
      await expect(docs(page)).toBeEnabled();
      await docs(page).click();
      const latest = page.getByRole('button', { name: /^◇ café\.txt/ });
      await expect(latest).toBeEnabled();
      const state = await reads(page, entriesPath);
      expect(state.maximum).toBe(1);
      expect(state.attempts.filter(attempt => attempt.url.endsWith('?path=docs')).map(attempt => attempt.outcome))
        .toEqual(['aborted', 'finished']);
      release.resolve();
      await settled.promise;
      await expect(latest).toBeEnabled();
      await expect(page.getByRole('alert')).toHaveCount(0);
      await expect(page.getByRole('button', { name: /obsolete\.txt/ })).toHaveCount(0);
      await latest.click();
      await expect(page.locator('pre')).toHaveText('Contents of docs/café.txt');
      await expect(download(page)).toHaveAttribute('href', `${endpoint}/download?path=docs%2Fcaf%C3%A9.txt`);
      await expect(download(page)).toHaveAttribute('download', 'café.txt');
    } finally {
      release.resolve();
    }
  });
}

test('a failed current shared-directory listing can be retried without reviving stale rows', async ({ page }) => {
  let docsReads = 0;
  await installShare(page, async (route, path) => {
    if (path === 'docs' && ++docsReads === 1) {
      await route.fulfill({ status: 404, json: { error: 'Unavailable directory' } });
      return;
    }
    await route.fulfill({ json: listing(path) });
  });
  await page.goto(`/share?token=${token}`);
  await docs(page).click();
  await expect(page.getByRole('alert')).toHaveText('This shared link has expired or is no longer available.');
  await expect(page.locator('main ul')).toHaveAttribute('aria-busy', 'false');
  await expect(report(page)).toBeDisabled();
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(report(page)).toBeEnabled();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await report(page).click();
  await expect(page.locator('pre')).toHaveText('Contents of docs/report.txt');
});

for (const pending of ['metadata', 'listing'] as const) {
  test(`same-document share token change cancels pending ${pending}`, async ({ page }) => {
    const oldPath = pending === 'metadata' ? endpoint : `${endpoint}/entries`;
    const otherToken = 'another-share-fixture';
    const otherEndpoint = `/api/v1/public/mcbrowser/shares/${otherToken}`;
    const started = deferred();
    const release = deferred();
    await trackReads(page, [oldPath]);
    await installShare(page, route => route.fulfill({ json: listing('') }));
    await page.route(`**${oldPath}${pending === 'listing' ? '?*' : ''}`, async route => {
      started.resolve();
      await release.promise;
      await route.fulfill({ json: {} }).catch(() => {});
    });
    await page.route(`**${otherEndpoint}`, route => route.fulfill({ json: { name: 'Another share' } }));
    try {
      await page.goto(`/share?token=${token}`);
      await started.promise;
      await page.evaluate(otherToken => {
        const current = location.href;
        history.replaceState(null, '', `/share?token=${otherToken}`);
        history.pushState(null, '', current);
        history.back();
      }, otherToken);
      await expect(page.getByText('Another share', { exact: true })).toBeVisible();
      await expect.poll(async () => (await reads(page, oldPath)).attempts.map(attempt => attempt.outcome))
        .toEqual(['aborted']);
      await expect(page.getByRole('alert')).toHaveCount(0);
    } finally {
      release.resolve();
    }
  });
}
