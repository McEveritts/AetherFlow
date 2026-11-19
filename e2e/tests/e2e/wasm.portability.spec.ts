import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type ArchiveWindow = Window & {
  releaseArchiveBlob?: () => void;
  archiveBlobResolved?: boolean;
  archiveDownloads?: number;
};

for (const transition of ['account', 'role', 'subtab', 'tab', 'none'] as const) {
  test(`native streaming archive completion respects ${transition} lifetime`, async ({ page }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let identity = 1;
    let role = 'admin';
    await page.route('**/api/v1/auth/session', route => route.fulfill({ json: {
      id: identity, username: identity === 1 ? 'alice' : 'bob', role, is_oauth: false,
    } }));
    const archive = JSON.stringify({ manifest: { format: 'aetherflow.streaming-history' }, data: { private_history: ['alice-playback'] } });
    await page.route('**/api/v1/auth/streaming/**', route => route.fulfill({ json: {} }));
    await page.route('**/api/v1/admin/streaming/**', route => route.fulfill({ json: {} }));
    await page.route('**/api/v1/admin/streaming/portability/export', route => route.fulfill({
      status: 200, contentType: 'application/json', body: archive,
    }));
    await page.addInitScript(() => {
      const target = window as ArchiveWindow;
      target.archiveDownloads = 0;
      const click = HTMLElement.prototype.click;
      HTMLElement.prototype.click = function () {
        if (this instanceof HTMLAnchorElement && this.download === 'aetherflow-streaming-archive.json') target.archiveDownloads!++;
        click.call(this);
      };
      const originalBlob = Response.prototype.blob;
      Response.prototype.blob = function () {
        if (!this.url.includes('/streaming/portability/export')) return originalBlob.call(this);
        // Read the real body before holding delivery: aborting its controller
        // later cannot stand in for the application's final ownership check.
        return originalBlob.call(this).then(blob => new Promise<Blob>(resolve => {
          target.releaseArchiveBlob = () => {
            resolve(blob);
            target.archiveBlobResolved = true;
          };
        }));
      };
    });
    await page.goto('/?tab=streaming');
    const administration = page.getByRole('tab', { name: 'History administration', exact: true });
    await administration.click();
    await page.locator('summary').filter({ hasText: /^Portable archive export \/ restore$/ }).click();
    const exportButton = page.getByRole('button', { name: 'Export native JSON archive', exact: true });
    await exportButton.click();
    await expect.poll(() => page.evaluate(() => typeof (window as ArchiveWindow).releaseArchiveBlob)).toBe('function');
    if (transition === 'account' || transition === 'role') {
      if (transition === 'account') identity = 2;
      role = 'user';
      await page.evaluate((change) => {
        window.dispatchEvent(change === 'account'
          ? new StorageEvent('storage', { key: 'af_login_sync' })
          : new CustomEvent('af:session-expired'));
      }, transition);
      await expect(administration).toHaveCount(0);
      await expect(exportButton).toHaveCount(0);
    } else if (transition === 'subtab') {
      await page.getByRole('tab', { name: 'Active playback sessions', exact: true }).click();
      await expect(exportButton).toHaveCount(0);
    } else if (transition === 'tab') {
      await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
      await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
      await expect(exportButton).toHaveCount(0);
    }
    const download = transition === 'none' ? page.waitForEvent('download') : undefined;
    await page.evaluate(() => (window as ArchiveWindow).releaseArchiveBlob!());
    await expect.poll(() => page.evaluate(() => (window as ArchiveWindow).archiveBlobResolved)).toBe(true);
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    expect(await page.evaluate(() => (window as ArchiveWindow).archiveDownloads)).toBe(transition === 'none' ? 1 : 0);
    if (download) {
      const result = await download;
      expect(result.suggestedFilename()).toBe('aetherflow-streaming-archive.json');
      const path = await result.path();
      expect(path).not.toBeNull();
      expect(await readFile(path!, 'utf8')).toBe(archive);
      await expect(exportButton).toBeEnabled();
    }
    expect(pageErrors).toEqual([]);
  });
}
