import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

test('applies the displayed bandwidth recommendation explicitly and reports daemon failures', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const applied: unknown[] = [];
  let reject = false;
  await page.route('**/api/v1/admin/ai/bandwidth/analyze', (route) => route.fulfill({ json: {
    reasoning: 'Keep capacity for active streams.', recommended_upload_kbps: 160, recommended_download_kbps: 960,
  } }));
  await page.route('**/api/v1/admin/ai/bandwidth/apply', (route) => {
    applied.push(route.request().postDataJSON());
    return reject ? route.fulfill({
      status: 502, json: { code: 'BAD_GATEWAY', error: 'Torrent daemon rejected RPC request' },
    }) : route.fulfill({ json: { message: 'Limits applied successfully to Torrent engine via RPC' } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Analyze bandwidth', exact: true }).click();
  await expect(page.getByText('RX 960 KiB/s · TX 160 KiB/s', { exact: true })).toBeVisible();
  expect(applied).toEqual([]);
  const apply = page.getByRole('button', { name: 'Apply bandwidth limits', exact: true });
  await apply.click();
  await expect(page.getByRole('status').filter({ hasText: 'Bandwidth limits applied' })).toBeVisible();
  expect(applied).toEqual([{ upload_kbps: 160, download_kbps: 960 }]);

  reject = true;
  await apply.click();
  await expect(page.getByRole('alert').filter({ hasText: 'Torrent daemon rejected RPC request' })).toBeVisible();
  await expect(apply).toBeEnabled();
  expect(applied).toHaveLength(2);
});

test('does not apply malformed recommendations or expose administrator actions to ordinary users', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let requests = 0;
  await page.route('**/api/v1/admin/ai/bandwidth/analyze', (route) => route.fulfill({ json: {
    reasoning: 'Invalid provider result', recommended_upload_kbps: -1,
  } }));
  await page.route('**/api/v1/admin/ai/bandwidth/apply', (route) => {
    requests += 1;
    return route.fulfill({ json: {} });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Analyze bandwidth', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Apply bandwidth limits', exact: true })).toBeDisabled();
  await expect(page.getByText('Invalid bandwidth recommendation', { exact: true })).toBeVisible();
  expect(requests).toBe(0);

  await page.route('**/api/v1/auth/session', (route) => route.fulfill({ json: {
    id: 2, username: 'member', role: 'user', is_oauth: false,
  } }));
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Analyze bandwidth', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Apply bandwidth limits', exact: true })).toHaveCount(0);
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  test(`keeps quantitative SVG chart labels readable at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    const labels = page.locator('.af-chart svg text');
    await expect(labels.first()).toBeVisible();
    const readSizes = () => labels.evaluateAll((elements) => elements.filter(element => {
      const box = element.getBoundingClientRect();
      return box.width > 0 && box.height > 0;
    }).map((element) => {
      const transform = (element as SVGTextElement).getScreenCTM();
      const scale = transform ? Math.hypot(transform.a, transform.b) : 0;
      return { text: element.textContent, cssPixels: parseFloat(getComputedStyle(element).fontSize) * scale };
    }));
    await expect.poll(async () => {
      const sizes = await readSizes();
      return sizes.length > 0 && sizes.every(size => Number.isFinite(size.cssPixels) && size.cssPixels >= 11.99);
    }).toBe(true);
    const sizes = await readSizes();
    expect(sizes.length).toBeGreaterThan(0);
    for (const size of sizes) expect(size.cssPixels, size.text || 'chart label').toBeGreaterThanOrEqual(11.99);
  });
}
