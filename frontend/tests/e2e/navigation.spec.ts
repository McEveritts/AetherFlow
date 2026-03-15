import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('navigates between overview, services, marketplace, and settings', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await stabilizeVisuals(page);

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  const sidebar = page.locator('aside').first();
  await sidebar.hover();

  await page.getByRole('button', { name: 'Services' }).click();
  await expect(page.getByRole('heading', { name: 'Services' })).toBeVisible();
  await expect(page.getByText('Core Platform')).toBeVisible();

  await sidebar.hover();
  await page.getByRole('button', { name: 'Marketplace' }).click();
  await expect(page.getByText('AetherMarketplace')).toBeVisible();
  await expect(page.getByText('Sonarr')).toBeVisible();

  await sidebar.hover();
  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.getByText('System Updates')).toBeVisible();
});
