import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('navigates between overview, services, marketplace, and settings', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await stabilizeVisuals(page);

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  const sidebar = page.locator('#desktop-sidebar-navigation');
  await sidebar.hover();
  const expandLogo = sidebar.getByRole('button', { name: 'Expand Sidebar' });
  await expect(expandLogo).toHaveAttribute('aria-expanded', 'false');

  await page.getByRole('button', { name: 'Services' }).click();
  await expect(page.getByRole('heading', { name: 'Services' })).toBeVisible();
  await expect(page.getByText('Core Platform')).toBeVisible();
  await expect(expandLogo).toHaveAttribute('aria-expanded', 'false');

  await expandLogo.click();
  const collapseLogo = sidebar.getByRole('button', { name: 'Collapse Sidebar' });
  await expect(collapseLogo).toHaveAttribute('aria-expanded', 'true');

  await page.getByRole('button', { name: 'Marketplace' }).click();
  await expect(page.getByText('AetherMarketplace')).toBeVisible();
  await expect(page.getByText('Sonarr')).toBeVisible();

  await collapseLogo.click();
  await expect(expandLogo).toHaveAttribute('aria-expanded', 'false');

  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.getByText('System Updates')).toBeVisible();
});
