import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('renders the login flat shell consistently @visual', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
  await stabilizeVisuals(page);

  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Unlock the Aether' })).toBeVisible();
  await expect(page).toHaveScreenshot('login-flat-shell.png', { fullPage: true });
});

test('renders the marketplace flat cards consistently @visual', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true });
  await stabilizeVisuals(page);

  await page.goto('/');
  await page.locator('aside').first().hover();
  await page.getByRole('button', { name: 'Marketplace' }).click();
  await expect(page.getByRole('heading', { name: 'AetherMarketplace' })).toBeVisible();
  await expect(page.getByText('Update v4.0.1', { exact: true })).toBeVisible();

  await expect(page).toHaveScreenshot('marketplace-flat-cards.png', { fullPage: true });
});
