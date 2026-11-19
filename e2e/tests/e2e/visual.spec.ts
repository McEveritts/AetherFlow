import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('renders the login glass shell consistently @visual', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
  await stabilizeVisuals(page);

  await page.goto('/login');
  await expect(page).toHaveScreenshot('login-glass-shell.png', { fullPage: true });
});

test('renders the marketplace glass cards consistently @visual', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true });
  await stabilizeVisuals(page);

  await page.goto('/');
  await page.locator('aside').first().hover();
  await page.getByRole('button', { name: 'Marketplace' }).click();
  await expect(page.getByText('AetherMarketplace')).toBeVisible();

  await expect(page).toHaveScreenshot('marketplace-glass-cards.png', { fullPage: true });
});
