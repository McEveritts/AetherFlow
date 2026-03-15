import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('creates the first admin account from the setup login flow', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: true });
  await stabilizeVisuals(page);

  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Create Admin Account' })).toBeVisible();

  await page.getByPlaceholder('Choose a Username').fill('admin');
  await page.getByPlaceholder('Choose a Password (min 6 chars)').fill('supersafepassword');
  await page.getByRole('button', { name: 'Create Account & Enter' }).click();

  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
});

test('logs into the dashboard with local auth', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
  await stabilizeVisuals(page);

  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Access Nexus' })).toBeVisible();

  await page.getByPlaceholder('Username').fill('admin');
  await page.getByPlaceholder('Password').fill('supersafepassword');
  await page.getByRole('button', { name: 'Unlock the Aether' }).click();

  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
});
