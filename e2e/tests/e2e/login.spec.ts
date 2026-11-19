import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('creates the first admin account from the setup login flow', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: true });
  await stabilizeVisuals(page);

  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Create Admin Account' })).toBeVisible();

  await page.getByPlaceholder('Choose a Username').fill('admin');
  await page.getByPlaceholder('Choose a Password (min 8 chars)').fill('supersafepassword');
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

for (const password of ['密码ab', 'éééé', '🔐🔐']) {
  test(`setup accepts a multibyte password with eight UTF-8 bytes: ${password}`, async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: false, setupRequired: true });
    const submitted: unknown[] = [];
    await page.route('**/api/v1/public/auth/setup', async route => {
      submitted.push(route.request().postDataJSON());
      await route.fallback();
    });
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Create Admin Account' })).toBeVisible();
    await page.locator('#username').fill('admin');
    await page.locator('#password').pressSequentially(password);
    await page.getByRole('button', { name: 'Create Account & Enter' }).click();
    await expect.poll(() => submitted).toEqual([{ username: 'admin', password }]);
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });
}

test('setup reports a short password in the localized application alert', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: true });
  let submissions = 0;
  await page.route('**/api/v1/public/auth/setup', async route => {
    submissions++;
    await route.fallback();
  });
  await page.goto('/login');
  await expect(page.locator('#username')).toBeVisible();
  await page.locator('select.af-locale-select').selectOption('fr');
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  await page.locator('#username').fill('admin');
  await page.locator('#password').pressSequentially('ééé');
  await page.locator('button[type="submit"]').click();
  await expect(page.getByRole('alert')).toHaveText('Le mot de passe doit contenir au moins 8 caractères');
  expect(submissions).toBe(0);
});
