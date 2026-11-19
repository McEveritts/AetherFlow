import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('runs a marketplace install loop from request to completed state', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true });
  await stabilizeVisuals(page);

  await page.goto('/');
  await page.locator('aside').first().hover();
  await page.getByRole('button', { name: 'Marketplace' }).click();

  await expect(page.getByText('Bazarr')).toBeVisible();
  await page.getByRole('button', { name: 'Install' }).click();

  await expect(page.getByText('Installation started for bazarr')).toBeVisible();
  await expect(page.getByText('Installing')).toBeVisible();

  await expect.poll(async () => {
    return await page.locator('text=Installed').count();
  }).toBeGreaterThan(2);

  await expect(page.getByText('Installed 1.1.0')).toBeVisible();
});
