import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('navigates to OAuth authorization via Google provider', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
  await stabilizeVisuals(page);

  // We intercept the redirect to Google
  await page.route(/\/api(\/v1)?\/public\/auth\/google\/login/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<html><body>Mock Google OAuth Page</body></html>',
    });
  });

  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Access Nexus' })).toBeVisible();

  // Click the OAuth link
  await page.getByRole('button', { name: 'Continue with Google OAuth' }).click();

  // Validate we arrived at the mock Google OAuth page
  await expect(page.locator('body')).toHaveText('Mock Google OAuth Page');
});
