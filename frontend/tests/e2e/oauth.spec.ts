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

test('OIDC consent page forwards nonce query parameter in consent JSON request', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await stabilizeVisuals(page);

  let capturedBody: Record<string, unknown> | null = null;
  await page.route('**/api/v1/auth/oidc/consent', async (route) => {
    capturedBody = route.request().postDataJSON();
    await route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'Intercepted for test' }),
    });
  });

  await page.goto(
    '/oauth/consent?client_id=test-oidc-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid%20profile&state=st-1&nonce=nonce-e2e-777&code_challenge=cc-1&code_challenge_method=S256'
  );

  await expect(page.getByRole('button', { name: 'Grant Authorization' })).toBeVisible();
  await page.getByRole('button', { name: 'Grant Authorization' }).click();

  await expect.poll(() => capturedBody).toMatchObject({
    client_id: 'test-oidc-client',
    redirect_uri: 'https://app.example.com/cb',
    response_type: 'code',
    state: 'st-1',
    nonce: 'nonce-e2e-777',
    code_challenge: 'cc-1',
    code_challenge_method: 'S256',
    approved: true,
  });
});
