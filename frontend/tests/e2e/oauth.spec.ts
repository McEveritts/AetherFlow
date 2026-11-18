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

for (const outcome of ['authenticated grant', 'unauthenticated grant', 'unauthenticated denial'] as const) {
  test(`OIDC waits for an unresolved session before ${outcome}`, async ({ page }) => {
    const authenticated = outcome === 'authenticated grant';
    await installAetherFlowMocks(page, { authenticated, setupRequired: false });
    await stabilizeVisuals(page);
    let releaseSession!: () => void;
    let sessionStarted!: () => void;
    const release = new Promise<void>(resolve => { releaseSession = resolve; });
    const started = new Promise<void>(resolve => { sessionStarted = resolve; });
    await page.route('**/api/v1/auth/session', async route => {
      sessionStarted();
      await release;
      await route.fulfill(authenticated ? { json: {
        id: 1, username: 'admin', role: 'admin', email: 'admin@example.com', avatar_url: '', is_oauth: false,
      } } : { status: 401, json: { error: 'Unauthorized' } });
    });
    const submitted: Record<string, unknown>[] = [];
    await page.route('**/api/v1/auth/oidc/consent', async route => {
      submitted.push(route.request().postDataJSON());
      await route.fulfill({ status: 400, json: { message: 'Consent reached the authenticated server' } });
    });
    const consentPath = '/oauth/consent?client_id=delayed-session-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid%20profile&state=held-session&nonce=held-nonce';
    try {
      await page.goto(consentPath);
      await started;
      const grant = page.getByRole('button', { name: 'Grant Authorization', exact: true });
      const deny = page.getByRole('button', { name: 'Deny Access', exact: true });
      await expect(grant).toBeVisible();
      // An early queued activation must not infer that a pending session is signed out.
      await grant.evaluate(button => {
        (button as HTMLButtonElement).click();
        button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      });
      await expect(page).toHaveURL(new URL(consentPath, page.url()).href);
      await expect(grant).toBeDisabled();
      await expect(deny).toBeDisabled();
      expect(submitted).toEqual([]);
      releaseSession();
      await expect(grant).toBeEnabled();
      await expect(deny).toBeEnabled();
      if (authenticated) {
        await grant.click();
        await expect.poll(() => submitted).toEqual([expect.objectContaining({ approved: true, state: 'held-session', nonce: 'held-nonce' })]);
        await expect(page).toHaveURL(new URL(consentPath, page.url()).href);
      } else if (outcome === 'unauthenticated grant') {
        await grant.click();
        await page.waitForURL('**/login?returnTo=*');
        expect(new URL(page.url()).searchParams.get('returnTo')).toBe(consentPath);
        expect(submitted).toEqual([]);
      } else {
        await deny.click();
        await expect(page.getByRole('link', { name: 'Access Nexus', exact: true })).toBeVisible();
        await expect(page).toHaveURL(new URL(consentPath, page.url()).href);
        expect(submitted).toEqual([]);
      }
    } finally {
      releaseSession();
    }
  });
}
