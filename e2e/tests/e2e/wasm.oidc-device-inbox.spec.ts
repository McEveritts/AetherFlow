import { expect, test, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const json = (route: Route, value: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(value),
  });

test.describe('WASM OIDC Device Flow & Approval Inbox structured parity', () => {
  test('protects /oauth/device across login, preserves CSRF, ignores spoofed query params, and completes Allow consent', async ({ page }) => {
    await installAetherFlowMocks(page, {
      authenticated: false,
      setupRequired: false,
      userRole: 'user',
      preserveStorage: true,
    });

    const verifyRequests: Array<{ csrf: string | null; body: unknown }> = [];
    const consentRequests: Array<{ csrf: string | null; body: unknown }> = [];

    await page.route('**/api/v1/auth/oidc/device/verify', async route => {
      verifyRequests.push({
        csrf: route.request().headers()['x-csrf-token'] ?? null,
        body: route.request().postDataJSON(),
      });
      await json(route, {
        status: 'pending',
        user_code: 'BCDF-2345',
        client_id: 'tv-jellyfin-01',
        client_name: 'Living Room Jellyfin TV',
        scope: 'openid profile email',
        expires_at: '2026-11-19T08:30:00Z',
      });
    });

    await page.route('**/api/v1/auth/oidc/device/consent', async route => {
      consentRequests.push({
        csrf: route.request().headers()['x-csrf-token'] ?? null,
        body: route.request().postDataJSON(),
      });
      await json(route, {
        status: 'approved',
        client_id: 'tv-jellyfin-01',
        client_name: 'Living Room Jellyfin TV',
        scope: 'openid profile email',
      });
    });

    // Attempt entry while unauthenticated with lowercase unhyphenated user_code and spoofed client query params.
    await page.goto('/oauth/device?user_code=bcdf2345&client_name=SpoofedPhishingClient&scope=admin');
    await expect(page).toHaveURL(/\/login\?returnTo=/);
    expect(verifyRequests).toHaveLength(0);

    await page.getByLabel('Username').fill('alice');
    await page.getByLabel('Password').fill('correct-horse-battery');
    await page.getByRole('button', { name: 'Unlock the Aether', exact: true }).click();

    await expect(page).toHaveURL(/\/oauth\/device\?user_code=BCDF-2345/);
    await expect.poll(() => verifyRequests.length).toBe(1);
    expect(verifyRequests[0]).toEqual({
      csrf: 'mock-csrf-token',
      body: { user_code: 'BCDF-2345' },
    });

    // Only server-confirmed client identity and scopes appear on the consent screen.
    await expect(page.getByRole('heading', { name: 'Authorize Device', exact: true })).toBeVisible();
    await expect(page.getByText('Living Room Jellyfin TV', { exact: true })).toBeVisible();
    await expect(page.getByText('tv-jellyfin-01', { exact: true })).toBeVisible();
    await expect(page.getByText('SpoofedPhishingClient')).toHaveCount(0);
    await expect(page.getByText('openid', { exact: true })).toBeVisible();
    await expect(page.getByText('profile', { exact: true })).toBeVisible();
    await expect(page.getByText('email', { exact: true })).toBeVisible();
    expect(consentRequests).toHaveLength(0);

    await page.getByRole('button', { name: 'Allow Access', exact: true }).click();
    await expect.poll(() => consentRequests.length).toBe(1);
    expect(consentRequests[0]).toEqual({
      csrf: 'mock-csrf-token',
      body: {
        user_code: 'BCDF-2345',
        client_id: 'tv-jellyfin-01',
        scope: 'openid profile email',
        approved: true,
      },
    });
    await expect(page.getByRole('status')).toContainText('Device Authorized');
    await expect(page.getByRole('status')).toContainText('Living Room Jellyfin TV has been granted access.');
    await expect(page).toHaveURL(/\/oauth\/device$/);
  });

  test('validates short device codes client-side and handles expired, invalid, and denied device grants', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let verifyCount = 0;
    const consentBodies: unknown[] = [];

    await page.route('**/api/v1/auth/oidc/device/verify', async route => {
      verifyCount += 1;
      const body = route.request().postDataJSON() as { user_code: string };
      if (body.user_code === 'EXPD-2345') {
        return json(route, { error: 'expired_token' }, 400);
      }
      if (body.user_code === 'DEAD-2345') {
        return json(route, { error: 'invalid_user_code' }, 400);
      }
      return json(route, {
        status: 'pending',
        user_code: body.user_code,
        client_id: 'cli-agent',
        client_name: 'AetherFlow CLI',
        scope: 'openid',
      });
    });

    await page.route('**/api/v1/auth/oidc/device/consent', async route => {
      const body = route.request().postDataJSON() as { user_code: string; approved: boolean };
      consentBodies.push(body);
      return json(route, {
        status: body.approved ? 'approved' : 'denied',
        client_id: 'cli-agent',
        client_name: 'AetherFlow CLI',
        scope: 'openid',
      });
    });

    await page.goto('/oauth/device');
    const codeField = page.getByLabel('Device verification code');
    await codeField.fill('BAD!');
    await page.getByRole('button', { name: 'Verify Code', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Enter a valid 8-character device code');
    expect(verifyCount).toBe(0);

    await codeField.fill('expd-2345');
    await page.getByRole('button', { name: 'Verify Code', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('This device code has expired.');
    expect(verifyCount).toBe(1);

    await codeField.fill('dead2345');
    await page.getByRole('button', { name: 'Verify Code', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Invalid or already-used device code.');
    expect(verifyCount).toBe(2);

    await codeField.fill('wxyz6789');
    await page.getByRole('button', { name: 'Verify Code', exact: true }).click();
    await expect(page.getByText('AetherFlow CLI', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Deny Access', exact: true }).click();
    await expect.poll(() => consentBodies.length).toBe(1);
    expect(consentBodies[0]).toMatchObject({
      user_code: 'WXYZ-6789',
      client_id: 'cli-agent',
      scope: 'openid',
      approved: false,
    });
    await expect(page.getByRole('status')).toContainText('Device Access Denied');
  });

  test('renders Approval Inbox risk summary, structured command breakdown, action parameters, core impact warning, and execution log', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

    const coreAction = {
      id: 41,
      action: 'restart_service:aetherflow-api:systemd',
      classification: 'critical',
      source: 'FlowAI',
      reason: 'Recycle control-plane API after socket saturation',
      status: 'pending',
      created_at: '2026-11-19T06:10:00Z',
    };
    const parameterizedAction = {
      id: 42,
      action: 'Apply egress bandwidth throttle',
      classification: 'warn',
      source: 'SecurityGateway',
      reason: 'Sustained outbound spike detected',
      status: 'pending',
      created_at: '2026-11-19T06:12:00Z',
      parameters: {
        interface: 'eth0',
        rate_mbps: 250,
        targets: ['198.51.100.82', '198.51.100.99'],
      },
      execution_log: 'tc qdisc replace dev eth0 root handle 1: htb default 30',
    };
    const safeAction = {
      id: 43,
      action: 'start:sonarr',
      classification: 'safe',
      source: 'af-heal',
      reason: 'Routine recovery check',
      status: 'pending',
      created_at: '2026-11-19T06:14:00Z',
    };

    await page.route('**/api/v1/admin/actions/pending?*', route => {
      const url = new URL(route.request().url());
      if (url.searchParams.get('limit') === '1') {
        return json(route, { count: 3, total: 3, actions: [coreAction] });
      }
      return json(route, {
        count: 3,
        total: 3,
        actions: [coreAction, parameterizedAction, safeAction],
      });
    });

    await page.route('**/api/v1/admin/actions/41', route => json(route, coreAction));
    await page.route('**/api/v1/admin/actions/42', route => json(route, parameterizedAction));

    await page.goto('/?tab=inbox');
    const summary = page.getByRole('region', { name: 'Approval queue summary' });
    await expect(summary).toContainText('Matching Records');
    await expect(summary).toContainText('Critical & High');
    await expect(summary).toContainText('Medium / Warning');
    await expect(summary).toContainText('Low / Safe');

    // Inline execution log preview renders on cards when present.
    await expect(page.getByText('tc qdisc replace dev eth0 root handle 1: htb default 30')).toBeVisible();

    // Inspect core restart action: shows Command & Blast Radius + Core Control-Plane Impact alert.
    await page.locator('section.glass-card', { hasText: 'restart_service:aetherflow-api:systemd' })
      .getByRole('button', { name: 'Inspect action', exact: true })
      .click();
    const detailDialog = page.getByRole('dialog', { name: 'Action details' });
    await expect(detailDialog).toBeVisible();
    await expect(detailDialog.getByRole('alert')).toContainText('Core Control-Plane Impact');
    await expect(detailDialog).toContainText('Executable Service Gate');
    await expect(detailDialog).toContainText('Command & Blast Radius');
    await expect(detailDialog).toContainText('aetherflow-api');
    await expect(detailDialog).toContainText('systemd');
    await detailDialog.getByRole('button', { name: 'Close dialog', exact: true }).click();

    // Inspect parameterized action: shows structured Action Parameters and Execution Log.
    await page.locator('section.glass-card', { hasText: 'Apply egress bandwidth throttle' })
      .getByRole('button', { name: 'Inspect action', exact: true })
      .click();
    await expect(detailDialog).toBeVisible();
    await expect(detailDialog).toContainText('Action Parameters');
    await expect(detailDialog).toContainText('eth0');
    await expect(detailDialog).toContainText('250');
    await expect(detailDialog).toContainText('198.51.100.82, 198.51.100.99');
    await expect(detailDialog).toContainText('Execution Log');
    await expect(detailDialog).toContainText('tc qdisc replace dev eth0 root handle 1: htb default 30');
  });
});
