import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

for (const editWhileSaving of [false, true]) {
  test(`a successful Settings save rejects older polls${editWhileSaving ? ' and preserves newer edits' : ''}`, async ({ page }) => {
    await page.clock.install({ time: new Date('2026-11-17T11:59:00Z') });
    await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let server = { timezone: 'UTC', language: 'en', defaultDashboard: 'overview', setupCompleted: true };
    const pollStarted = deferred();
    const releasePoll = deferred();
    const pollFinished = deferred();
    const saveStarted = deferred();
    const releaseSave = deferred();
    let holdPoll = false;
    let initialReads = 0;
    await page.route('**/api/v1/auth/settings', async route => {
      const snapshot = { ...server };
      if (holdPoll) {
        holdPoll = false;
        pollStarted.resolve();
        await releasePoll.promise;
        await route.fulfill({ json: snapshot });
        pollFinished.resolve();
      } else {
        await route.fulfill({ json: snapshot });
        initialReads++;
      }
    });
    await page.route('**/api/v1/admin/settings', async route => {
      expect(route.request().method()).toBe('PUT');
      const payload = route.request().postDataJSON() as typeof server;
      expect(payload.timezone).toBe('Europe/Berlin');
      saveStarted.resolve();
      await releaseSave.promise;
      server = { ...server, ...payload };
      await route.fulfill({ json: { success: true } });
    });
    await page.goto('/?tab=settings');
    const timezone = page.getByLabel('Timezone', { exact: true });
    const save = page.getByRole('button', { name: /^Save settings$/i });
    await expect(timezone).toHaveValue('UTC');
    await expect(save).toBeDisabled();
    await expect.poll(() => initialReads).toBeGreaterThanOrEqual(2);
    await page.clock.runFor(50);
    holdPoll = true;
    await page.clock.runFor(30_001);
    await pollStarted.promise;
    await timezone.fill('Europe/Berlin');
    await save.click();
    try {
      await saveStarted.promise;
      if (editWhileSaving) await timezone.fill('America/New_York');
    } finally {
      releaseSave.resolve();
    }
    await expect(page.getByRole('status').filter({ hasText: /^Settings saved$/ })).toBeVisible();
    await expect(timezone).toHaveValue(editWhileSaving ? 'America/New_York' : 'Europe/Berlin');
    releasePoll.resolve();
    await pollFinished.promise;
    await page.clock.runFor(50);
    await expect(timezone).toHaveValue(editWhileSaving ? 'America/New_York' : 'Europe/Berlin');
    expect(server.timezone).toBe('Europe/Berlin');
    if (editWhileSaving) {
      await expect(save).toBeEnabled();
      await timezone.fill('Europe/Berlin');
    }
    await expect(save).toBeDisabled();
  });
}

test('a delayed shell Settings bootstrap cannot replace an acknowledged save', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let server = { timezone: 'Etc/UTC', language: 'en', defaultDashboard: 'overview', setupCompleted: true };
  const shellStarted = deferred();
  const releaseShell = deferred();
  const shellFinished = deferred();
  const remountStarted = deferred();
  const releaseRemount = deferred();
  let firstRead = true;
  let holdRemount = false;
  await page.route('**/api/v1/auth/settings', async route => {
    const snapshot = { ...server };
    if (firstRead) {
      firstRead = false;
      shellStarted.resolve();
      await releaseShell.promise;
      await route.fulfill({ json: snapshot });
      shellFinished.resolve();
    } else if (holdRemount) {
      holdRemount = false;
      remountStarted.resolve();
      await releaseRemount.promise;
      await route.fulfill({ json: snapshot });
    } else {
      await route.fulfill({ json: snapshot });
    }
  });
  await page.route('**/api/v1/admin/settings', async route => {
    server = { ...server, ...route.request().postDataJSON() as typeof server };
    await route.fulfill({ json: { success: true } });
  });
  try {
    await page.goto('/');
    await shellStarted.promise;
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Settings', exact: true }).first().click();
    const timezone = page.getByLabel('Timezone', { exact: true });
    await expect(timezone).toHaveValue('Etc/UTC');
    await timezone.fill('Europe/Berlin');
    await page.getByRole('button', { name: /^Save settings$/i }).click();
    await expect(page.getByRole('status').filter({ hasText: /^Settings saved$/ })).toBeVisible();
    await expect(timezone).toHaveValue('Europe/Berlin');
    releaseShell.resolve();
    await shellFinished.promise;
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    holdRemount = true;
    await page.getByRole('button', { name: 'Settings', exact: true }).first().click();
    await remountStarted.promise;
    // With the remount's GET still held, this is the shared accepted baseline.
    await expect(timezone).toHaveValue('Europe/Berlin');
    expect(server.timezone).toBe('Europe/Berlin');
  } finally {
    releaseShell.resolve();
    releaseRemount.resolve();
  }
});

test('enrolls the authenticator through the CSRF-protected setup action', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true });
  let method = '';
  let csrf = '';
  await page.route('**/api/v1/auth/user/2fa/setup', route => {
    method = route.request().method();
    csrf = route.request().headers()['x-csrf-token'];
    return route.fulfill({ json: { secret: 'MOCK', otpauth_uri: 'otpauth://totp/Example?secret=MOCK' } });
  });
  await page.goto('/?tab=settings');
  await page.getByRole('tab', { name: /Security.*2FA/i }).click();
  await page.getByRole('button', { name: 'Enroll authenticator' }).click();
  const dialog = page.getByRole('dialog', { name: 'Enroll TOTP authenticator' });
  await expect(dialog.getByText('MOCK', {exact:true})).toBeVisible();
  await expect(dialog.locator('[role="img"] svg')).toBeVisible();
  expect(method).toBe('POST');
  expect(csrf).toBeTruthy();
});

test('forced MFA enrollment renders the server enrollment URI after password sign-in', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: false });
  await page.route('**/api/v1/public/auth/login', route =>
    route.fulfill({ json: { requires_mfa_setup: true } }));
  await page.route('**/api/v1/auth/user/2fa/setup', route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-csrf-token']).toBeTruthy();
    return route.fulfill({ json: { otpauth_uri: 'otpauth://totp/Example?secret=TEST' } });
  });
  await page.goto('/login');
  await page.locator('#username').fill('fixture-user');
  await page.locator('#password').fill('fixture-password');
  await page.locator('button[type=submit]').click();
  await expect(page.locator('#mfa-code')).toBeVisible();
  await expect(page.locator('.af-qr svg')).toBeVisible();
});

test('bulk session revocation targets only explicitly non-current session families', async ({ page }) => {
  await installAetherFlowMocks(page);
  const families = [
    { jti: 'current', is_current: true }, { jti: 'legacy' },
    { jti: 'first', is_current: false }, { jti: 'second', is_current: false },
  ];
  const deleted: string[] = [];
  await page.route('**/api/v1/auth/sessions', route =>
    route.fulfill({ json: { sessions: families.filter(item => !deleted.includes(item.jti)) } }));
  await page.route('**/api/v1/auth/sessions/*', route => {
    expect(route.request().method()).toBe('DELETE');
    deleted.push(new URL(route.request().url()).pathname.split('/').pop()!);
    return route.fulfill({ json: { success: true } });
  });
  await page.goto('/?tab=settings');
  await page.getByRole('tab', { name: /Security.*2FA/i }).click();
  const revoke = page.getByRole('button', { name: 'Revoke all other sessions' });
  await revoke.click();
  await expect(revoke).toBeDisabled();
  await expect.poll(() => deleted).toEqual(['first', 'second']);
  await expect(page.getByText(/current.*Current session/)).toBeVisible();
});

test('selects a metadata scan directory from server listings without starting a scan', async ({ page }) => {
  await installAetherFlowMocks(page);
  const scans: string[] = [];
  await page.route('**/api/v1/auth/fs?*', route => {
    const path = new URL(route.request().url()).searchParams.get('path');
    return route.fulfill({ json: { directories: path === '/' ? ['media'] : ['series'] } });
  });
  await page.route('**/api/v1/admin/ai/metadata/status', route => route.fulfill({ json: { scanning: false } }));
  await page.route('**/api/v1/admin/ai/metadata/scan', route => {
    scans.push(route.request().postDataJSON().path);
    return route.fulfill({ json: { success: true } });
  });
  await page.goto('/?tab=settings');
  await page.getByRole('tab', { name: /metadata/i }).click();
  await page.getByRole('button', { name: 'Browse Directories' }).click();
  const picker = page.getByRole('dialog', { name: 'Browse Directories' });
  await picker.getByRole('button', { name: 'media', exact: true }).click();
  await picker.getByRole('button', { name: 'series', exact: true }).click();
  await picker.getByRole('button', { name: 'Use this directory' }).click();
  await expect(page.getByLabel('Media directory')).toHaveValue('/media/series');
  expect(scans).toEqual([]);
  await page.getByRole('button', { name: 'Scan metadata' }).click();
  await expect.poll(() => scans).toEqual(['/media/series']);
});
