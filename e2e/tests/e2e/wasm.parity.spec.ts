import { expect, test, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

async function seedThemeBeforeWasm(page: Page, theme: 'light' | 'system') {
  // The shared mocks clear storage in an init script. Seed after those scripts
  // and before WASM starts, without depending on init-script execution order.
  await page.route(/\.wasm(?:\?.*)?$/, async (route) => {
    await page.evaluate((preference) => {
      window.localStorage.setItem('aetherflow-theme', preference);
    }, theme);
    await route.continue();
  }, { times: 1 });
}

async function seedLocaleBeforeWasm(page: Page, locale: 'dk' | 'fr' = 'dk') {
  await page.route(/\.wasm(?:\?.*)?$/, async (route) => {
    await page.evaluate((preference) => {
      window.localStorage.setItem('aetherflow-language', preference);
    }, locale);
    await route.continue();
  }, { times: 1 });
}

test.describe('Rust WASM appliance parity', () => {
  test('boots without inline scripts or a global WASM binding', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

    await expect(page.locator('script:not([src])')).toHaveCount(0);
    expect(await page.evaluate(() =>
      (window as Window & { wasmBindings?: unknown }).wasmBindings === undefined,
    )).toBe(true);
  });

  test('normalizes unknown SPA routes on dashboard mount and tab selection', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/unknown-spa-route');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await expect(page).toHaveURL((url) => url.pathname === '/' && url.searchParams.get('tab') === 'overview');

    // Keep the dashboard mounted while reproducing a fallback URL from history.
    await page.evaluate(() => history.replaceState(null, '', '/unknown-spa-route'));
    await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Services', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
    await expect(page).toHaveURL((url) => url.pathname === '/' && url.searchParams.get('tab') === 'services');
  });

  test('opens README.md with one Save action, keyboard saving, font controls and modal focus', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const content = '# AetherFlow\n\nEditor font and focus regression.\n';
    const saved: string[] = [];
    await page.route('**/api/v1/auth/mcbrowser/entries?*', (route) => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ path: '', entries: [{
        name: 'README.md', path: 'README.md', kind: 'file', size: content.length,
        modified: '2026-11-16T00:00:00Z',
      }] }),
    }));
    await page.route('**/api/v1/auth/mcbrowser/policy', (route) => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ scope: 'private', permissions: { read: true, modify: true }, rules: [] }),
    }));
    await page.route('**/api/v1/auth/mcbrowser/usage', (route) => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ used_bytes: content.length, quota_bytes: 1024 * 1024 }),
    }));
    await page.route('**/api/v1/auth/mcbrowser/content?*', async route => {
      if (route.request().method() === 'PUT') {
        expect(route.request().headers()['if-match']).toBe('"readme-v1"');
        const body = route.request().postDataJSON() as { content: string };
        saved.push(body.content);
        await route.fulfill({ json: { etag: '"readme-v2"' }, headers: { ETag: '"readme-v2"' } });
      } else {
        await route.fulfill({ json: { content, etag: '"readme-v1"' }, headers: { ETag: '"readme-v1"' } });
      }
    });
    await page.goto('/?tab=mcbrowser');
    await page.getByRole('button', { name: 'File README.md', exact: true }).click();

    const dialog = page.getByRole('dialog', { name: 'Code editor', exact: true });
    await expect(dialog).toBeVisible();
    const save = dialog.getByRole('button', { name: 'Save', exact: true });
    await expect(save).toHaveCount(1);
    await expect(save).toBeDisabled();
    const changed = `${content}Keyboard save regression.\n`;
    await dialog.locator('textarea.af-editor-input').fill(changed);
    await expect(save).toBeEnabled();
    await page.keyboard.press('Control+s');
    await expect.poll(() => saved).toEqual([changed]);
    await expect(save).toBeDisabled();
    const editor = dialog.locator('.af-editor-body');
    await expect(editor).toHaveClass(/\baf-editor-fs-14\b/);
    await dialog.getByRole('button', { name: 'Increase font size', exact: true }).click();
    await expect(editor).toHaveClass(/\baf-editor-fs-15\b/);
    await expect(editor).toHaveCSS('font-size', '15px');
    await dialog.getByRole('button', { name: 'Decrease font size', exact: true }).click();
    await expect(editor).toHaveClass(/\baf-editor-fs-14\b/);
    await expect(editor).toHaveCSS('font-size', '14px');
    const decreaseFont = dialog.getByRole('button', { name: 'Decrease font size', exact: true });
    await decreaseFont.click();
    await decreaseFont.click();
    await expect(editor).toHaveCSS('font-size', '12px');
    await expect(decreaseFont).toBeDisabled();
    await expect(dialog.locator('[style]')).toHaveCount(0);
    expect(await dialog.innerText()).not.toMatch(/on:(?:click|input|change|keydown|submit)=move\s*\||font\.(?:get|update)\(/);

    const focusable = dialog.locator('button:not([disabled]):visible, [href]:visible, input:not([disabled]):visible, select:not([disabled]):visible, textarea:not([disabled]):visible, [tabindex]:not([tabindex="-1"]):visible');
    await focusable.first().focus();
    await page.keyboard.press('Shift+Tab');
    await expect(focusable.last()).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(focusable.first()).toBeFocused();
  });

  for (const path of ['/login', '/']) {
    test(`applies the saved light theme on ${path}`, async ({ page }) => {
      await installAetherFlowMocks(page, {
        authenticated: path === '/',
        setupRequired: false,
      });
      await seedThemeBeforeWasm(page, 'light');
      await page.goto(path);
      await expect(page.getByRole('heading', {
        name: path === '/' ? 'Overview' : 'Access Nexus', exact: true,
      })).toBeVisible();

      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
      expect(await page.evaluate(() => localStorage.getItem('aetherflow-theme'))).toBe('light');
    });
  }

  test('preserves the system theme preference when the dashboard mounts', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.emulateMedia({ colorScheme: 'light' });
    await seedThemeBeforeWasm(page, 'system');
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    expect(await page.evaluate(() => localStorage.getItem('aetherflow-theme'))).toBe('system');
  });

  test('opens the command palette with focus on its search input', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page.keyboard.press('Control+k');

    const palette = page.getByRole('dialog', { name: 'Command Palette', exact: true });
    await expect(palette).toBeVisible();
    const search = palette.locator('input[type="search"]');
    await expect(search).toBeFocused();
    await expect(palette.getByRole('button', { name: 'Close dialog' })).not.toBeFocused();
  });

  test('clamps a non-admin users deep link back to Overview', async ({ page }) => {
    await installAetherFlowMocks(page, {
      authenticated: true,
      setupRequired: false,
      userRole: 'user',
    });
    await page.goto('/?tab=users');

    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Users', exact: true })).toHaveCount(0);
    await expect(page).toHaveURL((url) => url.pathname === '/' && !url.searchParams.has('tab'));
  });

  test('keeps a reopened dialog open when an earlier native close event arrives', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Command Palette', exact: true });
    await expect(dialog).toBeVisible();
    await dialog.evaluate((element) => {
      const target = window as Window & { __closeHeld?: boolean; __releaseClose?: () => void };
      let hold = true;
      element.addEventListener('close', (event) => {
        if (!hold) return;
        event.stopImmediatePropagation();
        target.__closeHeld = true;
        target.__releaseClose = () => {
          hold = false;
          element.dispatchEvent(new Event('close'));
        };
      }, { capture: true });
    });
    await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
    await expect(dialog).toBeHidden();
    await expect.poll(() => page.evaluate(() => (window as Window & { __closeHeld?: boolean }).__closeHeld)).toBe(true);
    await page.keyboard.press('Control+k');
    await expect(dialog).toBeVisible();
    await page.evaluate(() => (window as Window & { __releaseClose?: () => void }).__releaseClose!());
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('input[type="search"]')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
  });

  for (const { tab, restricted, fallback } of [
    { tab: 'fileshare', restricted: 'Audit log', fallback: 'Local Storage' },
    { tab: 'streaming', restricted: 'History administration', fallback: 'Active playback sessions' },
  ]) {
    test(`keeps ${tab} keyboard navigation valid after administrator demotion`, async ({ page }) => {
      await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
      let role = 'admin';
      await page.route('**/api/v1/auth/session', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ id: 1, username: 'admin', email: 'admin@example.com', role, is_oauth: false }),
      }));
      await page.goto(`/?tab=${tab}`);
      const restrictedTab = page.getByRole('tab', { name: restricted, exact: true });
      await restrictedTab.click();
      await expect(restrictedTab).toHaveAttribute('aria-selected', 'true');

      role = 'user';
      await page.evaluate(() => {
        const channel = new BroadcastChannel('aetherflow-auth');
        channel.postMessage({ type: 'role-refresh' });
        channel.close();
      });
      await expect(restrictedTab).toHaveCount(0);
      const fallbackTab = page.getByRole('tab', { name: fallback, exact: true });
      await expect(fallbackTab).toHaveAttribute('aria-selected', 'true');
      await expect(fallbackTab).toHaveAttribute('tabindex', '0');
      const panel = page.getByRole('tabpanel');
      await expect(panel).toHaveAttribute('aria-labelledby', `${tab}-tab-${tab === 'fileshare' ? 'local' : 'live'}`);
      await expect(page.locator('[role="tab"][tabindex="0"]')).toHaveCount(1);
      await fallbackTab.focus();
      await page.keyboard.press('ArrowRight');
      await expect(page.locator('[role="tab"][aria-selected="true"]')).toBeFocused();
    });
  }

  test('maps the Danish catalog to the valid BCP 47 document language', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

    await page.getByRole('combobox', { name: 'Locale', exact: true }).selectOption('dk');

    await expect(page.locator('html')).toHaveAttribute('lang', 'da');
    await expect(page.locator('html')).not.toHaveAttribute('lang', 'dk');
    await expect(page.getByRole('heading', { name: 'Oversigt', exact: true })).toBeVisible();
    await expect(page.locator('.af-skip-link')).toHaveText('Spring til indhold');
  });

  test('loads French once on demand and preserves the service search input', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const localeRequests: string[] = [];
    page.on('request', (request) => {
      const path = new URL(request.url()).pathname;
      if (path.startsWith('/locales/')) localeRequests.push(path);
    });
    await page.goto('/?tab=services');
    const search = page.getByRole('searchbox', { name: 'Search services', exact: true });
    await search.fill('grafana');
    const original = await search.elementHandle();
    expect(original).not.toBeNull();
    expect(localeRequests).toEqual([]);

    const locale = page.locator('select.af-locale-select');
    await locale.selectOption('fr');
    await expect(page.getByRole('searchbox', { name: 'Rechercher des services', exact: true })).toHaveValue('grafana');
    expect(await original!.evaluate((input) => input.isConnected)).toBe(true);
    expect(localeRequests).toEqual(['/locales/fr.json']);

    await locale.selectOption('en');
    await expect(search).toHaveValue('grafana');
    await locale.selectOption('fr');
    await expect(page.getByRole('searchbox', { name: 'Rechercher des services', exact: true })).toHaveValue('grafana');
    expect(await original!.evaluate((input) => input.isConnected)).toBe(true);
    expect(localeRequests).toEqual(['/locales/fr.json']);
  });

  test.describe('delayed catalog delivery', () => {
    // Keep the delayed request visible to Playwright's route handler.
    test.use({ serviceWorkers: 'block' });

    test('updates an active toast when the delayed French catalog arrives', async ({ page }) => {
      await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
      let releaseCatalog!: () => void;
      let signalCatalogStarted!: () => void;
      const toastShown = new Promise<void>((resolve) => { releaseCatalog = resolve; });
      const catalogStarted = new Promise<void>((resolve) => { signalCatalogStarted = resolve; });
      await page.route('**/locales/fr.json', async (route) => {
        signalCatalogStarted();
        await Promise.all([toastShown, new Promise<void>((resolve) => setTimeout(resolve, 250))]);
        await route.continue();
      });
      try {
        await page.goto('/?tab=notifications');
        await page.getByRole('button', { name: 'Add channel', exact: true }).waitFor();
        await page.locator('header select.af-locale-select').selectOption('fr');
        await catalogStarted;
        await page.getByRole('button', { name: 'Add channel', exact: true }).click();
        const dialog = page.getByRole('dialog', { name: 'Configure delivery channel', exact: true });
        await dialog.getByLabel('Delivery URL', { exact: true }).fill('https://example.com/webhook');
        await dialog.getByRole('button', { name: 'Create channel', exact: true }).click();
        const toast = page.locator('.af-toast span').filter({ hasText: 'Channel name is required' });
        await expect(toast).toHaveText('Channel name is required');
        const retained = await toast.elementHandle();
        const loaded = page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/locales/fr.json' && response.ok()
        );
        releaseCatalog();
        await loaded;
        await expect(page.locator('.af-toast span').filter({ hasText: 'Le nom de la chaîne est obligatoire' }))
          .toHaveText('Le nom de la chaîne est obligatoire');
        expect(await retained!.evaluate((element) => element.isConnected)).toBe(true);
      } finally {
        releaseCatalog();
      }
    });
  });

  test('preserves a shared Archive filename and download attribute in French', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: false, setupRequired: false });
    await seedLocaleBeforeWasm(page, 'fr');
    await page.route('**/locales/fr.json', async (route) => {
      const response = await route.fetch();
      const catalog = await response.json();
      // Make an accidental filename lookup distinguishable from verbatim text.
      await route.fulfill({ response, json: { ...catalog, Archive: 'Archiver' } });
    });
    await page.route('**/api/v1/public/mcbrowser/shares/archive-name-fixture', (route) => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ name: 'Archive', is_directory: false, allow_download: true, password_required: false }),
    }));
    await page.goto('/share?token=archive-name-fixture');
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(page.getByText('Archive', { exact: true })).toBeVisible();
    const download = page.getByRole('link', { name: 'Télécharger', exact: true });
    await expect(download).toHaveAttribute('download', 'Archive');
    await expect(page.getByText('Archiver', { exact: true })).toHaveCount(0);
  });

  for (const [path, heading] of [
    ['/login', 'Åbn Nexus'],
    ['/oauth/consent?client_id=test&response_type=code&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback', 'Operatørhandling påkrævet'],
    ['/share', 'Delt ressource'],
  ]) {
    test(`applies the saved Danish locale at the root of ${path.split('?')[0]}`, async ({ page }) => {
      await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
      await seedLocaleBeforeWasm(page);
      await page.goto(path);

      await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
      await expect(page.locator('html')).toHaveAttribute('lang', 'da');
      await expect(page.locator('.af-skip-link')).toHaveText('Spring til indhold');
    });
  }

  test('does not prompt non-admin users to complete administrator onboarding', async ({ page }) => {
    await installAetherFlowMocks(page, {
      authenticated: true,
      setupRequired: false,
      userRole: 'user',
    });
    const adminSettingsWrites: string[] = [];
    page.on('request', (request) => {
      if (request.method() === 'PUT' && new URL(request.url()).pathname === '/api/v1/admin/settings') {
        adminSettingsWrites.push(request.url());
      }
    });
    await page.route('**/api/v1/auth/settings', async (route) => {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          language: 'en',
          setupCompleted: false,
          baseDomain: '',
          defaultDashboard: 'services',
        }),
      });
    });
    await page.goto('/');

    // Applying the configured default proves the incomplete settings response
    // has reached the shell before checking that onboarding stays closed.
    await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
    await expect(page.getByRole('dialog', { name: 'Welcome to AetherFlow', exact: true })).not.toBeVisible();
    expect(adminSettingsWrites).toEqual([]);
  });

  test('fits all sixteen sidebar tabs and logout inside a 1024x768 viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

    const sidebar = page.locator('#desktop-sidebar-navigation');
    const tabs = sidebar.locator('nav .af-nav-button');
    await expect(tabs).toHaveCount(16);
    await expect(sidebar.getByRole('button', { name: 'Quotas', exact: true })).toBeVisible();
    for (const button of await sidebar.getByRole('button').all()) {
      const bounds = await button.boundingBox();
      expect(bounds, await button.getAttribute('aria-label') ?? 'Sidebar button').not.toBeNull();
      expect(bounds!.y).toBeGreaterThanOrEqual(0);
      expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(768);
    }
    const navigation = await tabs.evaluateAll((buttons) => {
      const nav = buttons[0].parentElement!;
      return { scrollHeight: nav.scrollHeight, clientHeight: nav.clientHeight, scrollTop: nav.scrollTop };
    });
    expect(navigation.scrollHeight).toBeLessThanOrEqual(navigation.clientHeight);
    expect(navigation.scrollTop).toBe(0);
  });

  test('keeps the mobile header and its controls within two compact rows', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

    const header = page.locator('header.af-header');
    const bounds = await header.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds!.height).toBeLessThanOrEqual(104);
    for (const name of ['Open navigation', 'Open Command Palette', 'Toggle theme', 'Notifications', 'Account menu']) {
      await expect(header.getByRole('button', { name, exact: true })).toBeVisible();
    }
    await expect(header.getByRole('combobox', { name: 'Locale', exact: true })).toBeVisible();
    const actions = await header.locator('.af-header-actions > *').evaluateAll((elements) =>
      elements.map((element) => {
        const rect = element.getBoundingClientRect();
        return { y: rect.y, right: rect.right, bottom: rect.bottom };
      }),
    );
    for (const action of actions) {
      expect(action.right).toBeLessThanOrEqual(390);
      expect(action.bottom).toBeLessThanOrEqual(bounds!.y + bounds!.height);
    }
    expect(Math.max(...actions.map((action) => action.y)) - Math.min(...actions.map((action) => action.y)))
      .toBeLessThanOrEqual(12);
  });
});
