import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

test.describe('WASM Flat Display, Cadence, Touch & Surface parity', () => {
  test('wires active display and touch controls to CSP-safe root selectors and computed CSS, retires atmosphere attributes, and persists across reload', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await installAetherFlowMocks(page, {
      authenticated: true,
      setupRequired: false,
      preserveStorage: true,
    });
    await page.goto('/login');
    await page.evaluate(() => window.localStorage.clear());

    await page.goto('/?tab=settings');
    const html = page.locator('html');

    // Default state uses CSP-safe root data-* selectors only (zero inline style, zero retired atmosphere attributes).
    await expect(html).toHaveAttribute('data-refresh-mode', 'auto');
    await expect(html).toHaveAttribute('data-touch-preference', 'auto');
    await expect(html).toHaveAttribute('data-density', 'compact');
    expect(await html.getAttribute('data-aurora-opacity')).toBeNull();
    expect(await html.getAttribute('data-aurora-animation')).toBeNull();
    expect(await html.getAttribute('data-grain')).toBeNull();
    expect(await html.getAttribute('data-card-lift')).toBeNull();
    expect(await html.getAttribute('style')).toBeNull();

    // Retired atmosphere & card-lift controls must not render in Settings.
    await expect(page.locator('#settings-aurora-opacity')).toHaveCount(0);
    await expect(page.locator('#settings-aurora-animation')).toHaveCount(0);
    await expect(page.locator('#settings-grain-display')).toHaveCount(0);
    await expect(page.locator('#settings-card-lift')).toHaveCount(0);
    await expect(page.getByTestId('settings-atmosphere-reset')).toHaveCount(0);

    const readComputedTokens = () =>
      page.evaluate(() => {
        const rootStyle = getComputedStyle(document.documentElement);
        const beforeStyle = getComputedStyle(document.body, '::before');
        const afterStyle = getComputedStyle(document.body, '::after');
        const pill = document.querySelector('.af-tab-pill');
        const durationMs = (name: string) => {
          const css = rootStyle.getPropertyValue(name).trim();
          return Math.round(Number.parseFloat(css) * (css.endsWith('ms') ? 1 : 1000));
        };
        return {
          durationFast: durationMs('--obs-duration-fast'),
          durationCard: durationMs('--obs-duration-card'),
          bodyBeforeContent: beforeStyle.content,
          bodyAfterContent: afterStyle.content,
          pillMinHeight: pill ? getComputedStyle(pill).minHeight : null,
          inlineRootStyle: document.documentElement.getAttribute('style'),
        };
      });

    expect(await readComputedTokens()).toMatchObject({
      bodyBeforeContent: 'none',
      bodyAfterContent: 'none',
      inlineRootStyle: null,
    });

    // 1. High refresh cadence: 60Hz standard vs 120Hz high refresh
    const refreshSelect = page.getByLabel('High refresh cadence');
    await refreshSelect.selectOption('standard');
    await expect(html).toHaveAttribute('data-refresh-mode', 'standard');
    await expect(html).toHaveAttribute('data-high-refresh', 'false');
    expect(await readComputedTokens()).toMatchObject({
      durationFast: 160,
      durationCard: 200,
    });

    await refreshSelect.selectOption('120hz');
    await expect(html).toHaveAttribute('data-refresh-mode', '120hz');
    await expect(html).toHaveAttribute('data-high-refresh', 'true');
    await expect(page.getByTestId('settings-display-status')).toContainText('120Hz active');
    expect(await readComputedTokens()).toMatchObject({
      durationFast: 110,
      durationCard: 150,
    });

    // 2. Touch mode: compact desktop (off -> 36px) vs >=44px touch targets (on -> 44px)
    const touchSelect = page.getByLabel('Touch mode');
    await touchSelect.selectOption('off');
    await expect(html).toHaveAttribute('data-touch-preference', 'off');
    await expect(html).toHaveAttribute('data-touch-mode', 'false');
    expect((await readComputedTokens()).pillMinHeight).toBe('36px');

    await touchSelect.selectOption('on');
    await expect(html).toHaveAttribute('data-touch-preference', 'on');
    await expect(html).toHaveAttribute('data-touch-mode', 'true');
    await expect(page.getByTestId('settings-input-status')).toContainText('≥44px');
    expect((await readComputedTokens()).pillMinHeight).toBe('44px');

    // 3. Layout density & widget/haptic toggles
    const immersiveToggle = page.getByLabel('Immersive dashboard layout');
    const gpuToggle = page.getByLabel('Show GPU telemetry');
    const transferToggle = page.getByLabel('Show transfer history');
    const hapticToggle = page.getByLabel('Haptic feedback');

    await immersiveToggle.check();
    await gpuToggle.uncheck();
    await transferToggle.uncheck();
    await hapticToggle.uncheck();
    await expect(html).toHaveAttribute('data-density', 'immersive');

    expect(await readComputedTokens()).toMatchObject({
      durationFast: 110,
      durationCard: 150,
      bodyBeforeContent: 'none',
      bodyAfterContent: 'none',
      pillMinHeight: '44px',
      inlineRootStyle: null,
    });

    // Verify active flat keys and legacy envelope persist without writing retired atmosphere keys.
    const stored = await page.evaluate(() => ({
      refresh: localStorage.getItem('aetherflow-high-refresh-mode'),
      touch: localStorage.getItem('aetherflow-touch-mode'),
      immersive: localStorage.getItem('aetherflow-immersive-overview'),
      gpu: localStorage.getItem('aetherflow-show-gpu'),
      transfer: localStorage.getItem('aetherflow-show-transfer-history'),
      haptic: localStorage.getItem('aetherflow-haptic-feedback'),
      retiredOpacity: localStorage.getItem('aetherflow-aurora-opacity'),
      retiredAnim: localStorage.getItem('aetherflow-aurora-animation'),
      retiredGrain: localStorage.getItem('aetherflow-grain-display'),
      retiredLift: localStorage.getItem('aetherflow-card-lift'),
      legacy: JSON.parse(localStorage.getItem('aetherflow-system-storage') ?? '{}'),
    }));
    expect(stored).toMatchObject({
      refresh: '120hz',
      touch: 'on',
      immersive: 'true',
      gpu: 'false',
      transfer: 'false',
      haptic: 'false',
      retiredOpacity: null,
      retiredAnim: null,
      retiredGrain: null,
      retiredLift: null,
    });
    expect(stored.legacy.state).toMatchObject({
      highRefreshMode: '120hz',
      touchMode: 'enabled',
      dashboardDensity: 'immersive',
      showGpuWidget: false,
      showDataUsageWidget: false,
      hapticFeedback: false,
    });
    expect(stored.legacy.state).not.toHaveProperty('auroraOpacity');
    expect(stored.legacy.state).not.toHaveProperty('auroraAnimation');
    expect(stored.legacy.state).not.toHaveProperty('grainDisplay');
    expect(stored.legacy.state).not.toHaveProperty('cardLift');

    // Reload and confirm full state + computed CSS round-trip.
    await page.reload();
    await expect(refreshSelect).toHaveValue('120hz');
    await expect(touchSelect).toHaveValue('on');
    await expect(immersiveToggle).toBeChecked();
    await expect(gpuToggle).not.toBeChecked();
    await expect(transferToggle).not.toBeChecked();
    await expect(hapticToggle).not.toBeChecked();
    expect(await html.getAttribute('data-aurora-opacity')).toBeNull();
    expect(await html.getAttribute('data-aurora-animation')).toBeNull();
    expect(await html.getAttribute('data-grain')).toBeNull();
    expect(await html.getAttribute('data-card-lift')).toBeNull();
    expect(await readComputedTokens()).toMatchObject({
      durationFast: 110,
      durationCard: 150,
      pillMinHeight: '44px',
      inlineRootStyle: null,
    });
  });

  test('hydrates legacy 109.1 Zustand storage shapes, passively ignores retired keys, and respects 120Hz + coarse-pointer auto defaults', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.addInitScript(() => {
      // Simulate a 120Hz panel (8.333ms frame interval) and coarse-pointer touchscreen.
      let syntheticNow = 100;
      window.requestAnimationFrame = (cb: FrameRequestCallback): number => {
        syntheticNow += 1000 / 120;
        const ts = syntheticNow;
        return window.setTimeout(() => cb(ts), 0);
      };
      const origMatchMedia = window.matchMedia.bind(window);
      window.matchMedia = (query: string): MediaQueryList => {
        if (query.includes('pointer: coarse')) {
          const base = origMatchMedia(query);
          Object.defineProperty(base, 'matches', { value: true });
          return base;
        }
        return origMatchMedia(query);
      };

      if (!sessionStorage.getItem('af-legacy-seeded')) {
        window.localStorage.clear();
        window.localStorage.setItem('aetherflow-card-lift', '-6');
        window.localStorage.setItem('aetherflow-aurora-opacity', '0.85');
        window.localStorage.setItem('aetherflow-aurora-animation', 'true');
        window.localStorage.setItem('aetherflow-grain-display', 'false');
        window.localStorage.setItem(
          'aetherflow-system-storage',
          JSON.stringify({
            state: {
              theme: 'dark',
              language: 'en',
              auroraOpacity: 0.3,
              auroraAnimation: true,
              grainDisplay: false,
              cardLift: -6,
              highRefreshMode: 'auto',
              touchMode: 'auto',
              hapticFeedback: false,
            },
            version: 0,
          }),
        );
        window.localStorage.setItem(
          'aetherflow-connection-storage',
          JSON.stringify({
            state: {
              dashboardDensity: 'immersive',
              showGpuWidget: false,
              showDataUsageWidget: false,
            },
          }),
        );
        sessionStorage.setItem('af-legacy-seeded', '1');
      }
    });

    await installAetherFlowMocks(page, {
      authenticated: true,
      setupRequired: false,
      preserveStorage: true,
    });

    await page.goto('/?tab=settings');
    const html = page.locator('html');

    // Surviving preferences hydrate cleanly while retired keys emit no root attributes or inline styles.
    await expect(html).toHaveAttribute('data-refresh-mode', 'auto');
    await expect(html).toHaveAttribute('data-high-refresh', 'true');
    await expect(html).toHaveAttribute('data-touch-preference', 'auto');
    await expect(html).toHaveAttribute('data-touch-mode', 'true');
    await expect(html).toHaveAttribute('data-density', 'immersive');
    expect(await html.getAttribute('data-aurora-opacity')).toBeNull();
    expect(await html.getAttribute('data-aurora-animation')).toBeNull();
    expect(await html.getAttribute('data-grain')).toBeNull();
    expect(await html.getAttribute('data-card-lift')).toBeNull();
    expect(await html.getAttribute('style')).toBeNull();

    await expect(page.getByTestId('settings-display-status')).toContainText('120Hz');
    await expect(page.getByTestId('settings-input-status')).toContainText('≥44px');
    await expect(page.getByLabel('Immersive dashboard layout')).toBeChecked();
    await expect(page.getByLabel('Show GPU telemetry')).not.toBeChecked();
    await expect(page.getByLabel('Show transfer history')).not.toBeChecked();
    await expect(page.getByLabel('Haptic feedback')).not.toBeChecked();

    // Explicit Touch Mode = Off overrides coarse-pointer hardware detection.
    await page.getByLabel('Touch mode').selectOption('off');
    await expect(html).toHaveAttribute('data-touch-mode', 'false');
    const pillMinHeight = await page.evaluate(() => {
      const pill = document.querySelector('.af-tab-pill');
      return pill ? getComputedStyle(pill).minHeight : null;
    });
    expect(pillMinHeight).toBe('36px');

    // Rollback safety: dormant legacy keys in localStorage are passively preserved untouched.
    const dormantLegacyKeys = await page.evaluate(() => ({
      cardLift: localStorage.getItem('aetherflow-card-lift'),
      auroraOpacity: localStorage.getItem('aetherflow-aurora-opacity'),
      auroraAnimation: localStorage.getItem('aetherflow-aurora-animation'),
      grainDisplay: localStorage.getItem('aetherflow-grain-display'),
    }));
    expect(dormantLegacyKeys).toEqual({
      cardLift: '-6',
      auroraOpacity: '0.85',
      auroraAnimation: 'true',
      grainDisplay: 'false',
    });
  });

  test('preserves reduced motion suppression across user toggle and OS prefers-reduced-motion', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await installAetherFlowMocks(page, {
      authenticated: true,
      setupRequired: false,
      preserveStorage: true,
    });
    await page.goto('/login');
    await page.evaluate(() => window.localStorage.clear());
    await page.goto('/?tab=settings');

    const html = page.locator('html');
    await page.getByLabel('High refresh cadence').selectOption('120hz');
    await expect(html).toHaveAttribute('data-high-refresh', 'true');
    expect(await html.getAttribute('data-aurora-animation')).toBeNull();
    expect(await html.getAttribute('data-card-lift')).toBeNull();

    // User reduced-motion toggle suppresses 120Hz cadence and exposes the status hint.
    const reducedMotionToggle = page.getByLabel('Reduce interface motion');
    await reducedMotionToggle.check();
    await expect(html).toHaveAttribute('data-reduced-motion', 'true');
    await expect(html).toHaveAttribute('data-high-refresh', 'false');
    await expect(page.getByTestId('settings-reduced-motion-hint')).toBeVisible();

    // Unchecking restores the underlying configured preference without loss.
    await reducedMotionToggle.uncheck();
    expect(await html.getAttribute('data-reduced-motion')).toBeNull();
    await expect(html).toHaveAttribute('data-high-refresh', 'true');

    // OS prefers-reduced-motion media query also suppresses motion immediately.
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await expect(html).toHaveAttribute('data-high-refresh', 'false');
    await expect(page.getByTestId('settings-reduced-motion-hint')).toBeVisible();
  });

  test('renders translated display preference labels across all six locales without raw keys', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/?tab=settings');

    const expectedByLocale: Array<{ code: string; cadenceLabel: string; touchLabel: string }> = [
      { code: 'de', cadenceLabel: 'Hohe Bildwiederholrate', touchLabel: 'Touch-Modus' },
      { code: 'dk', cadenceLabel: 'Høj opdateringskadence', touchLabel: 'Berøringstilstand' },
      { code: 'es', cadenceLabel: 'Cadencia de alta frecuencia', touchLabel: 'Modo táctil' },
      { code: 'fr', cadenceLabel: 'Cadence haute fréquence', touchLabel: 'Mode tactile' },
      { code: 'zh', cadenceLabel: '高刷新率节奏', touchLabel: '触控模式' },
      { code: 'en', cadenceLabel: 'High refresh cadence', touchLabel: 'Touch mode' },
    ];

    const localeSelect = page.locator('header.af-header .af-locale-select');
    for (const { code, cadenceLabel, touchLabel } of expectedByLocale) {
      await localeSelect.selectOption(code);
      await expect(page.locator('label[for="settings-high-refresh-mode"]')).toHaveText(cadenceLabel);
      await expect(page.locator('label[for="settings-touch-mode"]')).toHaveText(touchLabel);
      const mainText = (await page.locator('#main-content').textContent()) ?? '';
      expect(mainText).not.toContain('Settings.');
    }
  });

  test('enforces flat surface invariants across dark and light themes and coarse-pointer mobile', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.setViewportSize({ width: 1440, height: 900 });
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/?tab=notifications');
    await expect(page.getByRole('button', { name: 'Add channel', exact: true })).toBeVisible();

    const html = page.locator('html');
    const readBackdropFilter = (el: Element) => {
      const computed = getComputedStyle(el);
      return computed.backdropFilter || computed.getPropertyValue('-webkit-backdrop-filter') || 'none';
    };
    const readCardSurface = (el: Element) => {
      const computed = getComputedStyle(el);
      return {
        backdropFilter: computed.backdropFilter || computed.getPropertyValue('-webkit-backdrop-filter') || 'none',
        transform: computed.transform,
        boxShadow: computed.boxShadow,
        afterContent: getComputedStyle(el, '::after').content,
      };
    };

    const expectedThemes = [
      {
        theme: 'dark',
        tokens: {
          canvas: '#07090e',
          card: '#0d111a',
          borderCard: '#232d42',
          fgPrimary: '#f1f5f9',
          themeColor: '#07090e',
        },
      },
      {
        theme: 'light',
        tokens: {
          canvas: '#f4f6fa',
          card: '#ffffff',
          borderCard: '#cfd9e6',
          fgPrimary: '#0f172a',
          themeColor: '#f4f6fa',
        },
      },
    ] as const;

    for (const { theme, tokens } of expectedThemes) {
      if (theme === 'light') {
        await page.locator('header.af-header').getByRole('button', { name: 'Toggle theme', exact: true }).click();
      }
      await expect(html).toHaveAttribute('data-theme', theme);

      // Verify polarity-scoped semantic tokens and meta[name="theme-color"] sync.
      const observedTokens = await page.evaluate(() => {
        const root = getComputedStyle(document.documentElement);
        const normHex = (val: string) => {
          const s = val.trim().toLowerCase();
          return /^#[0-9a-f]{3}$/.test(s) ? `#${s[1]}${s[1]}${s[2]}${s[2]}${s[3]}${s[3]}` : s;
        };
        return {
          canvas: normHex(root.getPropertyValue('--af-bg-canvas')),
          card: normHex(root.getPropertyValue('--af-surface-card')),
          borderCard: normHex(root.getPropertyValue('--af-border-card')),
          fgPrimary: normHex(root.getPropertyValue('--af-fg-primary')),
          themeColor: (() => {
            const raw = document.querySelector('meta[name="theme-color"]')?.getAttribute('content');
            return raw ? normHex(raw) : null;
          })(),
        };
      });
      expect(observedTokens).toEqual(tokens);

      // 1. Persistent chrome has zero backdrop-filter blur.
      expect(await page.locator('.af-sidebar').first().evaluate(readBackdropFilter)).toBe('none');
      expect(await page.locator('.af-header').first().evaluate(readBackdropFilter)).toBe('none');

      // 2. Static .af-card has zero backdrop-filter, zero ::after rim, and zero hover transform/box-shadow change.
      const staticCard = page.locator('.af-card:not(.af-card-interactive)').first();
      await expect(staticCard).toBeVisible();
      await page.mouse.move(0, 0);
      const restCard = await staticCard.evaluate(readCardSurface);
      expect(restCard).toEqual({
        backdropFilter: 'none',
        transform: 'none',
        boxShadow: 'none',
        afterContent: 'none',
      });
      await staticCard.hover();
      expect(await staticCard.evaluate(readCardSurface)).toEqual(restCard);

      // 3. Tier 3 overlays (.af-modal, .af-popover, .af-toast) have zero backdrop-filter blur.
      await page.keyboard.press('Control+k');
      const modal = page.getByRole('dialog', { name: 'Command Palette', exact: true });
      await expect(modal).toBeVisible();
      expect(await modal.evaluate(readBackdropFilter)).toBe('none');
      await page.keyboard.press('Escape');
      await expect(modal).toBeHidden();

      await page.getByTestId('header-account-menu-trigger').click();
      const popover = page.getByTestId('header-account-menu');
      await expect(popover).toBeVisible();
      expect(await popover.evaluate(readBackdropFilter)).toBe('none');
      await page.keyboard.press('Escape');
      await expect(popover).toBeHidden();

      await page.getByRole('button', { name: 'Add channel', exact: true }).click();
      const channelDialog = page.getByRole('dialog', { name: 'Configure delivery channel', exact: true });
      await expect(channelDialog).toBeVisible();
      await channelDialog.getByLabel('Delivery URL', { exact: true }).fill('https://example.com/webhook');
      await channelDialog.getByRole('button', { name: 'Create channel', exact: true }).click();
      await page.keyboard.press('Escape');
      await expect(channelDialog).toBeHidden();
      const toast = page.locator('.af-toast').first();
      await expect(toast).toBeVisible();
      expect(await toast.evaluate(readBackdropFilter)).toBe('none');
      await toast.getByRole('button', { name: 'Dismiss notification', exact: true }).click();
      await expect(toast).toBeHidden();
    }

    // Switching Light -> Dark restores dark canvas token and meta[name="theme-color"].
    await page.locator('header.af-header').getByRole('button', { name: 'Toggle theme', exact: true }).click();
    await expect(html).toHaveAttribute('data-theme', 'dark');
    expect(
      await page.evaluate(() =>
        document.querySelector('meta[name="theme-color"]')?.getAttribute('content')?.trim().toLowerCase() ?? null,
      ),
    ).toBe('#07090e');

    // 4. Touch Mode on mobile viewport keeps >= 44px controls, zero blur on .af-mobile-dock, and header <= 104px.
    await page.goto('/?tab=settings');
    await page.getByLabel('Touch mode').selectOption('on');
    await expect(html).toHaveAttribute('data-touch-mode', 'true');
    await page.setViewportSize({ width: 390, height: 844 });

    const mobileDock = page.locator('.af-mobile-dock');
    await expect(mobileDock).toBeVisible();
    expect(await mobileDock.evaluate(readBackdropFilter)).toBe('none');

    const header = page.locator('header.af-header');
    await expect(header).toBeVisible();
    expect(await header.evaluate(readBackdropFilter)).toBe('none');
    const headerBounds = await header.boundingBox();
    expect(headerBounds).not.toBeNull();
    expect(headerBounds!.height).toBeLessThanOrEqual(104);

    for (const control of [
      page.locator('.af-tab-pill').first(),
      header.getByRole('button', { name: 'Toggle theme', exact: true }),
      header.getByRole('button', { name: 'Account menu', exact: true }),
      header.getByRole('combobox', { name: 'Locale', exact: true }),
    ]) {
      const bounds = await control.boundingBox();
      expect(bounds).not.toBeNull();
      expect(bounds!.height).toBeGreaterThanOrEqual(44);
    }
  });
});
