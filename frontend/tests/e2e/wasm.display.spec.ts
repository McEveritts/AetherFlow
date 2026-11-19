import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

test.describe('WASM Seed #8 Display, Cadence, Touch & Atmosphere parity', () => {
  test('wires all six display controls to CSP-safe root selectors and computed CSS, and persists across reload', async ({ page }) => {
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

    // Default state uses root data-* selectors only (strict style-src 'self' compliance).
    await expect(html).toHaveAttribute('data-refresh-mode', 'auto');
    await expect(html).toHaveAttribute('data-touch-preference', 'auto');
    await expect(html).toHaveAttribute('data-aurora-opacity', '55');
    await expect(html).toHaveAttribute('data-aurora-animation', 'false');
    await expect(html).toHaveAttribute('data-grain', 'true');
    await expect(html).toHaveAttribute('data-card-lift', '-4');
    await expect(html).toHaveAttribute('data-density', 'compact');
    expect(await html.getAttribute('style')).toBeNull();

    const readComputedTokens = () =>
      page.evaluate(() => {
        const rootStyle = getComputedStyle(document.documentElement);
        const beforeStyle = getComputedStyle(document.body, '::before');
        const afterStyle = getComputedStyle(document.body, '::after');
        const pill = document.querySelector('.obs-tab-pill');
        const durationMs = (name: string) => {
          const css = rootStyle.getPropertyValue(name).trim();
          return Math.round(Number.parseFloat(css) * (css.endsWith('ms') ? 1 : 1000));
        };
        return {
          durationFast: durationMs('--obs-duration-fast'),
          durationCard: durationMs('--obs-duration-card'),
          auroraOpacity: Number(rootStyle.getPropertyValue('--obs-aurora-opacity')),
          cardLift: rootStyle.getPropertyValue('--obs-card-lift').trim(),
          auroraAnimationName: beforeStyle.animationName,
          grainDisplay: afterStyle.display,
          pillMinHeight: pill ? getComputedStyle(pill).minHeight : null,
          inlineRootStyle: document.documentElement.getAttribute('style'),
        };
      });

    expect(await readComputedTokens()).toMatchObject({
      auroraOpacity: 0.55,
      cardLift: '-4px',
      auroraAnimationName: 'none',
      grainDisplay: 'block',
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

    // 2. Touch mode: compact desktop (off) vs >=44px touch targets (on)
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

    // 3. Aurora opacity (quantized CSP-safe root selector)
    const opacitySlider = page.getByLabel('Aurora opacity');
    await opacitySlider.fill('85');
    await opacitySlider.dispatchEvent('change');
    await expect(page.getByTestId('settings-aurora-opacity-value')).toHaveText('85%');
    await expect(html).toHaveAttribute('data-aurora-opacity', '85');

    // 4. Aurora animation
    const animationCheckbox = page.getByLabel('Aurora animation');
    await animationCheckbox.check();
    await expect(html).toHaveAttribute('data-aurora-animation', 'true');

    // 5. Tactile grain
    const grainCheckbox = page.getByLabel('Tactile grain');
    await grainCheckbox.uncheck();
    await expect(html).toHaveAttribute('data-grain', 'false');

    // 6. Card hover lift
    const cardLiftCheckbox = page.getByLabel('Card hover lift');
    await cardLiftCheckbox.uncheck();
    await expect(html).toHaveAttribute('data-card-lift', '0');

    expect(await readComputedTokens()).toMatchObject({
      durationFast: 110,
      durationCard: 150,
      auroraOpacity: 0.85,
      cardLift: '0px',
      auroraAnimationName: 'obs-aurora-shift',
      grainDisplay: 'none',
      pillMinHeight: '44px',
      inlineRootStyle: null,
    });

    // Verify both flat keys and legacy Zustand envelope were persisted.
    const stored = await page.evaluate(() => ({
      refresh: localStorage.getItem('aetherflow-high-refresh-mode'),
      touch: localStorage.getItem('aetherflow-touch-mode'),
      opacity: localStorage.getItem('aetherflow-aurora-opacity'),
      anim: localStorage.getItem('aetherflow-aurora-animation'),
      grain: localStorage.getItem('aetherflow-grain-display'),
      lift: localStorage.getItem('aetherflow-card-lift'),
      legacy: JSON.parse(localStorage.getItem('aetherflow-system-storage') ?? '{}'),
    }));
    expect(stored).toMatchObject({
      refresh: '120hz',
      touch: 'on',
      opacity: '0.85',
      anim: 'true',
      grain: 'false',
      lift: '0',
    });
    expect(stored.legacy.state).toMatchObject({
      highRefreshMode: '120hz',
      touchMode: 'enabled',
      auroraOpacity: 0.85,
      auroraAnimation: true,
      grainDisplay: false,
      cardLift: 0,
    });

    // Reload and confirm full state + computed CSS round-trip.
    await page.reload();
    await expect(refreshSelect).toHaveValue('120hz');
    await expect(touchSelect).toHaveValue('on');
    await expect(opacitySlider).toHaveValue('85');
    await expect(animationCheckbox).toBeChecked();
    await expect(grainCheckbox).not.toBeChecked();
    await expect(cardLiftCheckbox).not.toBeChecked();
    expect(await readComputedTokens()).toMatchObject({
      durationFast: 110,
      durationCard: 150,
      auroraOpacity: 0.85,
      cardLift: '0px',
      auroraAnimationName: 'obs-aurora-shift',
      grainDisplay: 'none',
      pillMinHeight: '44px',
      inlineRootStyle: null,
    });
  });

  test('hydrates legacy 109.1 Zustand storage shapes and respects 120Hz + coarse-pointer auto defaults', async ({ page }) => {
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

    await expect(html).toHaveAttribute('data-refresh-mode', 'auto');
    await expect(html).toHaveAttribute('data-high-refresh', 'true');
    await expect(html).toHaveAttribute('data-touch-preference', 'auto');
    await expect(html).toHaveAttribute('data-touch-mode', 'true');
    await expect(html).toHaveAttribute('data-aurora-opacity', '30');
    await expect(html).toHaveAttribute('data-aurora-animation', 'true');
    await expect(html).toHaveAttribute('data-grain', 'false');
    await expect(html).toHaveAttribute('data-card-lift', '-6');
    await expect(html).toHaveAttribute('data-density', 'immersive');

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
      const pill = document.querySelector('.obs-tab-pill');
      return pill ? getComputedStyle(pill).minHeight : null;
    });
    expect(pillMinHeight).toBe('36px');
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
    await page.getByLabel('Aurora animation').check();
    await expect(html).toHaveAttribute('data-high-refresh', 'true');
    await expect(html).toHaveAttribute('data-aurora-animation', 'true');
    await expect(html).toHaveAttribute('data-card-lift', '-4');

    // User reduced-motion toggle suppresses aurora animation, card lift, and 120Hz cadence.
    const reducedMotionToggle = page.getByLabel('Reduce interface motion');
    await reducedMotionToggle.check();
    await expect(html).toHaveAttribute('data-reduced-motion', 'true');
    await expect(html).toHaveAttribute('data-high-refresh', 'false');
    await expect(html).toHaveAttribute('data-aurora-animation', 'false');
    await expect(html).toHaveAttribute('data-card-lift', '0');
    await expect(page.getByTestId('settings-reduced-motion-hint')).toBeVisible();

    const suppressedStyles = await page.evaluate(() => ({
      auroraAnim: getComputedStyle(document.body, '::before').animationName,
      cardLift: getComputedStyle(document.documentElement).getPropertyValue('--obs-card-lift').trim(),
    }));
    expect(suppressedStyles).toEqual({ auroraAnim: 'none', cardLift: '0px' });

    // Unchecking restores the underlying configured preferences without loss.
    await reducedMotionToggle.uncheck();
    await expect(html).toHaveAttribute('data-high-refresh', 'true');
    await expect(html).toHaveAttribute('data-aurora-animation', 'true');
    await expect(html).toHaveAttribute('data-card-lift', '-4');

    // OS prefers-reduced-motion media query also suppresses motion immediately.
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await expect(html).toHaveAttribute('data-high-refresh', 'false');
    await expect(html).toHaveAttribute('data-aurora-animation', 'false');
    await expect(html).toHaveAttribute('data-card-lift', '0');
    await expect(page.getByTestId('settings-reduced-motion-hint')).toBeVisible();
  });

  test('renders translated display preference labels across all six locales without raw keys', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    await page.goto('/?tab=settings');

    const expectedByLocale: Array<{ code: string; cadenceLabel: string; opacityLabel: string }> = [
      { code: 'de', cadenceLabel: 'Hohe Bildwiederholrate', opacityLabel: 'Polarlicht-Deckkraft' },
      { code: 'dk', cadenceLabel: 'Høj opdateringskadence', opacityLabel: 'Nordlys-gennemsigtighed' },
      { code: 'es', cadenceLabel: 'Cadencia de alta frecuencia', opacityLabel: 'Opacidad de la aurora' },
      { code: 'fr', cadenceLabel: 'Cadence haute fréquence', opacityLabel: "Opacité de l'aurore" },
      { code: 'zh', cadenceLabel: '高刷新率节奏', opacityLabel: '极光不透明度' },
      { code: 'en', cadenceLabel: 'High refresh cadence', opacityLabel: 'Aurora opacity' },
    ];

    const localeSelect = page.locator('header.af-header .af-locale-select');
    for (const { code, cadenceLabel, opacityLabel } of expectedByLocale) {
      await localeSelect.selectOption(code);
      await expect(page.locator('label[for="settings-high-refresh-mode"]')).toHaveText(cadenceLabel);
      await expect(page.locator('label[for="settings-aurora-opacity"]')).toHaveText(opacityLabel);
      const mainText = (await page.locator('#main-content').textContent()) ?? '';
      expect(mainText).not.toContain('Settings.');
    }
  });
});
