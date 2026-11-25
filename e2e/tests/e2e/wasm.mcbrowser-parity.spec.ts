import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const json = (route: Route, value: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });

const TINY_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
  'base64',
);

const FULL_PERMISSIONS = {
  read: true,
  create: true,
  modify: true,
  delete: true,
  download: true,
  share: true,
  archive: true,
  extract: true,
};

async function mountMcBrowserBaseRoutes(page: Page, entries: Array<Record<string, unknown>>) {
  await page.route(/\/api\/v1\/auth\/mcbrowser\/policy(?:\/1)?(?:\?.*)?$/, async (route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, {
      user_id: 1,
      scope: 'private',
      permissions: FULL_PERMISSIONS,
      rules: [],
    });
  });
  await page.route('**/api/v1/auth/mcbrowser/usage', (route) =>
    json(route, { used_bytes: 1024 * 1024, quota_bytes: 10 * 1024 * 1024, status: 'ok' }),
  );
  await page.route(/\/api\/v1\/auth\/mcbrowser\/entries(?:\?.*)?$/, (route) =>
    json(route, { path: '', entries }),
  );
}

test('deep-links Settings to McBrowser Policy, renders lazy grid thumbnails, and navigates inert image/EPUB/CSV previews with encoding switch', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

  const prefPuts: Array<Record<string, unknown>> = [];
  let prefs = {
    view: 'list',
    sort: 'name',
    direction: 'asc',
    show_hidden: true,
    single_click: true,
    natural_sort: false,
    redirect_after_copy_move: true,
    date_format: true,
    editor_theme: 'monokai',
    locale: 'de',
  };

  await page.route('**/api/v1/auth/mcbrowser/preferences', async (route) => {
    if (route.request().method() === 'PUT') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      prefPuts.push(body);
      prefs = { ...prefs, ...body };
    }
    await json(route, prefs);
  });

  await mountMcBrowserBaseRoutes(page, [
    { name: 'cover.png', path: 'cover.png', kind: 'file', size: 2048, modified: '2026-11-19T00:00:00Z' },
    { name: 'metrics.csv', path: 'metrics.csv', kind: 'file', size: 256, modified: '2026-11-19T00:00:00Z' },
    { name: 'handbook.epub', path: 'handbook.epub', kind: 'file', size: 4096, modified: '2026-11-19T00:00:00Z' },
  ]);

  await page.route(/\/api\/v1\/auth\/mcbrowser\/preview\/(thumb|big)\?/, (route) =>
    route.fulfill({ status: 200, contentType: 'image/png', body: TINY_PNG }),
  );

  await page.route(/\/api\/v1\/auth\/mcbrowser\/media-info\?/, (route) =>
    json(route, {
      path: 'cover.png',
      name: 'cover.png',
      kind: 'file',
      content_type: 'image/png',
      size: 2048,
      modified: '2026-11-19T00:00:00Z',
      resolution: { width: 640, height: 480 },
      subtitles: [],
    }),
  );

  await page.route(/\/api\/v1\/auth\/mcbrowser\/csv\?/, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/csv; charset=utf-8',
      body: Buffer.concat([
        Buffer.from('host,note\n"<img src=x onerror=window.__csvXss=1>","caf', 'ascii'),
        Buffer.from([0xe9]),
        Buffer.from(' 10', 'ascii'),
        Buffer.from([0x80]),
        Buffer.from(', ""ok"""\n', 'ascii'),
      ]),
    }),
  );

  await page.route(/\/api\/v1\/auth\/mcbrowser\/epub\?/, (route) =>
    json(route, {
      path: 'handbook.epub',
      title: 'Operator Handbook',
      author: 'AetherFlow Team',
      language: 'en',
      description: 'Safe plain-text EPUB preview.',
      chapters: [
        {
          id: 'c1',
          title: 'Chapter 1',
          href: 'c1.xhtml',
          paragraphs: ['<script>window.__epubXss=1</script> First chapter'],
          text: '<script>window.__epubXss=1</script> First chapter',
        },
        {
          id: 'c2',
          title: 'Chapter 2',
          href: 'c2.xhtml',
          paragraphs: ['Second chapter body'],
          text: 'Second chapter body',
        },
      ],
    }),
  );

  // 1. Settings -> McBrowser Policy deep-link opens the Policy admin subtab directly.
  await page.goto('/?tab=settings');
  await page.getByRole('button', { name: 'McBrowser Policy', exact: true }).click();
  await expect(page.getByRole('tab', { name: 'Storage Policy', exact: true })).toHaveAttribute('aria-selected', 'true');

  // 2. Switch to Workspace, toggle Grid view -> persists preference preserving unrelated fields & renders lazy image thumbnail.
  await page.getByRole('tab', { name: 'Workspace', exact: true }).click();
  await page.getByRole('button', { name: 'Grid', exact: true }).click();
  await expect.poll(() => prefPuts.length).toBeGreaterThanOrEqual(1);
  expect(prefPuts.at(-1)).toMatchObject({
    view: 'grid',
    show_hidden: true,
    single_click: true,
    natural_sort: false,
    redirect_after_copy_move: true,
    date_format: true,
    editor_theme: 'monokai',
    locale: 'de',
  });
  await expect(page.getByTestId('mcbrowser-grid-thumb')).toHaveAttribute('src', /\/preview\/thumb\?path=cover\.png/);

  // 3. Open image preview -> hover stays opaque -> zoom & metadata + Next -> inert EPUB preview -> Next -> inert CSV preview with encoding switch.
  await page.getByRole('button', { name: /cover\.png/ }).first().click();
  await expect(page.getByTestId('media-preview-metadata')).toContainText('640×480');
  const previewDialog = page.getByRole('dialog', { name: 'Media preview', exact: true });
  const readSurface = (element: Element) => {
    const computed = getComputedStyle(element);
    return {
      backgroundColor: computed.backgroundColor,
      backgroundImage: computed.backgroundImage,
      borderTopColor: computed.borderTopColor,
      boxShadow: computed.boxShadow,
      backdropFilter: computed.backdropFilter || computed.getPropertyValue('-webkit-backdrop-filter') || 'none',
      transform: computed.transform,
      afterContent: getComputedStyle(element, '::after').content,
    };
  };
  await page.mouse.move(0, 0);
  const restSurface = await previewDialog.evaluate(readSurface);
  await previewDialog.locator('img').hover();
  expect(await previewDialog.evaluate(readSurface)).toEqual({
    backgroundColor: 'rgb(15, 20, 34)',
    backgroundImage: 'none',
    borderTopColor: restSurface.borderTopColor,
    boxShadow: restSurface.boxShadow,
    backdropFilter: 'none',
    transform: 'none',
    afterContent: 'none',
  });
  await page.getByTestId('image-zoom-in').click();
  await expect(page.getByText('125%', { exact: true })).toBeVisible();

  await page.getByTestId('media-preview-next').click();
  await expect(page.getByTestId('epub-preview')).toBeVisible();
  await expect(page.getByTestId('epub-preview')).toContainText('<script>window.__epubXss=1</script> First chapter');
  await page.getByTestId('epub-chapter-select').selectOption('1');
  await expect(page.getByTestId('epub-preview')).toContainText('Second chapter body');

  await page.getByTestId('media-preview-next').click();
  await expect(page.getByTestId('csv-preview')).toBeVisible();
  await expect(page.getByTestId('csv-preview')).toContainText('<img src=x onerror=window.__csvXss=1>');
  await page.getByTestId('csv-encoding-select').selectOption('windows-1252');
  await expect(page.getByTestId('csv-preview')).toContainText('café 10€, "ok"');
  expect(
    await page.evaluate(() => {
      const globals = window as unknown as { __csvXss?: number; __epubXss?: number };
      return Boolean(globals.__csvXss || globals.__epubXss);
    }),
  ).toBe(false);
});

function relativeLuminance(color: string): number {
  const match = color.match(/^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/);
  if (!match) {
    throw new Error(`Expected opaque rgb() color, got ${color}`);
  }
  const [r, g, b] = match.slice(1).map((n) => {
    const c = Number(n) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(foreground: string, background: string): number {
  const fg = relativeLuminance(foreground);
  const bg = relativeLuminance(background);
  return (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
}

async function expectEditorSurfaceContrast(
  editorRoot: import('@playwright/test').Locator,
  expectedTone: 'dark' | 'light',
) {
  await expect(editorRoot.locator('.af-token-comment').first()).toBeVisible();
  for (const selector of [
    '.af-editor-gutter',
    '.af-token-comment',
    '> [role="status"]',
    '.af-editor-toolbar button.glass-button:not([disabled])',
    '.af-editor-toolbar select.glass-input',
  ]) {
    const target = selector.startsWith('>')
      ? editorRoot.locator(`:scope ${selector}`).first()
      : editorRoot.locator(selector).first();
    const colors = await target.evaluate((element, sel) => {
      const activeColorTransitions = (node: Element) =>
        node
          .getAnimations()
          .map((animation) => ('transitionProperty' in animation ? String(animation.transitionProperty) : ''))
          .filter((prop) => prop === 'color' || prop === 'background-color');

      let surface: Element | null = element;
      while (surface) {
        const background = getComputedStyle(surface).backgroundColor;
        if (background !== 'rgba(0, 0, 0, 0)' && background !== 'transparent') {
          const colorTransitions = [
            ...activeColorTransitions(element),
            ...(surface === element ? [] : activeColorTransitions(surface)),
          ];
          return {
            foreground: getComputedStyle(element).color,
            background,
            colorTransitions,
          };
        }
        surface = surface.parentElement;
      }
      throw new Error(`Expected an opaque background for ${sel}`);
    }, selector);
    expect(
      colors.colorTransitions,
      `${selector} must switch color/background atomically without mid-transition contrast collapse`,
    ).toEqual([]);
    expect(colors.background, `${selector} background must be opaque`).toMatch(/^rgb\(/);
    const bgLuminance = relativeLuminance(colors.background);
    if (expectedTone === 'light') {
      expect(bgLuminance, `${selector} background must match light editor tone`).toBeGreaterThan(0.5);
    } else {
      expect(bgLuminance, `${selector} background must match dark editor tone`).toBeLessThan(0.2);
    }
    expect(contrastRatio(colors.foreground, colors.background), `${selector} contrast`).toBeGreaterThanOrEqual(4.5);
  }
}

test('honors persisted non-dropdown 109.1 editor themes and auto-detects filename syntax modes', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, preserveStorage: true });

  const prefPuts: Array<Record<string, unknown>> = [];
  let prefs = {
    view: 'list',
    sort: 'name',
    direction: 'asc',
    show_hidden: true,
    single_click: false,
    natural_sort: true,
    redirect_after_copy_move: false,
    date_format: false,
    editor_theme: 'nord_dark',
    locale: 'de',
  };

  await page.route('**/api/v1/auth/mcbrowser/preferences', async (route) => {
    if (route.request().method() === 'PUT') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      prefPuts.push(body);
      prefs = { ...prefs, ...body };
    }
    await json(route, prefs);
  });

  await mountMcBrowserBaseRoutes(page, [
    { name: 'Dockerfile', path: 'Dockerfile', kind: 'file', size: 64, modified: '2026-11-19T00:00:00Z' },
  ]);

  await page.route(/\/api\/v1\/auth\/mcbrowser\/content\?/, async (route) => {
    await route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/json', etag: 'docker-etag-1' },
      body: JSON.stringify({ path: 'Dockerfile', content: 'FROM alpine:3.20\n# build\nRUN echo ok\n', etag: 'docker-etag-1' }),
    });
  });

  await page.goto('/?tab=mcbrowser');

  // Open Dockerfile -> preserves persisted non-dropdown 109.1 theme 'nord_dark' and auto-detects 'dockerfile' mode.
  await page.getByRole('button', { name: /Dockerfile/ }).click();
  const editorDialog = page.getByRole('dialog', { name: 'Code editor' });
  const editorRoot = editorDialog.locator('.af-editor');
  await expect(editorRoot).toHaveAttribute('data-editor-theme', 'nord_dark');
  await expect(editorRoot).toHaveAttribute('data-editor-tone', 'dark');
  await expect(editorRoot).toHaveClass(/af-editor-theme-nord-dark/);
  await expect(editorRoot).toHaveAttribute('data-editor-language', 'dockerfile');
  await expect(editorDialog.getByTestId('editor-theme-select')).toHaveValue('nord_dark');

  // Verify dark editor remains WCAG AA readable inside a light outer dashboard.
  await page.evaluate(() => {
    document.documentElement.dataset.theme = 'light';
    document.documentElement.classList.remove('dark');
    document.documentElement.classList.add('light');
  });
  await expectEditorSurfaceContrast(editorRoot, 'dark');

  // Switch to light 'chrome' editor inside a dark outer dashboard and verify WCAG AA contrast.
  await page.evaluate(() => {
    document.documentElement.dataset.theme = 'dark';
    document.documentElement.classList.remove('light');
    document.documentElement.classList.add('dark');
  });
  await editorDialog.getByTestId('editor-theme-select').selectOption('chrome');
  await expect(editorRoot).toHaveAttribute('data-editor-theme', 'chrome');
  await expect(editorRoot).toHaveAttribute('data-editor-tone', 'light');
  await expect(editorRoot).toHaveClass(/af-editor-theme-chrome/);
  await expectEditorSurfaceContrast(editorRoot, 'light');

  // Switch theme to 'dracula' -> updates class & persists via PUT /preferences preserving unrelated fields.
  await editorDialog.getByTestId('editor-theme-select').selectOption('dracula');
  await expect(editorRoot).toHaveAttribute('data-editor-theme', 'dracula');
  await expect(editorRoot).toHaveAttribute('data-editor-tone', 'dark');
  await expect(editorRoot).toHaveClass(/af-editor-theme-dracula/);
  await expectEditorSurfaceContrast(editorRoot, 'dark');
  await expect.poll(() => prefPuts.at(-1)?.editor_theme).toBe('dracula');
  expect(prefPuts.at(-1)).toMatchObject({ editor_theme: 'dracula', show_hidden: true, locale: 'de' });
  await editorDialog.getByRole('button', { name: 'Close dialog' }).click();
});

test('supports >256 KiB plain-text Find/Replace with word wrap and ETag CAS conflict recovery', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, preserveStorage: true });

  await page.route('**/api/v1/auth/mcbrowser/preferences', async (route) => {
    await json(route, {
      view: 'list',
      sort: 'name',
      direction: 'asc',
      show_hidden: true,
      single_click: false,
      natural_sort: true,
      redirect_after_copy_move: false,
      date_format: false,
      editor_theme: 'dracula',
      locale: 'de',
    });
  });

  await mountMcBrowserBaseRoutes(page, [
    { name: 'large.log', path: 'large.log', kind: 'file', size: 300 * 1024, modified: '2026-11-19T00:00:00Z' },
  ]);

  const largePayload = `${'A'.repeat(270 * 1024)}\nFINDME one\nFINDME two\n`;
  const putHeaders: Array<string | undefined> = [];
  let currentEtag = 'etag-1';
  let forceConflictOnce = true;
  let savedLargeContent = '';

  await page.route(/\/api\/v1\/auth\/mcbrowser\/content\?/, async (route) => {
    if (route.request().method() === 'PUT') {
      const ifMatch = route.request().headers()['if-match'];
      putHeaders.push(ifMatch);
      if (forceConflictOnce) {
        forceConflictOnce = false;
        currentEtag = 'etag-2';
        await json(route, { error: 'ETag mismatch' }, 412);
        return;
      }
      const body = route.request().postDataJSON() as { content: string };
      savedLargeContent = body.content;
      currentEtag = 'etag-3';
      await route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/json', etag: currentEtag },
        body: JSON.stringify({ success: true, etag: currentEtag, accounting_pending: false }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/json', etag: currentEtag },
      body: JSON.stringify({ path: 'large.log', content: largePayload, etag: currentEtag }),
    });
  });

  await page.goto('/?tab=mcbrowser');

  // Open >256 KiB large.log -> plain-text mode, word wrap, Find Next + Replace All, ETag 412 conflict & CAS overwrite.
  await page.getByRole('button', { name: /large\.log/ }).click();
  const editorDialog = page.getByRole('dialog', { name: 'Code editor' });
  await expect(editorDialog.getByText('Plain text · >256 KiB')).toBeVisible();
  const wrapToggle = editorDialog.getByTestId('editor-word-wrap');
  await wrapToggle.click();
  await expect(wrapToggle).toHaveAttribute('aria-pressed', 'true');

  await editorDialog.getByRole('button', { name: 'Find / Replace', exact: true }).click();
  await editorDialog.getByLabel('Find', { exact: true }).fill('FINDME');
  await editorDialog.getByRole('button', { name: 'Find next', exact: true }).click();
  const firstSel = await editorDialog.getByLabel('Editor text').evaluate((el: HTMLTextAreaElement) => el.selectionStart);
  await editorDialog.getByRole('button', { name: 'Find next', exact: true }).click();
  const secondSel = await editorDialog.getByLabel('Editor text').evaluate((el: HTMLTextAreaElement) => el.selectionStart);
  expect(secondSel).toBeGreaterThan(firstSel);

  await editorDialog.getByLabel('Replace', { exact: true }).fill('REPLACED');
  await editorDialog.getByRole('button', { name: 'Replace all', exact: true }).click();

  // First save hits 412 with If-Match: etag-1; draft stays intact; Overwrite re-fetches etag-2 and succeeds.
  await editorDialog.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(editorDialog.getByRole('button', { name: 'Overwrite with my draft…', exact: true })).toBeVisible();
  await editorDialog.getByRole('button', { name: 'Overwrite with my draft…', exact: true }).click();
  await page.getByRole('dialog', { name: 'Replace server content?' }).getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect.poll(() => savedLargeContent.includes('REPLACED two')).toBe(true);
  expect(putHeaders).toEqual(['etag-1', 'etag-2']);
});

test('serializes and coalesces McBrowser preference PUTs and retries failed saves without marking them persisted', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });

  let prefs = {
    view: 'list',
    sort: 'name',
    direction: 'asc',
    show_hidden: true,
    single_click: false,
    natural_sort: true,
    redirect_after_copy_move: false,
    date_format: true,
    editor_theme: 'monokai',
    locale: 'fr',
  };
  const receivedPuts: Array<Record<string, unknown>> = [];
  let inFlight = 0;
  let maxInFlight = 0;
  let releaseFirstPut: () => void = () => {};
  let failSecondPutOnce = true;

  await page.route('**/api/v1/auth/mcbrowser/preferences', async (route) => {
    if (route.request().method() === 'GET') {
      await json(route, prefs);
      return;
    }
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    const body = route.request().postDataJSON() as Record<string, unknown>;
    receivedPuts.push(body);
    if (receivedPuts.length === 1) {
      await new Promise<void>((resolve) => {
        releaseFirstPut = resolve;
      });
    }
    inFlight -= 1;
    if (receivedPuts.length === 2 && failSecondPutOnce) {
      failSecondPutOnce = false;
      await json(route, { error: 'Temporary preference write failure' }, 503);
      return;
    }
    prefs = { ...prefs, ...body };
    await json(route, prefs);
  });

  await mountMcBrowserBaseRoutes(page, []);

  await page.goto('/?tab=mcbrowser');
  await expect(page.getByRole('button', { name: 'Grid', exact: true })).toBeVisible();

  // Trigger PUT #1 (held open) then rapidly change sort and direction while PUT #1 is in flight.
  await page.getByRole('button', { name: 'Grid', exact: true }).click();
  await expect.poll(() => receivedPuts.length).toBe(1);
  await page.getByLabel('Sort').selectOption('size');
  await page.getByLabel('Sort').selectOption('modified');
  await page.getByRole('button', { name: 'Ascending', exact: true }).click();
  expect(receivedPuts).toHaveLength(1);

  // Release PUT #1 -> coalesced PUT #2 fires and fails -> Retry banner appears and succeeds on retry.
  releaseFirstPut();
  await expect(page.getByTestId('mcbrowser-prefs-error')).toBeVisible();
  expect(maxInFlight).toBe(1);
  expect(receivedPuts).toHaveLength(2);
  expect(receivedPuts[1]).toMatchObject({
    view: 'grid',
    sort: 'modified',
    direction: 'desc',
    show_hidden: true,
    date_format: true,
    editor_theme: 'monokai',
    locale: 'fr',
  });

  await page.getByTestId('mcbrowser-prefs-retry').click();
  await expect(page.getByTestId('mcbrowser-prefs-error')).toHaveCount(0);
  await expect.poll(() => receivedPuts.length).toBe(3);
  expect(maxInFlight).toBe(1);
  expect(prefs).toMatchObject({
    view: 'grid',
    sort: 'modified',
    direction: 'desc',
    editor_theme: 'monokai',
    locale: 'fr',
  });
});
