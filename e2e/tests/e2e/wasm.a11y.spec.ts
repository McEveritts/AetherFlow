import { expect, test } from '@playwright/test';
import axe, { type Result } from 'axe-core';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const tabs = [
  'overview', 'inbox', 'services', 'marketplace', 'mcbrowser', 'fileshare',
  'streaming', 'mediaflow', 'ai', 'network', 'cluster', 'users', 'audit',
  'settings', 'notifications', 'quotas',
];

test('empty and populated Network and Fileshare expose valid table semantics', async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let populated = true;
  await page.route('**/api/v1/admin/ingress/configs', route => route.fulfill({ json: {
    configs: populated ? [{ appName: 'observation-service', listenPort: 21202,
      publicDomain: 'files.example.test', externalAccessEnabled: true, tlsEnabled: false }] : [],
  } }));
  await page.route(/\/api\/v1\/auth\/fileshare(?:\?|$)/, route => route.fulfill({ json: {
    files: populated ? [{ name: 'observation-folder', isDir: true, size: 0,
      modTime: '2026-11-18T00:00:00Z', extension: '' }] : [],
  } }));
  const observations = [];
  for (const filled of [true, false]) {
    populated = filled;
    for (const tab of ['network', 'fileshare']) {
      await page.goto(`/?tab=${tab}`);
      const table = page.getByRole('table', { name: tab === 'network'
        ? 'Application external access' : 'Files and directories in the current path', exact: true });
      if (filled) {
        await expect(table).toBeVisible();
        const row = table.getByRole('row').filter({ hasText: tab === 'network'
          ? 'observation-service' : 'observation-folder' });
        await expect(row).toHaveCount(1);
        await expect(row.getByRole('cell')).toHaveCount(tab === 'network' ? 2 : 4);
      } else {
        await expect(page.getByRole('heading', { name: tab === 'network'
          ? 'No ingress configurations' : 'This directory is empty', exact: true })).toBeVisible();
        await expect(table).toHaveCount(0);
      }
      await page.evaluate(axe.source);
      const result = await page.evaluate(async () => {
        const analyzer = (window as unknown as { axe: typeof axe }).axe;
        return analyzer.run(document, { runOnly: {
          type: 'rule', values: ['aria-required-children', 'th-has-data-cells'],
        } });
      });
      observations.push({ tab, populated: filled, violations: result.violations,
        incomplete: result.incomplete, aria: await page.locator('body').ariaSnapshot() });
      expect(result.violations).toEqual([]);
      expect(result.incomplete).toEqual([]);
    }
  }
  await testInfo.attach('table-semantics', {
    contentType: 'application/json', body: Buffer.from(JSON.stringify(observations, null, 2)),
  });
});

function contrastRatio(foreground: string, background: string): number {
  const luminance = (color: string) => {
    const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(channel => {
      const value = channel / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    });
    return channels.reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  };
  const a = luminance(foreground), b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

test.describe.configure({ retries: 0 });
for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  test.describe(`${viewport.width}px automated accessibility`, () => {
    test.use({ viewport });

    for (const theme of ['dark', 'light']) {
      test(`dashboard tabs meet automated WCAG checks in ${theme} mode`, async ({ page }, testInfo) => {
        test.setTimeout(90_000);
        const unhandled: string[] = [];
        await page.route('**/api/v1/**', route => {
          unhandled.push(`${route.request().method()} ${new URL(route.request().url()).pathname}`);
          return route.fulfill({ status: 599, json: { error: 'Missing accessibility fixture' } });
        });
        await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
        const reads: Record<string, unknown> = {
          '/api/v1/auth/fileshare': { files: [] },
          '/api/v1/auth/streaming/dashboard': { servers: [], activeSessions: [], liveSummary: {}, analytics: {} },
          '/api/v1/auth/blueprints': [],
          '/api/v1/admin/mediaflow/queue': [],
          '/api/v1/admin/network/status': { platform: 'linux', runner_available: false },
          '/api/v1/admin/ingress/configs': { configs: [] },
          '/api/v1/admin/services': [],
          '/api/v1/admin/peers': {
            identity: null, peer_protocol: 1, capabilities: ['links'], rtt_warn_ms: 120,
            peers: [], pairing_windows: [], pairing_attempts: [], detected_endpoints: [],
          },
          '/api/v1/admin/users': { users: [] },
          '/api/v1/admin/audit-log': { entries: [], total: 0 },
          '/api/v1/admin/quotas': { quotas: [] },
        };
        await page.route('**/api/v1/**', route => {
          const path = new URL(route.request().url()).pathname;
          if (route.request().method() === 'GET' && Object.hasOwn(reads, path)) {
            return route.fulfill({ json: reads[path] });
          }
          return route.fallback();
        });
        const content = '// Readable editor comment\nlet value = 42;\n';
        await page.route('**/api/v1/auth/mcbrowser/entries?*', route => route.fulfill({ json: {
          path: '', entries: [{ name: 'a11y.rs', path: 'a11y.rs', kind: 'file', size: content.length,
            modified: '2026-11-18T00:00:00Z' }],
        } }));
        await page.route('**/api/v1/auth/mcbrowser/policy', route => route.fulfill({ json: {
          scope: 'private', permissions: { read: true, modify: true }, rules: [],
        } }));
        await page.route('**/api/v1/auth/mcbrowser/usage', route => route.fulfill({
          json: { used_bytes: content.length, quota_bytes: 1024 * 1024 },
        }));
        await page.route('**/api/v1/auth/mcbrowser/content?*', route => route.fulfill({
          headers: { ETag: '"a11y-v1"' }, json: { content, etag: '"a11y-v1"' },
        }));
        await page.goto('/');
        await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
        if (await page.locator('html').getAttribute('data-theme') !== theme) {
          await page.locator('header button[aria-pressed]').click();
        }
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        const failures: unknown[] = [];
        const observations: Array<{ tab: string; violations: Result[]; incomplete: Result[];
          passedRules: string[]; inapplicableRules: string[]; aria: string }> = [];
        for (const tab of tabs) {
          await test.step(tab, async () => {
            const nav = page.getByTestId(`nav-${tab}`);
            if (await nav.isVisible()) await nav.click();
            else {
              await page.locator('.af-mobile-dock button').last().click();
              await page.getByTestId(`mobile-nav-${tab}`).click();
            }
            await expect(nav).toHaveAttribute('aria-current', 'page');
            await page.waitForLoadState('networkidle');
            // Diagnostic code enters via Playwright; the page keeps its real CSP.
            await page.evaluate(axe.source);
            const result = await page.evaluate(async () => {
              const analyzer = (window as unknown as { axe: typeof axe }).axe;
              return analyzer.run(document, {
                runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
              });
            });
            expect(result.testEngine.version).toBe('4.11.2');
            failures.push(...result.violations.map(violation => ({ tab, ...violation })));
            observations.push({ tab, violations: result.violations, incomplete: result.incomplete,
              passedRules: result.passes.map(rule => rule.id),
              inapplicableRules: result.inapplicable.map(rule => rule.id),
              aria: await page.locator('body').ariaSnapshot() });
            if (tab === 'mcbrowser') {
              await page.getByRole('button', { name: 'File a11y.rs', exact: true }).click();
              const editor = page.getByRole('dialog', { name: 'Code editor', exact: true });
              await expect(editor).toBeVisible();
              await expect(editor.locator('.af-token-comment')).toHaveCount(1);
              for (const selector of ['.af-editor-gutter', '.af-token-comment']) {
                const colors = await editor.locator(selector).evaluate(element => {
                  let surface: Element | null = element;
                  while (surface) {
                    const background = getComputedStyle(surface).backgroundColor;
                    if (background !== 'rgba(0, 0, 0, 0)' && background !== 'transparent') {
                      return { foreground: getComputedStyle(element).color, background };
                    }
                    surface = surface.parentElement;
                  }
                  throw new Error('Expected an opaque editor background');
                });
                expect(colors.background, 'editor surfaces must remain opaque for the contrast measurement').toMatch(/^rgb\(/);
                expect(contrastRatio(colors.foreground, colors.background), selector).toBeGreaterThanOrEqual(4.5);
              }
              const statusBounds = await editor.locator('.af-editor > [role="status"]').evaluate(status => {
                const row = status.getBoundingClientRect();
                const cursor = status.querySelector('span')!.getBoundingClientRect();
                return { rowTop: row.top, rowBottom: row.bottom, textTop: cursor.top, textBottom: cursor.bottom };
              });
              expect(statusBounds.textTop).toBeGreaterThanOrEqual(statusBounds.rowTop);
              expect(statusBounds.textBottom, 'cursor summary must fit inside the editor status row').toBeLessThanOrEqual(statusBounds.rowBottom);
              const input = editor.getByRole('textbox', { name: 'Editor text', exact: true });
              await input.focus();
              await input.press('Control+Home');
              await input.press('Shift+End');
              const selection = await input.evaluate(element => {
                const input = element as HTMLTextAreaElement;
                const style = getComputedStyle(input, '::selection');
                return {
                  foreground: style.color, fill: style.webkitTextFillColor,
                  background: style.backgroundColor,
                  selected: input.value.slice(input.selectionStart, input.selectionEnd),
                };
              });
              expect(selection.selected).toContain('//');
              expect(selection.foreground).toMatch(/^rgb\(/);
              expect(selection.fill).toBe(selection.foreground);
              expect(selection.background, 'selection must paint an opaque surface over the transparent editor overlay').toMatch(/^rgb\(/);
              expect(contrastRatio(selection.foreground, selection.background), 'selected editor text').toBeGreaterThanOrEqual(4.5);
              await testInfo.attach(`editor-selection-${theme}-${viewport.width}`, {
                contentType: 'image/png', body: await editor.screenshot({ caret: 'hide' }),
              });
              await input.press('ArrowLeft');
              await editor.getByRole('button', { name: 'Close dialog', exact: true }).click();
              await expect(editor).toBeHidden();
            }
          });
        }
        // Preserve rules needing human review separately; an automated pass
        // does not establish manual screen-reader or complete WCAG conformance.
        await testInfo.attach('automated-accessibility', {
          contentType: 'application/json', body: Buffer.from(JSON.stringify({ theme, viewport, observations, unhandled }, null, 2)),
        });
        expect(unhandled, 'every API request in this UI fixture must have an explicit response').toEqual([]);
        expect(failures).toEqual([]);
      });
    }
  });
}
