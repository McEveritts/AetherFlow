import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const PAGE_SIZE = 25;

function quotaRows(count: number, revision = 0) {
  return Array.from({ length: count }, (_, index) => ({
    user_id: index + 1,
    username: index === 0 ? 'first-draft-tenant'
      : index === 25 ? 'second-draft-tenant'
        : index === 999 ? 'last-marker-tenant'
          : `tenant-${String(index + 1).padStart(4, '0')}`,
    quota_bytes: revision ? revision * 4000 : 1000,
    used_bytes: index + 1,
    configured: true,
  }));
}

test('a thousand tenants stay reachable with bounded editors and keyed drafts through paging, search, and polling reorder', async ({ page }) => {
  test.setTimeout(120_000);
  await page.clock.install({ time: new Date('2026-11-17T12:00:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let revision = 0;
  let reads = 0;
  await page.route('**/api/v1/admin/quotas', async route => {
    reads += 1;
    const quotas = quotaRows(1000, revision);
    await route.fulfill({ json: { quotas: revision ? quotas.reverse() : quotas } });
  });
  await page.goto('/?tab=quotas');
  const rows = page.locator('[data-quota-row="true"]');
  // CSS locators count hidden inputs too, so an invisible full-list DOM fails.
  const editors = page.locator('input[placeholder="100GB, 2TB or exact bytes"]');
  const pager = page.getByRole('navigation', { name: 'Storage Quotas', exact: true });
  const status = pager.getByRole('status');
  const previous = pager.getByRole('button', { name: 'Previous', exact: true });
  const next = pager.getByRole('button', { name: 'Next', exact: true });
  const search = page.getByPlaceholder('Search tenants, IDs or quota status', { exact: true });
  const first = rows.filter({ has: page.getByRole('heading', { name: 'first-draft-tenant · #1', exact: true }) });
  const second = rows.filter({ has: page.getByRole('heading', { name: 'second-draft-tenant · #26', exact: true }) });
  const allocation = first.getByLabel('Allocated disk space', { exact: true });
  const configured = page.getByText('Configured tenants', { exact: true }).locator('..');
  const allocated = page.getByText('Allocated', { exact: true }).locator('..');
  const visitedIds = new Set<number>();
  const recordVisibleIds = async () => {
    for (const heading of await rows.locator('h3').allTextContents()) {
      const match = heading.match(/ · #(\d+)$/);
      expect(match).not.toBeNull();
      visitedIds.add(Number(match![1]));
    }
  };

  await expect(rows).toHaveCount(PAGE_SIZE, { timeout: 30_000 });
  await expect(editors).toHaveCount(PAGE_SIZE);
  await expect(status).toHaveText('Page 1 of 40 · 1000 matching records');
  await expect(configured).toContainText('1000');
  await expect(allocated).toContainText('976.6 KiB');
  await expect(previous).toBeDisabled();
  await expect(next).toBeEnabled();
  await expect(allocation).toHaveValue('1000B');
  await recordVisibleIds();
  await allocation.fill('2GB');

  // The native buttons support keyboard activation, and removing the editor
  // from the DOM must not discard its keyed state.
  await next.focus();
  await page.keyboard.press('Enter');
  await expect(status).toHaveText('Page 2 of 40 · 1000 matching records');
  await expect(rows).toHaveCount(PAGE_SIZE);
  await expect(allocation).toHaveCount(0);
  await expect(rows.getByRole('heading', { name: 'second-draft-tenant · #26', exact: true })).toBeVisible();
  await recordVisibleIds();
  await second.getByLabel('Allocated disk space', { exact: true }).fill('3GB');
  await previous.click();
  await expect(allocation).toHaveValue('2GB');
  await next.click();
  await expect(second.getByLabel('Allocated disk space', { exact: true })).toHaveValue('3GB');

  // Traverse all remaining pages, including the last tenant; this is a
  // functional reachability check, not a timing assertion.
  for (let number = 3; number <= 40; number += 1) {
    await next.click();
    await expect(status).toHaveText(`Page ${number} of 40 · 1000 matching records`);
    const firstId = (number - 1) * PAGE_SIZE + 1;
    await expect(rows.first().getByRole('heading')).toHaveText(`tenant-${String(firstId).padStart(4, '0')} · #${firstId}`);
    await expect(rows).toHaveCount(PAGE_SIZE);
    await expect(editors).toHaveCount(PAGE_SIZE);
    await recordVisibleIds();
  }
  expect([...visitedIds].sort((a, b) => a - b)).toEqual(Array.from({ length: 1000 }, (_, index) => index + 1));
  await expect(rows.getByRole('heading', { name: 'last-marker-tenant · #1000', exact: true })).toBeVisible();
  await expect(next).toBeDisabled();
  // A new query resets to page 1 even when enough results remain to keep the
  // old page valid; this distinguishes resetting from ordinary clamping.
  await search.fill('tenant-');
  await expect(status).toHaveText('Page 1 of 40 · 997 matching records');
  await expect(rows).toHaveCount(PAGE_SIZE);
  await search.fill('last-marker');
  await expect(status).toHaveText('Page 1 of 1 · 1 matching records');
  await expect(rows).toHaveCount(1);
  await expect(configured).toContainText('1000');
  await expect(allocated).toContainText('976.6 KiB');
  await search.fill('');
  await expect(status).toHaveText('Page 1 of 40 · 1000 matching records');
  await expect(rows).toHaveCount(PAGE_SIZE);
  await expect(allocation).toHaveValue('2GB');

  // Poll while the edited row stays visible and the server reverses the list.
  // Its editor identity and draft survive the reorder and refresh.
  await search.fill('first-draft');
  await expect(status).toHaveText('Page 1 of 1 · 1 matching records');
  await expect(allocation).toHaveValue('2GB');
  const originalInput = await allocation.elementHandle();
  const readsBeforePoll = reads;
  revision = 1;
  await page.clock.fastForward('00:16');
  await expect.poll(() => reads).toBeGreaterThan(readsBeforePoll);
  await expect(allocated).toContainText('3.8 MiB');
  await expect(allocation).toHaveValue('2GB');
  expect(await originalInput!.evaluate(input => input.isConnected)).toBe(true);
  await first.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(allocation).toHaveValue('4000B');
  await expect(first.getByRole('button', { name: 'Apply Quota', exact: true })).toBeDisabled();

  await search.fill('second-draft');
  await expect(status).toHaveText('Page 1 of 1 · 1 matching records');
  await expect(second.getByLabel('Allocated disk space', { exact: true })).toHaveValue('3GB');
  const readsBeforeRefresh = reads;
  revision = 2;
  await page.getByRole('button', { name: 'Refresh quotas', exact: true }).click();
  await expect.poll(() => reads).toBeGreaterThan(readsBeforeRefresh);
  await expect(allocated).toContainText('7.6 MiB');
  await expect(second.getByLabel('Allocated disk space', { exact: true })).toHaveValue('3GB');
  await second.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(second.getByLabel('Allocated disk space', { exact: true })).toHaveValue('8000B');
  await search.fill('');
  await expect(status).toHaveText('Page 1 of 40 · 1000 matching records');
  await expect(rows).toHaveCount(PAGE_SIZE);
  await expect(rows.getByRole('heading', { name: 'last-marker-tenant · #1000', exact: true })).toBeVisible();
  await expect(rows.getByLabel('Allocated disk space', { exact: true }).first()).toHaveValue('8000B');
});

test('a quota save keeps newer edits when its row leaves the page and is filtered out before acknowledgement', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-17T12:00:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let amount = 1000;
  let release!: () => void;
  let started!: () => void;
  const saveStarted = new Promise<void>(resolve => { started = resolve; });
  const releaseSave = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/v1/admin/quotas', route => route.fulfill({ json: { quotas: quotaRows(26).map(row => ({
    ...row,
    username: row.user_id === 1 ? 'pending-tenant' : row.user_id === 2 ? 'selected-other' : row.username,
    quota_bytes: row.user_id === 1 ? amount : 1000,
  })) } }));
  await page.route('**/api/v1/admin/quotas/1', async route => {
    expect(route.request().method()).toBe('PUT');
    expect(route.request().postDataJSON()).toEqual({ quota: '2GB', source: 'manual' });
    started();
    await releaseSave;
    amount = 2_000_000_000;
    await route.fulfill({ json: { success: true } });
  });
  try {
    await page.goto('/?tab=quotas');
    const rows = page.locator('[data-quota-row="true"]');
    const pager = page.getByRole('navigation', { name: 'Storage Quotas', exact: true });
    await expect(rows).toHaveCount(PAGE_SIZE);
    const edited = rows.filter({ has: page.getByRole('heading', { name: 'pending-tenant · #1', exact: true }) });
    const allocation = edited.getByLabel('Allocated disk space', { exact: true });
    await allocation.fill('2GB');
    await edited.getByRole('button', { name: 'Apply Quota', exact: true }).click();
    await saveStarted;
    await allocation.fill('3GB');
    await pager.getByRole('button', { name: 'Next', exact: true }).click();
    await expect(pager.getByRole('status')).toHaveText('Page 2 of 2 · 26 matching records');
    await expect(rows).toHaveCount(1);
    await expect(allocation).toHaveCount(0);
    await pager.getByRole('button', { name: 'Previous', exact: true }).click();
    await expect(allocation).toHaveValue('3GB');
    await expect(edited.getByRole('button', { name: 'Saving…', exact: true })).toBeDisabled();
    await pager.getByRole('button', { name: 'Next', exact: true }).click();
    const search = page.getByPlaceholder('Search tenants, IDs or quota status', { exact: true });
    await search.fill('selected-other');
    await expect(pager.getByRole('status')).toHaveText('Page 1 of 1 · 1 matching records');
    await expect(rows.getByRole('heading', { name: 'selected-other · #2', exact: true })).toBeVisible();
    await search.fill('pending-tenant');
    await expect(allocation).toHaveValue('3GB');
    await expect(edited.getByRole('button', { name: 'Saving…', exact: true })).toBeDisabled();
    await search.fill('selected-other');
    await expect(rows.getByRole('heading', { name: 'selected-other · #2', exact: true })).toBeVisible();
    release();
    await expect(page.getByRole('status').filter({ hasText: /^Quota saved and filesystem enforcement updated$/ })).toBeVisible();
    await search.fill('');
    await expect(rows).toHaveCount(PAGE_SIZE);
    await expect(allocation).toHaveValue('3GB');
    await expect(edited.getByRole('button', { name: 'Apply Quota', exact: true })).toBeEnabled();
    await edited.getByRole('button', { name: 'Discard changes', exact: true }).click();
    await expect(allocation).toHaveValue('2000000000B');
  } finally {
    release();
  }
});

test('quota pages clamp after shrink and remain clamped if the dataset grows again', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-17T12:00:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let count = 80;
  await page.route('**/api/v1/admin/quotas', route => route.fulfill({ json: { quotas: quotaRows(count) } }));
  await page.goto('/?tab=quotas');
  const rows = page.locator('[data-quota-row="true"]');
  const pager = page.getByRole('navigation', { name: 'Storage Quotas', exact: true });
  const status = pager.getByRole('status');
  const next = pager.getByRole('button', { name: 'Next', exact: true });
  const previous = pager.getByRole('button', { name: 'Previous', exact: true });
  const refresh = page.getByRole('button', { name: 'Refresh quotas', exact: true });
  await expect(status).toHaveText('Page 1 of 4 · 80 matching records');
  await next.click();
  await expect(status).toHaveText('Page 2 of 4 · 80 matching records');
  await next.click();
  await expect(status).toHaveText('Page 3 of 4 · 80 matching records');
  const retained = rows.filter({ has: page.getByRole('heading', { name: 'tenant-0051 · #51', exact: true }) });
  await retained.getByLabel('Allocated disk space', { exact: true }).fill('9GB');
  await next.click();
  await expect(status).toHaveText('Page 4 of 4 · 80 matching records');
  await expect(rows).toHaveCount(5);
  count = 52;
  await refresh.click();
  await expect(status).toHaveText('Page 3 of 3 · 52 matching records');
  await expect(rows).toHaveCount(2);
  await expect(retained.getByLabel('Allocated disk space', { exact: true })).toHaveValue('9GB');
  await expect(next).toBeDisabled();
  count = 80;
  await refresh.click();
  await expect(status).toHaveText('Page 3 of 4 · 80 matching records');
  await expect(rows).toHaveCount(PAGE_SIZE);
  await expect(retained.getByLabel('Allocated disk space', { exact: true })).toHaveValue('9GB');
  await expect(next).toBeEnabled();

  count = 0;
  await refresh.click();
  await expect(status).toHaveText('Page 1 of 1 · 0 matching records');
  await expect(rows).toHaveCount(0);
  await expect(page.getByText('No quota records found', { exact: true })).toBeVisible();
  await expect(previous).toBeDisabled();
  await expect(next).toBeDisabled();
  count = 26;
  await refresh.click();
  await expect(status).toHaveText('Page 1 of 2 · 26 matching records');
  await expect(rows).toHaveCount(PAGE_SIZE);
});

test('quota reconciliation includes every authoritative tenant while search shows one', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-17T12:00:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const refreshed: number[] = [];
  await page.route('**/api/v1/admin/quotas', route => route.fulfill({ json: { quotas: quotaRows(30) } }));
  await page.route(/\/api\/v1\/admin\/quotas\/\d+\/refresh$/, async route => {
    refreshed.push(Number(new URL(route.request().url()).pathname.split('/').at(-2)));
    await route.fulfill({ json: { success: true } });
  });
  await page.goto('/?tab=quotas');
  const rows = page.locator('[data-quota-row="true"]');
  await expect(rows).toHaveCount(PAGE_SIZE);
  await page.getByPlaceholder('Search tenants, IDs or quota status', { exact: true }).fill('first-draft');
  await expect(rows).toHaveCount(1);
  await expect(page.getByText('Configured tenants', { exact: true }).locator('..')).toContainText('30');
  await page.getByRole('button', { name: 'Sync / reconcile quotas', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: /^Quota reconciliation completed$/ })).toBeVisible();
  expect(refreshed).toEqual(Array.from({ length: 30 }, (_, index) => index + 1));
});

test('removed tenants and disposed quota views do not retain drafts or accept an old save', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-11-17T12:00:00Z') });
  await page.clock.pauseAt(new Date('2026-11-17T12:00:00Z'));
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let present = true;
  let amount = 1000;
  let release!: () => void;
  let started!: () => void;
  const saveStarted = new Promise<void>(resolve => { started = resolve; });
  const releaseSave = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/v1/admin/quotas', route => route.fulfill({ json: { quotas: present ? [
    { user_id: 1, username: 'returning-tenant', quota_bytes: amount, configured: true },
  ] : [] } }));
  await page.route('**/api/v1/admin/quotas/1', async route => {
    started();
    await releaseSave;
    await route.fulfill({ json: { success: true } });
  });
  try {
    await page.goto('/?tab=quotas');
    const rows = page.locator('[data-quota-row="true"]');
    const allocation = rows.getByLabel('Allocated disk space', { exact: true });
    const refresh = page.getByRole('button', { name: 'Refresh quotas', exact: true });
    await expect(allocation).toHaveValue('1000B');
    await allocation.fill('2GB');
    await rows.getByRole('button', { name: 'Apply Quota', exact: true }).click();
    await saveStarted;
    present = false;
    await refresh.click();
    await expect(rows).toHaveCount(0);
    present = true;
    amount = 4000;
    await refresh.click();
    await expect(allocation).toHaveValue('4000B');
    const response = page.waitForResponse(response => response.url().endsWith('/api/v1/admin/quotas/1') && response.request().method() === 'PUT');
    release();
    await response;
    await expect(allocation).toHaveValue('4000B');
    await expect(rows.getByRole('button', { name: 'Apply Quota', exact: true })).toBeDisabled();

    await allocation.fill('5GB');
    await page.getByRole('button', { name: 'Overview', exact: true }).first().click();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Quotas', exact: true }).first().click();
    await expect(allocation).toHaveValue('4000B');
  } finally {
    release();
  }
});
