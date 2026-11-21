import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

test('shell reports the entire approval backlog and refreshes it outside the inbox', async ({ page }) => {
  await page.clock.install();
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  let total = 137;
  const queries: URLSearchParams[] = [];
  await page.route('**/api/v1/admin/actions/pending?*', async (route) => {
    const query = new URL(route.request().url()).searchParams;
    queries.push(query);
    const count = Math.min(Number(query.get('limit') ?? 100), total);
    await route.fulfill({ json: {
      count, total, actions: Array.from({ length: count }, (_, index) => ({
        id: index + 1, action: `Pending action ${index + 1}`, status: 'pending',
      })),
    } });
  });

  await page.goto('/?tab=services');
  const badge = page.locator('#desktop-sidebar-navigation .af-pending-badge');
  await expect(badge).toHaveText('137');
  await expect(badge).toHaveAttribute('aria-label', '137 pending actions');

  const initialReads = queries.length;
  total = 205;
  await page.clock.fastForward('00:31');
  await expect.poll(() => queries.length).toBeGreaterThan(initialReads);
  await expect(badge).toHaveText('205');
  await expect(badge).toHaveAttribute('aria-label', '205 pending actions');
  expect(queries.every((query) => query.get('status') === 'pending' && query.get('limit') === '1')).toBe(true);
});

test('shell retains the legacy approval count when the response has no total', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await page.route('**/api/v1/admin/actions/pending?*', (route) => route.fulfill({
    json: { count: 7, actions: [{ id: 1, action: 'Legacy pending action', status: 'pending' }] },
  }));
  await page.goto('/?tab=services');
  await expect(page.locator('#desktop-sidebar-navigation .af-pending-badge')).toHaveText('7');
});

test('Approval Inbox follows the durable core restart status in history', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  const jobUnit = 'aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service';
  let status = 'pending';
  let approvals = 0;
  const action = () => ({
    id: 41,
    action: 'systemctl restart aetherflow-api',
    classification: 'MEDIUM',
    source: 'af-heal',
    reason: 'Fixture restart',
    status,
    ...(status === 'pending' ? {} : { job_unit: jobUnit }),
  });
  await page.route('**/api/v1/admin/actions/pending?*', async route => {
    const filter = new URL(route.request().url()).searchParams.get('status');
    const matches = status === 'pending' ? filter === 'pending' : filter === 'approved_history';
    const actions = matches ? [action()] : [];
    await route.fulfill({ json: { actions, total: actions.length } });
  });
  await page.route('**/api/v1/admin/actions/41', route => route.fulfill({ json: action() }));
  await page.route('**/api/v1/admin/actions/41/approve', async route => {
    expect(route.request().method()).toBe('POST');
    approvals += 1;
    status = 'queued';
    await route.fulfill({ status: 202, json: { status, action: action() } });
  });

  await page.goto('/?tab=inbox');
  await page.getByRole('button', { name: 'Inspect action' }).click();
  const details = page.getByRole('dialog', { name: 'Action details' });
  await details.getByRole('button', { name: 'Approve & Queue Restart' }).click();
  await expect(details.getByRole('status').filter({ hasText: jobUnit })).toBeVisible();
  await details.getByRole('button', { name: 'Close dialog' }).click();
  await expect(page.getByRole('tab', { name: 'Approved / Executed' })).toHaveAttribute('aria-selected', 'true');
  const history = page.getByRole('tabpanel');
  await expect(history.getByText('queued', { exact: true })).toBeVisible();
  await expect(history.getByText('executed', { exact: true })).toHaveCount(0);

  status = 'executed';
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(history.getByText('executed', { exact: true })).toBeVisible();
  expect(approvals).toBe(1);
});

test('Enter sorts a user column without opening a row and grid navigation still activates rows', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await page.route('**/api/v1/admin/users', (route) => route.fulfill({ json: { users: [
    { id: 1, username: 'zeta', email: 'zeta@example.com', role: 'admin' },
    { id: 2, username: 'alpha', email: 'alpha@example.com', role: 'user' },
  ] } }));
  await page.goto('/?tab=users');
  const grid = page.getByRole('grid', { name: 'User directory', exact: true });
  const column = grid.getByRole('columnheader').filter({ has: page.getByRole('button', { name: 'Username', exact: true }) });
  const inspector = page.getByRole('dialog', { name: 'Manage user', exact: true });
  await expect(grid.getByRole('gridcell', { name: 'alpha', exact: true })).toBeVisible();
  await column.getByRole('button', { name: 'Username', exact: true }).press('Enter');
  await expect(column).toHaveAttribute('aria-sort', 'ascending');
  await expect(inspector).toBeHidden();

  await grid.focus();
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(inspector).toBeVisible();
  await expect(inspector.getByText('zeta', { exact: true })).toBeVisible();
});
