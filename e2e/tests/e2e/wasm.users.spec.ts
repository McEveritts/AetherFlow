import { expect, test } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

test('user role save keeps its acknowledged baseline through held and failed list reads', async ({ page }) => {
  await installAetherFlowMocks(page);
  await page.addInitScript(() => {
    const outcomes: string[] = [];
    (window as Window & { __userReads?: string[] }).__userReads = outcomes;
    const fetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input), location.href);
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
      if (url.pathname !== '/api/v1/admin/users' || method.toUpperCase() !== 'GET') return fetch(input, init);
      const index = outcomes.push('pending') - 1;
      const settle = (outcome: string) => { if (outcomes[index] === 'pending') outcomes[index] = outcome; };
      const signal = init?.signal;
      if (signal?.aborted) settle('aborted');
      else signal?.addEventListener('abort', () => settle('aborted'), { once: true });
      return fetch(input, init).then(response => { settle('finished'); return response; }, (error: unknown) => { settle('failed'); throw error; });
    };
  });
  const oldReadStarted = deferred();
  const releaseOldRead = deferred();
  const oldReadFinished = deferred();
  const saveStarted = deferred();
  const releaseSave = deferred();
  const newReadStarted = deferred();
  const releaseNewRead = deferred();
  const server = [
    { id: 1, username: 'admin', email: 'admin@example.com', role: 'admin' },
    { id: 2, username: 'teammate', email: 'teammate@example.com', role: 'user' },
  ];
  const writes: { path: string; body: { role: string } }[] = [];
  let holdNextRead = false;
  let saveAcknowledged = false;
  let holdPostSaveRead = true;
  await page.route('**/api/v1/admin/users**', async route => {
    const request = route.request();
    if (request.method() === 'GET') {
      const snapshot = server.map(user => ({ ...user }));
      if (holdNextRead) {
        holdNextRead = false;
        oldReadStarted.resolve();
        await releaseOldRead.promise;
        await route.fulfill({ json: { users: snapshot } }).catch(() => {});
        oldReadFinished.resolve();
        return;
      }
      if (saveAcknowledged) {
        if (holdPostSaveRead) {
          holdPostSaveRead = false;
          newReadStarted.resolve();
          await releaseNewRead.promise;
        }
        return route.fulfill({ status: 503, json: { message: 'User list refresh failed' } }).catch(() => {});
      }
      return route.fulfill({ json: { users: snapshot } });
    }
    expect(request.method()).toBe('PUT');
    const body = request.postDataJSON() as { role: string };
    writes.push({ path: new URL(request.url()).pathname, body });
    if (writes.length === 1) {
      saveStarted.resolve();
      await releaseSave.promise;
    }
    server[1].role = body.role;
    saveAcknowledged = true;
    return route.fulfill({ json: { message: 'Role updated successfully' } });
  });
  try {
    await page.goto('/?tab=users');
    const grid = page.getByRole('grid', { name: 'User directory', exact: true });
    const teammate = grid.getByRole('row').filter({ hasText: 'teammate' });
    await expect(teammate).toBeVisible();
    holdNextRead = true;
    await page.getByRole('button', { name: 'Refresh users', exact: true }).click();
    await oldReadStarted.promise;
    const staleReadIndex = await page.evaluate(() => (window as Window & { __userReads?: string[] }).__userReads?.lastIndexOf('pending') ?? -1);
    expect(staleReadIndex).toBeGreaterThanOrEqual(0);
    await teammate.click();
    const dialog = page.getByRole('dialog', { name: 'Manage user', exact: true });
    const role = dialog.getByRole('combobox', { name: 'Role', exact: true });
    const save = dialog.getByRole('button', { name: 'Update role', exact: true });
    await expect(role).toHaveValue('user');
    await role.selectOption('admin');
    await save.click();
    await saveStarted.promise;
    // An explicit reversion while PUT is pending is still a newer edit.
    await role.selectOption('user');
    releaseSave.resolve();
    await expect(page.getByRole('status').filter({ hasText: /^User role updated$/ })).toBeVisible();
    await newReadStarted.promise;
    await expect.poll(() => page.evaluate(index => (window as Window & { __userReads?: string[] }).__userReads?.[index], staleReadIndex)).toBe('aborted');
    await expect(role).toHaveValue('user');
    await expect(save).toBeEnabled();
    releaseOldRead.resolve();
    await oldReadFinished.promise;
    await expect(role).toHaveValue('user');
    releaseNewRead.resolve();
    await expect(page.locator('[role="alert"]').filter({ hasText: 'User list refresh failed' })).toBeVisible();
    await expect(role).toHaveValue('user');
    await dialog.getByRole('button', { name: 'Discard changes', exact: true }).click();
    await expect(role).toHaveValue('admin');
    await expect(save).toBeDisabled();
    // Reopen the same identity after the failed read: the grid mirror must also
    // contain the acknowledged row, not the old typed-resource snapshot.
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();
    await expect(grid.getByRole('row').filter({ hasText: 'admin@example.com' })).toHaveCount(1);
    await teammate.click();
    await expect(role).toHaveValue('admin');
    await role.selectOption('user');
    await save.click();
    await expect.poll(() => writes.length).toBe(2);
    await expect(save).toBeDisabled();
    expect(writes).toEqual([
      { path: '/api/v1/admin/users/2/role', body: { role: 'admin' } },
      { path: '/api/v1/admin/users/2/role', body: { role: 'user' } },
    ]);
    expect(server[1]).toMatchObject({ id: 2, username: 'teammate', role: 'user' });
  } finally {
    releaseOldRead.resolve();
    releaseSave.resolve();
    releaseNewRead.resolve();
  }
});

test('accepted user deletion refreshes the directory and reports pending storage cleanup', async ({ page }) => {
  await installAetherFlowMocks(page);
  const admin = { id: 1, username: 'admin', email: 'admin@example.com', role: 'admin' };
  const member = { id: 2, username: 'teammate', email: 'teammate@example.com', role: 'user' };
  let removed = false;
  await page.route('**/api/v1/admin/users', route =>
    route.fulfill({ json: { users: removed ? [admin] : [admin, member] } }),
  );
  await page.route('**/api/v1/admin/users/2', route => {
    expect(route.request().method()).toBe('DELETE');
    removed = true;
    return route.fulfill({
      status: 202,
      json: {
        message: 'User deleted. Storage cleanup is pending.',
        cleanup_pending: true,
        pending_cleanup_count: 1,
      },
    });
  });

  await page.goto('/?tab=users');
  const grid = page.getByRole('grid', { name: 'User directory', exact: true });
  const row = grid.getByRole('row').filter({ hasText: 'teammate' });
  await expect(row).toBeVisible();
  await row.click();
  await page.getByRole('dialog', { name: 'Manage user' })
    .getByRole('button', { name: 'Delete User', exact: true }).click();
  const confirm = page.getByRole('dialog', { name: 'Permanently delete this user?' });
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByRole('alert').filter({
    hasText: /^User deleted\. Storage cleanup is pending\.$/,
  })).toBeVisible();
  await expect(row).toHaveCount(0);
});
