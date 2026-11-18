import { expect, test, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

interface Rule {
  id: number;
  name: string;
  condition_type: string;
  condition_value: string;
  level: string;
  enabled: boolean;
}

async function rulesFixture(page: Page, withExisting = false) {
  await installAetherFlowMocks(page);
  const records: Rule[] = withExisting ? [{
    id: 7, name: 'Existing rule', condition_type: 'cpu_usage',
    condition_value: '60', level: 'warning', enabled: true,
  }] : [];
  const writes: { method: string; path: string }[] = [];
  const started = deferred();
  const release = deferred();
  let nextId = 42;
  await page.route('**/api/v1/admin/notifications/channels', route => route.fulfill({ json: { channels: [] } }));
  await page.route('**/api/v1/admin/notifications/rules**', async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (method === 'GET') return route.fulfill({ json: { rules: records } });
    writes.push({ method, path });
    if (method === 'POST') {
      const sent = request.postDataJSON() as Omit<Rule, 'id'>;
      const id = nextId++;
      started.resolve();
      await release.promise;
      records.push({ ...sent, id, name: sent.name.trim(), condition_value: sent.condition_value.trim(), level: sent.level.trim() || 'warning', enabled: true });
      return route.fulfill({ status: 201, json: { message: 'Rule created', id } });
    }
    const id = Number(path.split('/').at(-1));
    const index = records.findIndex(rule => rule.id === id);
    expect(index).toBeGreaterThanOrEqual(0);
    if (method === 'PUT') {
      records[index] = { ...records[index], ...request.postDataJSON() as Partial<Rule>, id };
      return route.fulfill({ json: { message: 'Rule updated' } });
    }
    expect(method).toBe('DELETE');
    records.splice(index, 1);
    return route.fulfill({ json: { message: 'Rule deleted' } });
  });
  return { records, writes, started, release };
}

async function createWithRetainedEdit(page: Page, fixture: Awaited<ReturnType<typeof rulesFixture>>, padded = false) {
  await page.getByRole('button', { name: 'Add alert rule', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Configure alert rule', exact: true });
  await dialog.getByLabel('Rule name', { exact: true }).fill(padded ? '  CPU saturation  ' : 'CPU saturation');
  await dialog.getByRole('combobox', { name: 'Event trigger', exact: true }).selectOption('cpu_usage');
  const threshold = dialog.getByLabel('Service name or percentage threshold', { exact: true });
  await threshold.fill(padded ? ' 75 ' : '75');
  await dialog.getByRole('button', { name: 'Save alert rule', exact: true }).click();
  await fixture.started.promise;
  await threshold.fill('90');
  fixture.release.resolve();
  await expect(page.getByRole('status').filter({ hasText: /^Alert rule saved$/ })).toBeVisible();
  await expect(dialog).toBeVisible();
  await expect(threshold).toHaveValue('90');
  await expect(dialog.getByRole('button', { name: 'Save alert rule', exact: true })).toBeEnabled();
  return { dialog, threshold };
}

test('retained edits after alert creation update the returned ID without creating another rule', async ({ page }) => {
  const fixture = await rulesFixture(page);
  try {
    await page.goto('/?tab=notifications');
    const { dialog } = await createWithRetainedEdit(page, fixture);
    await dialog.getByRole('button', { name: 'Save alert rule', exact: true }).click();
    await expect(dialog).not.toBeVisible();
    expect(fixture.writes).toEqual([
      { method: 'POST', path: '/api/v1/admin/notifications/rules' },
      { method: 'PUT', path: '/api/v1/admin/notifications/rules/42' },
    ]);
    expect(fixture.records).toHaveLength(1);
    expect(fixture.records[0]).toMatchObject({ id: 42, condition_value: '90', enabled: true });
  } finally {
    fixture.release.resolve();
  }
});

test('discard after alert creation restores the canonical saved values and retains its identity', async ({ page }) => {
  const fixture = await rulesFixture(page);
  try {
    await page.goto('/?tab=notifications');
    const { dialog, threshold } = await createWithRetainedEdit(page, fixture, true);
    await expect(dialog.getByLabel('Rule name', { exact: true })).toHaveValue('CPU saturation');
    await expect(dialog.getByLabel('Enable alert rule', { exact: true })).toBeChecked();
    await dialog.getByRole('button', { name: 'Discard changes', exact: true }).click();
    await expect(threshold).toHaveValue('75');
    await expect(dialog.getByRole('button', { name: 'Save alert rule', exact: true })).toBeDisabled();
    await threshold.fill('90');
    await dialog.getByRole('button', { name: 'Save alert rule', exact: true }).click();
    await expect(dialog).not.toBeVisible();
    expect(fixture.writes.map(write => write.method)).toEqual(['POST', 'PUT']);
    expect(fixture.records).toHaveLength(1);
    expect(fixture.records[0]).toMatchObject({ id: 42, name: 'CPU saturation', condition_value: '90' });
  } finally {
    fixture.release.resolve();
  }
});

test('deleting a retained newly created alert uses its ID rather than an earlier selection', async ({ page }) => {
  const fixture = await rulesFixture(page, true);
  try {
    await page.goto('/?tab=notifications');
    await page.getByRole('grid', { name: 'Notification alert rules', exact: true }).getByRole('row').filter({ hasText: 'Existing rule' }).click();
    const oldDialog = page.getByRole('dialog', { name: 'Configure alert rule', exact: true });
    await expect(oldDialog).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(oldDialog).not.toBeVisible();
    const { dialog } = await createWithRetainedEdit(page, fixture);
    await dialog.getByRole('button', { name: 'Delete alert rule', exact: true }).click();
    await page.getByRole('dialog', { name: 'Delete notification configuration?', exact: true }).getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect(dialog).not.toBeVisible();
    expect(fixture.writes).toEqual([
      { method: 'POST', path: '/api/v1/admin/notifications/rules' },
      { method: 'DELETE', path: '/api/v1/admin/notifications/rules/42' },
    ]);
    expect(fixture.records.map(rule => rule.id)).toEqual([7]);
  } finally {
    fixture.release.resolve();
  }
});

test('existing alert save keeps its acknowledged baseline through held and failed list reads', async ({ page }) => {
  await installAetherFlowMocks(page);
  await page.addInitScript(() => {
    const outcomes: string[] = [];
    (window as Window & { __alertReads?: string[] }).__alertReads = outcomes;
    const fetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input), location.href);
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
      if (url.pathname !== '/api/v1/admin/notifications/rules' || method.toUpperCase() !== 'GET') return fetch(input, init);
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
  let holdNextRead = false;
  let saveAcknowledged = false;
  let holdPostSaveRead = true;
  let server: Rule = { id: 7, name: 'Existing rule', condition_type: 'cpu_usage', condition_value: '60', level: 'warning', enabled: true };
  const other: Rule = { id: 8, name: 'Other rule', condition_type: 'disk_usage', condition_value: '80', level: 'critical', enabled: true };
  const writes: { path: string; body: Omit<Rule, 'id'> }[] = [];
  await page.route('**/api/v1/admin/notifications/channels', route => route.fulfill({ json: { channels: [] } }));
  await page.route('**/api/v1/admin/notifications/rules**', async route => {
    const request = route.request();
    if (request.method() === 'GET') {
      const snapshot = { ...server };
      if (holdNextRead) {
        holdNextRead = false;
        oldReadStarted.resolve();
        await releaseOldRead.promise;
        await route.fulfill({ json: { rules: [snapshot, other] } }).catch(() => {});
        oldReadFinished.resolve();
        return;
      }
      if (saveAcknowledged) {
        if (holdPostSaveRead) {
          holdPostSaveRead = false;
          newReadStarted.resolve();
          await releaseNewRead.promise;
        }
        return route.fulfill({ status: 503, json: { message: 'Alert list refresh failed' } }).catch(() => {});
      }
      return route.fulfill({ json: { rules: [snapshot, other] } });
    }
    expect(request.method()).toBe('PUT');
    const body = request.postDataJSON() as Omit<Rule, 'id'>;
    writes.push({ path: new URL(request.url()).pathname, body });
    if (writes.length === 1) {
      saveStarted.resolve();
      await releaseSave.promise;
    }
    server = { ...server, ...body };
    saveAcknowledged = true;
    return route.fulfill({ json: { message: 'Rule updated' } });
  });
  try {
    await page.goto('/?tab=notifications');
    const grid = page.getByRole('grid', { name: 'Notification alert rules', exact: true });
    await expect(grid.getByText('Existing rule', { exact: true })).toBeVisible();
    holdNextRead = true;
    await page.getByRole('button', { name: 'Refresh notifications', exact: true }).click();
    await oldReadStarted.promise;
    const staleReadIndex = await page.evaluate(() => (window as Window & { __alertReads?: string[] }).__alertReads?.lastIndexOf('pending') ?? -1);
    expect(staleReadIndex).toBeGreaterThanOrEqual(0);
    await grid.getByRole('row').filter({ hasText: 'Existing rule' }).click();
    const dialog = page.getByRole('dialog', { name: 'Configure alert rule', exact: true });
    const name = dialog.getByLabel('Rule name', { exact: true });
    const threshold = dialog.getByLabel('Service name or percentage threshold', { exact: true });
    const save = dialog.getByRole('button', { name: 'Save alert rule', exact: true });
    await name.fill('Saved rule');
    await threshold.fill('70');
    await save.click();
    await saveStarted.promise;
    await threshold.fill('90');
    releaseSave.resolve();
    await expect(page.getByRole('status').filter({ hasText: /^Alert rule saved$/ })).toBeVisible();
    await newReadStarted.promise;
    await expect.poll(() => page.evaluate(index => (window as Window & { __alertReads?: string[] }).__alertReads?.[index], staleReadIndex)).toBe('aborted');
    const cachedGrid = page.locator('[role="grid"][aria-label="Notification alert rules"]');
    await expect(cachedGrid.getByText('Saved rule', { exact: true })).toBeVisible();
    await expect(cachedGrid.getByText('Other rule', { exact: true })).toBeVisible();
    await expect(name).toHaveValue('Saved rule');
    await expect(threshold).toHaveValue('90');
    await expect(save).toBeEnabled();
    releaseOldRead.resolve();
    await oldReadFinished.promise;
    await expect(name).toHaveValue('Saved rule');
    releaseNewRead.resolve();
    await expect(page.locator('[role="alert"]').filter({ hasText: 'Alert list refresh failed' })).toBeVisible();
    await expect(name).toHaveValue('Saved rule');
    await expect(threshold).toHaveValue('90');
    await dialog.getByRole('button', { name: 'Discard changes', exact: true }).click();
    await expect(name).toHaveValue('Saved rule');
    await expect(threshold).toHaveValue('70');
    await expect(save).toBeDisabled();
    await threshold.fill('90');
    await save.click();
    await expect(dialog).not.toBeVisible();
    expect(writes).toHaveLength(2);
    expect(writes.map(write => write.path)).toEqual([
      '/api/v1/admin/notifications/rules/7',
      '/api/v1/admin/notifications/rules/7',
    ]);
    expect(writes[0].body).toMatchObject({ name: 'Saved rule', condition_value: '70' });
    expect(writes[1].body).toMatchObject({ name: 'Saved rule', condition_value: '90' });
    expect(server).toMatchObject({ id: 7, name: 'Saved rule', condition_value: '90' });
  } finally {
    releaseOldRead.resolve();
    releaseSave.resolve();
    releaseNewRead.resolve();
  }
});
