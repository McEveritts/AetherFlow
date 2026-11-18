import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { basename, dirname } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { expect, test, type Page } from '@playwright/test';

const usersPath = '/api/v1/admin/users';
const rulesPath = '/api/v1/admin/notifications/rules';
type User = { id: number; username: string; role: string };
type Rule = {
  id: number;
  name: string;
  condition_type: string;
  condition_value: string;
  level: string;
  enabled: boolean;
};

function disposableDatabase(baseURL: string | undefined): string {
  const origin = baseURL ? new URL(baseURL) : null;
  if (process.env.AETHERFLOW_E2E_ISOLATED !== '1' || origin?.protocol !== 'http:'
    || origin.hostname !== '127.0.0.1' || origin.port !== process.env.PORT) {
    throw new Error('Run the persistence suite through scripts/run_embedded_e2e.sh --playwright');
  }
  const configured = process.env.AETHERFLOW_DB_PATH || process.env.DB_PATH;
  if (!configured) throw new Error('The runner did not configure an isolated database');
  const path = realpathSync(configured);
  const data = dirname(path);
  if (basename(path) !== 'aetherflow.sqlite' || basename(data) !== 'data'
    || !basename(dirname(data)).startsWith('aetherflow-embedded-e2e.')) {
    throw new Error('The runner database is outside the disposable E2E directory');
  }
  return path;
}

function seedMember(database: string, username: string): number {
  // The backend has no create-user API. Seed only this disposable account.
  // Its password is unused, and PUT/GET/DELETE still go through the real API.
  const result = execFileSync('python3', ['-c', `
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=15) as connection:
    row = connection.execute("INSERT INTO users (username, role) VALUES (?, 'user')", (sys.argv[2],))
    print(row.lastrowid)
`, database, username], { encoding: 'utf8' });
  const id = Number(result.trim());
  expect(id).toBeGreaterThan(0);
  expect(Number.isSafeInteger(id)).toBe(true);
  return id;
}

async function mutationHeaders(page: Page): Promise<Record<string, string>> {
  const response = await page.request.get('/api/v1/public/csrf-token', { maxRedirects: 0 });
  expect(response.status()).toBe(200);
  const { csrf_token: token } = await response.json();
  expect(typeof token).toBe('string');
  expect(token.length).toBeGreaterThan(0);
  return {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-CSRF-Token': token,
  };
}

async function signIn(page: Page) {
  const username = process.env.E2E_ADMIN_USER;
  const password = process.env.E2E_ADMIN_PASS;
  if (!username || !password) throw new Error('The runner did not configure the disposable administrator');

  await page.goto('/login');
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  const login = async () => {
    const response = apiWrite(page, 'POST', '/api/v1/public/auth/login');
    await page.locator('button[type="submit"]').first().click();
    return response;
  };
  let response = await login();
  if (response.status() === 429) {
    const retryAfter = Number(response.headers()['retry-after']);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
    console.info(`LIVE_AUTH_RETRY: persistence login 429; retry after ${retryAfter}s`);
    await delay(retryAfter * 1000);
    response = await login();
  }
  expect(response.status(), 'disposable administrator login').toBe(200);
  await expect(page.locator('.af-user-badge')).toHaveText(username);
  const session = await page.request.get('/api/v1/auth/session', { maxRedirects: 0 });
  expect(session.status()).toBe(200);
  expect(await session.json()).toMatchObject({ username, role: 'admin' });
}

function apiWrite(page: Page, method: 'POST' | 'PUT', path: string) {
  return page.waitForResponse(response =>
    response.request().method() === method && new URL(response.url()).pathname === path,
    { timeout: 15_000 },
  );
}

async function readUsers(page: Page): Promise<User[]> {
  const response = await page.request.get(usersPath, { maxRedirects: 0 });
  expect(response.status()).toBe(200);
  return await response.json() as User[];
}

async function readRules(page: Page): Promise<Rule[]> {
  const response = await page.request.get(rulesPath, { maxRedirects: 0 });
  expect(response.status()).toBe(200);
  return (await response.json() as { rules: Rule[] }).rules;
}

test('real Users role and Notifications alert changes persist for their server identities', async ({ page, context, baseURL }) => {
  test.setTimeout(120_000); // The shared live login limiter can return Retry-After: 60.
  const database = disposableDatabase(baseURL);
  const origin = new URL(baseURL!).origin;
  await context.route(url => url.origin !== origin, route => route.abort());
  await signIn(page);

  const run = randomUUID().slice(0, 12);
  await test.step('save a role through Users and read back the same user', async () => {
    const username = `role-persistence-${run}`;
    const seededId = seedMember(database, username);
    const userPath = `${usersPath}/${seededId}`;
    try {
      const [member] = (await readUsers(page)).filter(user => user.username === username);
      expect(member).toMatchObject({ id: seededId, username, role: 'user' });
      const settings = page.waitForResponse(response =>
        new URL(response.url()).pathname === '/api/v1/auth/settings' && response.ok(),
        { timeout: 15_000 },
      );
      await page.goto('/?tab=users');
      if ((await (await settings).json()).setupCompleted === false) {
        // A stand-alone live run starts with a disposable, unconfigured dashboard.
        const onboarding = page.getByRole('dialog', { name: 'Welcome to AetherFlow', exact: true });
        await onboarding.getByRole('button', { name: 'Continue', exact: true }).click();
        await onboarding.getByRole('button', { name: 'Enter Dashboard', exact: true }).click();
        await expect(onboarding).toBeHidden();
      }
      const grid = page.getByRole('grid', { name: 'User directory', exact: true });
      const row = grid.getByRole('row').filter({ has: page.getByRole('gridcell', { name: username, exact: true }) });
      await expect(row.getByRole('gridcell', { name: String(member.id), exact: true })).toBeVisible();
      await row.click();
      const dialog = page.getByRole('dialog', { name: 'Manage user', exact: true });
      const role = dialog.getByRole('combobox', { name: 'Role', exact: true });
      await expect(role).toHaveValue('user');
      await role.selectOption('admin');
      const updated = apiWrite(page, 'PUT', `${usersPath}/${member.id}/role`);
      await dialog.getByRole('button', { name: 'Update role', exact: true }).click();
      const response = await updated;
      expect(response.status()).toBe(200);
      expect(response.request().postDataJSON()).toEqual({ role: 'admin' });
      expect(await response.json()).toEqual({ message: 'Role updated successfully' });
      await expect(page.getByRole('status').filter({ hasText: /^User role updated$/ })).toBeVisible();
      expect((await readUsers(page)).find(user => user.id === member.id)).toMatchObject({ username, role: 'admin' });
      await page.reload();
      await row.click();
      await expect(role).toHaveValue('admin');
    } finally {
      // Delete the dedicated account even if a UI or readback assertion fails.
      const removed = await page.request.delete(userPath, { headers: await mutationHeaders(page), maxRedirects: 0 });
      expect(removed.status(), 'remove seeded persistence account').toBe(200);
      expect((await readUsers(page)).some(user => user.id === seededId)).toBe(false);
    }
  });

  await test.step('create and update an alert rule using its returned ID', async () => {
    const name = `Alert persistence ${run}`;
    const updatedName = `Alert persistence updated ${run}`;
    let ruleId: number | undefined;
    let submitted = false;
    try {
      await page.goto('/?tab=notifications');
      await page.getByRole('button', { name: 'Add alert rule', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Configure alert rule', exact: true });
      const ruleName = dialog.getByLabel('Rule name', { exact: true });
      const trigger = dialog.getByRole('combobox', { name: 'Event trigger', exact: true });
      const threshold = dialog.getByLabel('Service name or percentage threshold', { exact: true });
      const severity = dialog.getByRole('combobox', { name: 'Severity', exact: true });
      const enabled = dialog.getByLabel('Enable alert rule', { exact: true });
      const save = dialog.getByRole('button', { name: 'Save alert rule', exact: true });
      await ruleName.fill(`  ${name}  `);
      await trigger.selectOption('cpu_usage');
      await threshold.fill(' 75 ');
      await severity.selectOption('warning');
      const created = apiWrite(page, 'POST', rulesPath);
      submitted = true;
      await save.click();
      const response = await created;
      expect(response.status()).toBe(201);
      const createdBody = await response.json() as { id: number; message: string };
      ruleId = createdBody.id;
      expect(ruleId).toBeGreaterThan(0);
      expect(Number.isSafeInteger(ruleId)).toBe(true);
      expect(createdBody.message).toBe('Rule created');
      expect(response.request().postDataJSON()).toEqual({
        name: `  ${name}  `, condition_type: 'cpu_usage', condition_value: ' 75 ', level: 'warning',
      });
      await expect(dialog).toBeHidden();
      const createdRule = {
        id: ruleId, name, condition_type: 'cpu_usage', condition_value: '75', level: 'warning', enabled: true,
      };
      expect((await readRules(page)).filter(rule => rule.name === name)).toMatchObject([createdRule]);

      await page.reload();
      const grid = page.getByRole('grid', { name: 'Notification alert rules', exact: true });
      const row = (label: string) => grid.getByRole('row').filter({
        has: page.getByRole('gridcell', { name: label, exact: true }),
      });
      await row(name).click();
      await expect(ruleName).toHaveValue(name);
      await expect(trigger).toHaveValue('cpu_usage');
      await expect(threshold).toHaveValue('75');
      await expect(enabled).toBeChecked();
      await ruleName.fill(updatedName);
      await threshold.fill('90');
      await severity.selectOption('critical');
      await enabled.uncheck();
      const update = apiWrite(page, 'PUT', `${rulesPath}/${ruleId}`);
      await save.click();
      const changed = await update;
      expect(changed.status()).toBe(200);
      const rule = { ...createdRule, name: updatedName, condition_value: '90', level: 'critical', enabled: false };
      expect(changed.request().postDataJSON()).toEqual({
        name: updatedName, condition_type: 'cpu_usage', condition_value: '90', level: 'critical', enabled: false,
      });
      expect(await changed.json()).toEqual({ message: 'Rule updated' });
      await expect(dialog).toBeHidden();
      const rules = await readRules(page);
      expect(rules.filter(item => item.name === name || item.name === updatedName)).toMatchObject([rule]);
      await page.reload();
      await row(updatedName).click();
      await expect(threshold).toHaveValue('90');
      await expect(severity).toHaveValue('critical');
      await expect(enabled).not.toBeChecked();
    } finally {
      if (submitted) {
        // Also catch duplicate creates or a committed POST whose body was lost.
        const ownRules = (await readRules(page)).filter(rule =>
          rule.id === ruleId || rule.name === name || rule.name === updatedName,
        );
        for (const rule of ownRules) {
          const removed = await page.request.delete(`${rulesPath}/${rule.id}`, {
            headers: await mutationHeaders(page), maxRedirects: 0,
          });
          expect(removed.status(), `remove persistence rule ${rule.id}`).toBe(200);
        }
        expect((await readRules(page)).filter(rule =>
          rule.id === ruleId || rule.name === name || rule.name === updatedName,
        )).toEqual([]);
      }
    }
  });
});
