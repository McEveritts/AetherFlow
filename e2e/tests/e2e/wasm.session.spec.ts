import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

type Identity = 'alice' | 'bob';
type AuthSignal = 'storage' | 'broadcast';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function json(route: Route, value: unknown, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
}

async function requestCookie(page: Page, route: Route): Promise<string> {
  const header = (await route.request().allHeaders()).cookie;
  if (header !== undefined) return header;
  // WebKit's interception protocol can omit cookies. The fixture's identity
  // comes from the same context cookie jar; live cases use the real session API.
  return (await page.context().cookies(route.request().url()))
    .map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
}

async function setIdentity(page: Page, origin: string, identity: Identity) {
  await page.context().addCookies([{ name: 'session', value: identity, url: origin }]);
}

async function sessionFixture(page: Page, origin: string) {
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
  await setIdentity(page, origin, 'alice');
  const started = deferred();
  const release = deferred();
  let holdBob = false;
  await page.route('**/api/v1/auth/session', async (route) => {
    const cookie = await requestCookie(page, route);
    const identity: Identity = /(?:^|;\s*)session=bob(?:;|$)/.test(cookie) ? 'bob' : 'alice';
    if (holdBob && identity === 'bob') {
      started.resolve();
      await release.promise;
    }
    await json(route, {
      id: identity === 'alice' ? 1 : 2,
      username: identity,
      email: `${identity}@example.com`,
      role: identity === 'alice' ? 'admin' : 'user',
    }).catch(() => {}); // An auth epoch change may abort a held request.
  });
  return { started, release, holdBob: () => { holdBob = true; } };
}

async function installBrowserMocks(page: Page) {
  await page.route('**/api/v1/auth/mcbrowser/entries?*', (route) => json(route, { path: '', entries: [] }));
  await page.route('**/api/v1/auth/mcbrowser/policy', (route) => json(route, {
    scope: 'private', permissions: { read: true, create: true, modify: true }, rules: [],
  }));
  await page.route('**/api/v1/auth/mcbrowser/usage', (route) => json(route, { used_bytes: 0, quota_bytes: 0 }));
}

async function signalFromAnotherTab(page: Page, origin: string, kind: AuthSignal) {
  const sender = await page.context().newPage();
  try {
    // Use an HTML document so every engine shares the normal first-party
    // storage partition with the application page.
    await sender.goto(`${origin}/login`);
    await sender.evaluate((kind) => {
      if (kind === 'storage') {
        localStorage.setItem('af_login_sync', `${Date.now()}-${Math.random()}`);
      } else {
        const channel = new BroadcastChannel('aetherflow-auth');
        channel.postMessage({ type: 'login' });
        channel.close();
      }
    }, kind);
  } finally {
    await sender.close();
  }
}

async function browserTurns(page: Page) {
  await page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
}

for (const kind of ['storage', 'broadcast'] as const) {
  test(`invalidates a private draft immediately on ${kind} while the new session is held`, async ({ page, baseURL }) => {
    const origin = new URL(baseURL!).origin;
    const session = await sessionFixture(page, origin);
    await installBrowserMocks(page);
    const mutations: string[] = [];
    const pageErrors: string[] = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await page.route('**/api/v1/auth/mcbrowser/file', async (route) => {
      mutations.push(await requestCookie(page, route));
      await json(route, { ok: true });
    });

    await page.goto('/?tab=mcbrowser');
    await page.getByRole('button', { name: 'Toggle theme' }).click();
    await page.locator('select.af-locale-select').selectOption('dk');
    await expect(page.locator('html')).toHaveAttribute('lang', 'da');
    const theme = await page.locator('html').getAttribute('data-theme');
    const savedTheme = await page.evaluate(() => localStorage.getItem('aetherflow-theme'));
    await page.getByRole('button', { name: 'Ny tom fil' }).click();
    const dialog = page.getByRole('dialog', { name: 'Filhandling' });
    await dialog.getByLabel('Nyt filnavn').fill('alice-draft.txt');
    const oldForm = await dialog.locator('form').elementHandle();
    expect(oldForm).not.toBeNull();

    // This listener runs after the app's storage listener, in the very same
    // browser event, before Leptos can remove the old form from the DOM.
    if (kind === 'storage') {
      await oldForm!.evaluate((form) => {
        window.addEventListener('storage', (event) => {
          if (event.key === 'af_login_sync') {
            (window as Window & { __afSuspendedSynchronously?: boolean }).__afSuspendedSynchronously =
              Boolean(form.closest('dialog')?.hasAttribute('inert') && form.closest('.af-shell')?.hasAttribute('inert'));
            form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
          }
        }, { once: true });
      });
    }
    session.holdBob();
    await setIdentity(page, origin, 'bob');
    try {
      await signalFromAnotherTab(page, origin, kind);
      await session.started.promise;
      if (kind === 'storage') {
        expect(await page.evaluate(() =>
          (window as Window & { __afSuspendedSynchronously?: boolean }).__afSuspendedSynchronously,
        )).toBe(true);
      }
      await expect.poll(() => oldForm!.evaluate((form) => form.isConnected)).toBe(false);
      expect(await page.locator('input').evaluateAll((inputs) =>
        inputs.some((input) => (input as HTMLInputElement).value === 'alice-draft.txt'),
      )).toBe(false);
      await oldForm!.evaluate((form) => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
      await browserTurns(page);
      expect(mutations).toEqual([]);
    } finally {
      session.release.resolve();
    }
    await expect(page.locator('.af-user-badge')).toHaveText('bob');
    await expect(page.locator('html')).toHaveAttribute('lang', 'da');
    if (theme !== null) await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    expect(await page.evaluate(() => localStorage.getItem('aetherflow-theme'))).toBe(savedTheme);
    expect(await page.evaluate(() => localStorage.getItem('aetherflow-language'))).toBe('dk');
    await browserTurns(page);
    expect(mutations).toEqual([]);
    expect(pageErrors).toEqual([]);
  });
}

const quotaRows = [
  { user_id: 3, username: 'tenant-a', quota_bytes: 100, used_bytes: 10 },
  { user_id: 5, username: 'tenant-b', quota_bytes: 100, used_bytes: 20 },
];

async function installQuotaMocks(page: Page) {
  await page.route('**/api/v1/admin/quotas', (route) => json(route, { quotas: quotaRows }));
  await page.goto('/?tab=quotas');
  await expect(page.getByText('tenant-a · #3')).toBeVisible();
}

for (const end of ['account change', 'component disposal'] as const) {
  test(`quota batch stops after ${end} while the first refresh is held`, async ({ page, baseURL }) => {
    const origin = new URL(baseURL!).origin;
    await sessionFixture(page, origin);
    const started = deferred();
    const release = deferred();
    const firstSettled = deferred();
    const refreshes: string[] = [];
    const cookies: string[] = [];
    await page.route(/\/api\/v1\/admin\/quotas\/\d+\/refresh$/, async (route) => {
      refreshes.push(new URL(route.request().url()).pathname);
      cookies.push(await requestCookie(page, route));
      if (refreshes.length === 1) {
        started.resolve();
        await release.promise;
        await json(route, { ok: true }).catch(() => {});
        firstSettled.resolve();
        return;
      }
      await json(route, { ok: true }).catch(() => {});
    });
    await installQuotaMocks(page);
    await page.getByRole('button', { name: 'Sync / reconcile quotas' }).click();
    await started.promise;
    try {
      if (end === 'account change') {
        await setIdentity(page, origin, 'bob');
        await signalFromAnotherTab(page, origin, 'storage');
        await expect(page.locator('.af-user-badge')).toHaveText('bob');
      } else {
        await page.locator('#desktop-sidebar-navigation').getByRole('button', { name: 'Services', exact: true }).click();
        await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
      }
    } finally {
      release.resolve();
    }
    await firstSettled.promise;
    await browserTurns(page);
    expect(refreshes).toEqual(['/api/v1/admin/quotas/3/refresh']);
    expect(cookies[0]).toMatch(/(?:^|;\s*)session=alice(?:;|$)/);
    await expect(page.getByText('Quota reconciliation completed')).toHaveCount(0);
  });
}

test('SESSION_CHANGED terminates the quota batch without a success notification', async ({ page, baseURL }) => {
  await sessionFixture(page, new URL(baseURL!).origin);
  const refreshes: string[] = [];
  await page.route(/\/api\/v1\/admin\/quotas\/\d+\/refresh$/, async (route) => {
    refreshes.push(new URL(route.request().url()).pathname);
    await json(route, { code: 'SESSION_CHANGED', message: 'Session changed' }, 409);
  });
  await installQuotaMocks(page);
  await page.getByRole('button', { name: 'Sync / reconcile quotas' }).click();
  await expect.poll(() => refreshes.length).toBe(1);
  await expect(page.getByRole('button', { name: 'Sync / reconcile quotas' })).toBeEnabled();
  await browserTurns(page);
  expect(refreshes).toEqual(['/api/v1/admin/quotas/3/refresh']);
  await expect(page.getByText('Quota reconciliation completed')).toHaveCount(0);
});

for (const value of ['error', 'skip', 'overwrite', 'resume'] as const) {
  test(`large uploads offer only supported TUS policies and send ${value}`, async ({ page, baseURL }) => {
    test.setTimeout(60_000);
    await sessionFixture(page, new URL(baseURL!).origin);
    await installBrowserMocks(page);
    const created: Array<{ policy: string; metadata: string }> = [];
    await page.route(/\/api\/v1\/auth\/mcbrowser\/uploads(?:\?.*)?$/, async (route) => {
      if (route.request().method() === 'GET') return json(route, { uploads: [] });
      const headers = route.request().headers();
      created.push({ policy: headers['x-upload-conflict'] ?? '', metadata: headers['upload-metadata'] ?? '' });
      await json(route, { message: 'Stop after inspecting creation' }, 409);
    });
    await page.goto('/?tab=mcbrowser');
    const policy = page.getByLabel('Large upload conflicts');
    await expect(policy.locator('option')).toHaveCount(4);
    expect(await policy.locator('option').evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value)))
      .toEqual(['error', 'skip', 'overwrite', 'resume']);
    await page.evaluate(() => {
      (window as Window & { __afLargeFile?: File }).__afLargeFile = new File(
        [new Uint8Array(64 * 1024 * 1024 + 1)], 'large.bin', { type: 'application/octet-stream' },
      );
    });
    await policy.selectOption(value);
    await page.locator('input[aria-label="Choose files to upload"]').evaluate((element) => {
      const input = element as HTMLInputElement;
      const transfer = new DataTransfer();
      const file = (window as Window & { __afLargeFile?: File }).__afLargeFile;
      if (!file) throw new Error('Large upload fixture is missing');
      transfer.items.add(file);
      input.files = transfer.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await expect.poll(() => created.length, { timeout: 15_000 }).toBe(1);
    expect(created[0].policy).toBe(value);
    const encoded = created[0].metadata.split(',').find((item) => item.trim().startsWith('conflict '))?.trim().split(' ')[1];
    expect(encoded).toBeDefined();
    expect(Buffer.from(encoded!, 'base64').toString('utf8')).toBe(value);
  });
}
