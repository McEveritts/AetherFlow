import { expect, test, type Page, type Route } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const json = (route: Route, value: unknown, status = 200) => route.fulfill({
  status, contentType: 'application/json', body: JSON.stringify(value),
});

async function settings(page: Page, tab: 'Backups & Restore' | 'Security & 2FA') {
  await page.goto('/?tab=settings');
  await page.getByRole('tab', { name: tab, exact: true }).click();
}

test.describe('WASM restored workflows', () => {
  test('shows persisted backup schedule, toggles it, and preserves the password draft across polling', async ({ page }) => {
    await page.clock.install();
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let mode: 'smart' | 'manual' = 'smart';
    let reads = 0;
    const writes: string[] = [];
    await page.route('**/api/v1/admin/backup/list', route => json(route, [{
      filename: 'snapshot.sqlite', size: 100, checksum: 'abc', timestamp: '2026-11-17T00:00:00Z',
    }]));
    await page.route('**/api/v1/admin/ai/backup/optimal-window', route => {
      reads++;
      return json(route, { mode, running: mode === 'smart',
        optimal_window: { hour: 4, day_of_week: 'Sunday', duration_mins: 90, confidence: 0.8, reason: 'Quiet hours' },
        next_backup_at: mode === 'smart' ? '2026-11-18T04:00:00Z' : '' });
    });
    await page.route('**/api/v1/admin/ai/backup/schedule', async route => {
      const body = route.request().postDataJSON() as { mode: 'smart' | 'manual' };
      writes.push(body.mode);
      mode = body.mode;
      await json(route, { mode, running: mode === 'smart', next_backup_at: mode === 'smart' ? '2026-11-18T04:00:00Z' : '' });
    });
    await settings(page, 'Backups & Restore');
    const schedule = page.getByRole('region', { name: 'Automatic backup schedule' });
    await expect(schedule).toContainText('Schedule mode: Smart');
    await expect(schedule).toContainText('Sunday 04:00 UTC');
    await expect(schedule).toContainText('Window duration: 90 minutes');
    await expect(schedule).toContainText('Confidence: 80%');
    await expect(schedule).toContainText('2026-11-18T04:00:00Z');
    await page.getByRole('grid', { name: 'Verified backup manifests' }).getByText('snapshot.sqlite').click();
    const password = page.getByRole('dialog', { name: 'Download verified backup' }).getByLabel('Current password');
    await password.fill('unfinished-draft');
    await page.clock.fastForward('00:31');
    await expect.poll(() => reads).toBeGreaterThanOrEqual(2);
    await expect(password).toHaveValue('unfinished-draft');
    await page.getByRole('dialog', { name: 'Download verified backup' }).getByRole('button', { name: 'Close dialog' }).click();
    const disableSchedule = schedule.getByRole('button', { name: 'Disable automatic backups' });
    await expect(disableSchedule).toBeEnabled();
    await disableSchedule.press('Enter');
    await expect(schedule).toContainText('Schedule mode: Manual');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByRole('tab', { name: 'Backups & Restore' }).press('Enter');
    await expect(schedule).toContainText('Schedule mode: Manual');
    const enableSchedule = schedule.getByRole('button', { name: 'Enable automatic backups' });
    await expect(enableSchedule).toBeEnabled();
    await enableSchedule.press('Enter');
    await expect(schedule).toContainText('Schedule mode: Smart');
    expect(writes).toEqual(['manual', 'smart']);
  });

  test('uploads and removes a self-scoped raster avatar and refreshes the session without losing an email draft', async ({ page }) => {
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    let avatar = '/existing-avatar.png';
    let accountId = 1;
    let sessionReads = 0;
    const writes: Array<{ method: string; avatar?: string }> = [];
    await page.route('**/api/v1/auth/session', route => {
      sessionReads++;
      return json(route, { id: accountId, username: accountId === 1 ? 'admin' : 'other-user', role: 'admin', email: 'admin@example.com', avatar_url: avatar });
    });
    await page.route('**/api/v1/auth/profile/avatar', async route => {
      if (route.request().method() === 'PUT') {
        const body = route.request().postDataJSON() as { avatar: string };
        writes.push({ method: 'PUT', avatar: body.avatar });
        avatar = body.avatar;
      } else {
        writes.push({ method: route.request().method() });
        avatar = '';
      }
      await json(route, { status: 'success', avatar_url: avatar });
    });
    await settings(page, 'Security & 2FA');
    const image = page.getByRole('img', { name: 'Profile avatar' });
    await expect(image).toHaveAttribute('src', '/existing-avatar.png');
    const email = page.getByLabel('Email address');
    await email.fill('draft@example.com');
    const input = page.getByLabel('Upload avatar');
    await input.setInputFiles({ name: 'unsafe.svg', mimeType: 'image/svg+xml', buffer: Buffer.from('<svg/>') });
    await expect(page.getByText('Choose a PNG, JPEG, WEBP, or GIF image.')).toBeVisible();
    expect(writes).toHaveLength(0);
    await input.setInputFiles({ name: 'too-large.png', mimeType: 'image/png', buffer: Buffer.alloc(2 * 1024 * 1024) });
    await expect(page.getByText('Avatar encoded size must not exceed 2 MiB.')).toBeVisible();
    expect(writes).toHaveLength(0);
    const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==', 'base64');
    const beforeUpload = sessionReads;
    await input.setInputFiles({ name: 'avatar.png', mimeType: 'image/png', buffer: pixel });
    await expect.poll(() => sessionReads).toBeGreaterThan(beforeUpload);
    await expect(image).toHaveAttribute('src', `data:image/png;base64,${pixel.toString('base64')}`);
    await expect(email).toHaveValue('draft@example.com');
    expect(writes[0]).toEqual({ method: 'PUT', avatar: `data:image/png;base64,${pixel.toString('base64')}` });
    const beforeRemoval = sessionReads;
    await page.getByRole('button', { name: 'Remove avatar' }).click();
    await expect.poll(() => sessionReads).toBeGreaterThan(beforeRemoval);
    await expect(page.getByRole('button', { name: 'Remove avatar' })).toBeDisabled();
    await expect(email).toHaveValue('draft@example.com');
    expect(writes[1]).toEqual({ method: 'DELETE' });

    // Hold the browser's file read across an account change. The completed read
    // must never become a PUT authenticated as the new account.
    await page.evaluate(() => {
      const original = Blob.prototype.arrayBuffer;
      Blob.prototype.arrayBuffer = function () {
        if (this instanceof File && this.name === 'held.png') {
          return new Promise<ArrayBuffer>((resolve, reject) => {
            (window as unknown as { releaseAvatarRead: () => void }).releaseAvatarRead = () => {
              void original.call(this).then(resolve, reject);
            };
          });
        }
        return original.call(this);
      };
    });
    await input.setInputFiles({ name: 'held.png', mimeType: 'image/png', buffer: pixel });
    await expect.poll(() => page.evaluate(() => typeof (window as unknown as { releaseAvatarRead?: () => void }).releaseAvatarRead)).toBe('function');
    accountId = 2;
    avatar = '/other-avatar.png';
    await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', { key: 'af_login_sync' })));
    await expect.poll(() => sessionReads).toBeGreaterThan(beforeRemoval + 1);
    await page.evaluate(async () => {
      (window as unknown as { releaseAvatarRead: () => void }).releaseAvatarRead();
      await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
    });
    expect(writes).toHaveLength(2);
  });

  test('keeps cohort reports on the history snapshot and applies stable scoped identities', async ({ page, browserName }) => {
    if (browserName === 'webkit') test.setTimeout(90_000);
    await installAetherFlowMocks(page, { authenticated: true, setupRequired: false });
    const historyQueries: URLSearchParams[] = [];
    const analyticsQueries: Array<{ path: string; params: URLSearchParams }> = [];
    const snapshotFilters = new Map<string, string>();
    let sequence = 0;
    let conflict = false;
    let releaseHeldHistory!: () => void;
    let historyWasHeld!: () => void;
    let heldHistoryFinished!: () => void;
    const releaseHistory = new Promise<void>(resolve => { releaseHeldHistory = resolve; });
    const historyHeld = new Promise<void>(resolve => { historyWasHeld = resolve; });
    const heldHistoryDone = new Promise<void>(resolve => { heldHistoryFinished = resolve; });
    let holdPageSizeResponse = true;
    const fingerprint = (params: URLSearchParams) => {
      const copy = new URLSearchParams(params);
      copy.delete('cursor'); copy.delete('snapshot'); copy.sort();
      return copy.toString();
    };
    await page.route('**/api/v1/auth/streaming/history?*', async route => {
      const params = new URL(route.request().url()).searchParams;
      historyQueries.push(params);
      const fp = fingerprint(params);
      let snapshot: string;
      if (params.has('cursor')) {
        expect(params.has('snapshot')).toBe(false);
        snapshot = (params.get('cursor') ?? '').replace(/^page-two:/, '');
      } else if (params.has('snapshot')) {
        snapshot = params.get('snapshot') ?? '';
      } else {
        snapshot = `snapshot-${++sequence}`;
        snapshotFilters.set(snapshot, fp);
      }
      expect(snapshotFilters.get(snapshot)).toBe(fp);
      const hold = holdPageSizeResponse && !params.has('cursor')
        && params.get('pageSize') === '25' && params.get('sort') === 'startedDesc';
      if (hold) {
        holdPageSizeResponse = false;
        historyWasHeld();
        await releaseHistory;
      }
      try {
        await json(route, { scope: { snapshotToken: snapshot, asOf: '2026-11-17T00:00:00Z', expiresAt: '2026-11-18T00:00:00Z' },
          counts: { matchingRecords: 2, availableRecords: 2, confirmedPlays: 2, watchTimeSecs: 7200, undatedRecords: 0 },
          items: [{ id: 1, provider: 'jellyfin', serverId: 'server-a', userId: 'user-a', userName: 'Same viewer', itemId: 'item-a', itemName: 'Playback record' }],
          nextCursor: params.has('cursor') ? null : `page-two:${snapshot}` });
      } finally {
        if (hold) heldHistoryFinished();
      }
    });
    await page.route(/\/api\/v1\/auth\/streaming\/(patterns|drilldown)\?.*/, route => {
      const url = new URL(route.request().url());
      const params = url.searchParams;
      analyticsQueries.push({ path: url.pathname, params });
      expect(snapshotFilters.get(params.get('snapshot') ?? '')).toBe(fingerprint(params));
      expect(params.has('cursor')).toBe(false);
      if (url.pathname.endsWith('/patterns')) {
        return json(route, { activity: { timeseries: [] }, concurrency: { buckets: [] } });
      }
      if (conflict) { conflict = false; return json(route, { message: 'snapshot expired' }, 409); }
      return json(route, {
        cohortDistinctPlays: 2, cohortDistinctUsers: 2, cohortDistinctItems: 2,
        users: [
          { provider: 'jellyfin', serverId: 'server-a', userId: 'user-a', userName: 'Same viewer', playCount: 1, watchTimeSecs: 3600 },
          { provider: 'jellyfin', serverId: 'server-b', userId: 'user-b', userName: 'Same viewer', playCount: 1, watchTimeSecs: 3600 },
          { provider: 'jellyfin', serverId: '', userId: '', userName: 'Unidentified viewer', playCount: 1, watchTimeSecs: 0 },
        ],
        clients: [{ clientName: 'Web', deviceName: 'Desktop', playCount: 2, watchTimeSecs: 7200 }],
        items: [{ provider: 'jellyfin', serverId: 'server-b', itemId: 'item-b', itemName: 'Same title', playCount: 1, watchTimeSecs: 3600 }],
        libraries: [{ provider: 'jellyfin', serverId: 'server-b', libraryId: 'library-b', libraryName: 'Movies', playCount: 1, watchTimeSecs: 3600 }],
        genres: [{ genre: 'Drama', playCount: 1, watchTimeSecs: 3600 }],
      });
    });
    await page.goto('/?tab=streaming');
    await page.getByRole('tab', { name: 'Canonical playback history' }).click();
    await expect(page.getByRole('region', { name: 'Cohort drilldowns' })).toContainText('2 distinct plays');
    await page.getByText('Advanced archive filters').click();
    await page.getByLabel('Page size').selectOption('25');
    try {
      await historyHeld;
      await expect(page.getByText('Loading history snapshot…')).toBeVisible();
      expect(analyticsQueries.some(q => q.params.get('pageSize') === '25' && q.params.get('sort') === 'startedDesc')).toBe(false);
      // Complete a newer query before releasing the previous history response.
      await page.getByLabel('Date ordering').selectOption('startedAsc');
      await expect.poll(() => ['patterns', 'drilldown'].every(endpoint => analyticsQueries.some(q =>
        q.params.get('pageSize') === '25' && q.params.get('sort') === 'startedAsc' && q.path.endsWith(`/${endpoint}`),
      ))).toBe(true);
    } finally {
      releaseHeldHistory();
    }
    await heldHistoryDone;
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    expect(analyticsQueries.some(q => q.params.get('pageSize') === '25' && q.params.get('sort') === 'startedDesc')).toBe(false);
    await page.getByRole('button', { name: 'Next', exact: true }).click();
    await expect(page.getByText('Page 2', { exact: true })).toBeVisible();
    const users = page.getByRole('region', { name: 'Viewers' });
    await expect(users.getByRole('button', { name: /Unidentified viewer/ })).toBeDisabled();
    await users.getByRole('button', { name: /Same viewer.*server-b.*user-b/ }).click();
    await expect(page.getByText('Page 1', { exact: true })).toBeVisible();
    await expect.poll(() => historyQueries.some(q => q.get('serverId') === 'server-b' && q.get('userId') === 'user-b' && !q.has('cursor'))).toBe(true);
    await expect.poll(() => analyticsQueries.some(q => q.path.endsWith('/drilldown') && q.params.get('serverId') === 'server-b' && q.params.get('userId') === 'user-b')).toBe(true);
    for (const [region, button, field, expected] of [
      ['Clients and devices', /Web.*Desktop/, 'client', 'Web'],
      ['Media items', /Same title.*server-b.*item-b/, 'itemId', 'item-b'],
      ['Libraries', /Movies.*server-b.*library-b/, 'libraryId', 'library-b'],
      ['Genres', /Drama/, 'genre', 'Drama'],
    ] as const) {
      await page.getByRole('region', { name: region }).getByRole('button', { name: button }).click();
      await expect.poll(() => historyQueries.some(q => q.get(field) === expected && !q.has('cursor'))).toBe(true);
      await expect.poll(() => analyticsQueries.some(q => q.path.endsWith('/drilldown') && q.params.get(field) === expected)).toBe(true);
      await expect(page.getByRole('region', { name: region })).toBeVisible();
    }
    conflict = true;
    await page.getByRole('button', { name: 'New snapshot' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Analytics snapshot expired or changed' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Cohort drilldowns' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Export CSV · all matches' })).toBeDisabled();
    await expect(page.getByText('Playback record', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('grid', { name: 'Canonical playback history; worker-backed page search', exact: true }).getByRole('row')).toHaveCount(1);
    await page.getByRole('button', { name: 'Restart history snapshot' }).click();
    await expect(page.getByRole('region', { name: 'Cohort drilldowns' })).toBeVisible();
    await page.getByLabel('Date window').selectOption('custom');
    await page.getByLabel('From (inclusive, UTC)').fill('2026-11-01');
    await page.getByLabel('Until (exclusive, UTC)').fill('2026-11-08');
    await expect.poll(() => analyticsQueries.some(q => q.path.endsWith('/drilldown')
      && q.params.get('from') === '2026-11-01T00:00:00Z'
      && q.params.get('until') === '2026-11-08T00:00:00Z')).toBe(true);
    expect(analyticsQueries.some(q => q.params.get('pageSize') === '25' && q.params.get('sort') === 'startedDesc')).toBe(false);
  });
});
