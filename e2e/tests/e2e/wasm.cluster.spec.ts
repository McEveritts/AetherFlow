import { expect, test, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const peerApi = '/api/v1/admin/peers';
const wgPublicKey = Buffer.alloc(32, 7).toString('base64');
const pairingString = `afpair1:${Buffer.from(JSON.stringify({
  https_url: 'https://peer.example.test',
  endpoint: '192.0.2.21',
  wg_pubkey: wgPublicKey,
  wg_port: 51821,
  tunnel_ip: '10.231.0.21',
  code: '7'.repeat(64),
})).toString('base64url')}`;

function peerList() {
  return {
    identity: null,
    peer_protocol: 1,
    capabilities: ['links'],
    rtt_warn_ms: 120,
    peers: [],
    pairing_windows: [],
    pairing_attempts: [],
    detected_endpoints: [{ address: '192.0.2.20', interface: 'eth0', family: 'ipv4', recommended: true }],
  };
}

async function mountCluster(page: Page, list: () => unknown = peerList) {
  await installAetherFlowMocks(page);
  await page.route(`**${peerApi}`, async route => {
    expect(route.request().method()).toBe('GET');
    await route.fulfill({ json: list() });
  });
}

test('the Cluster URL opens peer pairing on an unlinked server', async ({ page }) => {
  await mountCluster(page);
  const response = page.waitForResponse(response => new URL(response.url()).pathname === peerApi);
  await page.goto('/?tab=cluster');
  expect((await response).ok()).toBe(true);
  await expect(page.getByRole('button', { name: 'Allow a server to manage this one' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Pair with a server' })).toBeVisible();
});

test('opens a pairing window and closes its single-use string', async ({ page }) => {
  const windowId = 'window-1';
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  let windowOpen = false;
  await mountCluster(page, () => ({
    ...peerList(),
    pairing_windows: windowOpen ? [{ id: windowId, expires_at: expiresAt }] : [],
  }));
  await page.route(`**${peerApi}/pairing-window`, async route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toMatchObject({ endpoint: '192.0.2.20' });
    windowOpen = true;
    await route.fulfill({ status: 201, json: {
      window_id: windowId,
      expires_at: expiresAt,
      ttl_seconds: 600,
      pairing_string: pairingString,
      https_url: 'https://peer.example.test',
      endpoint: '192.0.2.20',
      wg_port: 51821,
      tunnel_ip: '10.231.0.21',
      wg_pubkey: wgPublicKey,
    } });
  });
  await page.route(`**${peerApi}/pairing-window/${windowId}`, async route => {
    expect(route.request().method()).toBe('DELETE');
    windowOpen = false;
    await route.fulfill({ json: { closed: true, window_id: windowId } });
  });

  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: 'Allow a server to manage this one' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'Open pairing window' }).click();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveValue(pairingString);
  await expect(dialog.getByRole('button', { name: 'Copy pairing string' })).toBeEnabled();
  await dialog.getByRole('button', { name: 'Close window', exact: true }).click();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveCount(0);
  expect(windowOpen).toBe(false);
});

test('pairing shows the typed recovery action and preserves the pairing string', async ({ page }) => {
  await mountCluster(page);
  await page.route(`**${peerApi}/pair`, async route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toMatchObject({ pairing_string: pairingString });
    await route.fulfill({
      status: 410,
      headers: { 'X-Request-ID': 'req-pair-hdr-410' },
      json: {
        code: 'CODE_EXPIRED',
        server: 'peer.example.test',
        step: 'public_pairing_request',
        message: 'The pairing code has expired.',
        action: 'Open a new pairing window on the peer and try again.',
      },
    });
  });

  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: 'Pair with a server' }).click();
  const dialog = page.getByRole('dialog');
  const pairingInput = dialog.getByRole('textbox', { name: /pairing string/i });
  await pairingInput.fill(pairingString);
  await dialog.getByRole('button', { name: /^(pair|start pairing)$/i }).click();
  await expect(dialog.getByText('Open a new pairing window on the peer and try again.')).toBeVisible();
  await expect(dialog.getByTestId('peer-error-request-id')).toHaveText('Request ID: req-pair-hdr-410');
  await expect(pairingInput).toHaveValue(pairingString);
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(page.locator('#cluster-pair-string')).toHaveValue('');
  await page.getByRole('button', { name: 'Pair with a server' }).click();
  await expect(pairingInput).toHaveValue('');
  await expect(dialog.getByText('Open a new pairing window on the peer and try again.')).toHaveCount(0);
  await expect(dialog.getByTestId('peer-error-request-id')).toHaveCount(0);
});

test('shows the comparison code only while the initiated pairing is pending', async ({ page }) => {
  const attemptId = 'outgoing-1';
  const linkId = 'media-peer';
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  let pending = false;
  await mountCluster(page, () => ({
    ...peerList(),
    peers: pending ? [{
      id: linkId,
      name: 'Media server',
      state: 'pending',
      pending_attempt_id: attemptId,
      pending_expires_at: expiresAt,
    }] : [],
  }));
  await page.route(`**${peerApi}/pair`, async route => {
    expect(route.request().method()).toBe('POST');
    pending = true;
    await route.fulfill({ status: 201, json: {
      link_id: linkId,
      attempt_id: attemptId,
      name: 'Media server',
      remote_server_name: 'Media server',
      comparison_code: '204229',
      expires_at: expiresAt,
      state: 'pending',
    } });
  });

  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: 'Pair with a server' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('textbox', { name: /pairing string/i }).fill(pairingString);
  await dialog.getByRole('button', { name: 'Start pairing' }).click();
  const comparison = page.getByText('204229', { exact: true });
  await expect(comparison).toBeVisible();
  pending = false;
  await page.getByRole('button', { name: 'Refresh peer links' }).click();
  await expect(comparison).toHaveCount(0);
});

test('confirms a pending peer after displaying its comparison code', async ({ page }) => {
  const attempt = {
    id: 'pending-1',
    window_id: 'window-1',
    remote_name: 'Media server',
    remote_pubkey: wgPublicKey,
    remote_tunnel_ip: '10.231.0.21',
    remote_endpoint: '192.0.2.21',
    source_ip: '192.0.2.21',
    status: 'pending',
    comparison_code: '104229',
    expires_at: Math.floor(Date.now() / 1000) + 600,
    created_at: new Date().toISOString(),
  };
  let confirmed = false;
  await mountCluster(page, () => ({
    ...peerList(),
    pairing_attempts: confirmed ? [] : [attempt],
  }));
  await page.route(`**${peerApi}/pairing/${attempt.id}/confirm`, async route => {
    expect(route.request().method()).toBe('POST');
    confirmed = true;
    await route.fulfill({ json: {
      link_id: 'media-peer',
      name: attempt.remote_name,
      state: 'active',
      attempt_id: attempt.id,
      confirmed: true,
      rtt_ms: 8,
    } });
  });

  await page.goto('/?tab=cluster');
  await expect(page.getByText(attempt.comparison_code, { exact: true })).toBeVisible();
  const response = page.waitForResponse(response =>
    new URL(response.url()).pathname === `${peerApi}/pairing/${attempt.id}/confirm`,
  );
  await page.getByRole('button', { name: 'Approve & link' }).click();
  expect((await response).ok()).toBe(true);
  await expect(page.getByText(attempt.comparison_code, { exact: true })).toHaveCount(0);
});

test('updates an existing endpoint and confirms revocation before deleting its link', async ({ page }) => {
  const peer = {
    id: 'media-peer',
    name: 'Media server',
    wg_pubkey: wgPublicKey,
    tunnel_ip: '10.231.0.21',
    endpoint: '192.0.2.21',
    wg_port: 51821,
    state: 'active',
    peer_version: '4.0.0',
    peer_protocol: 1,
    capabilities: ['links'],
    compatibility: 'compatible',
    missing_capabilities: [],
    rtt_ms: 8,
    high_latency: false,
    last_ok_at: null,
    last_error: null,
    consecutive_failures: 0,
    pending_attempt_id: null,
    pending_expires_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    grants: { inbound: null, outbound: null },
    exports: [],
    mounts: [],
    transcode_worker: null,
  };
  let revoked = false;
  let revocations = 0;
  await mountCluster(page, () => ({ ...peerList(), peers: revoked ? [] : [peer] }));
  await page.route(`**${peerApi}/${peer.id}/endpoint`, async route => {
    expect(route.request().method()).toBe('PUT');
    expect(route.request().postDataJSON()).toMatchObject({ endpoint: '192.0.2.22' });
    peer.endpoint = '192.0.2.22';
    await route.fulfill({ json: { peer, updated: true } });
  });
  await page.route(`**${peerApi}/${peer.id}`, async route => {
    expect(route.request().method()).toBe('DELETE');
    revocations += 1;
    revoked = true;
    await route.fulfill({ json: {
      revoked: true, notice_delivered: true, link_id: peer.id, name: peer.name,
    } });
  });

  await page.goto('/?tab=cluster');
  await expect(page.getByText(peer.name, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: `Edit endpoint for ${peer.name}` }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('textbox', { name: 'Endpoint IP address or hostname' }).fill('192.0.2.22');
  await dialog.getByRole('button', { name: /^(save|save endpoint|update endpoint)$/i }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(peer.endpoint).toBe('192.0.2.22');

  await page.getByRole('button', { name: `Revoke link for ${peer.name}` }).click();
  await expect(dialog).toBeVisible();
  expect(revocations).toBe(0);
  await dialog.getByRole('button', { name: /^(revoke|revoke link)$/i }).click();
  await expect(page.getByText(peer.name, { exact: true })).toHaveCount(0);
  expect(revocations).toBe(1);
});

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>(r => {
    resolve = r;
  });
  return { promise, resolve };
}

function makePairingString(codeChar: string, endpoint = '192.0.2.21') {
  return `afpair1:${Buffer.from(JSON.stringify({
    https_url: 'https://peer.example.test',
    endpoint,
    wg_pubkey: wgPublicKey,
    wg_port: 51821,
    tunnel_ip: '10.231.0.21',
    code: codeChar.repeat(64),
  })).toString('base64url')}`;
}

function makePeer(id: string, name: string, endpoint: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    name,
    wg_pubkey: wgPublicKey,
    tunnel_ip: '10.231.0.21',
    endpoint,
    wg_port: 51821,
    state: 'active',
    peer_version: '4.0.0',
    peer_protocol: 1,
    capabilities: ['links'],
    compatibility: 'compatible',
    missing_capabilities: [] as string[],
    rtt_ms: 8 as number | null,
    high_latency: false,
    last_ok_at: null as string | null,
    last_error: null as string | null,
    consecutive_failures: 0,
    pending_attempt_id: null as string | null,
    pending_expires_at: null as number | null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    grants: { inbound: null, outbound: null },
    exports: [] as unknown[],
    mounts: [] as unknown[],
    transcode_worker: null as unknown,
    ...overrides,
  };
}

test('pairing window keeps focus across view swaps and fences stale open/close completions', async ({ page }) => {
  test.setTimeout(60_000);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  const activeWindows: Array<{ id: string; expires_at: number }> = [];
  let listReads = 0;

  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      pairing_windows: [...activeWindows],
    };
  });

  const secret0 = makePairingString('1');
  const secret1 = makePairingString('2');
  const secret2 = makePairingString('3');
  const secret3 = makePairingString('4');
  const secret4 = makePairingString('5');
  const open1Gate = deferred();
  const open2Gate = deferred();
  const open3Gate = deferred();
  const close2Gate = deferred();
  const close3Gate = deferred();
  let openCalls = 0;

  await page.route(`**${peerApi}/pairing-window`, async route => {
    expect(route.request().method()).toBe('POST');
    openCalls += 1;
    const call = openCalls;
    if (call === 2) {
      await open1Gate.promise;
    } else if (call === 3) {
      await open2Gate.promise;
    } else if (call === 4) {
      await open3Gate.promise;
    }
    const id = `win-${call - 1}`;
    const secrets = [secret0, secret1, secret2, secret3, secret4];
    activeWindows.push({ id, expires_at: expiresAt });
    await route.fulfill({
      status: 201,
      json: {
        window_id: id,
        expires_at: expiresAt,
        ttl_seconds: 600,
        pairing_string: secrets[call - 1],
        https_url: 'https://peer.example.test',
        endpoint: '192.0.2.20',
        wg_port: 51821,
        tunnel_ip: '10.231.0.21',
        wg_pubkey: wgPublicKey,
      },
    });
  });

  await page.route(`**${peerApi}/pairing-window/*`, async route => {
    expect(route.request().method()).toBe('DELETE');
    const windowId = new URL(route.request().url()).pathname.split('/').at(-1)!;
    if (windowId === 'win-2') {
      await close2Gate.promise;
    } else if (windowId === 'win-3') {
      await close3Gate.promise;
    }
    const idx = activeWindows.findIndex(w => w.id === windowId);
    if (idx >= 0) {
      activeWindows.splice(idx, 1);
    }
    await route.fulfill({ json: { closed: true, window_id: windowId } });
  });

  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: 'Allow a server to manage this one' }).click();
  const dialog = page.getByRole('dialog');
  const endpointSelect = dialog.locator('#cluster-window-endpoint');
  await expect(endpointSelect).toBeFocused();

  // Form -> generated pairing string keeps focus on the primary Copy action inside the dialog.
  await dialog.getByRole('button', { name: 'Open pairing window' }).click();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveValue(secret0);
  await expect(dialog.getByRole('button', { name: 'Copy pairing string' })).toBeFocused();
  await expect(page.getByText('Pairing window win-0')).toBeVisible();

  // Closing the window swaps back to the form and restores focus to the endpoint picker.
  await dialog.getByRole('button', { name: 'Close window', exact: true }).click();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveCount(0);
  await expect(endpointSelect).toBeFocused();
  await expect(page.getByText('Pairing window win-0')).toHaveCount(0);

  // Dismiss via Escape while POST #1 is in flight, reopen, and start POST #2.
  await dialog.getByRole('button', { name: 'Open pairing window' }).click();
  await expect(dialog.getByRole('button', { name: 'Opening pairing window…' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Allow a server to manage this one' }).click();
  await expect(dialog.getByRole('button', { name: 'Open pairing window' })).toBeEnabled();
  await dialog.getByRole('button', { name: 'Open pairing window' }).click();
  const busySubmit = dialog.getByRole('button', { name: 'Opening pairing window…' });
  await expect(busySubmit).toBeDisabled();

  // Stale POST #1 completes while POST #2 is in flight: refresh runs, but #2 stays busy and
  // #1's secret is never displayed inside the replacement dialog.
  const readsBeforeStaleOpen = listReads;
  open1Gate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBeforeStaleOpen);
  await expect(busySubmit).toBeDisabled();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveCount(0);
  await expect(page.getByText('Pairing window win-1')).toBeVisible();

  // Current POST #2 completes and displays its own secret with focus on Copy.
  open2Gate.resolve();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveValue(secret2);
  await expect(dialog.getByRole('button', { name: 'Copy pairing string' })).toBeFocused();
  await expect(page.getByText('Pairing window win-2')).toBeVisible();

  // Dismiss via X button while DELETE for win-2 is in flight, reopen, and start POST for win-3.
  await dialog.getByRole('button', { name: 'Close window', exact: true }).click();
  await expect(dialog.getByRole('button', { name: 'Close window', exact: true })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Allow a server to manage this one' }).click();
  await dialog.getByRole('button', { name: 'Open pairing window' }).click();
  await expect(busySubmit).toBeDisabled();

  // Stale DELETE for win-2 completes while POST for win-3 is busy: refresh removes win-2,
  // while POST for win-3 remains busy.
  const readsBeforeStaleCloseBusy = listReads;
  close2Gate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBeforeStaleCloseBusy);
  await expect(busySubmit).toBeDisabled();
  await expect(page.getByText('Pairing window win-2')).toHaveCount(0);

  open3Gate.resolve();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveValue(secret3);
  await expect(dialog.getByRole('button', { name: 'Copy pairing string' })).toBeFocused();
  await expect(page.getByText('Pairing window win-3')).toBeVisible();

  // Stale DELETE for win-3 (dismissed via Escape) does not wipe a newly opened win-4.
  await dialog.getByRole('button', { name: 'Close window', exact: true }).click();
  await expect(dialog.getByRole('button', { name: 'Close window', exact: true })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Allow a server to manage this one' }).click();
  await dialog.getByRole('button', { name: 'Open pairing window' }).click();
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveValue(secret4);
  await expect(dialog.getByRole('button', { name: 'Copy pairing string' })).toBeFocused();
  await expect(page.getByText('Pairing window win-4')).toBeVisible();

  const readsBeforeStaleCloseOpen = listReads;
  close3Gate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBeforeStaleCloseOpen);
  await expect(dialog.getByRole('textbox', { name: 'Pairing string' })).toHaveValue(secret4);
  await expect(page.getByText('Pairing window win-3')).toHaveCount(0);
  await expect(page.getByText('Pairing window win-4')).toBeVisible();
});

test('start pairing fences stale success and error completions across close button and Escape', async ({ page }) => {
  test.setTimeout(60_000);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  const peers: Array<Record<string, unknown>> = [];
  let listReads = 0;

  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      peers: [...peers],
    };
  });

  const str1 = makePairingString('a');
  const str2 = makePairingString('b');
  const str3 = makePairingString('c');
  const pair1Gate = deferred();
  const pair2Gate = deferred();
  const pair3Gate = deferred();
  let pairCalls = 0;

  await page.route(`**${peerApi}/pair`, async route => {
    expect(route.request().method()).toBe('POST');
    pairCalls += 1;
    const call = pairCalls;
    if (call === 1) {
      await pair1Gate.promise;
      peers.push(makePeer('peer-1', 'Alpha', '192.0.2.21', {
        state: 'pending',
        pending_attempt_id: 'att-1',
        pending_expires_at: expiresAt,
      }));
      await route.fulfill({
        status: 201,
        json: {
          link_id: 'peer-1',
          attempt_id: 'att-1',
          name: 'Alpha',
          remote_server_name: 'Alpha',
          comparison_code: '111111',
          expires_at: expiresAt,
          state: 'pending',
        },
      });
      return;
    }
    if (call === 2) {
      await pair2Gate.promise;
      peers.push(makePeer('peer-2', 'Beta', '192.0.2.22', {
        state: 'pending',
        pending_attempt_id: 'att-2',
        pending_expires_at: expiresAt,
      }));
      await route.fulfill({
        status: 201,
        json: {
          link_id: 'peer-2',
          attempt_id: 'att-2',
          name: 'Beta',
          remote_server_name: 'Beta',
          comparison_code: '222222',
          expires_at: expiresAt,
          state: 'pending',
        },
      });
      return;
    }
    await pair3Gate.promise;
    await route.fulfill({
      status: 410,
      json: {
        code: 'CODE_EXPIRED',
        server: 'peer.example.test',
        step: 'public_pairing_request',
        message: 'Stale pairing failure should not leak.',
        action: 'Generate a fresh pairing string.',
      },
    });
  });

  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: 'Pair with a server' }).click();
  const dialog = page.getByRole('dialog');
  const pairInput = dialog.locator('#cluster-pair-string');
  const nameInput = dialog.locator('#cluster-pair-name');

  // Start request #1 and dismiss via close (X) button while busy.
  await pairInput.fill(str1);
  await dialog.getByRole('button', { name: 'Start pairing' }).click();
  await expect(dialog.getByRole('button', { name: 'Contacting peer…' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.locator('#cluster-pair-string')).toHaveValue('');

  // Reopen immediately and start request #2 with a distinct draft.
  await page.getByRole('button', { name: 'Pair with a server' }).click();
  await expect(pairInput).toBeEnabled();
  await pairInput.fill(str2);
  await nameInput.fill('Beta');
  await dialog.getByRole('button', { name: 'Start pairing' }).click();
  const busyButton = dialog.getByRole('button', { name: 'Contacting peer…' });
  await expect(busyButton).toBeDisabled();

  // Stale request #1 succeeds during request #2: peer list refreshes, but modal stays open/busy
  // with request #2's draft intact and without showing request #1's comparison code.
  const readsBeforeStalePair = listReads;
  pair1Gate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBeforeStalePair);
  await expect(dialog).toBeVisible();
  await expect(busyButton).toBeDisabled();
  await expect(pairInput).toHaveValue(str2);
  await expect(nameInput).toHaveValue('Beta');
  await expect(page.getByText('111111', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Alpha', { exact: true })).toBeVisible();

  // Request #2 completes and displays its comparison code.
  pair2Gate.resolve();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('222222', { exact: true })).toBeVisible();

  // Stale error from an Escape-dismissed request never leaks into a reopened dialog.
  await page.getByRole('button', { name: 'Pair with a server' }).click();
  await pairInput.fill(str3);
  await dialog.getByRole('button', { name: 'Start pairing' }).click();
  await expect(dialog.getByRole('button', { name: 'Contacting peer…' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Pair with a server' }).click();
  await pairInput.fill(str2);
  const staleErrorResponse = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/pair` && resp.status() === 410,
  );
  pair3Gate.resolve();
  await staleErrorResponse;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Stale pairing failure should not leak.')).toHaveCount(0);
  await expect(pairInput).toHaveValue(str2);
});

test('endpoint edit and revoke modals fence stale completions across target switches', async ({ page }) => {
  test.setTimeout(60_000);
  let peers = [
    makePeer('peer-a', 'Media server', '192.0.2.21'),
    makePeer('peer-b', 'Backup server', '192.0.2.31'),
  ];
  let listReads = 0;

  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      peers: peers.map(p => ({ ...p })),
    };
  });

  const editAGate = deferred();
  const editBGate = deferred();
  const editAErrorGate = deferred();
  const revokeAErrorGate = deferred();
  const revokeAGate = deferred();
  const revokeBGate = deferred();
  let editACalls = 0;
  let revokeACalls = 0;

  await page.route(`**${peerApi}/peer-a/endpoint`, async route => {
    expect(route.request().method()).toBe('PUT');
    editACalls += 1;
    if (editACalls === 1) {
      await editAGate.promise;
      peers = peers.map(p => (p.id === 'peer-a' ? { ...p, endpoint: '192.0.2.91' } : p));
      await route.fulfill({ json: { peer: peers[0], updated: true } });
      return;
    }
    await editAErrorGate.promise;
    await route.fulfill({
      status: 502,
      json: {
        code: 'ENDPOINT_UNREACHABLE',
        server: 'Media server',
        step: 'update_peer_endpoint',
        message: 'Stale edit error for Media server.',
        action: 'Check firewall rules.',
      },
    });
  });

  await page.route(`**${peerApi}/peer-b/endpoint`, async route => {
    expect(route.request().method()).toBe('PUT');
    await editBGate.promise;
    peers = peers.map(p => (p.id === 'peer-b' ? { ...p, endpoint: '192.0.2.92' } : p));
    await route.fulfill({ json: { peer: peers[1], updated: true } });
  });

  await page.route(`**${peerApi}/peer-a`, async route => {
    expect(route.request().method()).toBe('DELETE');
    revokeACalls += 1;
    if (revokeACalls === 1) {
      await revokeAErrorGate.promise;
      await route.fulfill({
        status: 502,
        json: {
          code: 'ENDPOINT_UNREACHABLE',
          server: 'Media server',
          step: 'revoke_peer',
          message: 'Stale revoke error for Media server.',
          action: 'Retry revocation.',
        },
      });
      return;
    }
    await revokeAGate.promise;
    peers = peers.filter(p => p.id !== 'peer-a');
    await route.fulfill({
      json: { revoked: true, notice_delivered: true, link_id: 'peer-a', name: 'Media server' },
    });
  });

  await page.route(`**${peerApi}/peer-b`, async route => {
    expect(route.request().method()).toBe('DELETE');
    await revokeBGate.promise;
    peers = peers.filter(p => p.id !== 'peer-b');
    await route.fulfill({
      json: { revoked: true, notice_delivered: true, link_id: 'peer-b', name: 'Backup server' },
    });
  });

  await page.goto('/?tab=cluster');
  await expect(page.getByText('Media server', { exact: true })).toBeVisible();
  await expect(page.getByText('Backup server', { exact: true })).toBeVisible();

  // EditEndpointModal: dismiss peer-a via Escape while busy, switch to peer-b, submit peer-b.
  await page.getByRole('button', { name: 'Edit endpoint for Media server' }).click();
  const dialog = page.getByRole('dialog');
  const hostInput = dialog.locator('#cluster-edit-endpoint-host');
  await hostInput.fill('192.0.2.91');
  await dialog.getByRole('button', { name: 'Update endpoint' }).click();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Edit endpoint for Backup server' }).click();
  await expect(hostInput).toHaveValue('192.0.2.31');
  await expect(hostInput).toBeEnabled();
  await hostInput.fill('192.0.2.92');
  await dialog.getByRole('button', { name: 'Update endpoint' }).click();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();

  // Stale peer-a edit succeeds: peer list refreshes with peer-a's new endpoint while peer-b stays busy/open.
  const readsBeforeStaleEdit = listReads;
  editAGate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBeforeStaleEdit);
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await expect(hostInput).toHaveValue('192.0.2.92');
  await expect(page.getByText('192.0.2.91:51821 · 10.231.0.21')).toBeVisible();

  editBGate.resolve();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('192.0.2.92:51821 · 10.231.0.21')).toBeVisible();

  // Stale peer-a edit error dismissed via X does not leak into peer-b's reopened Edit dialog.
  await page.getByRole('button', { name: 'Edit endpoint for Media server' }).click();
  await hostInput.fill('192.0.2.99');
  await dialog.getByRole('button', { name: 'Update endpoint' }).click();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Edit endpoint for Backup server' }).click();
  const staleEditErr = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/endpoint` && resp.status() === 502,
  );
  editAErrorGate.resolve();
  await staleEditErr;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Stale edit error for Media server.')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  // RevokeLinkModal: stale peer-a error dismissed via Escape does not leak into peer-b's dialog.
  await page.getByRole('button', { name: 'Revoke link for Media server' }).click();
  await dialog.getByRole('button', { name: 'Revoke link' }).click();
  await expect(dialog.getByRole('button', { name: 'Revoke link' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Revoke link for Backup server' }).click();
  const staleRevokeErr = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a` && resp.status() === 502,
  );
  revokeAErrorGate.resolve();
  await staleRevokeErr;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Stale revoke error for Media server.')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  // RevokeLinkModal: dismiss peer-a via X while busy, switch to peer-b, confirm peer-b.
  await page.getByRole('button', { name: 'Revoke link for Media server' }).click();
  await dialog.getByRole('button', { name: 'Revoke link' }).click();
  await expect(dialog.getByRole('button', { name: 'Revoke link' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await page.getByRole('button', { name: 'Revoke link for Backup server' }).click();
  const revokeSubmit = dialog.getByRole('button', { name: 'Revoke link' });
  await expect(revokeSubmit).toBeEnabled();
  await revokeSubmit.click();
  await expect(revokeSubmit).toBeDisabled();

  // Stale peer-a revoke succeeds: Media server disappears via refresh, while Backup server modal stays open/busy.
  const readsBeforeStaleRevoke = listReads;
  revokeAGate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBeforeStaleRevoke);
  await expect(dialog).toBeVisible();
  await expect(revokeSubmit).toBeDisabled();
  await expect(page.getByText('Media server', { exact: true })).toHaveCount(0);

  revokeBGate.resolve();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Backup server', { exact: true })).toHaveCount(0);
});

test('peer row preserves keyboard focus and updates live data across 10s health polls', async ({ page }) => {
  await page.clock.install();
  const peer = makePeer('peer-a', 'Media server', '192.0.2.21', {
    rtt_ms: 8.0,
    high_latency: false,
    state: 'active',
    last_error: null,
  });
  let listReads = 0;
  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      peers: [{ ...peer }],
    };
  });

  await page.goto('/?tab=cluster');
  await expect(page.getByText('8.0 ms', { exact: true })).toBeVisible();
  await expect(page.getByText('192.0.2.21:51821 · 10.231.0.21')).toBeVisible();

  const editButton = page.getByRole('button', { name: 'Edit endpoint for Media server' });
  await editButton.focus();
  await expect(editButton).toBeFocused();

  // Trigger a normal 10s health poll with updated live fields for the same keyed peer.
  peer.rtt_ms = 145.5;
  peer.high_latency = true;
  peer.endpoint = '192.0.2.44';
  peer.state = 'down';
  peer.last_error = 'WireGuard handshake stale';
  const readsBefore = listReads;
  await page.clock.fastForward('00:11');
  await expect.poll(() => listReads).toBeGreaterThan(readsBefore);

  // Live fields updated in place without dropping focus on the row control.
  const rtt = page.getByRole('definition').filter({ hasText: 'High latency' });
  await expect(rtt).toContainText('145.5 ms');
  await expect(page.getByText('High latency (above 120 ms threshold)')).toBeVisible();
  await expect(page.getByText('192.0.2.44:51821 · 10.231.0.21')).toBeVisible();
  await expect(page.getByText('Link down').first()).toBeVisible();
  await expect(page.getByText('WireGuard handshake stale')).toBeVisible();
  await expect(editButton).toBeFocused();

  // Activating the focused row control uses the live updated peer data, not initial snapshot values.
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('#cluster-edit-endpoint-host')).toHaveValue('192.0.2.44');
});

function makeAccessMap(level: 'none' | 'read' | 'write' = 'none', overrides: Record<string, 'none' | 'read' | 'write'> = {}) {
  return {
    services: level,
    marketplace: level,
    settings: level,
    files: level,
    users: level,
    network: level,
    updates: level,
    transcoding: level,
    ...overrides,
  };
}

function makeGrantSummary(
  id: string,
  access: Record<string, 'none' | 'read' | 'write'>,
  createdBy = 'alice',
) {
  return {
    id,
    run_as_user_id: 42,
    access,
    created_by: createdBy,
    created_at: '2026-11-23T12:00:00Z',
  };
}

test('grant editor enforces link gating, directional wording, presets, contracts, keyboard flow, and no credential inputs', async ({ page }) => {
  const outboundGrant = makeGrantSummary('grant-out-1', makeAccessMap('read'), 'remote-admin');
  let inboundGrant: ReturnType<typeof makeGrantSummary> | null = null;
  let savedPayload: unknown = null;
  let revokeCalls = 0;
  let offerCalls = 0;
  let offerBody: string | null = 'unset';
  const offlineGrant = makeGrantSummary('grant-down-in', makeAccessMap('none', { services: 'read' }));

  const peers = [
    makePeer('peer-active', 'Media server', '192.0.2.21', {
      state: 'active',
      compatibility: 'compatible',
      grants: { inbound: null, outbound: outboundGrant },
    }),
    makePeer('peer-pending', 'Pending node', '192.0.2.22', {
      state: 'pending',
      pending_attempt_id: 'att-pending',
      pending_expires_at: Math.floor(Date.now() / 1000) + 600,
    }),
    makePeer('peer-revoked', 'Revoked node', '192.0.2.23', {
      state: 'revoked',
      last_error: 'Link revoked by Revoked node',
    }),
    makePeer('peer-incompat', 'Legacy node', '192.0.2.24', {
      state: 'active',
      compatibility: 'incompatible',
    }),
    makePeer('peer-link-only', 'Link-only node', '192.0.2.27', {
      state: 'active',
      compatibility: 'limited',
      missing_capabilities: ['grants'],
    }),
    makePeer('peer-down-empty', 'Offline empty', '192.0.2.25', {
      state: 'down',
      grants: { inbound: null, outbound: null },
    }),
    makePeer('peer-down-granted', 'Offline granted', '192.0.2.26', {
      state: 'down',
      compatibility: 'limited',
      missing_capabilities: ['grants'],
      grants: { inbound: offlineGrant, outbound: null },
    }),
  ];

  await mountCluster(page, () => ({
    ...peerList(),
    peers: peers.map(p => (p.id === 'peer-active'
      ? { ...p, grants: { inbound: inboundGrant, outbound: outboundGrant } }
      : { ...p })),
  }));

  await page.route(`**${peerApi}/peer-active/grant`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({ json: { inbound: inboundGrant, outbound: outboundGrant } });
      return;
    }
    if (method === 'PUT') {
      savedPayload = route.request().postDataJSON();
      const body = savedPayload as { access: Record<string, 'none' | 'read' | 'write'> };
      inboundGrant = makeGrantSummary('grant-in-1', body.access, 'admin');
      await route.fulfill({ json: { inbound: inboundGrant, outbound: outboundGrant } });
      return;
    }
    if (method === 'DELETE') {
      revokeCalls += 1;
      inboundGrant = null;
      await route.fulfill({ json: { inbound: null, outbound: outboundGrant } });
      return;
    }
    throw new Error(`Unexpected method on /grant: ${method}`);
  });

  await page.route(`**${peerApi}/peer-down-granted/grant`, route => {
    expect(route.request().method()).toBe('GET');
    return route.fulfill({ json: { inbound: offlineGrant, outbound: null } });
  });

  await page.route(`**${peerApi}/peer-active/grant-offer`, async route => {
    expect(route.request().method()).toBe('POST');
    offerCalls += 1;
    offerBody = route.request().postData();
    await route.fulfill({ json: { sent: true } });
  });

  await page.goto('/?tab=cluster');

  // Limit controls to usable, completed links (and down links that already carry a grant).
  const grantsTrigger = page.getByRole('button', { name: 'Manage access grants for Media server' });
  await expect(grantsTrigger).toBeVisible();
  await expect(page.getByRole('button', { name: 'Manage access grants for Offline granted' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Manage access grants for Pending node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage access grants for Revoked node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage access grants for Legacy node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage access grants for Link-only node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage access grants for Offline empty' })).toHaveCount(0);

  // Open via keyboard and confirm initial focus lands on the primary editor preset once loaded.
  await grantsTrigger.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: 'Access grants for Media server' });
  await expect(dialog).toBeVisible();
  const readOnlyPreset = dialog.locator('#cluster-grant-preset-ro');
  const readWritePreset = dialog.locator('#cluster-grant-preset-rw');
  await expect(readOnlyPreset).toBeFocused();

  // Absence of credential/secret inputs.
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  await expect(dialog.locator('input, textarea')).toHaveCount(0);
  await expect(dialog.locator('select')).toHaveCount(8);

  // Explicit directional wording for inbound (editable) vs outbound (read-only).
  await expect(dialog.getByRole('heading', { name: 'Access this server grants to Media server' })).toBeVisible();
  await expect(dialog.getByText('Editable here', { exact: true })).toBeVisible();
  await expect(dialog.getByRole('heading', { name: 'Access Media server granted to this server' })).toBeVisible();
  await expect(dialog.getByText('Read-only here', { exact: true })).toBeVisible();
  await expect(dialog.getByText(/Only an admin on Media server can create, edit, or revoke this direction/i)).toBeVisible();
  const outboundSection = dialog.locator('section[aria-labelledby="cluster-grant-outbound-heading"]');
  await expect(outboundSection.locator('select')).toHaveCount(0);
  await expect(outboundSection.getByText('Read-only (everything)')).toBeVisible();

  // Presets fill all eight fields without auto-submitting (verify keyboard Tab + Enter flow too).
  const areas = ['services', 'marketplace', 'settings', 'files', 'users', 'network', 'updates', 'transcoding'];
  await page.keyboard.press('Enter');
  await expect(readOnlyPreset).toHaveAttribute('aria-pressed', 'true');
  for (const area of areas) {
    await expect(dialog.locator(`#cluster-grant-area-${area}`)).toHaveValue('read');
  }
  await page.keyboard.press('Tab');
  await expect(readWritePreset).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(readWritePreset).toHaveAttribute('aria-pressed', 'true');
  for (const area of areas) {
    await expect(dialog.locator(`#cluster-grant-area-${area}`)).toHaveValue('write');
  }
  await page.keyboard.press('Tab');
  await expect(dialog.locator('#cluster-grant-area-services')).toBeFocused();

  // Custom area tweaks clear preset pressed state and save via PUT /grant.
  await dialog.locator('#cluster-grant-area-services').selectOption('read');
  await dialog.locator('#cluster-grant-area-users').selectOption('none');
  await expect(readWritePreset).toHaveAttribute('aria-pressed', 'false');
  await dialog.locator('#cluster-grant-save').click();

  await expect(dialog.getByText('Saved access grant for Media server on this server.')).toBeVisible();
  expect(savedPayload).toEqual({
    access: makeAccessMap('write', { services: 'read', users: 'none' }),
  });
  await expect(dialog.locator('#cluster-grant-save')).toBeFocused();
  await expect(dialog.getByText(/Revoking removes Media server's access to this server\. Both servers can still check the WireGuard link/i)).toBeVisible();

  // Two-way informational offer sends POST /grant-offer with no body and states no auto-grant.
  await dialog.locator('#cluster-grant-offer').click();
  await expect(dialog.getByText(/No access was granted automatically; an admin on Media server must decide/i)).toBeVisible();
  expect(offerCalls).toBe(1);
  expect(offerBody).toBeNull();
  await expect(dialog.locator('#cluster-grant-offer')).toBeFocused();

  // Revoke confirmation keeps keyboard focus, lets admin cancel, and revokes only inbound.
  await dialog.locator('#cluster-grant-revoke-open').click();
  await expect(dialog.locator('#cluster-grant-revoke-keep')).toBeFocused();
  await dialog.locator('#cluster-grant-revoke-keep').click();
  await expect(dialog.locator('#cluster-grant-revoke-open')).toBeFocused();
  expect(revokeCalls).toBe(0);

  await dialog.locator('#cluster-grant-revoke-open').click();
  await dialog.locator('#cluster-grant-revoke-confirm').click();
  await expect(dialog.getByText("Revoked Media server's access to this server. The WireGuard link stays configured.")).toBeVisible();
  expect(revokeCalls).toBe(1);
  await expect(readOnlyPreset).toBeFocused();
  await expect(dialog.locator('#cluster-grant-revoke-open')).toHaveCount(0);
  // Outbound grant remains unchanged after inbound revocation.
  await expect(outboundSection.getByText('Read-only (everything)')).toBeVisible();
  for (const area of areas) {
    await expect(dialog.locator(`#cluster-grant-area-${area}`)).toHaveValue('none');
  }

  // Escape dismisses modal and restores keyboard focus to the triggering peer row control.
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(grantsTrigger).toBeFocused();

  // A link-only peer cannot accept new credentials. Its existing local grant can still be revoked.
  await page.getByRole('button', { name: 'Manage access grants for Offline granted' }).click();
  const offlineDialog = page.getByRole('dialog', { name: 'Access grants for Offline granted' });
  await expect(offlineDialog.getByText(/Update Offline granted to use missing capabilities/)).toBeVisible();
  await expect(offlineDialog.locator('#cluster-grant-save')).toBeDisabled();
  await expect(offlineDialog.locator('#cluster-grant-offer')).toBeDisabled();
  await expect(offlineDialog.locator('#cluster-grant-revoke-open')).toBeFocused();
});

test('grant editor retains form draft on typed PeerError and blocks all-none save locally', async ({ page }) => {
  let putCalls = 0;
  let inboundGrant: ReturnType<typeof makeGrantSummary> | null = null;
  const peer = makePeer('peer-a', 'Media server', '192.0.2.21');

  await mountCluster(page, () => ({
    ...peerList(),
    peers: [{ ...peer, grants: { inbound: inboundGrant, outbound: null } }],
  }));

  await page.route(`**${peerApi}/peer-a/grant`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({ json: { inbound: inboundGrant, outbound: null } });
      return;
    }
    if (method === 'PUT') {
      putCalls += 1;
      if (putCalls === 1) {
        await route.fulfill({
          status: 502,
          headers: { 'X-Request-ID': 'req-grant-hdr-ignored' },
          json: {
            code: 'LINK_DOWN',
            server: 'Media server',
            step: 'deliver_grant_token',
            message: 'Could not deliver grant token to Media server.',
            action: 'Confirm UDP 51821 connectivity and retry saving.',
            request_id: 'req-grant-body-502',
          },
        });
        return;
      }
      const body = route.request().postDataJSON() as { access: Record<string, 'none' | 'read' | 'write'> };
      inboundGrant = makeGrantSummary('grant-in-retry', body.access, 'admin');
      await route.fulfill({ json: { inbound: inboundGrant, outbound: null } });
      return;
    }
    throw new Error(`Unexpected method: ${method}`);
  });

  await page.goto('/?tab=cluster');
  await page.getByRole('button', { name: 'Manage access grants for Media server' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('#cluster-grant-preset-ro')).toBeVisible();

  // Saving with all 8 areas set to none shows local validation without firing PUT.
  await dialog.locator('#cluster-grant-save').click();
  await expect(dialog.getByText('Select read or write access for at least one area before saving.')).toBeVisible();
  expect(putCalls).toBe(0);

  // Customize areas and trigger typed backend error; every edited field stays intact.
  await dialog.locator('#cluster-grant-area-services').selectOption('read');
  await dialog.locator('#cluster-grant-area-files').selectOption('write');
  await dialog.locator('#cluster-grant-area-transcoding').selectOption('write');
  await dialog.locator('#cluster-grant-save').click();

  await expect(dialog.getByText('Could not deliver grant token to Media server.')).toBeVisible();
  await expect(dialog.getByText('Confirm UDP 51821 connectivity and retry saving.')).toBeVisible();
  await expect(dialog.getByTestId('peer-error-request-id')).toHaveText('Request ID: req-grant-body-502');
  await expect(dialog.locator('#cluster-grant-area-services')).toHaveValue('read');
  await expect(dialog.locator('#cluster-grant-area-files')).toHaveValue('write');
  await expect(dialog.locator('#cluster-grant-area-transcoding')).toHaveValue('write');
  await expect(dialog.locator('#cluster-grant-area-users')).toHaveValue('none');

  // Retry succeeds using the preserved draft without re-entering selections.
  await dialog.locator('#cluster-grant-save').click();
  await expect(dialog.getByText('Saved access grant for Media server on this server.')).toBeVisible();
  expect(putCalls).toBe(2);
  const savedGrant = inboundGrant as ReturnType<typeof makeGrantSummary> | null;
  expect(savedGrant?.access).toEqual(makeAccessMap('none', {
    services: 'read',
    files: 'write',
    transcoding: 'write',
  }));
});

async function mountGrantRace(page: Page, scenario: 'fetch' | 'save' | 'revoke') {
  let grantAIn: ReturnType<typeof makeGrantSummary> | null = makeGrantSummary(
    'g-a-initial',
    makeAccessMap('write'),
    'admin',
  );
  let grantBIn: ReturnType<typeof makeGrantSummary> | null = makeGrantSummary(
    'g-b-initial',
    makeAccessMap('none', { services: 'read', files: scenario === 'revoke' ? 'write' : 'none' }),
    'admin',
  );
  let listReads = 0;

  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      peers: [
        makePeer('peer-a', 'Media server', '192.0.2.21', {
          grants: { inbound: grantAIn, outbound: null },
        }),
        makePeer('peer-b', 'Backup server', '192.0.2.31', {
          grants: { inbound: grantBIn, outbound: null },
        }),
      ],
    };
  });

  const getA1Gate = deferred();
  const getA2ErrorGate = deferred();
  const getB1Gate = deferred();
  const putAGate = deferred();
  const putAErrorGate = deferred();
  const putBGate = deferred();
  const delAGate = deferred();
  const offerBGate = deferred();
  const offerAGate = deferred();
  let getACalls = 0;
  let getBCalls = 0;
  let putACalls = 0;

  await page.route(`**${peerApi}/peer-a/grant`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      getACalls += 1;
      if (scenario === 'fetch' && getACalls === 1) {
        await getA1Gate.promise;
        await route.fulfill({ json: { inbound: grantAIn, outbound: null } });
        return;
      }
      if (scenario === 'fetch' && getACalls === 2) {
        await getA2ErrorGate.promise;
        await route.fulfill({
          status: 502,
          json: {
            code: 'LINK_DOWN',
            server: 'Media server',
            step: 'get_peer_grant',
            message: 'Stale GET error for Media server.',
            action: 'Retry loading.',
          },
        });
        return;
      }
      await route.fulfill({ json: { inbound: grantAIn, outbound: null } });
      return;
    }
    if (method === 'PUT') {
      putACalls += 1;
      if (putACalls === 1) {
        await putAGate.promise;
        const body = route.request().postDataJSON() as { access: Record<string, 'none' | 'read' | 'write'> };
        grantAIn = makeGrantSummary('g-a-saved', body.access, 'admin');
        await route.fulfill({ json: { inbound: grantAIn, outbound: null } });
        return;
      }
      await putAErrorGate.promise;
      await route.fulfill({
        status: 502,
        json: {
          code: 'LINK_DOWN',
          server: 'Media server',
          step: 'deliver_grant_token',
          message: 'Stale PUT error for Media server.',
          action: 'Check tunnel connectivity.',
        },
      });
      return;
    }
    if (method === 'DELETE') {
      await delAGate.promise;
      grantAIn = null;
      await route.fulfill({ json: { inbound: null, outbound: null } });
      return;
    }
    throw new Error(`Unexpected method on peer-a/grant: ${method}`);
  });

  await page.route(`**${peerApi}/peer-b/grant`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      getBCalls += 1;
      if (scenario === 'fetch' && getBCalls === 1) {
        await getB1Gate.promise;
      }
      await route.fulfill({ json: { inbound: grantBIn, outbound: null } });
      return;
    }
    if (method === 'PUT') {
      await putBGate.promise;
      const body = route.request().postDataJSON() as { access: Record<string, 'none' | 'read' | 'write'> };
      grantBIn = makeGrantSummary('g-b-saved', body.access, 'admin');
      await route.fulfill({ json: { inbound: grantBIn, outbound: null } });
      return;
    }
    throw new Error(`Unexpected method on peer-b/grant: ${method}`);
  });

  await page.route(`**${peerApi}/peer-a/grant-offer`, async route => {
    expect(route.request().method()).toBe('POST');
    await offerAGate.promise;
    await route.fulfill({ json: { sent: true } });
  });

  await page.route(`**${peerApi}/peer-b/grant-offer`, async route => {
    expect(route.request().method()).toBe('POST');
    await offerBGate.promise;
    await route.fulfill({ json: { sent: true } });
  });

  await page.goto('/?tab=cluster');
  const openA = page.getByRole('button', { name: 'Manage access grants for Media server' });
  const openB = page.getByRole('button', { name: 'Manage access grants for Backup server' });
  const dialog = page.getByRole('dialog');

  return {
    openA, openB, dialog, listReads: () => listReads,
    getA1Gate, getA2ErrorGate, getB1Gate, putAGate, putAErrorGate, putBGate, delAGate, offerBGate, offerAGate,
  };
}

test('grant editor fences stale fetches across close and peer switch', async ({ page }) => {
  test.setTimeout(60_000);
  const { openA, openB, dialog, getA1Gate, getA2ErrorGate, getB1Gate } = await mountGrantRace(page, 'fetch');

  // Stale GET success for Media server must never populate Backup server while Backup is loading.
  await openA.click();
  await expect(dialog.getByText('Loading access grants…')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await expect(dialog.getByText('Loading access grants…')).toBeVisible();
  const staleGetAResp = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/grant` && resp.request().method() === 'GET',
  );
  getA1Gate.resolve();
  await staleGetAResp;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Loading access grants…')).toBeVisible();
  await expect(dialog.locator('#cluster-grant-area-services')).toHaveCount(0);

  getB1Gate.resolve();
  await expect(dialog.locator('#cluster-grant-area-services')).toHaveValue('read');
  await expect(dialog.locator('#cluster-grant-area-files')).toHaveValue('none');
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  // Stale GET error for Media server dismissed via X never leaks into Backup server.
  await openA.click();
  await expect(dialog.getByText('Loading access grants…')).toBeVisible();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await expect(dialog.locator('#cluster-grant-area-services')).toHaveValue('read');
  const staleGetAErrResp = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/grant` && resp.status() === 502,
  );
  getA2ErrorGate.resolve();
  await staleGetAErrResp;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Stale GET error for Media server.')).toHaveCount(0);
  await expect(dialog.locator('#cluster-grant-area-services')).toHaveValue('read');
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
});

test('grant editor fences stale saves across close and peer switch', async ({ page }) => {
  test.setTimeout(60_000);
  const { openA, openB, dialog, listReads, putAGate, putAErrorGate, putBGate } = await mountGrantRace(page, 'save');

  // Stale PUT success for Media server refreshes peer list without unlocking or clobbering Backup server's PUT.
  await openA.click();
  await expect(dialog.locator('#cluster-grant-area-services')).toHaveValue('write');
  await dialog.locator('#cluster-grant-preset-ro').click();
  await dialog.locator('#cluster-grant-save').click();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await dialog.locator('#cluster-grant-area-files').selectOption('write');
  await dialog.locator('#cluster-grant-save').click();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();

  const readsBeforeStalePut = listReads();
  putAGate.resolve();
  await expect.poll(listReads).toBeGreaterThan(readsBeforeStalePut);
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await expect(dialog.locator('#cluster-grant-area-files')).toHaveValue('write');
  await expect(dialog.getByText('Saved access grant for Media server on this server.')).toHaveCount(0);

  putBGate.resolve();
  await expect(dialog.getByText('Saved access grant for Backup server on this server.')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  // Stale PUT error for Media server dismissed via X never leaks into Backup server.
  await openA.click();
  await dialog.locator('#cluster-grant-area-updates').selectOption('write');
  await dialog.locator('#cluster-grant-save').click();
  await expect(dialog.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await expect(dialog.locator('#cluster-grant-area-files')).toHaveValue('write');
  const stalePutAErrResp = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/grant`
      && resp.request().method() === 'PUT'
      && resp.status() === 502,
  );
  putAErrorGate.resolve();
  await stalePutAErrResp;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Stale PUT error for Media server.')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
});

test('grant editor fences stale revocations and offers across close and peer switch', async ({ page }) => {
  test.setTimeout(60_000);
  const { openA, openB, dialog, listReads, delAGate, offerBGate, offerAGate } = await mountGrantRace(page, 'revoke');

  // Stale DELETE for Media server never wipes Backup server's inbound grant or unlocks Backup's offer call.
  await openA.click();
  await dialog.locator('#cluster-grant-revoke-open').click();
  await dialog.locator('#cluster-grant-revoke-confirm').click();
  await expect(dialog.getByRole('button', { name: 'Revoking…' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await dialog.locator('#cluster-grant-offer').click();
  await expect(dialog.getByRole('button', { name: 'Sending offer…' })).toBeDisabled();

  const readsBeforeStaleDelete = listReads();
  delAGate.resolve();
  await expect.poll(listReads).toBeGreaterThan(readsBeforeStaleDelete);
  await expect(dialog.getByRole('button', { name: 'Sending offer…' })).toBeDisabled();
  await expect(dialog.locator('#cluster-grant-area-files')).toHaveValue('write');
  await expect(dialog.getByText("Revoked Media server's access to this server. The WireGuard link stays configured.")).toHaveCount(0);

  offerBGate.resolve();
  await expect(dialog.getByText(/Informational notice sent to Backup server/i)).toBeVisible();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  // Stale POST /grant-offer for Media server never leaks confirmation banner into Backup server.
  await openA.click();
  await dialog.locator('#cluster-grant-offer').click();
  await expect(dialog.getByRole('button', { name: 'Sending offer…' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await expect(dialog.locator('#cluster-grant-area-files')).toHaveValue('write');
  const staleOfferResp = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/grant-offer`,
  );
  offerAGate.resolve();
  await staleOfferResp;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText(/Informational notice sent to Media server/i)).toHaveCount(0);
});

function makePeerExport(
  id: string,
  linkId: string,
  path: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    id,
    link_id: linkId,
    path,
    writable: false,
    squash_uid: null as number | null,
    squash_gid: null as number | null,
    created_at: '2026-11-24T00:10:00Z',
    ...overrides,
  };
}

function makePeerMount(
  id: string,
  linkId: string,
  remotePath: string,
  mountPath: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    id,
    link_id: linkId,
    remote_path: remotePath,
    mount_path: mountPath,
    unit_name: `mnt-af\\x2dpeers-${linkId}-${id}.mount`,
    writable: false,
    purpose: 'media',
    state: 'mounted',
    last_error: null as string | null,
    ...overrides,
  };
}

async function mountStorageControls(
  page: Page,
  existing: {
    exports?: ReturnType<typeof makePeerExport>[];
    mounts?: ReturnType<typeof makePeerMount>[];
  } = {},
) {
  const activeExports = existing.exports ?? [];
  const activeMounts = existing.mounts ?? [];
  const remoteCatalog = [
    makePeerExport('rem-ro', 'peer-active', '/srv/media/movies', { writable: false }),
    makePeerExport('rem-rw', 'peer-active', '/srv/media/incoming', { writable: true }),
  ];
  const p6StoredExport = makePeerExport('p6-exp-1', 'peer-p6-stored', '/srv/legacy/shows');
  const p6StoredMount = makePeerMount(
    'p6-mnt-1',
    'peer-p6-stored',
    '/srv/remote/shows',
    '/mnt/af-peers/p6-stored/shows',
    { state: 'mounted' },
  );
  const downStoredMount = makePeerMount(
    'down-mnt-1',
    'peer-down-stored',
    '/srv/remote/archive',
    '/mnt/af-peers/offline-stored/archive',
    { state: 'stopped_link_down', last_error: 'WireGuard peer handshake expired' },
  );

  const exportPostPayloads: unknown[] = [];
  const exportDeletePayloads: unknown[] = [];
  const mountPostPayloads: unknown[] = [];
  const mountDeletePayloads: unknown[] = [];

  const peers = [
    makePeer('peer-active', 'Media server', '192.0.2.21', {
      state: 'active',
      capabilities: ['links', 'grants', 'storage'],
      compatibility: 'compatible',
    }),
    makePeer('peer-pending', 'Pending node', '192.0.2.22', {
      state: 'pending',
      pending_attempt_id: 'att-pending',
      pending_expires_at: Math.floor(Date.now() / 1000) + 600,
    }),
    makePeer('peer-revoked', 'Revoked node', '192.0.2.23', {
      state: 'revoked',
      last_error: 'Link revoked by Revoked node',
    }),
    makePeer('peer-incompat', 'Legacy node', '192.0.2.24', {
      state: 'active',
      compatibility: 'incompatible',
    }),
    makePeer('peer-no-storage', 'P6 node', '192.0.2.25', {
      state: 'active',
      capabilities: ['links', 'grants'],
      compatibility: 'limited',
      missing_capabilities: ['storage'],
    }),
    makePeer('peer-p6-stored', 'P6 stored node', '192.0.2.26', {
      state: 'active',
      capabilities: ['links', 'grants'],
      compatibility: 'limited',
      missing_capabilities: ['storage'],
      exports: [p6StoredExport],
      mounts: [p6StoredMount],
    }),
    makePeer('peer-down-empty', 'Offline empty', '192.0.2.27', {
      state: 'down',
    }),
    makePeer('peer-down-stored', 'Offline stored', '192.0.2.28', {
      state: 'down',
      mounts: [downStoredMount],
    }),
  ];

  await mountCluster(page, () => ({
    ...peerList(),
    capabilities: ['links', 'grants', 'storage'],
    rtt_warn_ms: 25,
    peers: peers.map(p => (p.id === 'peer-active'
      ? { ...p, exports: [...activeExports], mounts: [...activeMounts] }
      : { ...p })),
  }));

  await page.route('**/api/v1/auth/fs?*', async route => {
    const dir = new URL(route.request().url()).searchParams.get('path') ?? '/srv';
    if (dir === '/srv') {
      await route.fulfill({ json: { current_path: '/srv', parent_path: '', directories: ['media'] } });
      return;
    }
    if (dir === '/srv/media') {
      await route.fulfill({ json: { current_path: '/srv/media', parent_path: '/srv', directories: ['movies', 'uploads'] } });
      return;
    }
    await route.fulfill({ json: { current_path: dir, parent_path: '/srv/media', directories: [] } });
  });

  await page.route(`**${peerApi}/peer-active/exports`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({ json: { exports: [...activeExports] } });
      return;
    }
    if (method === 'POST') {
      const body = route.request().postDataJSON() as { path: string; writable: boolean };
      exportPostPayloads.push(body);
      const created = makePeerExport('exp-created-1', 'peer-active', body.path, {
        writable: body.writable,
        squash_uid: body.writable ? 1000 : null,
        squash_gid: body.writable ? 1000 : null,
      });
      activeExports.push(created);
      await route.fulfill({ status: 201, json: { export: created } });
      return;
    }
    if (method === 'DELETE') {
      const body = route.request().postDataJSON() as { export_id: string };
      exportDeletePayloads.push(body);
      const idx = activeExports.findIndex(e => e.id === body.export_id);
      if (idx >= 0) activeExports.splice(idx, 1);
      await route.fulfill({ status: 204, body: '' });
      return;
    }
    throw new Error(`Unexpected method on /exports: ${method}`);
  });

  await page.route(`**${peerApi}/peer-active/mounts`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({ json: { mounts: [...activeMounts], available_exports: remoteCatalog } });
      return;
    }
    if (method === 'POST') {
      const body = route.request().postDataJSON() as { export_id: string; writable: boolean };
      mountPostPayloads.push(body);
      const chosen = remoteCatalog.find(e => e.id === body.export_id)!;
      const slug = chosen.path.split('/').at(-1) ?? 'share';
      const created = makePeerMount(
        `mnt-${chosen.id}`,
        'peer-active',
        chosen.path,
        `/mnt/af-peers/media-server/${slug}`,
        { writable: body.writable, state: 'mounted' },
      );
      activeMounts.push(created);
      await route.fulfill({ status: 201, json: { mount: created } });
      return;
    }
    if (method === 'DELETE') {
      const body = route.request().postDataJSON() as { mount_id: string };
      mountDeletePayloads.push(body);
      const idx = activeMounts.findIndex(m => m.id === body.mount_id);
      if (idx >= 0) activeMounts.splice(idx, 1);
      await route.fulfill({ status: 204, body: '' });
      return;
    }
    throw new Error(`Unexpected method on /mounts: ${method}`);
  });

  await page.route(`**${peerApi}/peer-p6-stored/exports`, route =>
    route.fulfill({ json: { exports: [p6StoredExport] } }));
  await page.route(`**${peerApi}/peer-p6-stored/mounts`, route =>
    route.fulfill({ json: { mounts: [p6StoredMount], available_exports: [] } }));

  await page.goto('/?tab=cluster');

  const storageTrigger = page.getByRole('button', { name: 'Manage media storage for Media server' });
  const dialog = page.getByRole('dialog', { name: 'Media storage for Media server' });
  return { storageTrigger, dialog, exportPostPayloads, exportDeletePayloads, mountPostPayloads, mountDeletePayloads };
}

test('storage controls enforce link capability gates and show media safety guidance', async ({ page }) => {
  const { storageTrigger, dialog } = await mountStorageControls(page);
  await expect(storageTrigger).toBeVisible();
  await expect(page.getByRole('button', { name: 'Manage media storage for P6 stored node' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Manage media storage for Offline stored' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Manage media storage for Pending node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage media storage for Revoked node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage media storage for Legacy node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage media storage for P6 node' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Manage media storage for Offline empty' })).toHaveCount(0);

  // Open via keyboard and confirm initial focus + media safety guidance.
  await storageTrigger.focus();
  await page.keyboard.press('Enter');
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('#cluster-storage-export-path')).toBeFocused();
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);

  const safety = dialog.getByTestId('cluster-storage-media-safety');
  await expect(safety).toContainText('Jellyfin 12.4');
  await expect(safety).toContainText('Plex');
  await expect(safety).toContainText('Emby');
  await expect(safety).toContainText('interior subfolder');

  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(storageTrigger).toBeFocused();

  // Older peers can manage existing storage even when creation is unavailable.
  await page.getByRole('button', { name: 'Manage media storage for P6 stored node' }).click();
  const p6Dialog = page.getByRole('dialog', { name: 'Media storage for P6 stored node' });
  await expect(p6Dialog.getByTestId('cluster-storage-compat-warning')).toContainText('storage');
  await expect(p6Dialog.locator('#cluster-storage-export-submit')).toBeDisabled();
  await expect(p6Dialog.locator('#cluster-storage-export-remove-p6-exp-1')).toBeEnabled();
  await expect(p6Dialog.locator('#cluster-storage-mount-remove-p6-mnt-1')).toBeEnabled();
});

test('storage folder picker and explicit write opt-in create an export', async ({ page }) => {
  const { storageTrigger, dialog, exportPostPayloads } = await mountStorageControls(page);
  await storageTrigger.click();

  // Local folder browser picks a folder without auto-submitting; write opt-in defaults false and shows warning when checked.
  await dialog.locator('#cluster-storage-browse-toggle').click();
  const browser = dialog.getByTestId('cluster-storage-folder-browser');
  await expect(browser).toBeVisible();
  await browser.getByRole('button', { name: 'media', exact: true }).click();
  await browser.getByRole('button', { name: 'uploads', exact: true }).click();
  await dialog.locator('#cluster-storage-browser-use').click();
  await expect(dialog.locator('#cluster-storage-export-path')).toHaveValue('/srv/media/uploads');
  expect(exportPostPayloads).toHaveLength(0);

  const exportWriteToggle = dialog.locator('#cluster-storage-export-writable');
  await expect(exportWriteToggle).not.toBeChecked();
  await expect(dialog.getByTestId('cluster-export-write-warning')).toHaveCount(0);
  await exportWriteToggle.check();
  await expect(dialog.getByTestId('cluster-export-write-warning')).toBeVisible();

  await dialog.locator('#cluster-storage-export-submit').click();
  await expect(dialog.getByText('Exported /srv/media/uploads to Media server.')).toBeVisible();
  expect(exportPostPayloads).toEqual([{ path: '/srv/media/uploads', writable: true }]);
  await expect(dialog.locator('#cluster-storage-export-path')).toHaveValue('');
  await expect(exportWriteToggle).not.toBeChecked();
  await expect(dialog.getByText('Remote writes mapped to UID 1000, GID 1000')).toBeVisible();
});

test('storage export removal requires confirmation and preserves focus on cancel', async ({ page }) => {
  const { storageTrigger, dialog, exportDeletePayloads } = await mountStorageControls(page, {
    exports: [makePeerExport('exp-created-1', 'peer-active', '/srv/media/uploads')],
  });
  await storageTrigger.click();

  // Two-step export removal keeps focus and sends DELETE { export_id }.
  await dialog.locator('#cluster-storage-export-remove-exp-created-1').click();
  await expect(dialog.locator('#cluster-storage-export-keep-exp-created-1')).toBeFocused();
  await dialog.locator('#cluster-storage-export-keep-exp-created-1').click();
  await expect(dialog.locator('#cluster-storage-export-remove-exp-created-1')).toBeFocused();
  expect(exportDeletePayloads).toHaveLength(0);

  await dialog.locator('#cluster-storage-export-remove-exp-created-1').click();
  await dialog.locator('#cluster-storage-export-confirm-exp-created-1').click();
  await expect(dialog.getByText('Removed export /srv/media/uploads for Media server.')).toBeVisible();
  expect(exportDeletePayloads).toEqual([{ export_id: 'exp-created-1' }]);
});

test('storage uses catalog mount IDs, explicit write opt-in, and interior library paths', async ({ page }) => {
  const { storageTrigger, dialog, mountPostPayloads } = await mountStorageControls(page);
  await storageTrigger.click();

  // Remote export catalog: read-only export disables write opt-in; writable export shows warning and resets on switch.
  const mountSelect = dialog.locator('#cluster-storage-mount-export');
  const mountWriteToggle = dialog.locator('#cluster-storage-mount-writable');
  await expect(mountSelect).toHaveValue('rem-ro');
  await expect(mountWriteToggle).toBeDisabled();
  await expect(dialog.getByTestId('cluster-mount-readonly-hint')).toBeVisible();

  await mountSelect.selectOption('rem-rw');
  await expect(mountWriteToggle).toBeEnabled();
  await expect(mountWriteToggle).not.toBeChecked();
  await mountWriteToggle.check();
  await expect(dialog.getByTestId('cluster-mount-write-warning')).toBeVisible();

  await mountSelect.selectOption('rem-ro');
  await expect(mountWriteToggle).toBeDisabled();
  await expect(mountWriteToggle).not.toBeChecked();

  // Create mount sends ONLY { export_id, writable } (no remote path, host, or mount options).
  await dialog.locator('#cluster-storage-mount-submit').click();
  await expect(dialog.getByText('Mounted /srv/media/movies from Media server.')).toBeVisible();
  expect(mountPostPayloads).toEqual([{ export_id: 'rem-ro', writable: false }]);
  expect(Object.keys(mountPostPayloads[0] as Record<string, unknown>).sort()).toEqual(['export_id', 'writable']);

  // Only expose the interior library path (/library), never the bare mount root.
  const modalLibraryPath = dialog.getByTestId('storage-mount-library-path');
  await expect(modalLibraryPath).toHaveText('/mnt/af-peers/media-server/movies/library');
  const dialogText = await dialog.innerText();
  const mountPathsInDialog = dialogText.match(/\/mnt\/af-peers\/[^\s)·,]+/g) ?? [];
  expect(mountPathsInDialog.length).toBeGreaterThan(0);
  for (const pathMatch of mountPathsInDialog) {
    expect(pathMatch.endsWith('/library')).toBe(true);
  }
});

test('storage mount removal requires confirmation and preserves focus on cancel', async ({ page }) => {
  const { storageTrigger, dialog, mountDeletePayloads } = await mountStorageControls(page, {
    mounts: [makePeerMount('mnt-rem-ro', 'peer-active', '/srv/media/movies', '/mnt/af-peers/media-server/movies')],
  });
  await storageTrigger.click();

  // Two-step mount removal sends DELETE { mount_id }.
  await dialog.locator('#cluster-storage-mount-remove-mnt-rem-ro').click();
  await expect(dialog.locator('#cluster-storage-mount-keep-mnt-rem-ro')).toBeFocused();
  await dialog.locator('#cluster-storage-mount-keep-mnt-rem-ro').click();
  await expect(dialog.locator('#cluster-storage-mount-remove-mnt-rem-ro')).toBeFocused();
  expect(mountDeletePayloads).toHaveLength(0);

  await dialog.locator('#cluster-storage-mount-remove-mnt-rem-ro').click();
  await dialog.locator('#cluster-storage-mount-confirm-mnt-rem-ro').click();
  await expect(dialog.getByText('Removed mount for /srv/media/movies from Media server.')).toBeVisible();
  expect(mountDeletePayloads).toEqual([{ mount_id: 'mnt-rem-ro' }]);
});

test('storage keeps stored exports and mounts manageable when remote catalog is down and updates mount state and RTT warnings live', async ({ page }) => {
  await page.clock.install();
  const storedExports = [makePeerExport('exp-local-1', 'peer-a', '/srv/media/local-tv')];
  const storedMounts = [
    makePeerMount('mnt-1', 'peer-a', '/srv/media/movies', '/mnt/af-peers/media-server/movies', {
      state: 'mounted',
      last_error: null,
    }),
  ];
  const peer = makePeer('peer-a', 'Media server', '192.0.2.21', {
    state: 'active',
    capabilities: ['links', 'grants', 'storage'],
    rtt_ms: 6.4,
    high_latency: false,
  });
  let listReads = 0;
  let exportPostCalls = 0;
  let catalogRetryCount = 0;

  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      capabilities: ['links', 'grants', 'storage'],
      rtt_warn_ms: 25,
      peers: [{ ...peer, exports: [...storedExports], mounts: [...storedMounts] }],
    };
  });

  await page.route(`**${peerApi}/peer-a/exports`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({ json: { exports: [...storedExports] } });
      return;
    }
    if (method === 'POST') {
      exportPostCalls += 1;
      await route.fulfill({
        status: 400,
        json: {
          code: 'INVALID_REQUEST',
          server: 'local',
          step: 'create_export',
          message: 'Export path does not exist on disk.',
          action: 'Create the folder or pick an existing directory, then retry.',
        },
      });
      return;
    }
    if (method === 'DELETE') {
      const body = route.request().postDataJSON() as { export_id: string };
      const idx = storedExports.findIndex(e => e.id === body.export_id);
      if (idx >= 0) storedExports.splice(idx, 1);
      await route.fulfill({ status: 204, body: '' });
      return;
    }
    throw new Error(`Unexpected method on /exports: ${method}`);
  });

  await page.route(`**${peerApi}/peer-a/mounts`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      catalogRetryCount += 1;
      await route.fulfill({
        json: {
          mounts: [...storedMounts],
          available_exports: [],
          exports_error: {
            code: 'LINK_DOWN',
            server: 'Media server',
            step: 'list_remote_exports',
            message: 'Remote export catalog is unreachable.',
            action: 'Verify WireGuard connectivity on UDP 51821 and retry.',
            request_id: 'req-catalog-body-77',
          },
        },
      });
      return;
    }
    if (method === 'DELETE') {
      const body = route.request().postDataJSON() as { mount_id: string };
      const idx = storedMounts.findIndex(m => m.id === body.mount_id);
      if (idx >= 0) storedMounts.splice(idx, 1);
      await route.fulfill({ status: 204, body: '' });
      return;
    }
    throw new Error(`Unexpected method on /mounts: ${method}`);
  });

  await page.goto('/?tab=cluster');

  // Peer row initially shows live Mounted summary with interior library path only.
  const rowSummary = page.getByTestId('peer-storage-summary-peer-a');
  await expect(rowSummary).toBeVisible();
  await expect(rowSummary.getByText('Mounted', { exact: true })).toBeVisible();
  await expect(rowSummary.getByTestId('peer-mount-library-path')).toHaveText('/mnt/af-peers/media-server/movies/library');
  await expect(rowSummary.getByTestId('peer-storage-latency-warning')).toHaveCount(0);

  // Live 10s poll transitions peer to high latency + stopped mount (backend state "stopped" while link is down).
  peer.state = 'down';
  peer.rtt_ms = 68.5;
  peer.high_latency = true;
  storedMounts[0] = {
    ...storedMounts[0],
    state: 'stopped',
    last_error: 'Sentinel probe timed out twice',
  };
  const readsBefore = listReads;
  await page.clock.fastForward('00:11');
  await expect.poll(() => listReads).toBeGreaterThan(readsBefore);

  await expect(rowSummary.getByText('Stopped: link down', { exact: true })).toBeVisible();
  await expect(rowSummary.getByText('Sentinel probe timed out twice')).toBeVisible();
  await expect(rowSummary.getByTestId('peer-storage-latency-warning')).toContainText('68.5 ms');
  await expect(rowSummary.getByTestId('peer-storage-latency-warning')).toContainText('NFS');

  // Open Storage modal: remote catalog error displays typed recovery action while stored exports & mounts stay manageable.
  await page.getByRole('button', { name: 'Manage media storage for Media server' }).click();
  const dialog = page.getByRole('dialog', { name: 'Media storage for Media server' });
  await expect(dialog.getByTestId('cluster-storage-down-warning')).toBeVisible();
  await expect(dialog.getByTestId('cluster-storage-latency-warning')).toContainText('68.5 ms');
  await expect(dialog.getByTestId('cluster-storage-catalog-error')).toContainText('Remote export catalog is unreachable.');
  await expect(dialog.getByTestId('cluster-storage-catalog-error')).toContainText('Verify WireGuard connectivity on UDP 51821 and retry.');
  await expect(dialog.getByTestId('cluster-storage-catalog-error').getByTestId('peer-error-request-id')).toHaveText('Request ID: req-catalog-body-77');

  // Retrying remote catalog re-fetches /mounts without losing stored mounts.
  const retriesBefore = catalogRetryCount;
  await dialog.locator('#cluster-storage-retry-catalog').click();
  await expect.poll(() => catalogRetryCount).toBeGreaterThan(retriesBefore);
  await expect(dialog.getByTestId('cluster-storage-mounts-list')).toContainText('/srv/media/movies');

  // Typed PeerError on export create retains draft path & write checkbox so operator can correct and retry.
  await dialog.locator('#cluster-storage-export-path').fill('/srv/missing-folder');
  await dialog.locator('#cluster-storage-export-writable').check();
  await dialog.locator('#cluster-storage-export-submit').click();
  await expect(dialog.getByText('Export path does not exist on disk.')).toBeVisible();
  await expect(dialog.getByText('Create the folder or pick an existing directory, then retry.')).toBeVisible();
  await expect(dialog.locator('#cluster-storage-export-path')).toHaveValue('/srv/missing-folder');
  await expect(dialog.locator('#cluster-storage-export-writable')).toBeChecked();
  expect(exportPostCalls).toBe(1);

  // Stored local export and stored local mount remain removable even while remote catalog is down.
  await dialog.locator('#cluster-storage-export-remove-exp-local-1').click();
  await dialog.locator('#cluster-storage-export-confirm-exp-local-1').click();
  await expect(dialog.getByText('Removed export /srv/media/local-tv for Media server.')).toBeVisible();

  await dialog.locator('#cluster-storage-mount-remove-mnt-1').click();
  await dialog.locator('#cluster-storage-mount-confirm-mnt-1').click();
  await expect(dialog.getByText('Removed mount for /srv/media/movies from Media server.')).toBeVisible();
});

test('storage requests and local folder browsing stay same-origin local while managing a remote peer server', async ({ page }) => {
  const outboundGrant = makeGrantSummary('grant-out-b', makeAccessMap('write'), 'remote-admin');
  const peers = [
    makePeer('peer-a', 'Media server', '192.0.2.21', {
      state: 'active',
      capabilities: ['links', 'grants', 'storage'],
    }),
    makePeer('peer-b', 'Remote target', '192.0.2.31', {
      state: 'active',
      capabilities: ['links', 'grants', 'storage'],
      grants: { inbound: null, outbound: outboundGrant },
    }),
  ];
  const localHits: string[] = [];
  const leakedRemoteHits: string[] = [];

  await mountCluster(page, () => ({
    ...peerList(),
    capabilities: ['links', 'grants', 'storage'],
    peers: peers.map(p => ({ ...p })),
  }));

  await page.route('**/api/v1/peers/peer-b/**', async route => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname.includes('/admin/peers') || pathname.includes('/auth/fs')) {
      leakedRemoteHits.push(pathname);
    }
    await route.fulfill({ json: {} });
  });

  await page.route('**/api/v1/auth/fs?*', async route => {
    const url = new URL(route.request().url());
    localHits.push(`GET ${url.pathname}${url.search}`);
    await route.fulfill({ json: { current_path: '/srv', parent_path: '', directories: ['media'] } });
  });

  await page.route(`**${peerApi}/peer-a/exports`, async route => {
    const url = new URL(route.request().url());
    localHits.push(`${route.request().method()} ${url.pathname}`);
    if (route.request().method() === 'GET') {
      await route.fulfill({ json: { exports: [] } });
      return;
    }
    const body = route.request().postDataJSON() as { path: string; writable: boolean };
    await route.fulfill({
      status: 201,
      json: { export: makePeerExport('exp-local', 'peer-a', body.path, { writable: body.writable }) },
    });
  });

  await page.route(`**${peerApi}/peer-a/mounts`, async route => {
    const url = new URL(route.request().url());
    localHits.push(`${route.request().method()} ${url.pathname}`);
    if (route.request().method() === 'GET') {
      await route.fulfill({
        json: {
          mounts: [],
          available_exports: [makePeerExport('rem-1', 'peer-a', '/srv/media/films')],
        },
      });
      return;
    }
    await route.fulfill({
      status: 201,
      json: {
        mount: makePeerMount('mnt-local', 'peer-a', '/srv/media/films', '/mnt/af-peers/media-server/films'),
      },
    });
  });

  await page.goto('/?tab=cluster');
  await page.getByTestId('peer-manage-peer-b').click();
  await expect(page.getByTestId('cluster-local-scope-note')).toBeVisible();
  await expect(page.getByTestId('peer-manage-peer-b')).toHaveAttribute('data-active', 'true');

  await page.getByRole('button', { name: 'Manage media storage for Media server' }).click();
  const dialog = page.getByRole('dialog', { name: 'Media storage for Media server' });
  await expect(dialog).toBeVisible();

  await dialog.locator('#cluster-storage-browse-toggle').click();
  await expect(dialog.getByTestId('cluster-storage-folder-browser')).toContainText('/srv');
  await dialog.locator('#cluster-storage-browser-use').click();
  await dialog.locator('#cluster-storage-export-submit').click();
  await expect(dialog.getByText('Exported /srv to Media server.')).toBeVisible();

  await dialog.locator('#cluster-storage-mount-submit').click();
  await expect(dialog.getByText('Mounted /srv/media/films from Media server.')).toBeVisible();

  // Active selected remote server remained intact and zero storage/fs calls leaked onto the peer proxy.
  expect(leakedRemoteHits).toEqual([]);
  expect(localHits).toContain('GET /api/v1/auth/fs?path=%2Fsrv');
  expect(localHits).toContain('GET /api/v1/admin/peers/peer-a/exports');
  expect(localHits).toContain('POST /api/v1/admin/peers/peer-a/exports');
  expect(localHits).toContain('GET /api/v1/admin/peers/peer-a/mounts');
  expect(localHits).toContain('POST /api/v1/admin/peers/peer-a/mounts');
  await expect(page.getByTestId('cluster-local-scope-note')).toBeVisible();
  await expect(page.getByTestId('peer-manage-peer-b')).toHaveAttribute('data-active', 'true');
});

test('storage modal fences stale fetches and mutations across close and peer switch', async ({ page }) => {
  test.setTimeout(60_000);
  const peers = [
    makePeer('peer-a', 'Media server', '192.0.2.21', {
      state: 'active',
      capabilities: ['links', 'grants', 'storage'],
    }),
    makePeer('peer-b', 'Backup server', '192.0.2.31', {
      state: 'active',
      capabilities: ['links', 'grants', 'storage'],
    }),
  ];
  let listReads = 0;

  await mountCluster(page, () => {
    listReads += 1;
    return {
      ...peerList(),
      capabilities: ['links', 'grants', 'storage'],
      peers: peers.map(p => ({ ...p })),
    };
  });

  const getAExportsGate = deferred();
  const getBExportsGate = deferred();
  const postAExportErrGate = deferred();
  const postBExportGate = deferred();
  let getAExportsCalls = 0;

  await page.route(`**${peerApi}/peer-a/exports`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      getAExportsCalls += 1;
      if (getAExportsCalls === 1) {
        await getAExportsGate.promise;
        await route.fulfill({
          json: { exports: [makePeerExport('stale-exp-a', 'peer-a', '/srv/stale-from-a')] },
        });
        return;
      }
      await route.fulfill({ json: { exports: [] } });
      return;
    }
    if (method === 'POST') {
      await postAExportErrGate.promise;
      await route.fulfill({
        status: 502,
        json: {
          code: 'PEER_INTERNAL_ERROR',
          server: 'Media server',
          step: 'create_export',
          message: 'Stale export error for Media server.',
          action: 'Check nfs-server status.',
        },
      });
      return;
    }
    throw new Error(`Unexpected method on peer-a/exports: ${method}`);
  });

  await page.route(`**${peerApi}/peer-a/mounts`, route =>
    route.fulfill({ json: { mounts: [], available_exports: [] } }));

  await page.route(`**${peerApi}/peer-b/exports`, async route => {
    const method = route.request().method();
    if (method === 'GET') {
      await getBExportsGate.promise;
      await route.fulfill({
        json: { exports: [makePeerExport('exp-b-1', 'peer-b', '/srv/backup-b')] },
      });
      return;
    }
    if (method === 'POST') {
      await postBExportGate.promise;
      const body = route.request().postDataJSON() as { path: string; writable: boolean };
      await route.fulfill({
        status: 201,
        json: { export: makePeerExport('exp-b-2', 'peer-b', body.path, { writable: body.writable }) },
      });
      return;
    }
    throw new Error(`Unexpected method on peer-b/exports: ${method}`);
  });

  await page.route(`**${peerApi}/peer-b/mounts`, route =>
    route.fulfill({ json: { mounts: [], available_exports: [] } }));

  await page.goto('/?tab=cluster');
  const openA = page.getByRole('button', { name: 'Manage media storage for Media server' });
  const openB = page.getByRole('button', { name: 'Manage media storage for Backup server' });
  const dialog = page.getByRole('dialog');

  // 1) Stale GET /exports for Media server must never populate Backup server while Backup is loading.
  await openA.click();
  await expect(dialog.getByText('Loading local exports…')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await expect(dialog.getByText('Loading local exports…')).toBeVisible();
  const staleGetResp = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/exports` && resp.request().method() === 'GET',
  );
  getAExportsGate.resolve();
  await staleGetResp;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('/srv/stale-from-a')).toHaveCount(0);

  getBExportsGate.resolve();
  await expect(dialog.getByText('/srv/backup-b')).toBeVisible();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  // 2) Stale POST /exports error for Media server dismissed via X never leaks into Backup server or unlocks Backup's POST.
  await openA.click();
  await dialog.locator('#cluster-storage-export-path').fill('/srv/fail-a');
  await dialog.locator('#cluster-storage-export-submit').click();
  await expect(dialog.getByRole('button', { name: 'Exporting…' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await expect(dialog).toHaveCount(0);

  await openB.click();
  await dialog.locator('#cluster-storage-export-path').fill('/srv/new-b');
  await dialog.locator('#cluster-storage-export-submit').click();
  await expect(dialog.getByRole('button', { name: 'Exporting…' })).toBeDisabled();

  const stalePostErrResp = page.waitForResponse(
    resp => new URL(resp.url()).pathname === `${peerApi}/peer-a/exports` && resp.status() === 502,
  );
  postAExportErrGate.resolve();
  await stalePostErrResp;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0))));
  await expect(dialog.getByText('Stale export error for Media server.')).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: 'Exporting…' })).toBeDisabled();

  const readsBefore = listReads;
  postBExportGate.resolve();
  await expect.poll(() => listReads).toBeGreaterThan(readsBefore);
  await expect(dialog.getByText('Exported /srv/new-b to Backup server.')).toBeVisible();
});
