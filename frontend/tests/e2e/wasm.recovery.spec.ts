import { expect, test, type Page } from '@playwright/test';
import { installAetherFlowMocks } from './support/mockAetherFlow';

const sessionPath = '/api/v1/auth/session';
const connected = (page: Page) => page.getByText('API Connected', { exact: true });

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

test.beforeEach(async ({ context, baseURL }) => {
  if (!baseURL) throw new Error('The isolated WASM server URL is required');
  const origin = new URL(baseURL);
  if (origin.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname)) {
    throw new Error('Recovery tests require a loopback HTTP server');
  }
  await context.route(url => url.origin !== origin.origin, route => route.abort());
});

async function installConnectedMocks(page: Page, userRole: 'admin' | 'user' = 'admin') {
  // Block unmatched APIs from using the disposable server with fixture auth.
  // Specific page routes registered later take precedence.
  await page.route('**/api/**', route => route.fulfill({ status: 404, json: { message: 'Unmocked recovery API' } }));
  await installAetherFlowMocks(page, { authenticated: true, setupRequired: false, enableWS: true, userRole });
  await page.route('**/api/v1/auth/ws/ticket', route => route.fulfill({ json: { ticket: 'recovery-fixture' } }));
  await page.routeWebSocket(/\/api\/v1\/auth\/ws(?:\?|$)/, socket => {
    socket.onMessage(message => {
      if (message === '{"type":"PING"}') socket.send('{"type":"PONG"}');
    });
  });
}

type ChatMode = 'chat' | 'support';
type ChatTurn = { role: 'user' | 'assistant'; text: string };
type ChatRequest = { path: string; body: Record<string, unknown> };
type ChatReply = { reply: string } | { failure: true; release?: Promise<void> };

const prompt = 'Check the worker queue';
const earlierReply = 'The queue was healthy earlier';
const successReply = 'The queue has recovered';
const unavailable = 'The inference fixture is temporarily unavailable';
const userTurn = (text: string): ChatTurn => ({ role: 'user', text });
const assistantTurn = (text: string): ChatTurn => ({ role: 'assistant', text });

async function openChat(page: Page, mode: ChatMode, replies: ChatReply[]) {
  await installConnectedMocks(page, mode === 'support' ? 'admin' : 'user');
  await page.route('**/api/v1/auth/settings', route => route.fulfill({
    json: { aiModel: 'gemini-4-argon', language: 'en', setupCompleted: true },
  }));
  const requests: ChatRequest[] = [];
  const endpoint = `/api/v1/auth/ai/${mode}`;
  await page.route(/\/api\/v1\/auth\/ai\/(?:chat|support)$/, async route => {
    const request = route.request();
    expect(request.method()).toBe('POST');
    const path = new URL(request.url()).pathname;
    const reply = replies[requests.length];
    requests.push({ path, body: request.postDataJSON() as ChatRequest['body'] });
    if (!reply) {
      await route.fulfill({ status: 500, json: { message: 'Unexpected FlowAI submission' } });
      return;
    }
    if ('failure' in reply) {
      await reply.release;
      await route.fulfill({ status: 503, json: { code: 'PROVIDER_UNAVAILABLE', message: unavailable } });
    } else {
      await route.fulfill({ json: { reply: reply.reply } });
    }
  });

  await page.goto('/?tab=ai');
  await expect(connected(page)).toBeVisible();
  await expect(page.getByLabel('Inference model ID', { exact: true })).toHaveValue('gemini-4-argon');
  const composer = page.getByRole('textbox', { name: 'Message FlowAI', exact: true });
  const send = page.getByRole('button', { name: 'Send', exact: true });
  const newConversation = page.getByRole('button', { name: 'New conversation', exact: true });
  const history = page.getByRole('navigation', { name: 'Conversation history', exact: true });
  const transcript = page.getByRole('log', { name: 'FlowAI conversation', exact: true });
  const error = page.getByRole('alert').filter({ hasText: unavailable });
  return { requests, endpoint, composer, send, newConversation, history, transcript, error };
}

function expectChatRequest(request: ChatRequest, mode: ChatMode, message: string, history: ChatTurn[]) {
  expect(request.path).toBe(`/api/v1/auth/ai/${mode}`);
  expect(request.body).toMatchObject({ message, model: 'gemini-4-argon', provider: 'gemini' });
  // The Rust chat and support handlers both deserialize history as ChatMessage
  // { role, text }. Assistant entries can also carry optional UI metadata.
  expect.soft(request.body.history, 'provider-bound history').toMatchObject(history);
  if (mode === 'support') {
    expect(request.body).toMatchObject({
      context_mode: 'full',
      metrics_snapshot: { service_health: expect.any(Array) },
      system_logs: expect.any(Array),
    });
  } else {
    for (const key of ['context_mode', 'metrics_snapshot', 'system_logs']) {
      expect(request.body).not.toHaveProperty(key);
    }
  }
}

for (const mode of ['chat', 'support'] as const) {
  test(`FlowAI ${mode} drops failed optimistic turns through repeated 503 retries`, async ({ page }) => {
    const chat = await openChat(page, mode, [
      { reply: earlierReply }, { failure: true }, { failure: true },
      { reply: successReply }, { reply: 'Follow-up accepted' },
    ]);
    const matchingTurns = chat.transcript.getByText(prompt, { exact: true });
    await chat.composer.fill(prompt);
    await chat.send.click();
    await expect(chat.transcript.getByText(earlierReply, { exact: true })).toBeVisible();
    await expect(matchingTurns).toHaveCount(1);

    await chat.composer.fill(prompt);
    for (const attempt of [1, 2]) {
      const failed = page.waitForResponse(response =>
        new URL(response.url()).pathname === chat.endpoint && response.status() === 503 && response.request().method() === 'POST',
      );
      await chat.send.click();
      await failed;
      await expect(chat.error).toBeVisible();
      await expect(chat.composer).toHaveValue(prompt);
      await expect(chat.send).toBeEnabled();
      await expect.soft(matchingTurns, `visible history after failed attempt ${attempt}`).toHaveCount(1, { timeout: 1_000 });
    }

    await chat.send.click();
    await expect(chat.transcript.getByText(successReply, { exact: true })).toBeVisible();
    await expect.soft(matchingTurns, 'earlier committed turn and one successful retry').toHaveCount(2, { timeout: 1_000 });
    await expect(chat.composer).toHaveValue('');
    await expect(chat.error).toBeHidden();

    const followUp = 'Summarize the queue';
    await chat.composer.fill(followUp);
    await chat.send.click();
    await expect(chat.transcript.getByText('Follow-up accepted', { exact: true })).toBeVisible();
    expect(chat.requests).toHaveLength(5);
    expectChatRequest(chat.requests[0], mode, prompt, []);
    const committed = [userTurn(prompt), assistantTurn(earlierReply)];
    for (const request of chat.requests.slice(1, 4)) {
      expectChatRequest(request, mode, prompt, committed);
    }
    expectChatRequest(chat.requests[4], mode, followUp, [
      ...committed, userTurn(prompt), assistantTurn(successReply),
    ]);
  });
}

test('FlowAI keeps a newer composer edit when a held chat request fails', async ({ page }) => {
  const release = deferred();
  const chat = await openChat(page, 'chat', [{ failure: true, release: release.promise }, { reply: successReply }]);
  const newer = 'Check the current memory pressure instead';
  try {
    await chat.composer.fill(prompt);
    await chat.send.click();
    await expect(chat.transcript.getByText(prompt, { exact: true })).toBeVisible();
    await expect(chat.newConversation).toBeDisabled();
    await chat.composer.fill(newer);
    await expect(chat.send).toBeDisabled();
  } finally {
    release.resolve();
  }
  await expect(chat.error).toBeVisible();
  await expect(chat.composer).toHaveValue(newer);
  await expect.soft(chat.transcript.getByText(prompt, { exact: true })).toHaveCount(0, { timeout: 1_000 });
  await chat.send.click();
  await expect(chat.transcript.getByText(successReply, { exact: true })).toBeVisible();
  expect(chat.requests).toHaveLength(2);
  expectChatRequest(chat.requests[0], 'chat', prompt, []);
  expectChatRequest(chat.requests[1], 'chat', newer, []);
});

test('FlowAI rolls back the origin thread after selecting another existing conversation', async ({ page }) => {
  const release = deferred();
  const chat = await openChat(page, 'support', [
    { reply: earlierReply }, { reply: 'The other queue was healthy' },
    { failure: true, release: release.promise }, { reply: 'The other draft was accepted' },
    { reply: successReply },
  ]);
  const otherPrompt = 'Check the other queue';
  const otherReply = 'The other queue was healthy';
  const otherDraft = 'Keep this draft in the other thread';
  const origin = chat.history.getByRole('button', { name: prompt, exact: true });
  const other = chat.history.getByRole('button', { name: otherPrompt, exact: true });

  try {
    await chat.composer.fill(prompt);
    await chat.send.click();
    await expect(chat.transcript.getByText(earlierReply, { exact: true })).toBeVisible();

    await chat.newConversation.click();
    await chat.composer.fill(otherPrompt);
    await chat.send.click();
    await expect(chat.transcript.getByText(otherReply, { exact: true })).toBeVisible();

    await origin.click();
    await chat.composer.fill(prompt);
    await chat.send.click();
    await expect(chat.transcript.getByText(prompt, { exact: true })).toHaveCount(2);
    await expect(chat.newConversation).toBeDisabled();
    const remove = chat.history.getByRole('button', { name: 'Delete conversation', exact: true });
    await expect(remove).toHaveCount(2);
    for (const button of await remove.all()) await expect(button).toBeDisabled();
    await expect(other).toBeEnabled();
    await other.click();
    await expect(other).toHaveAttribute('aria-current', 'true');
    await expect(chat.transcript.getByText(otherReply, { exact: true })).toBeVisible();
    await chat.composer.fill(otherDraft);
  } finally {
    release.resolve();
  }

  await expect(chat.send).toBeEnabled();
  await expect(other).toHaveAttribute('aria-current', 'true');
  await expect(chat.composer).toHaveValue(otherDraft);
  await expect(chat.transcript.getByText(prompt, { exact: true })).toHaveCount(0);
  await chat.send.click();
  await expect(chat.transcript.getByText('The other draft was accepted', { exact: true })).toBeVisible();

  await origin.click();
  await expect(chat.transcript.getByText(earlierReply, { exact: true })).toBeVisible();
  await expect.soft(chat.transcript.getByText(prompt, { exact: true })).toHaveCount(1, { timeout: 1_000 });
  await chat.composer.fill(prompt);
  await chat.send.click();
  await expect(chat.transcript.getByText(successReply, { exact: true })).toBeVisible();
  await expect.soft(chat.transcript.getByText(prompt, { exact: true })).toHaveCount(2, { timeout: 1_000 });

  expect(chat.requests).toHaveLength(5);
  const originHistory = [userTurn(prompt), assistantTurn(earlierReply)];
  expectChatRequest(chat.requests[2], 'support', prompt, originHistory);
  expectChatRequest(chat.requests[3], 'support', otherDraft, [userTurn(otherPrompt), assistantTurn(otherReply)]);
  expectChatRequest(chat.requests[4], 'support', prompt, originHistory);
});

const plugin = { id: 'telemetry-inspector', name: 'Telemetry Inspector', version: '1.0.0', enabled: true, healthy: true };
const proxyPath = `/api/v1/auth/plugins/${plugin.id}/proxy/status`;
const pluginMarker = 'x-aetherflow-proxied-plugin';
const pluginError = 'Telemetry Inspector rejected the upstream request';
const pluginUiCsp = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts";
const proxyCsp = "sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const pluginDocument = `<!doctype html>
<html lang="en">
<title>Telemetry Inspector bridge fixture</title>
<button id="probe" type="button" disabled>Probe status</button>
<output id="result" data-testid="bridge-result"></output>
<script>
  const pluginId = ${JSON.stringify(plugin.id)};
  const button = document.getElementById('probe');
  const result = document.getElementById('result');
  let nextRequest = 0;
  window.addEventListener('message', event => {
    const message = event.data;
    if (event.source !== window.parent || message?.pluginId !== pluginId) return;
    if (message.type === 'AF_PLUGIN_INIT') button.disabled = false;
    if (message.type === 'AF_PLUGIN_PROXY_RESPONSE') result.textContent = JSON.stringify(message);
  });
  button.addEventListener('click', () => {
    const request = {
      type: 'AF_PLUGIN_PROXY_REQUEST', pluginId, requestId: 'recovery-' + ++nextRequest,
      method: 'GET', path: 'status',
    };
    if (nextRequest === 1) {
      window.parent.postMessage({ ...request, pluginId: 'wrong-plugin', requestId: 'wrong-id' }, '*');
    }
    window.parent.postMessage(request, '*');
  });
  window.parent.postMessage({ type: 'AF_PLUGIN_READY', pluginId }, '*');
</script>
</html>`;

async function trackSessionProbes(page: Page) {
  const probes: string[] = [];
  await page.route(`**${sessionPath}`, route => {
    probes.push(route.request().method());
    return route.fulfill({ json: { id: 1, username: 'admin', role: 'admin', email: 'admin@example.com', is_oauth: false } });
  });
  return probes;
}

async function openFileDraft(page: Page) {
  await installConnectedMocks(page);
  const probes = await trackSessionProbes(page);
  await page.route('**/api/v1/auth/mcbrowser/entries?*', route => route.fulfill({ json: { path: '', entries: [] } }));
  await page.route('**/api/v1/auth/mcbrowser/policy', route => route.fulfill({
    json: { scope: 'private', permissions: { read: true, create: true, modify: true }, rules: [] },
  }));
  await page.route('**/api/v1/auth/mcbrowser/usage', route => route.fulfill({ json: { used_bytes: 0, quota_bytes: 0 } }));
  await page.goto('/?tab=mcbrowser');
  await expect(connected(page)).toBeVisible();
  await page.getByRole('button', { name: 'New empty file', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'File operation', exact: true });
  const input = dialog.getByLabel('New file name', { exact: true });
  const value = 'unsaved-mcbrowser-draft.txt';
  await input.fill(value);
  await expect(input).toHaveValue(value);
  return { dialog, input, value, probes };
}

for (const marked of [true, false]) {
  test(marked ? 'a marked upstream 401 stays scoped to the plugin bridge'
    : 'an unmarked host 401 on the same bridge refreshes once and expires', async ({ page, context }) => {
    const trace: string[] = [];
    let reject = false;
    await installConnectedMocks(page);
    const probes = await trackSessionProbes(page);
    await page.route('**/api/v1/auth/plugins', route => route.fulfill({ json: { plugins: [plugin] } }));
    await page.route(`**/api/v1/auth/plugins/${plugin.id}/ui`, route => route.fulfill({
      contentType: 'text/html; charset=utf-8',
      headers: { 'content-security-policy': pluginUiCsp, 'x-frame-options': 'SAMEORIGIN' },
      body: pluginDocument,
    }));
    await page.route('**/api/v1/auth/refresh', route => {
      trace.push(`${route.request().method()} refresh`);
      return route.fulfill({ json: { message: 'Fixture refresh accepted' } });
    });
    await page.route(`**${proxyPath}`, async route => {
      trace.push(`${route.request().method()} proxy`);
      const proxyHeaders = { [pluginMarker]: plugin.id, 'content-security-policy': proxyCsp };
      if (!reject) return route.fulfill({ headers: proxyHeaders, json: { status: 'ok' } });
      if (marked) return route.fulfill({ status: 401, headers: proxyHeaders, json: { message: pluginError } });

      // The browser has only a modeled session. Forward this exact GET to real
      // Rust auth middleware, which has no cookie and never reaches the plugin.
      const response = await route.fetch({ maxRedirects: 0 });
      expect(response.status()).toBe(401);
      expect(response.headers()[pluginMarker]).toBeUndefined();
      expect(await response.json()).toEqual({ code: 'UNAUTHORIZED', message: 'Unauthorized' });
      return route.fulfill({ response });
    });
    await page.addInitScript(() => {
      window.addEventListener('af:session-expired', () => {
        document.documentElement.dataset.recoveryExpiry = 'seen';
      });
    });

    const draftPage = await context.newPage();
    try {
      // A Marketplace modal and a McBrowser dialog belong to different tabs of
      // the app. Keep the real editor alive in a same-context browser tab.
      const draft = await openFileDraft(draftPage);
      await page.bringToFront();
      await page.goto('/?tab=marketplace');
      await expect(page.locator('.af-user-badge')).toHaveText('admin');
      await expect(connected(page)).toBeVisible();
      await page.getByTestId(`open-plugin-ui-${plugin.id}`).click();
      const iframe = page.getByTestId('plugin-sandbox-iframe');
      await expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');
      const frame = iframe.contentFrame();
      const probe = frame.getByRole('button', { name: 'Probe status', exact: true });
      const output = frame.getByTestId('bridge-result');
      await expect(probe).toBeEnabled(); // The actual host accepted AF_PLUGIN_READY.
      expect(await probe.evaluate(() => window.origin)).toBe('null');
      await probe.click();
      await expect(output).toContainText('"requestId":"recovery-1"');
      expect(JSON.parse(await output.innerText())).toEqual({
        ok: true, payload: { status: 'ok' }, pluginId: plugin.id,
        requestId: 'recovery-1', status: 200, type: 'AF_PLUGIN_PROXY_RESPONSE',
      });
      expect(trace).toEqual(['GET proxy']);
      expect(probes).toEqual(['GET']);
      expect(draft.probes).toEqual(['GET']);

      // Wait on the top document's native clock. Playwright's frame clock
      // controller is unavailable in this WebKit sandbox fixture.
      // Sampling after bootstrap guarantees the full session grace interval.
      const acceptedBy = await page.evaluate(() => Date.now());
      await page.evaluate(accepted => new Promise<void>(resolve => {
        window.setTimeout(resolve, Math.max(0, 11_000 - (Date.now() - accepted)));
      }), acceptedBy);
      expect(await page.evaluate(() => Date.now()) - acceptedBy).toBeGreaterThan(10_000);
      await expect(connected(page)).toBeVisible();
      await expect(draft.input).toHaveValue(draft.value);
      expect(probes).toEqual(['GET']);
      trace.length = 0;
      reject = true;
      await probe.click();

      const expired = page.waitForURL(url => url.pathname === '/login', { waitUntil: 'commit', timeout: 10_000 });
      if (!marked) {
        await expired;
        expect(trace).toEqual(['GET proxy', 'POST refresh', 'GET proxy']);
        expect(probes).toEqual(['GET']);
        await expect(draft.dialog).toBeHidden(); // Real cross-tab logout invalidation.
        await expect(draftPage.locator('.af-user-badge')).toHaveText('admin');
        expect(draft.probes).toEqual(['GET', 'GET']);
        return;
      }

      // The old transport tears down the iframe. Race that real redirect
      // against the scoped error so old21 reports the refresh/retry sequence.
      const scoped = expect(output).toContainText('"requestId":"recovery-2"', { timeout: 10_000 });
      const outcome = await Promise.race([
        scoped.then(() => 'plugin error'),
        expired.then(() => 'host expiry'),
      ]);
      expect.soft(trace).toEqual(['GET proxy']);
      if (outcome === 'host expiry') await expect(draft.dialog).toBeHidden();
      expect(outcome).toBe('plugin error');
      expect(JSON.parse(await output.innerText())).toEqual({
        error: pluginError, ok: false, pluginId: plugin.id,
        requestId: 'recovery-2', status: 401, type: 'AF_PLUGIN_PROXY_RESPONSE',
      });
      expect(probes).toEqual(['GET']);
      expect(draft.probes).toEqual(['GET']);
      await expect(page.locator('html')).not.toHaveAttribute('data-recovery-expiry', 'seen');
      await expect(page.getByText(pluginError, { exact: true })).toHaveCount(0);
      expect(await page.evaluate(() => localStorage.getItem('af_logout_sync'))).toBeNull();
      await page.getByTestId('close-plugin-sandbox').click();
      await expect(iframe).toHaveCount(0);
      await expect(page.locator('.af-user-badge')).toHaveText('admin');
      await expect(connected(page)).toBeVisible();
      await expect(draft.input).toHaveValue(draft.value);
    } finally {
      await draftPage.close();
    }
  });
}
