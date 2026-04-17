import { expect, test } from '@playwright/test';
import { installAetherFlowMocks, stabilizeVisuals } from './support/mockAetherFlow';

test('validates WebSocket connection drops and automatic reconnection UI durability', async ({ page }) => {
  await installAetherFlowMocks(page, { authenticated: true, enableWS: true });
  await stabilizeVisuals(page);

  // Provide a mock ticket endpoint for the initial WS connection setup
  await page.route(/\/api(\/v1)?\/auth\/ws\/ticket/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ticket: 'mock-ticket-123' }),
    });
  });

  // Mock the WebSocket Server
  let mockSocket: { close: () => void } | undefined;
  await page.routeWebSocket(/\/api(\/v1)?\/auth\/ws/, ws => {
    mockSocket = ws;
    ws.onMessage(message => {
      if (message === '{"type":"PING"}') {
        ws.send(JSON.stringify({ type: 'PONG' }));
      }
    });
  });

  await page.goto('/');

  // Wait for the UI to represent CONNECTED
  await expect(page.getByText('API Connected')).toBeVisible({ timeout: 10000 });

  // Simulate network disruption
  mockSocket?.close();

  // Wait for fallback/reconnect mode to trigger
  await expect(page.getByText('Connection lost — reconnecting...')).toBeVisible();
  await expect(page.getByText('Reconnecting')).toBeVisible();
});
