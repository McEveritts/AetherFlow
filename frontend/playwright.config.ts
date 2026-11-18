import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL;
if (!baseURL && !process.argv.includes('--list')) {
  throw new Error('Run scripts/run_embedded_e2e.sh --playwright, or set PLAYWRIGHT_BASE_URL to an isolated Rust API serving the WASM bundle.');
}

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30 * 1000,
  expect: {
    timeout: 5000
  },
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    actionTimeout: 0,
    trace: 'on-first-retry',
    baseURL,
    // Fixture routes must receive requests before a service worker can handle
    // them. The dedicated live cache suite explicitly enables service workers.
    serviceWorkers: 'block',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      testIgnore: '**/visual.spec.ts',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      testIgnore: '**/visual.spec.ts',
      use: {
        ...devices['Desktop Safari'],
        ...(process.env.PLAYWRIGHT_WEBKIT_EXECUTABLE_PATH
          ? { launchOptions: { executablePath: process.env.PLAYWRIGHT_WEBKIT_EXECUTABLE_PATH } }
          : {}),
      },
    },
  ],
});
