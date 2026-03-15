import { Page, Route } from '@playwright/test';

type UserRole = 'admin' | 'user';

interface MockOptions {
  authenticated?: boolean;
  setupRequired?: boolean;
  userRole?: UserRole;
}

interface MockApp {
  id: string;
  name: string;
  desc: string;
  hits: number;
  category: string;
  status: string;
  progress: number;
  installed_version?: string;
  latest_version?: string;
  update_available: boolean;
  update_url?: string;
  log_line?: string;
  started_at?: string;
}

function buildUser(role: UserRole) {
  return {
    id: 1,
    username: 'admin',
    email: 'admin@example.com',
    avatar_url: '',
    role,
    is_oauth: false,
  };
}

function buildMarketplaceApps(): MockApp[] {
  return [
    {
      id: 'sonarr',
      name: 'Sonarr',
      desc: 'TV automation for the glass control plane.',
      hits: 12400,
      category: 'Media',
      status: 'installed',
      progress: 0,
      installed_version: '4.0.0',
      latest_version: '4.0.1',
      update_available: true,
      update_url: 'https://github.com/Sonarr/Sonarr/releases',
    },
    {
      id: 'bazarr',
      name: 'Bazarr',
      desc: 'Subtitle sync and discovery for Plex and Jellyfin libraries.',
      hits: 8400,
      category: 'Media',
      status: 'available',
      progress: 0,
      update_available: false,
    },
    {
      id: 'grafana',
      name: 'Grafana',
      desc: 'Operational dashboards for the AetherFlow substrate.',
      hits: 9200,
      category: 'Observability',
      status: 'installed',
      progress: 0,
      installed_version: '11.0.0',
      latest_version: '11.0.0',
      update_available: false,
    },
  ];
}

function json(route: Route, payload: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(payload),
  });
}

export async function installAetherFlowMocks(page: Page, options: MockOptions = {}) {
  const state = {
    authenticated: options.authenticated ?? true,
    setupRequired: options.setupRequired ?? false,
    userRole: options.userRole ?? 'admin',
    apps: buildMarketplaceApps(),
    installPolls: 0,
  };

  await page.addInitScript(() => {
    (window as Window & { __AF_DISABLE_WS__?: boolean }).__AF_DISABLE_WS__ = true;
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  await page.route(/\/api(\/v1)?\/auth\/setup\/check/, async (route: Route) => {
    await json(route, { setupRequired: state.setupRequired });
  });

  await page.route(/\/api(\/v1)?\/auth\/session/, async (route: Route) => {
    if (!state.authenticated) {
      await json(route, { error: 'Unauthorized' }, 401);
      return;
    }
    await json(route, buildUser(state.userRole));
  });

  await page.route(/\/api(\/v1)?\/auth\/login/, async (route: Route) => {
    state.authenticated = true;
    await json(route, { message: 'Login successful', user: buildUser(state.userRole) });
  });

  await page.route(/\/api(\/v1)?\/auth\/setup$/, async (route: Route) => {
    state.authenticated = true;
    state.setupRequired = false;
    await json(route, { message: 'Admin account created', username: 'admin' });
  });

  await page.route(/\/api(\/v1)?\/auth\/logout/, async (route: Route) => {
    state.authenticated = false;
    await json(route, { message: 'Logged out' });
  });

  await page.route(/\/api(\/v1)?\/settings/, async (route: Route) => {
    const method = route.request().method();
    if (method === 'PUT') {
      await json(route, { message: 'Settings saved successfully', data: {} });
      return;
    }
    await json(route, {
      aiModel: 'gemini-2.5-pro',
      systemPrompt: 'You are FlowAI.',
      language: 'en',
      timezone: 'UTC',
      updateChannel: 'stable',
      defaultDashboard: 'overview',
      setupCompleted: true,
      geminiApiKey: '',
    });
  });

  await page.route(/\/api(\/v1)?\/system\/metrics/, async (route: Route) => {
    await json(route, {
      cpu_usage: 18.2,
      memory: { used: 12, total: 64 },
      network: { down: '12.3MB/s', up: '1.4MB/s' },
      disk_io: { read_bytes_sec: 1048576, write_bytes_sec: 524288 },
      disks: [{ mount_point: '/', used_pct: 51.4 }],
    });
  });

  await page.route(/\/api(\/v1)?\/system\/hardware/, async (route: Route) => {
    await json(route, {
      cpu: { model: 'AMD EPYC 7543' },
      memory: { total_gb: 64 },
      storage: [{ model: 'NVMe Array' }],
    });
  });

  await page.route(/\/api(\/v1)?\/system\/update\/check/, async (route: Route) => {
    await json(route, {
      updateAvailable: true,
      currentVersion: 'v3.1.0',
      latestVersion: 'v3.1.1',
      message: 'Patch release available',
      url: 'https://github.com/McEveritts/AetherFlow/releases/tag/v3.1.1',
    });
  });

  await page.route(/\/api(\/v1)?\/system\/update\/run/, async (route: Route) => {
    await json(route, { message: 'Update sequence initiated.' });
  });

  await page.route(/\/api(\/v1)?\/services/, async (route: Route) => {
    await json(route, {
      'aetherflow-api': { status: 'running', version: '3.1.0', uptime: '4d', managed_by: 'pm2', process: 'aetherflow-api' },
      'aetherflow-frontend': { status: 'running', version: '3.1.0', uptime: '4d', managed_by: 'pm2', process: 'aetherflow-frontend' },
      sonarr: { status: 'running', version: '4.0.0', uptime: '10h', managed_by: 'systemd', process: 'sonarr' },
    });
  });

  await page.route(/\/api(\/v1)?\/marketplace/, async (route: Route) => {
    const installing = state.apps.find((app) => app.status === 'installing');
    if (installing) {
      state.installPolls += 1;
      if (state.installPolls >= 3) {
        installing.status = 'installed';
        installing.progress = 100;
        installing.installed_version = '1.1.0';
        installing.latest_version = '1.1.0';
        installing.update_available = false;
        delete installing.log_line;
      } else {
        installing.progress = state.installPolls === 1 ? 34 : 78;
        installing.log_line = state.installPolls === 1 ? 'Pulling package archive' : 'Applying runtime hooks';
        installing.started_at = '2026-03-15T12:00:00Z';
      }
    }
    await json(route, state.apps);
  });

  await page.route(/\/api(\/v1)?\/packages\/[^/]+\/install/, async (route: Route) => {
    const packageID = route.request().url().split('/').slice(-2)[0];
    const app = state.apps.find((candidate) => candidate.id === packageID);
    if (app) {
      app.status = 'installing';
      app.progress = 12;
      app.log_line = 'Preparing install plan';
      app.started_at = '2026-03-15T12:00:00Z';
      state.installPolls = 0;
    }
    await json(route, { message: 'Installation started successfully', package: packageID, status: 'installing' });
  });

  await page.route(/\/api(\/v1)?\/packages\/[^/]+\/uninstall/, async (route: Route) => {
    const packageID = route.request().url().split('/').slice(-2)[0];
    const app = state.apps.find((candidate) => candidate.id === packageID);
    if (app) {
      app.status = 'available';
      app.progress = 0;
      delete app.installed_version;
    }
    await json(route, { message: 'Uninstallation started successfully', package: packageID, status: 'uninstalling' });
  });

  await page.route(/\/api(\/v1)?\/packages\/[^/]+\/progress/, async (route: Route) => {
    await json(route, { status: 'idle', progress: 0 });
  });
}

export async function stabilizeVisuals(page: Page) {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript(() => {
    const style = document.createElement('style');
    style.textContent = `
      * {
        caret-color: transparent !important;
      }
      html {
        scroll-behavior: auto !important;
      }
    `;
    const install = () => {
      if (!document.head.querySelector('style[data-af-visual]')) {
        style.setAttribute('data-af-visual', 'true');
        document.head.appendChild(style);
      }
    };
    if (document.head) {
      install();
    } else {
      window.addEventListener('DOMContentLoaded', install, { once: true });
    }
  });
}
