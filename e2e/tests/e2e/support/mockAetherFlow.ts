import { Page, Route } from '@playwright/test';

type UserRole = 'admin' | 'user';

interface MockOptions {
  authenticated?: boolean;
  setupRequired?: boolean;
  userRole?: UserRole;
  enableWS?: boolean;
  preserveStorage?: boolean;
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
  inventory_known: boolean;
  inventory_authenticated: boolean;
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
      inventory_known: true,
      inventory_authenticated: true,
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
      inventory_known: true,
      inventory_authenticated: true,
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
      inventory_known: true,
      inventory_authenticated: true,
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

  await page.addInitScript((options) => {
    if (!options.enableWS) {
      (window as Window & { __AF_DISABLE_WS__?: boolean }).__AF_DISABLE_WS__ = true;
    }
    if (!options.preserveStorage) {
      window.localStorage.clear();
      window.sessionStorage.clear();
    }
  }, { enableWS: options.enableWS, preserveStorage: options.preserveStorage });

  await page.route(/\/api(\/v1)?(\/public)?\/csrf-token/, async (route: Route) => {
    await json(route, { csrf_token: 'mock-csrf-token' });
  });

  await page.route(/\/api(\/v1)?(\/public)?\/auth\/setup\/check/, async (route: Route) => {
    await json(route, { setupRequired: state.setupRequired });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/session/, async (route: Route) => {
    if (!state.authenticated) {
      await json(route, { error: 'Unauthorized' }, 401);
      return;
    }
    await json(route, buildUser(state.userRole));
  });

  await page.route(/\/api(\/v1)?(\/public)?\/auth\/login/, async (route: Route) => {
    state.authenticated = true;
    await json(route, { message: 'Login successful', user: buildUser(state.userRole) });
  });

  await page.route(/\/api(\/v1)?(\/public)?\/auth\/setup$/, async (route: Route) => {
    state.authenticated = true;
    state.setupRequired = false;
    await json(route, { message: 'Admin account created', username: 'admin' });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/logout/, async (route: Route) => {
    state.authenticated = false;
    await json(route, { message: 'Logged out' });
  });

  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/settings/, async (route: Route) => {
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

  await page.route(/\/api(\/v1)?(\/auth)?\/system\/metrics(\/history)?/, async (route: Route) => {
    const parsedUrl = new URL(route.request().url());
    if (parsedUrl.pathname.endsWith('/history')) {
      if (parsedUrl.searchParams.get('aggregate') === 'daily_transfer') {
        await json(route, {
          days: [],
          counter_resets: 0,
          invalid_samples: 0,
          conflicting_samples: 0,
          duplicate_samples: 0,
        });
        return;
      }
      await json(route, { points: [] });
      return;
    }
    await json(route, {
      cpu_usage: 18.2,
      memory: { used: 12, total: 64 },
      network: { down: '12.3MB/s', up: '1.4MB/s' },
      disk_io: { read_bytes_sec: 1048576, write_bytes_sec: 524288 },
      disks: [{ mount_point: '/', used_pct: 51.4 }],
    });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/system\/hardware/, async (route: Route) => {
    await json(route, {
      cpu: { model: 'AMD EPYC 7543' },
      memory: { total_gb: 64 },
      storage: [{ model: 'NVMe Array' }],
    });
  });

  // Overview reads this as soon as its admin widgets mount. Keep the contract
  // inside the authenticated mock session instead of falling through to the
  // isolated live server, whose unrelated cookies correctly return 401.
  await page.route(/\/api\/v1\/admin\/ai\/predictions(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, {});
  });

  await page.route(/\/api\/v1\/admin\/ai\/predictions\/history(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, []);
  });

  // StreamingTab mounts a live dashboard resource and 5s poll immediately, and
  // CanonicalHistory mounts HistoryAnalytics (patterns + drilldown) as soon as
  // a snapshot loads. Keep them inside the mocked session instead of falling
  // through to the isolated live server, whose unrelated cookies return 401 and
  // trigger session-expiry logout once >10s have elapsed since auth.
  await page.route(/\/api\/v1\/auth\/streaming\/dashboard(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, { servers: [], activeSessions: [], liveSummary: {}, analytics: {} });
  });

  await page.route(/\/api\/v1\/auth\/streaming\/patterns(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, { activity: { timeseries: [] }, concurrency: { buckets: [] } });
  });

  await page.route(/\/api\/v1\/auth\/streaming\/drilldown(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, { cohortDistinctPlays: 0, cohortDistinctUsers: 0, cohortDistinctItems: 0 });
  });

  // SettingsTab mounts SystemUpdates immediately on the default General subtab,
  // and NetworkTab mounts ExternalAccessSettings (polling ingress configs and
  // admin services every 15s). Keep them inside the mocked session so they
  // cannot fall through to the isolated live server, get HTTP 401, and trigger
  // session-expiry revalidation or logout.
  await page.route(/\/api\/v1\/admin\/network\/status(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, { platform: 'linux', runner_available: false });
  });

  await page.route(/\/api\/v1\/admin\/ingress\/configs(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, { configs: [] });
  });

  await page.route(/\/api\/v1\/admin\/services(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, []);
  });

  await page.route(/\/api\/v1\/admin\/peers(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, {
      identity: null,
      peer_protocol: 1,
      capabilities: ['links'],
      rtt_warn_ms: 120,
      peers: [],
      pairing_windows: [],
      pairing_attempts: [],
      detected_endpoints: [],
    });
  });

  await page.route(/\/api\/v1\/admin\/peers\/transcode(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await json(route, {
      enabled: false,
      worker_service_enabled: false,
      worker_service_active: false,
      dispatcher_active: false,
      dispatcher_socket: '/run/aetherflow/transcode.sock',
      shim_installed: false,
      shim_path: '/usr/local/lib/aetherflow/bin/af-transcode',
      jellyfin_dropin_enabled: false,
      jellyfin_reported_ffmpeg: null,
      local: {
        server_name: 'aetherflow',
        ffmpeg_version: null,
        package_name: null,
        package_version: null,
        encoders: [],
        render_nodes: [],
        primary_render_node: null,
        transcoding_temp_path: null,
        tmp_dir: null,
      },
      workers: [],
      recent_jobs: [],
    });
  });

  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/system\/update\/(check|status)/, async (route: Route) => {
    if (new URL(route.request().url()).pathname.endsWith('/status')) {
      await json(route, { state: 'idle', phase: '', operationId: '', error: '' });
      return;
    }
    await json(route, {
      updateAvailable: true,
      currentVersion: 'v3.1.0',
      latestVersion: 'v3.1.1',
      message: 'Patch release available',
      url: 'https://github.com/McEveritts/AetherFlow/releases/tag/v3.1.1',
    });
  });

  await page.route(/\/api(\/v1)?(\/admin)?\/system\/update\/run/, async (route: Route) => {
    await json(route, { message: 'Update sequence initiated.' });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/services/, async (route: Route) => {
    await json(route, {
      'aetherflow-api': { status: 'running', version: '3.1.0', uptime: '4d', managed_by: 'pm2', process: 'aetherflow-api' },
      'aetherflow-frontend': { status: 'running', version: '3.1.0', uptime: '4d', managed_by: 'pm2', process: 'aetherflow-frontend' },
      sonarr: { status: 'running', version: '4.0.0', uptime: '10h', managed_by: 'systemd', process: 'sonarr' },
    });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/system\/topology/, async (route: Route) => {
    await json(route, { nodes: [], edges: [] });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/notifications/, async (route: Route) => {
    await json(route, []);
  });

  await page.route(/\/api(\/v1)?\/admin\/notifications\/(channels|rules)$/, async (route: Route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const collection = new URL(route.request().url()).pathname.split('/').at(-1)!;
    await json(route, { [collection]: [] });
  });

  await page.route(/\/api(\/v1)?(\/admin)?\/actions\/pending/, async (route: Route) => {
    await json(route, { count: 0, actions: [] });
  });

  await page.route(/\/api(\/v1)?(\/auth)?\/plugins/, async (route: Route) => {
    await json(route, []);
  });

  await page.route(/\/api(\/v1)?(\/(public|auth|admin))?\/marketplace/, async (route: Route) => {
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

  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/packages\/[^/]+\/install/, async (route: Route) => {
    const packageID = new URL(route.request().url()).pathname.split('/').slice(-2)[0];
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

  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/packages\/[^/]+\/uninstall/, async (route: Route) => {
    const packageID = new URL(route.request().url()).pathname.split('/').slice(-2)[0];
    const app = state.apps.find((candidate) => candidate.id === packageID);
    if (app) {
      app.status = 'available';
      app.progress = 0;
      delete app.installed_version;
    }
    await json(route, { message: 'Uninstallation started successfully', package: packageID, status: 'uninstalling' });
  });

  await page.route(/\/api(\/v1)?(\/(auth|admin))?\/packages\/[^/]+\/progress/, async (route: Route) => {
    await json(route, { status: 'idle', progress: 0 });
  });

  let mcbrowserPrefs = {
    view: 'list',
    sort: 'name',
    direction: 'asc',
    show_hidden: false,
    single_click: false,
    natural_sort: true,
    redirect_after_copy_move: false,
    date_format: false,
    editor_theme: 'chrome',
    locale: 'en',
  };
  await page.route(/\/api\/v1\/auth\/mcbrowser\/preferences(?:\?.*)?$/, async (route: Route) => {
    if (route.request().method() === 'PUT') {
      const next = route.request().postDataJSON();
      if (next && typeof next === 'object') {
        mcbrowserPrefs = { ...mcbrowserPrefs, ...(next as Record<string, unknown>) };
      }
      await json(route, mcbrowserPrefs);
      return;
    }
    await json(route, mcbrowserPrefs);
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
