import { create } from 'zustand';
import { apiFetch } from '@/lib/fetcher';

export interface AppIngressConfig {
  appName?: string;
  publicDomain: string;
  externalAccessEnabled: boolean;
  listenPort?: number;
  tlsEnabled?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export type AppIngressPatch = Partial<AppIngressConfig>;

function normalizeIngressConfig(appName: string, raw: Record<string, unknown> | AppIngressConfig | undefined): AppIngressConfig {
  const source = (raw || {}) as Record<string, unknown>;
  const rawDomain = typeof source.publicDomain === 'string'
    ? source.publicDomain
    : typeof source.public_domain === 'string'
      ? source.public_domain
      : '';
  const publicDomain = rawDomain.trim();
  const externalAccessEnabled = Boolean(
    source.externalAccessEnabled !== undefined
      ? source.externalAccessEnabled
      : source.external_access_enabled
  );
  const rawPort = source.listenPort !== undefined ? source.listenPort : source.listen_port;
  const listenPort = typeof rawPort === 'number' && Number.isFinite(rawPort) && rawPort > 0
    ? Math.trunc(rawPort)
    : undefined;
  const rawTls = source.tlsEnabled !== undefined ? source.tlsEnabled : source.tls_enabled;
  const tlsEnabled = typeof rawTls === 'boolean'
    ? rawTls
    : Boolean(publicDomain);

  const normalized: AppIngressConfig = {
    appName: typeof source.appName === 'string' && source.appName.trim() ? source.appName.trim() : appName,
    publicDomain,
    externalAccessEnabled,
    listenPort,
    tlsEnabled,
  };
  if (typeof source.createdAt === 'string') {
    normalized.createdAt = source.createdAt;
  }
  if (typeof source.updatedAt === 'string') {
    normalized.updatedAt = source.updatedAt;
  }
  return normalized;
}

interface IngressState {
  configs: Record<string, AppIngressConfig>;
  isSaving: boolean;
  error: string | null;
  fetchConfigs: () => Promise<void>;
  updateConfig: (appName: string, config: AppIngressPatch) => Promise<AppIngressConfig>;
  updateAppIngress: (appName: string, config: AppIngressPatch) => Promise<AppIngressConfig>;
}

export const useIngressStore = create<IngressState>((set, get) => ({
  configs: {},
  isSaving: false,
  error: null,
  fetchConfigs: async () => {
    try {
      const response = await apiFetch('/api/v1/admin/ingress/configs');
      if (!response.ok) throw new Error('Failed to fetch ingress configs');
      const data = await response.json();
      const configsMap: Record<string, AppIngressConfig> = {};
      if (Array.isArray(data?.configs)) {
        for (const item of data.configs) {
          if (item && typeof item === 'object') {
            const record = item as Record<string, unknown>;
            const key = String(record.appName || record.app_name || '').trim();
            if (key) {
              configsMap[key] = normalizeIngressConfig(key, record);
            }
          }
        }
      } else if (data && typeof data === 'object') {
        for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
          if (key === 'configs') continue;
          if (val && typeof val === 'object') {
            configsMap[key] = normalizeIngressConfig(key, val as Record<string, unknown>);
          }
        }
      }
      set({ configs: configsMap, error: null });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch ingress configs';
      console.error('Error fetching ingress configs:', error);
      set({ error: message });
    }
  },
  updateConfig: async (appName, patch) => {
    set({ isSaving: true, error: null });
    const existing = get().configs[appName];
    const publicDomain = (patch.publicDomain ?? existing?.publicDomain ?? '').trim();
    const externalAccessEnabled = patch.externalAccessEnabled !== undefined
      ? Boolean(patch.externalAccessEnabled)
      : Boolean(existing?.externalAccessEnabled);
    const listenPort = typeof patch.listenPort === 'number' && patch.listenPort > 0
      ? Math.trunc(patch.listenPort)
      : existing?.listenPort && existing.listenPort > 0
        ? existing.listenPort
        : undefined;
    const tlsEnabled = typeof patch.tlsEnabled === 'boolean'
      ? patch.tlsEnabled
      : typeof existing?.tlsEnabled === 'boolean'
        ? existing.tlsEnabled
        : Boolean(publicDomain);

    const payload: AppIngressConfig = {
      appName: existing?.appName || appName,
      publicDomain,
      externalAccessEnabled,
      ...(listenPort !== undefined ? { listenPort } : {}),
      tlsEnabled,
    };

    try {
      const response = await apiFetch(`/api/v1/admin/ingress/apps/${encodeURIComponent(appName)}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        const serverMessage =
          (body && typeof body === 'object' && (
            (typeof (body as Record<string, unknown>).message === 'string' && (body as Record<string, unknown>).message) ||
            (typeof (body as Record<string, unknown>).error === 'string' && (body as Record<string, unknown>).error)
          )) ||
          `Failed to update ingress config for ${appName}`;
        throw new Error(String(serverMessage));
      }

      const serverConfigRaw =
        body && typeof body === 'object' && (body as Record<string, unknown>).config && typeof (body as Record<string, unknown>).config === 'object'
          ? ((body as Record<string, unknown>).config as Record<string, unknown>)
          : body && typeof body === 'object' && ('publicDomain' in body || 'externalAccessEnabled' in body || 'tlsEnabled' in body || 'listenPort' in body)
            ? (body as Record<string, unknown>)
            : null;

      const authoritative = serverConfigRaw
        ? normalizeIngressConfig(appName, { ...payload, ...serverConfigRaw })
        : normalizeIngressConfig(appName, payload);

      set((state) => ({
        configs: { ...state.configs, [appName]: authoritative },
        isSaving: false,
        error: null,
      }));
      return authoritative;
    } catch (error) {
      const message = error instanceof Error ? error.message : `Failed to update ingress config for ${appName}`;
      console.error(`Error updating config for ${appName}:`, error);
      set({ isSaving: false, error: message });
      throw error instanceof Error ? error : new Error(message);
    }
  },
  updateAppIngress: async (appName, config) => {
    return get().updateConfig(appName, config);
  },
}));
