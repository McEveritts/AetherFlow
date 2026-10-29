import { create } from 'zustand';
import { apiFetch } from '@/lib/fetcher';

export interface AppIngressConfig {
  publicDomain: string;          // User-defined external URL mapping
  externalAccessEnabled: boolean; // Killswitch for external ingress
}

interface IngressState {
  configs: Record<string, AppIngressConfig>; // Keyed by appName
  isSaving: boolean;
  fetchConfigs: () => Promise<void>;
  updateConfig: (appName: string, config: AppIngressConfig) => Promise<void>;
  updateAppIngress: (appName: string, config: AppIngressConfig) => Promise<void>;
}

export const useIngressStore = create<IngressState>((set, get) => ({
  configs: {},
  isSaving: false,
  fetchConfigs: async () => {
    try {
      const response = await apiFetch('/api/v1/admin/ingress/configs');
      if (!response.ok) throw new Error('Failed to fetch ingress configs');
      const data = await response.json();
      const configsMap: Record<string, AppIngressConfig> = {};
      if (Array.isArray(data.configs)) {
        for (const item of data.configs) {
          configsMap[item.appName] = {
            publicDomain: item.publicDomain || '',
            externalAccessEnabled: Boolean(item.externalAccessEnabled),
          };
        }
      } else if (data && typeof data === 'object') {
        Object.assign(configsMap, data);
      }
      set({ configs: configsMap });
    } catch (error) {
      console.error("Error fetching ingress configs:", error);
    }
  },
  updateConfig: async (appName, config) => {
    set({ isSaving: true });
    try {
      const response = await apiFetch(`/api/v1/admin/ingress/apps/${encodeURIComponent(appName)}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      });
      if (!response.ok) throw new Error(`Failed to update ingress config for ${appName}`);
      
      set((state) => ({ 
        configs: { ...state.configs, [appName]: config },
        isSaving: false 
      }));
    } catch (error) {
      console.error(`Error updating config for ${appName}:`, error);
      set({ isSaving: false });
    }
  },
  updateAppIngress: async (appName, config) => {
    return get().updateConfig(appName, config);
  }
}));
