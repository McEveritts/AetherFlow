import { create } from 'zustand';

export interface AppIngressConfig {
  publicDomain: string;          // User-defined external URL mapping
  externalAccessEnabled: boolean; // Killswitch for external ingress
}

interface IngressState {
  configs: Record<string, AppIngressConfig>; // Keyed by appName
  isSaving: boolean;
  fetchConfigs: () => Promise<void>;
  updateConfig: (appName: string, config: AppIngressConfig) => Promise<void>;
}

export const useIngressStore = create<IngressState>((set) => ({
  configs: {},
  isSaving: false,
  fetchConfigs: async () => {
    try {
      const response = await fetch('/api/ingress/configs');
      if (!response.ok) throw new Error('Failed to fetch ingress configs');
      const data = await response.json();
      set({ configs: data });
    } catch (error) {
      console.error("Error fetching ingress configs:", error);
    }
  },
  updateConfig: async (appName, config) => {
    set({ isSaving: true });
    try {
      const response = await fetch(`/api/ingress/apps/${appName}`, {
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
  }
}));
