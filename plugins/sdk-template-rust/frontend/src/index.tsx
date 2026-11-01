import { PluginPanel } from './PluginPanel';

export interface PluginDefinition {
    id: string;
    name: string;
    slot: 'overview' | 'services' | 'marketplace' | 'settings';
    mount: typeof PluginPanel;
}

const plugin: PluginDefinition = {
    id: '{{PLUGIN_ID}}',
    name: '{{PLUGIN_NAME}}',
    slot: 'marketplace',
    mount: PluginPanel,
};

export default plugin;
