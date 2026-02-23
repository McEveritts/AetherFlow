export type TabId = 'overview' | 'services' | 'marketplace' | 'ai' | 'security' | 'settings' | 'logout';

export interface SystemMetrics {
    cpu_usage: number;
    disk_space: {
        total: number;
        used: number;
        free: number;
    };
    is_windows: boolean;
    services: {
        [key: string]: { status: 'running' | 'stopped' | 'error', uptime: string, version: string };
    };
    memory: {
        total: number;
        used: number;
    };
    network: {
        down: string;
        up: string;
        active_connections: number;
    };
    uptime: string;
    load_average: [number, number, number];
}
