export type TabId = 'overview' | 'services' | 'marketplace' | 'fileshare' | 'ai' | 'backups' | 'security' | 'profile' | 'settings' | 'users' | 'logout';

export interface ProcessInfo {
    pid: number;
    name: string;
    cpu: number;
    mem: number;
}

export interface SystemMetrics {
    cpu_usage: number;
    per_core_cpu: number[];
    cpu_freq_mhz: number;
    disk_space: {
        total: number;
        used: number;
        free: number;
    };
    disk_io: {
        read_bytes_sec: number;
        write_bytes_sec: number;
    };
    is_windows: boolean;
    services: {
        [key: string]: { status: 'running' | 'stopped' | 'error', uptime: string, version: string };
    };
    memory: {
        total: number;
        used: number;
    };
    swap: {
        total: number;
        used: number;
    };
    network: {
        down: string;
        up: string;
        active_connections: number;
    };
    total_net_bytes: {
        rx: number;
        tx: number;
    };
    uptime: string;
    load_average: [number, number, number];
    processes: ProcessInfo[];
}

export interface MetricsHistory {
    cpu: number[];
    memory: number[];
    netDown: number[];
    netUp: number[];
    diskRead: number[];
    diskWrite: number[];
    timestamps: number[];
}

export interface CPUInfo {
    vendor: string;
    model: string;
    cores: number;
    threads: number;
}

export interface MemoryInfo {
    total_bytes: number;
    banks: number;
    type: string;
}

export interface GPUInfo {
    vendor: string;
    product: string;
    driver?: string;
}

export interface NetworkInfo {
    name: string;
    mac: string;
    vendor: string;
    product: string;
}

export interface StorageInfo {
    name: string;
    model: string;
    size_bytes: number;
    drive_type: string;
    is_removable: boolean;
}

export interface HardwareReport {
    system_vendor: string;
    system_product: string;
    cpu?: CPUInfo;
    memory?: MemoryInfo;
    gpus?: GPUInfo[];
    network?: NetworkInfo[];
    storage?: StorageInfo[];
}
