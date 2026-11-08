import { ServiceTelemetryInfo } from '@/types/dashboard';

export function isServiceException(serviceInfo?: ServiceTelemetryInfo | null): boolean {
    if (!serviceInfo) return false;
    if (serviceInfo.status === 'error') return true;
    if (serviceInfo.status === 'degraded') return true;
    if (serviceInfo.job_status === 'install_failed' || serviceInfo.job_status === 'failed') return true;
    if (serviceInfo.last_job?.status === 'failed') return true;
    if (serviceInfo.last_job?.action === 'install' && serviceInfo.last_job?.status !== 'completed' && Boolean(serviceInfo.last_job?.error)) return true;
    if (serviceInfo.health === 'degraded' || serviceInfo.health === 'unhealthy') return true;
    if (serviceInfo.degraded_components && serviceInfo.degraded_components.length > 0) return true;
    return false;
}

export function getServiceExceptionDetail(serviceInfo?: ServiceTelemetryInfo | null): string {
    if (!serviceInfo) return 'Unknown state';
    if (serviceInfo.job_status === 'install_failed' || (serviceInfo.last_job?.action === 'install' && serviceInfo.last_job?.status === 'failed')) {
        return serviceInfo.last_job?.error ? `Install failed: ${serviceInfo.last_job.error}` : 'Installation failed';
    }
    if (serviceInfo.last_job?.error) {
        return `Job failed: ${serviceInfo.last_job.error}`;
    }
    if (serviceInfo.status === 'error') {
        return 'Error state reported';
    }
    if (serviceInfo.status === 'degraded') {
        return 'Degraded status reported';
    }
    if (serviceInfo.health === 'degraded' || (serviceInfo.degraded_components && serviceInfo.degraded_components.length > 0)) {
        return serviceInfo.degraded_components ? `Degraded: ${serviceInfo.degraded_components.join(', ')}` : 'Component degraded';
    }
    return 'Exception reported';
}

export function isCoreService(rawSlug: string): boolean {
    const normalizedSlug = rawSlug.toLowerCase().replace(/[\s_-]+/g, '');
    return (
        normalizedSlug === 'aetherflowapi' ||
        normalizedSlug === 'aetherflowfrontend' ||
        normalizedSlug === 'aetherflow' ||
        normalizedSlug === 'apache2' ||
        normalizedSlug === 'nginx'
    );
}

export function formatServiceName(rawSlug: string): string {
    const knownServiceNames: Record<string, string> = {
        'aetherflow-api': 'AetherFlow API',
        'aetherflow_api': 'AetherFlow API',
        'aetherflow-frontend': 'AetherFlow Frontend',
        'aetherflow_frontend': 'AetherFlow Frontend',
        'aetherflow': 'AetherFlow Core',
        'apache2': 'Apache Gateway',
        calibreweb: 'Calibre-Web',
        qbittorrent: 'qBittorrent',
        jellyfin: 'Jellyfin',
        jellyseerr: 'Jellyseerr',
        sonarr: 'Sonarr',
        radarr: 'Radarr',
        prowlarr: 'Prowlarr',
        bazarr: 'Bazarr',
        lidarr: 'Lidarr',
        readarr: 'Readarr',
        deluge: 'Deluge',
        transmission: 'Transmission',
        nextcloud: 'Nextcloud',
        homeassistant: 'Home Assistant',
        vaultwarden: 'Vaultwarden',
        wireguard: 'WireGuard',
        tailscale: 'Tailscale',
        paperless: 'Paperless-ngx',
    };
    const lowercaseSlug = rawSlug.toLowerCase();
    if (knownServiceNames[lowercaseSlug]) {
        return knownServiceNames[lowercaseSlug];
    }
    return rawSlug
        .split(/[-_]/)
        .map(wordSegment => wordSegment.charAt(0).toUpperCase() + wordSegment.slice(1))
        .join(' ');
}
