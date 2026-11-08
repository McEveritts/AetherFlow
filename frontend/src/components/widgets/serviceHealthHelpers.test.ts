import { isServiceException, getServiceExceptionDetail, formatServiceName, isCoreService } from '@/components/widgets/serviceHealthHelpers';
import { ServiceTelemetryInfo } from '@/types/dashboard';

describe('serviceHealthHelpers', () => {
    describe('isServiceException', () => {
        it('returns false for undefined or null inputs', () => {
            expect(isServiceException(undefined)).toBe(false);
            expect(isServiceException(null)).toBe(false);
        });

        it('identifies status error as exception', () => {
            const errorService: ServiceTelemetryInfo = {
                status: 'error',
                uptime: '0m',
                version: '1.0.0',
            };
            expect(isServiceException(errorService)).toBe(true);
        });

        it('identifies the backend degraded status as an exception', () => {
            expect(isServiceException({ status: 'degraded' })).toBe(true);
            expect(getServiceExceptionDetail({ status: 'degraded' })).toBe('Degraded status reported');
        });

        it('identifies install_failed job_status as exception even when status is stopped', () => {
            const failedInstallService: ServiceTelemetryInfo = {
                status: 'stopped',
                uptime: '',
                version: '1.0.0',
                job_status: 'install_failed',
                last_job: { action: 'install', status: 'failed', error: 'Missing package' },
            };
            expect(isServiceException(failedInstallService)).toBe(true);
        });

        it('identifies incomplete install job as exception when daemon is stopped', () => {
            const incompleteInstallService: ServiceTelemetryInfo = {
                status: 'stopped',
                uptime: '',
                version: '1.0.0',
                last_job: { action: 'install', status: 'failed' },
            };
            expect(isServiceException(incompleteInstallService)).toBe(true);
        });

        it('identifies degraded health or degraded components as exception', () => {
            const degradedService: ServiceTelemetryInfo = {
                status: 'running',
                uptime: '1d',
                version: '2.0.0',
                health: 'degraded',
                degraded_components: ['auth-proxy'],
            };
            expect(isServiceException(degradedService)).toBe(true);
        });

        it('preserves clean stopped daemon as non-exception standby', () => {
            const cleanStoppedService: ServiceTelemetryInfo = {
                status: 'stopped',
                uptime: '',
                version: '1.2.0',
            };
            expect(isServiceException(cleanStoppedService)).toBe(false);
        });

        it('preserves normal running service as non-exception', () => {
            const healthyRunningService: ServiceTelemetryInfo = {
                status: 'running',
                uptime: '10d',
                version: '3.4.1',
            };
            expect(isServiceException(healthyRunningService)).toBe(false);
        });
    });

    describe('getServiceExceptionDetail', () => {
        it('returns install failure detail with error message if present', () => {
            const failedInstallService: ServiceTelemetryInfo = {
                status: 'stopped',
                uptime: '',
                version: '1.0.0',
                job_status: 'install_failed',
                last_job: { action: 'install', status: 'failed', error: 'Storage volume unmounted' },
            };
            expect(getServiceExceptionDetail(failedInstallService)).toBe('Install failed: Storage volume unmounted');
        });

        it('returns generic installation failed when no error text present', () => {
            const failedInstallService: ServiceTelemetryInfo = {
                status: 'stopped',
                uptime: '',
                version: '1.0.0',
                job_status: 'install_failed',
            };
            expect(getServiceExceptionDetail(failedInstallService)).toBe('Installation failed');
        });

        it('returns degraded components detail', () => {
            const degradedService: ServiceTelemetryInfo = {
                status: 'running',
                uptime: '2d',
                version: '1.0.0',
                degraded_components: ['database', 'cache'],
            };
            expect(getServiceExceptionDetail(degradedService)).toBe('Degraded: database, cache');
        });

        it('returns error state reported for generic error status', () => {
            const errorService: ServiceTelemetryInfo = {
                status: 'error',
                uptime: '0m',
                version: '1.0.0',
            };
            expect(getServiceExceptionDetail(errorService)).toBe('Error state reported');
        });
    });

    describe('formatServiceName', () => {
        it('translates known service slugs into proper brand titles aligned with Services friendly names', () => {
            expect(formatServiceName('aetherflow-frontend')).toBe('AetherFlow Frontend');
            expect(formatServiceName('aetherflow_frontend')).toBe('AetherFlow Frontend');
            expect(formatServiceName('apache2')).toBe('Apache Gateway');
            expect(formatServiceName('aetherflow-api')).toBe('AetherFlow API');
            expect(formatServiceName('aetherflow')).toBe('AetherFlow Core');
            expect(formatServiceName('calibreweb')).toBe('Calibre-Web');
            expect(formatServiceName('qbittorrent')).toBe('qBittorrent');
            expect(formatServiceName('jellyfin')).toBe('Jellyfin');
            expect(formatServiceName('homeassistant')).toBe('Home Assistant');
            expect(formatServiceName('paperless')).toBe('Paperless-ngx');
        });

        it('formats unknown kebab-case or snake_case slugs properly', () => {
            expect(formatServiceName('custom-torrent-daemon')).toBe('Custom Torrent Daemon');
            expect(formatServiceName('media_indexer')).toBe('Media Indexer');
        });
    });

    describe('isCoreService', () => {
        it('identifies canonical core services accurately', () => {
            expect(isCoreService('aetherflow-api')).toBe(true);
            expect(isCoreService('aetherflow_api')).toBe(true);
            expect(isCoreService('aetherflow-frontend')).toBe(true);
            expect(isCoreService('aetherflow_frontend')).toBe(true);
            expect(isCoreService('aetherflow')).toBe(true);
            expect(isCoreService('apache2')).toBe(true);
            expect(isCoreService('nginx')).toBe(true);
        });

        it('returns false for non-core managed applications', () => {
            expect(isCoreService('qbittorrent')).toBe(false);
            expect(isCoreService('jellyfin')).toBe(false);
            expect(isCoreService('sonarr')).toBe(false);
            expect(isCoreService('radarr')).toBe(false);
        });
    });
});
