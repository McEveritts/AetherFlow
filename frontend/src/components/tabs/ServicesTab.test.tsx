import React from 'react';
import { act, render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import ServicesTab from '@/components/tabs/ServicesTab';
import { apiFetch } from '@/lib/fetcher';

let mockUserRole = 'admin';
const mockAddToast = jest.fn();
const mockSetActiveTab = jest.fn();
const mockMutateServices = jest.fn();
const mockGlobalMutate = jest.fn();
const mockLogsModalSpy = jest.fn();
let mockServicesPayload: Record<string, unknown> | undefined = {};
let mockServicesError: Error | undefined;
let mockServicesIsValidating = false;
let mockServicesIsLoading = false;
let mockServicesOptions: { onSuccess: (services: Record<string, unknown>) => void };

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: { id: 1, username: 'viewer', role: mockUserRole },
        isAuthenticated: true,
    }),
}));

jest.mock('@/store/useSystemStore', () => ({
    useSystemStore: () => ({
        setActiveTab: mockSetActiveTab,
    }),
}));

jest.mock('@/components/auth/RequireClaim', () => {
    return function MockRequireClaim({ children }: { children: React.ReactNode }) {
        return <>{children}</>;
    };
});

jest.mock('@/components/tabs/ServiceLogsModal', () => {
    return function MockServiceLogsModal(props: { serviceName: string | null; units?: string[]; onClose: () => void }) {
        mockLogsModalSpy(props);
        if (!props.serviceName) return null;
        return (
            <div data-testid="mock-logs-modal" data-service={props.serviceName} data-units={(props.units || []).join(',')} />
        );
    };
});

jest.mock('@/components/ingress/ExternalAccessCard', () => ({
    ExternalAccessCard: () => null,
}));

jest.mock('@/components/deploy/DeploymentStatus', () => ({
    DeploymentStatus: () => null,
}));

jest.mock('swr', () => {
    const useSWRMock = jest.fn((key: string, options: typeof mockServicesOptions) => {
        if (key === '/api/v1/auth/services') {
            mockServicesOptions = options;
            return {
                data: mockServicesPayload,
                error: mockServicesError,
                isValidating: mockServicesIsValidating,
                mutate: mockMutateServices,
                isLoading: mockServicesIsLoading,
            };
        }
        return { data: null, mutate: jest.fn(), isLoading: false };
    });
    const actual = jest.requireActual('swr');
    return {
        __esModule: true,
        default: useSWRMock,
        useSWRConfig: () => ({
            cache: actual.useSWRConfig().cache,
            mutate: mockGlobalMutate,
        }),
    };
});

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

describe('ServicesTab Loopback, Protocol, Update, Component & Control Contracts', () => {
    let openSpy: jest.SpyInstance;

    beforeEach(() => {
        mockUserRole = 'admin';
        mockServicesPayload = {};
        mockServicesError = undefined;
        mockServicesIsValidating = false;
        mockServicesIsLoading = false;
        mockAddToast.mockReset();
        mockSetActiveTab.mockReset();
        mockMutateServices.mockReset();
        mockGlobalMutate.mockReset();
        mockLogsModalSpy.mockReset();
        mockedApiFetch.mockReset();
        openSpy = jest.spyOn(window, 'open').mockImplementation(() => null);
    });

    afterEach(() => {
        openSpy.mockRestore();
    });

    it('keeps an unobserved installed version unknown until a measured version arrives', () => {
        mockServicesPayload = {
            Sonarr: { id: 'sonarr', process: 'sonarr', status: 'running', version: '',
                installed_version: '', latest_version: '', uptime: '2h', managed_by: 'systemd' },
        };
        const { rerender } = render(<ServicesTab />);
        const sonarrArticle = screen.getByRole('article', { name: 'Sonarr service' });
        const versionBox = within(sonarrArticle).getByText('Version').parentElement?.parentElement;
        expect(versionBox).toBeInTheDocument();
        expect(versionBox).toHaveTextContent('-');
        expect(versionBox).not.toHaveTextContent(/latest/i);
        mockServicesPayload = {
            Sonarr: { ...mockServicesPayload.Sonarr as Record<string, unknown>, version: '2.4.1', installed_version: '2.4.1' },
        };
        rerender(<ServicesTab />);
        const updatedArticle = screen.getByRole('article', { name: 'Sonarr service' });
        const updatedVersionBox = within(updatedArticle).getByText('Version').parentElement?.parentElement;
        expect(updatedVersionBox).toHaveTextContent('v2.4.1');
    });

    it.each(['user', 'admin'])('limits credential controls to a human admin (%s)', (role) => {
        mockUserRole = role;
        mockServicesPayload = {
            Sonarr: { id: 'sonarr', process: 'sonarr', status: 'running', version: '1.0',
                uptime: '2h', managed_by: 'systemd', api_key: 'synthetic-service-credential' },
        };
        render(<ServicesTab />);
        expect(screen.queryByRole('button', { name: 'Copy Sonarr API key' }) !== null).toBe(role === 'admin');
        expect(screen.queryByRole('button', { name: 'Reveal Sonarr API key' }) !== null).toBe(role === 'admin');
        expect(screen.queryByText('API Key') !== null).toBe(role === 'admin');
    });

    it.each([
        ['Maintainerr', 'maintainerr', 'af-maintainerr', 6246],
        ['Palate', 'palate', 'af-palate', 28014],
        ['KasmVNC', 'kasmvnc', 'af-kasmvnc', 6081],
        ['McVNC', 'mcvnc', 'af-mcvnc', 6900],
    ])('disables direct Web UI and Settings shortcuts on remote browser for loopback app %s when external access is disabled', (label, id, process, port) => {
        mockServicesPayload = {
            [label]: {
                id,
                process,
                status: 'running',
                version: '1.0.0',
                uptime: '2h 10m',
                managed_by: 'systemd',
                default_port: port,
                active_port: port,
                external_access_enabled: false,
                public_domain: '',
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'https:', hostname: 'seedbox.example.com' }} />);

        const webUiButton = screen.getByRole('button', { name: /^Web UI$/i });
        expect(webUiButton).toBeDisabled();

        const accessButton = screen.getByRole('button', { name: new RegExp(`Connection details for ${label}`, 'i') });
        expect(accessButton).toBeInTheDocument();
        fireEvent.click(accessButton);

        const ingressButton = screen.getByRole('menuitem', { name: `Ingress and deployment for ${label}` });
        const settingsButton = screen.getByRole('menuitem', { name: `Settings for ${label}` });

        expect(ingressButton).not.toBeDisabled();
        expect(settingsButton).toBeDisabled();
        expect(settingsButton).toHaveAttribute('title', `${label} binds strictly to 127.0.0.1. Enable External Access with a public domain in Ingress & Deployment to open its Web UI remotely.`);

        fireEvent.click(webUiButton);
        expect(openSpy).not.toHaveBeenCalled();
    });

    it('honors additive bind_scope="loopback" on remote browsers and opens public domain when enabled', () => {
        mockServicesPayload = {
            Maintainerr: {
                id: 'maintainerr',
                process: 'af-maintainerr',
                status: 'running',
                version: '3.31.0',
                uptime: '2h 10m',
                managed_by: 'systemd',
                default_port: 6246,
                active_port: 17846,
                bind_scope: 'loopback',
                external_access_enabled: true,
                public_domain: 'maintainerr.example.com',
                tls_enabled: true,
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'https:', hostname: 'seedbox.example.com' }} />);

        const webUiButton = screen.getByRole('button', { name: /Web UI/i });
        expect(webUiButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).toHaveBeenCalledWith('https://maintainerr.example.com/', '_blank');
    });

    it.each([
        ['http:', 'localhost'],
        ['https:', 'localhost'],
        ['http:', '127.0.0.1'],
        ['https:', '127.0.0.1'],
        ['http:', '::1'],
        ['https:', '::1'],
        ['http:', '[::1]'],
        ['https:', '[::1]'],
    ])('uses the IPv4 HTTP listener for a local browser at %s//%s without public ingress', (protocol, hostname) => {
        mockServicesPayload = {
            Maintainerr: {
                id: 'maintainerr',
                process: 'af-maintainerr',
                status: 'running',
                version: '3.31.0',
                uptime: '2h 10m',
                managed_by: 'systemd',
                default_port: 6246,
                active_port: 17846,
                external_access_enabled: false,
                public_domain: '',
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol, hostname }} />);

        const webUiButton = screen.getByRole('button', { name: /Web UI/i });
        expect(webUiButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).toHaveBeenCalledWith('http://127.0.0.1:17846/', '_blank');
    });

    it('uses plain HTTP (or explicit web_scheme) for direct app URLs even when the dashboard runs over HTTPS', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 8989,
                active_port: 8989,
                external_access_enabled: false,
                public_domain: '',
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'https:', hostname: 'seedbox.example.com' }} />);

        const webUiButton = screen.getByRole('button', { name: /Web UI/i });
        expect(webUiButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).toHaveBeenCalledWith('http://seedbox.example.com:8989/', '_blank');
    });

    it('uses https: when web_scheme is explicitly set to https', () => {
        mockServicesPayload = {
            CustomTLSApp: {
                id: 'customtls',
                process: 'customtls',
                status: 'running',
                version: '1.2.0',
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 9443,
                active_port: 9443,
                web_scheme: 'https',
                external_access_enabled: false,
                public_domain: '',
                web_path: '/app',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'http:', hostname: 'seedbox.example.com' }} />);

        fireEvent.click(screen.getByRole('button', { name: /Web UI/i }));
        expect(openSpy).toHaveBeenCalledWith('https://seedbox.example.com:9443/app', '_blank');
    });

    it('normalizes nested Rust check-update payloads and reports available updates accurately', async () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                installed_version: '4.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 8989,
            },
        };
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                message: 'Package update check completed',
                package: 'sonarr',
                update: {
                    package_id: 'sonarr',
                    installed: true,
                    installed_version: '4.0.0',
                    latest_version: 'v4.0.9',
                    update_available: true,
                    checked_at: '2026-11-02T12:00:00Z',
                    release_url: 'https://github.com/Sonarr/Sonarr/releases/tag/v4.0.9',
                    error: '',
                },
            }),
        } as Response);

        render(<ServicesTab />);

        const manageButton = screen.getByRole('button', { name: /Manage Sonarr service actions/i });
        fireEvent.click(manageButton);
        fireEvent.click(screen.getByRole('menuitem', { name: /Check for updates/i }));

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Update available for Sonarr: v4.0.9', 'info');
        });
    });

    it('reports unavailable bulk inventory as a failed check without a zero-update success', async () => {
        mockServicesPayload = {};
        mockedApiFetch.mockResolvedValueOnce({
            ok: false, status: 503,
            json: async () => ({ code: 'STATUS_UNAVAILABLE', message: 'Application inventory could not be confirmed' }),
        } as Response);
        render(<ServicesTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Check Updates & Sync' }));
        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Failed to check remote updates; try again shortly.', 'error');
        });
        expect(mockAddToast.mock.calls.some(([, level]) => level === 'success')).toBe(false);
        expect(mockMutateServices).not.toHaveBeenCalled();
    });

    it('surfaces failed update checks as errors instead of reporting up to date', async () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                installed_version: '4.0.0',
                update_available: true,
                update_error: 'latest version: GitHub API rate limit exceeded',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 8989,
            },
        };
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                message: 'Package update check completed',
                package: 'sonarr',
                update: {
                    package_id: 'sonarr',
                    installed: true,
                    installed_version: '4.0.0',
                    latest_version: '',
                    update_available: false,
                    checked_at: '2026-11-02T12:00:00Z',
                    release_url: '',
                    error: 'latest version: GitHub API rate limit exceeded',
                },
            }),
        } as Response);

        render(<ServicesTab />);

        expect(screen.getByText(/Check failed/i)).toBeInTheDocument();

        const manageButton = screen.getByRole('button', { name: /Manage Sonarr service actions/i });
        fireEvent.click(manageButton);
        fireEvent.click(screen.getByRole('menuitem', { name: /Check for updates/i }));

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                'Update check failed for Sonarr: latest version: GitHub API rate limit exceeded',
                'error'
            );
        });
    });

    it('sends canonical app id for service control and disables daemon controls for shared Apache vhost apps', async () => {
        mockServicesPayload = {
            Nextcloud: {
                id: 'nextcloud',
                process: 'apache2',
                status: 'running',
                version: '29.0.0',
                uptime: '4d',
                managed_by: 'systemd',
                default_port: 8088,
                control_scope: 'shared-vhost',
            },
            Deluge: {
                id: 'deluge',
                process: 'deluged',
                status: 'running',
                version: '2.1.1',
                uptime: '4d',
                managed_by: 'systemd',
                default_port: 8112,
            },
        };
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ message: 'ok' }),
        } as Response);

        render(<ServicesTab />);

        expect(screen.getByText(/shared vhost/i)).toBeInTheDocument();
        const nextcloudArticle = screen.getByRole('article', { name: 'Nextcloud service' });
        const nextcloudManage = within(nextcloudArticle).getByRole('button', { name: /Manage.*actions/i });
        fireEvent.click(nextcloudManage);

        const sharedStopButtons = screen.getAllByTitle(/shared Apache web server/i).filter((element) => element.tagName === 'BUTTON');
        expect(sharedStopButtons.length).toBeGreaterThanOrEqual(2);
        for (const sharedButton of sharedStopButtons) {
            expect(sharedButton).toBeDisabled();
        }

        const delugeArticle = screen.getByRole('article', { name: 'Deluge service' });
        const delugeManage = within(delugeArticle).getByRole('button', { name: /Manage.*actions/i });
        fireEvent.click(delugeManage);
        const restartButton = within(delugeArticle).getByRole('menuitem', { name: /Restart/i });
        fireEvent.click(restartButton);

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/services/deluge/control',
                expect.objectContaining({
                    method: 'POST',
                    body: JSON.stringify({
                        action: 'restart',
                        managed_by: 'systemd',
                        process: 'deluge',
                    }),
                })
            );
        });
    });

    it.each([
        ['collector.timer', 'timer', 'stopped', true, 'running'],
        ['required.service', 'required', 'failed', false, 'stopped'],
    ])('does not exempt unhealthy required components: %s', (unit, role, status, configured, overallStatus) => {
        mockServicesPayload = {
            Scrutiny: {
                id: 'scrutiny', process: 'scrutiny', status: overallStatus,
                version: '1.0', uptime: '-', managed_by: 'systemd', default_port: 8098,
                components: [
                    { unit: 'scrutiny.service', role: 'required', status: overallStatus === 'running' ? 'running' : 'failed', configured: true },
                    { unit, role, status, configured },
                ],
            },
        };
        render(<ServicesTab />);
        expect(screen.getByText('degraded')).toBeInTheDocument();
        expect(screen.getByText(new RegExp(unit.replaceAll('.', '\\.') + '.*down'))).toBeInTheDocument();
    });

    it('shows degraded required-component status distinctly while exempting idle timers, oneshots, and unconfigured optional mounts, and passes all units to ServiceLogsModal', () => {
        mockServicesPayload = {
            Deluge: {
                id: 'deluge',
                process: 'deluged',
                status: 'running',
                version: '2.1.1',
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 8112,
                units: ['deluged.service', 'deluge-web.service'],
                components: [
                    { unit: 'deluged.service', role: 'required', status: 'running', configured: true },
                    { unit: 'deluge-web.service', role: 'required', status: 'stopped', configured: true },
                ],
            },
            Rclone: {
                id: 'rclone',
                process: 'rclone',
                status: 'running',
                version: '1.68.0',
                uptime: '3d',
                managed_by: 'systemd',
                default_port: 5572,
                units: ['rclone.service', 'rclone-vfs.service'],
                components: [
                    { unit: 'rclone.service', role: 'required', status: 'running', configured: true },
                    { unit: 'rclone-vfs.service', role: 'optional', status: 'stopped', configured: false },
                ],
            },
            Scrutiny: {
                id: 'scrutiny',
                process: 'scrutiny',
                status: 'running',
                version: '0.8.1',
                uptime: '3d',
                managed_by: 'systemd',
                default_port: 8098,
                units: ['scrutiny.service', 'scrutiny-collector.service', 'scrutiny-collector.timer'],
                components: [
                    { unit: 'scrutiny.service', role: 'required', status: 'running', configured: true },
                    { unit: 'scrutiny-collector.service', role: 'oneshot', status: 'inactive', configured: true },
                    { unit: 'scrutiny-collector.timer', role: 'timer', status: 'active', configured: true },
                ],
            },
        };

        render(<ServicesTab />);

        expect(screen.getByText('degraded')).toBeInTheDocument();
        expect(screen.getByText(/deluge-web\.service down/i)).toBeInTheDocument();
        expect(screen.queryByText(/rclone-vfs\.service down/i)).not.toBeInTheDocument();
        expect(screen.getByText('scrutiny-collector.service: inactive (oneshot)')).toBeInTheDocument();

        const logButtons = screen.getAllByTitle('View live logs');
        fireEvent.click(logButtons[0]);

        const modal = screen.getByTestId('mock-logs-modal');
        expect(modal).toHaveAttribute('data-service', 'deluged.service');
        expect(modal).toHaveAttribute('data-units', 'deluged.service,deluge-web.service');
    });
});

describe('Services lifecycle receipts and diagnostics', () => {
    const service = (extra: Record<string, unknown> = {}) => ({
        id: 'fixture', process: 'fixture', managed_by: 'systemd', status: 'running', version: '1.0', installed_version: '1.0', latest_version: '2.0', update_available: true, uptime: '1h', ...extra,
    });
    beforeEach(() => {
        mockAddToast.mockReset(); mockMutateServices.mockReset(); mockGlobalMutate.mockReset(); mockLogsModalSpy.mockReset(); mockedApiFetch.mockReset();
        mockServicesPayload = { Fixture: service() };
        mockServicesError = undefined; mockServicesIsValidating = false;
    });
    it.each(['completed', 'failed', 'deduplicated'])('keeps a long active update tracked through identical polls then reports %s once', async status => {
        jest.useFakeTimers();
        mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ job_id: 'accepted-A' }) } as Response);
        const view = render(<ServicesTab />);
        const manageButton = screen.getByRole('button', { name: 'Manage Fixture service actions' });
        fireEvent.click(manageButton);
        await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
        mockServicesPayload = { Fixture: service({ job_id: 'accepted-A', job_status: 'updating' }) };
        view.rerender(<ServicesTab />);
        for (let poll = 0; poll < 6; poll++) {
            await act(async () => { await jest.advanceTimersByTimeAsync(60000); });
            if (status === 'deduplicated') {
                mockServicesIsValidating = true; view.rerender(<ServicesTab />);
                mockServicesIsValidating = false; view.rerender(<ServicesTab />);
            } else {
                act(() => mockServicesOptions.onSuccess(mockServicesPayload!));
            }
            expect(screen.getByTitle('Restart service')).toBeDisabled();
            expect(mockAddToast.mock.calls.some(call => String(call[0]).includes('receipt may have been superseded'))).toBe(false);
        }
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'accepted-A', action: 'update', status: status === 'deduplicated' ? 'completed' : status, started_at: 'now', finished_at: 'later' } }) };
        view.rerender(<ServicesTab />);
        const terminal = () => mockAddToast.mock.calls.filter(call => String(call[0]).includes(`update ${status === 'deduplicated' ? 'completed' : status}`));
        expect(terminal()).toHaveLength(1);
        view.rerender(<ServicesTab />);
        expect(terminal()).toHaveLength(1);
        expect(screen.getByTitle('Restart service')).toBeEnabled();
        view.unmount(); expect(jest.getTimerCount()).toBe(0); jest.useRealTimers();
    });

    it('bounds stale active data during fetch errors and later reports the exact terminal receipt', async () => {
        jest.useFakeTimers();
        mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ job_id: 'accepted-A' }) } as Response);
        const view = render(<ServicesTab />);
        await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
        mockServicesPayload = { Fixture: service({ job_id: 'accepted-A', job_status: 'updating' }) };
        view.rerender(<ServicesTab />);
        for (let poll = 0; poll < 4; poll++) {
            mockServicesError = new Error('offline');
            view.rerender(<ServicesTab />);
            await act(async () => { await jest.advanceTimersByTimeAsync(30000); });
        }
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes('receipt may have been superseded'))).toHaveLength(1);
        mockServicesError = undefined;
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'accepted-A', action: 'update', status: 'failed', started_at: 'now', finished_at: 'later' } }) };
        view.rerender(<ServicesTab />);
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes('update failed'))).toHaveLength(1);
        view.unmount(); expect(jest.getTimerCount()).toBe(0); jest.useRealTimers();
    });

    it('releases an unobserved superseded update without reporting the other client success', async () => {
        jest.useFakeTimers();
        mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ job_id: 'accepted-A' }) } as Response);
        const view = render(<ServicesTab />);
        const manageButton = screen.getByRole('button', { name: 'Manage Fixture service actions' });
        fireEvent.click(manageButton);
        await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'client-B', action: 'update', status: 'completed', started_at: 'later', finished_at: 'later' } }) };
        view.rerender(<ServicesTab />);
        expect(screen.getByTitle('Restart service')).toBeDisabled();
        await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('receipt may have been superseded'), 'error');
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        expect(screen.getByTitle('Restart service')).toBeEnabled();
        view.unmount(); expect(jest.getTimerCount()).toBe(0); jest.useRealTimers();
    });

    it.each(['failed', 'succeeded'])('tracks accepted core restart through stale healthy snapshots to %s', async terminal => {
        jest.useFakeTimers();
        const unit = 'aetherflow-self-update-restart-aetherflow-api-12345678.service';
        mockServicesPayload = { 'AetherFlow API': service({ id: 'aetherflow-api', process: 'aetherflow-api' }) };
        mockedApiFetch.mockImplementation(async url => ({ ok: true, json: async () => String(url).endsWith('/control')
            ? { status: 'accepted', job_unit: unit }
            : String(url).endsWith('/auth/ready')
                ? { service: 'aetherflow-api', status: 'ready', database: 'ok' }
                : { job_unit: unit, status: terminal, completed: true, success: terminal === 'succeeded', error: terminal === 'failed' ? 'Activation failed' : '' } }) as Response);
        const view = render(<ServicesTab />);
        const manageButton = screen.getByRole('button', { name: 'Manage AetherFlow API service actions' });
        fireEvent.click(manageButton);
        await act(async () => { fireEvent.click(screen.getByTitle('Restart service')); });
        view.rerender(<ServicesTab />);
        expect(screen.getByTitle('Restart service')).toBeDisabled();
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining(terminal === 'failed' ? 'Activation failed' : 'API readiness confirmed'), terminal === 'failed' ? 'error' : 'success');
        expect(mockedApiFetch.mock.calls.some(([url]) => String(url).endsWith('/auth/ready'))).toBe(terminal === 'succeeded');
        expect(screen.getByTitle('Restart service')).toBeEnabled();
        view.unmount(); expect(jest.getTimerCount()).toBe(0); jest.useRealTimers();
    });
    it('does not re-open an expired update when its POST acknowledgment arrives late', async () => {
        jest.useFakeTimers();
        let resolvePost!: (response: Response) => void;
        mockedApiFetch.mockReturnValue(new Promise<Response>(resolve => { resolvePost = resolve; }));
        const view = render(<ServicesTab />);
        const manageButton = screen.getByRole('button', { name: 'Manage Fixture service actions' });
        fireEvent.click(manageButton);
        await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
        await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
        expect(screen.getByTitle('Restart service')).toBeEnabled();
        await act(async () => { resolvePost({ ok: true, json: async () => ({ job_id: 'accepted-too-late' }) } as Response); });
        expect(screen.getByTitle('Restart service')).toBeEnabled();
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('tracking expired'), 'error');
        view.unmount();
        act(() => jest.runAllTicks());
        expect(jest.getTimerCount()).toBe(0); jest.useRealTimers();
    });
    it.each(['completed', 'failed', 'interrupted', 'unknown'])('waits for a matching update receipt (%s)', async status => {
        mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ job_id: 'accepted', started_at: 'now' }) } as Response);
        const { rerender } = render(<ServicesTab />);
        const manageButton = screen.getByRole('button', { name: 'Manage Fixture service actions' });
        fireEvent.click(manageButton);
        fireEvent.click(screen.getByTitle('Update Fixture to v2.0'));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'old', action: 'update', status: 'completed', started_at: 'old', finished_at: 'old' } }) };
        rerender(<ServicesTab />);
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        expect(screen.getByTitle('Restart service')).toBeDisabled();
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'accepted', action: 'update', status, started_at: 'now', finished_at: 'later', message: status === 'failed' ? 'Installer activation failed' : undefined } }) };
        rerender(<ServicesTab />);
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining(status === 'completed' ? 'completed' : status === 'failed' ? 'Installer activation failed' : 'could not be confirmed'), status === 'completed' ? 'success' : 'error');
        expect(screen.getByTitle('Restart service')).toBeEnabled();
    });
    it('keeps companion status and logs available during another client\'s lifecycle job', () => {
        mockServicesPayload = { Fixture: service({ job_status: 'installing', job_id: 'another-client', started_at: '2026-11-05T00:00:00Z', components: [
            { unit: 'fixture.timer', role: 'timer', status: 'running', configured: true },
            { unit: 'fixture.service', role: 'oneshot', status: 'stopped', configured: true },
        ] }) };
        render(<ServicesTab />);
        const manageButton = screen.getByRole('button', { name: 'Manage Fixture service actions' });
        fireEvent.click(manageButton);
        expect(screen.getByTitle('Restart service')).toBeDisabled();
        expect(screen.getByText('fixture.timer: running (timer)')).toBeInTheDocument();
        expect(screen.getByTitle('View live logs')).toBeEnabled();
        fireEvent.click(screen.getByTitle('View logs for fixture.service'));
        expect(screen.getByTestId('mock-logs-modal')).toHaveAttribute('data-service', 'fixture.service');
    });
    it('renders retained terminal failure on remount and rejects a foreign completion', () => {
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'prior', action: 'update', status: 'interrupted', message: 'API restarted before completion was confirmed.' } }) };
        const { rerender } = render(<ServicesTab />);
        expect(screen.getByRole('status')).toHaveTextContent('API restarted before completion was confirmed');
        expect(mockAddToast).not.toHaveBeenCalled();
        mockServicesPayload = { Fixture: service({ job_status: 'updating', job_id: 'external', started_at: 'now' }) };
        rerender(<ServicesTab />);
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'different', action: 'update', status: 'completed' } }) };
        rerender(<ServicesTab />);
        expect(mockAddToast).not.toHaveBeenCalled();
        mockServicesPayload = { Fixture: service({ last_job: { job_id: 'external', action: 'update', status: 'failed', message: 'External activation failed' } }) };
        rerender(<ServicesTab />);
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('External activation failed'), 'error');
    });
});

describe('Services UI/UX Fleet Triage, Search, Filtering, and Lifecycle Safety', () => {
    let windowOpenSpy: jest.SpyInstance;

    beforeEach(() => {
        mockUserRole = 'admin';
        mockServicesPayload = {};
        mockServicesError = undefined;
        mockServicesIsValidating = false;
        mockServicesIsLoading = false;
        mockAddToast.mockReset();
        mockSetActiveTab.mockReset();
        mockMutateServices.mockReset();
        mockGlobalMutate.mockReset();
        mockLogsModalSpy.mockReset();
        mockedApiFetch.mockReset();
        windowOpenSpy = jest.spyOn(window, 'open').mockImplementation(() => null);
    });

    afterEach(() => {
        windowOpenSpy.mockRestore();
    });

    it('keeps first-load loading separate from an unavailable fleet', () => {
        mockServicesPayload = undefined;
        mockServicesIsLoading = true;

        render(<ServicesTab />);

        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(screen.queryByText('No Services Detected')).not.toBeInTheDocument();
    });

    it('shows a retryable unavailable state instead of a false empty fleet on initial inventory failure', () => {
        mockServicesPayload = undefined;
        mockServicesError = new Error('service API unreachable');

        render(<ServicesTab />);

        expect(screen.getByRole('alert')).toHaveTextContent('Service inventory unavailable');
        expect(screen.getByRole('alert')).toHaveTextContent('an empty fleet cannot be confirmed');
        expect(screen.queryByText('No Services Detected')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Retry service inventory' }));
        expect(mockMutateServices).toHaveBeenCalled();
    });

    it('keeps successful empty inventory distinct from unavailable data', () => {
        mockServicesPayload = {};

        render(<ServicesTab />);

        expect(screen.getByText('No Services Detected')).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('retains the latest WebSocket-updated service snapshot when a background refresh fails', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.1.0',
                uptime: '3h',
                managed_by: 'systemd',
                default_port: 8989,
            },
        };
        mockServicesError = new Error('refresh request failed');

        render(<ServicesTab />);

        expect(screen.getByText(/Service refresh failed/)).toHaveAttribute('role', 'status');
        expect(screen.getByText(/newer WebSocket service updates remain visible/)).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toHaveTextContent('v4.1.0');
        expect(screen.getByRole('button', { name: 'Running (1)' })).toBeInTheDocument();
        expect(screen.queryByText('No Services Detected')).not.toBeInTheDocument();
    });

    it('handles search, status filters, reset controls, and empty states accurately', () => {
        mockServicesPayload = {
            'AetherFlow API': {
                id: 'aetherflow-api',
                process: 'aetherflow-api',
                status: 'running',
                version: '4.0.0',
                uptime: '2d',
                managed_by: 'systemd',
            },
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                latest_version: '4.1.0',
                update_available: true,
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 8989,
                public_domain: 'sonarr.internal.net',
            },
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'stopped',
                version: '5.0.0',
                uptime: '-',
                managed_by: 'systemd',
                default_port: 7878,
            },
            'Calibre-Web': {
                id: 'calibreweb',
                process: 'calibreweb',
                status: 'stopped',
                version: '',
                uptime: '-',
                managed_by: 'systemd',
                default_port: 8083,
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip install failed: wheels missing',
                },
            },
        };

        render(<ServicesTab />);

        expect(screen.getByText('4 Total')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Running (2)' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Stopped (1)' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Needs Attention \(1\)/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Updates \(1\)/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Check Updates & Sync' })).toBeInTheDocument();
        expect(screen.queryByText('2 Running')).not.toBeInTheDocument();

        const attentionRegion = screen.getByRole('region', { name: 'Fleet attention required' });
        expect(attentionRegion).toHaveTextContent('Calibre-Web — Install failed \u00b7 Recovery unconfirmed');

        const showAttentionButton = screen.getByRole('button', { name: 'Filter affected service' });
        expect(showAttentionButton).toBeInTheDocument();
        fireEvent.click(showAttentionButton);
        expect(screen.getByText('Showing 1 of 4 services')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Show all services' })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Show all services' }));

        const searchInput = screen.getByPlaceholderText('Name, domain or port');
        expect(searchInput).toHaveAttribute('aria-label', 'Search services by name, domain, port');
        fireEvent.change(searchInput, { target: { value: 'calibre' } });

        expect(screen.getByText('Showing 1 of 4 services')).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Calibre-Web service' })).toBeInTheDocument();
        expect(screen.queryByRole('article', { name: 'Sonarr service' })).not.toBeInTheDocument();

        fireEvent.click(screen.getAllByRole('button', { name: 'Reset filters' })[0]);
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Radarr service' })).toBeInTheDocument();

        fireEvent.change(searchInput, { target: { value: 'sonarr.internal.net' } });
        expect(screen.getByText('Showing 1 of 4 services')).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();
        expect(screen.queryByRole('article', { name: 'Radarr service' })).not.toBeInTheDocument();

        fireEvent.click(screen.getAllByRole('button', { name: 'Reset filters' })[0]);

        fireEvent.click(screen.getByRole('button', { name: 'Running (2)' }));
        expect(screen.getByText('Showing 2 of 4 services')).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'AetherFlow API service' })).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();
        expect(screen.queryByRole('article', { name: 'Radarr service' })).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Needs Attention \(1\)/i }));
        expect(screen.getByText('Showing 1 of 4 services')).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Calibre-Web service' })).toBeInTheDocument();
        expect(screen.queryByRole('article', { name: 'Sonarr service' })).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Updates \(1\)/i }));
        expect(screen.getByText('Showing 1 of 4 services')).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();

        fireEvent.change(searchInput, { target: { value: 'unknown-missing-service' } });
        expect(screen.getByText('No matching services found')).toBeInTheDocument();
        fireEvent.click(screen.getAllByRole('button', { name: 'Reset filters' })[0]);
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();

        fireEvent.click(screen.getByTitle('Card grid view'));
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();
        fireEvent.click(screen.getByTitle('Compact list view'));
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toBeInTheDocument();
    });

    it('prioritizes failure inspection for failed installs with contextual unconfirmed recovery warning and guarded secondary start', () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibreweb',
                process: 'calibreweb',
                status: 'stopped',
                version: '',
                uptime: 'stopped',
                managed_by: 'systemd',
                default_port: 8083,
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip install failed: wheels missing',
                },
            },
        };

        const { rerender } = render(<ServicesTab />);

        const calibreArticle = screen.getByRole('article', { name: 'Calibre-Web service' });
        expect(within(calibreArticle).getByText('Not running')).toBeInTheDocument();

        const statusNotice = screen.getByRole('status');
        expect(statusNotice).toHaveTextContent('Install failed — rollback/recovery unconfirmed');
        expect(statusNotice).toHaveTextContent('pip install failed: wheels missing');

        const inspectButtons = screen.getAllByRole('button', { name: /Review installation failure/i });
        expect(inspectButtons.length).toBeGreaterThanOrEqual(1);

        fireEvent.click(inspectButtons[0]);
        expect(mockLogsModalSpy).toHaveBeenCalledWith(
            expect.objectContaining({
                serviceName: 'calibreweb',
            })
        );

        const guardedButton = screen.getByRole('button', { name: /Start Service \(Guarded\)/i });
        expect(guardedButton).toBeInTheDocument();
        expect(guardedButton).toHaveAttribute(
            'title',
            expect.stringContaining('warning: install failed and recovery state is unconfirmed')
        );

        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibreweb',
                process: 'calibreweb',
                status: 'running',
                version: '',
                uptime: '1m',
                managed_by: 'systemd',
                default_port: 8083,
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip install failed: wheels missing',
                },
            },
        };
        rerender(<ServicesTab />);

        expect(screen.getByRole('status')).toHaveTextContent('Install failed — rollback/recovery unconfirmed');
    });

    it('distinguishes headless core endpoints from valid browser endpoints and guards destructive stop with confirmation', async () => {
        mockServicesPayload = {
            'AetherFlow API': {
                id: 'aetherflow-api',
                process: 'aetherflow-api',
                status: 'running',
                version: '4.0.0',
                uptime: '1d',
                managed_by: 'systemd',
            },
            'AetherFlow Frontend': {
                id: 'aetherflow-frontend',
                process: 'aetherflow-frontend',
                status: 'running',
                version: '4.0.0',
                uptime: '1d',
                managed_by: 'systemd',
            },
        };
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ message: 'ok' }),
        } as Response);

        render(<ServicesTab browserOrigin={{ protocol: 'http:', hostname: 'seedbox.local' }} />);

        const apiArticle = screen.getByRole('article', { name: 'AetherFlow API service' });
        const frontendArticle = screen.getByRole('article', { name: 'AetherFlow Frontend service' });

        expect(within(apiArticle).getByText('Headless')).toBeInTheDocument();
        expect(within(apiArticle).queryByRole('button', { name: /Web UI/i })).not.toBeInTheDocument();

        const frontendWebUi = within(frontendArticle).getByRole('button', { name: /Web UI/i });
        expect(frontendWebUi).toBeInTheDocument();
        fireEvent.click(frontendWebUi);
        expect(windowOpenSpy).toHaveBeenCalledWith('http://seedbox.local/', '_blank');

        const manageButton = within(apiArticle).getByRole('button', { name: 'Manage AetherFlow API service actions' });
        fireEvent.click(manageButton);

        const stopButton = within(apiArticle).getByRole('menuitem', { name: 'Stop AetherFlow API service' });
        fireEvent.click(stopButton);

        const stopDialog = screen.getByRole('dialog');
        expect(stopDialog).toBeInTheDocument();
        expect(stopDialog).toHaveTextContent('Stop AetherFlow API?');

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();

        fireEvent.click(manageButton);
        const reopenedStopButton = within(apiArticle).getByRole('menuitem', { name: 'Stop AetherFlow API service' });
        fireEvent.click(reopenedStopButton);
        fireEvent.click(screen.getByRole('button', { name: 'Confirm Stop' }));

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/services/aetherflow-api/control',
                expect.objectContaining({
                    method: 'POST',
                    body: JSON.stringify({
                        action: 'stop',
                        managed_by: 'systemd',
                        process: 'aetherflow-api',
                    }),
                })
            );
        });
    });

    it('renders technical slug aetherflow-frontend in full alongside dominant human name and keeps list action targets contained', () => {
        mockServicesPayload = {
            'aetherflow-frontend': {
                id: 'aetherflow-frontend',
                process: 'aetherflow-frontend',
                status: 'running',
                version: '4.0.0',
                uptime: '3d',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);

        const frontendArticle = screen.getByRole('article', { name: 'aetherflow-frontend service' });
        expect(within(frontendArticle).getByText('AetherFlow Frontend')).toBeInTheDocument();
        const technicalSlug = within(frontendArticle).getByText('aetherflow-frontend');
        expect(technicalSlug).toBeInTheDocument();
        expect(technicalSlug).toHaveClass('break-all');

        const actionButtons = within(frontendArticle).getAllByRole('button');
        expect(actionButtons.length).toBeGreaterThanOrEqual(3);
        actionButtons.forEach((buttonElement) => {
            expect(buttonElement.className).toMatch(/min-h-\[(?:40|44)px\]/);
        });
    });

    it('uses adaptive w-auto for actions wrapper in list view to prevent forced full-width row splitting', () => {
        mockServicesPayload = {
            'aetherflow-frontend': {
                id: 'aetherflow-frontend',
                process: 'aetherflow-frontend',
                status: 'running',
                version: '4.0.0',
                uptime: '3d',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);

        const frontendArticle = screen.getByRole('article', { name: 'aetherflow-frontend service' });
        const logsButton = within(frontendArticle).getByRole('button', { name: /Logs/i });
        const actionsContainer = logsButton.parentElement;
        expect(actionsContainer).toBeInTheDocument();
        expect(actionsContainer).toHaveClass('sm:w-auto');
        expect(actionsContainer).toHaveClass('grid', 'grid-cols-3');
        expect(actionsContainer?.className).toContain('@[1250px]:w-[280px]');
    });

    it('differentiates routine inspection from lifecycle mutations with restrained cues and destructive rose outline', () => {
        mockServicesPayload = {
            'AetherFlow API': {
                id: 'aetherflow-api',
                process: 'aetherflow-api',
                status: 'running',
                version: '4.0.0',
                uptime: '2d',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);

        const serviceArticle = screen.getByRole('article', { name: 'AetherFlow API service' });
        const logsButton = within(serviceArticle).getByRole('button', { name: /Logs/i });
        const manageButton = within(serviceArticle).getByRole('button', { name: 'Manage AetherFlow API service actions' });

        expect(logsButton).toHaveClass('bg-slate-800/90');
        expect(manageButton).toHaveClass('bg-slate-800/90');

        expect(within(serviceArticle).queryByRole('menuitem', { name: /Restart/i })).not.toBeInTheDocument();
        expect(within(serviceArticle).queryByRole('menuitem', { name: /Stop/i })).not.toBeInTheDocument();

        fireEvent.click(manageButton);

        const restartButton = within(serviceArticle).getByRole('menuitem', { name: /Restart/i });
        const stopButton = within(serviceArticle).getByRole('menuitem', { name: /Stop/i });

        expect(restartButton).toHaveClass('bg-amber-500/10');
        expect(restartButton).toHaveClass('text-amber-300/90');
        expect(stopButton).toHaveClass('bg-rose-500/15');
        expect(stopButton).toHaveClass('text-rose-300');
    });

    it('aligns metadata columns so labels and values share respective baselines with inline centered port controls', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 8989,
                active_port: 8989,
            },
        };

        render(<ServicesTab />);

        const sonarrArticle = screen.getByRole('article', { name: 'Sonarr service' });
        const versionLabel = within(sonarrArticle).getByText('Version');
        const portLabel = within(sonarrArticle).getByText('Port');
        const uptimeLabel = within(sonarrArticle).getByText('Uptime');

        expect(versionLabel).toHaveClass('@[1250px]:hidden');
        expect(portLabel).toHaveClass('@[1250px]:hidden');
        expect(uptimeLabel).toHaveClass('@[1250px]:hidden');

        const portValueContainer = within(sonarrArticle).getByText(':8989').parentElement;
        expect(portValueContainer).toHaveClass('min-h-[40px]');
        expect(portValueContainer).toHaveClass('flex');
        expect(portValueContainer).toHaveClass('items-center');

        const accessButton = within(portValueContainer!).getByRole('button', { name: 'Connection details for Sonarr' });
        expect(accessButton).toBeInTheDocument();
        expect(accessButton).toHaveClass('min-h-[44px]', 'sm:min-h-[40px]');

        fireEvent.click(accessButton);
        const settingsItem = screen.getByRole('menuitem', { name: 'Settings for Sonarr' });
        expect(settingsItem).toBeInTheDocument();
        expect(settingsItem).toHaveClass('min-h-[40px]');
    });

    it('renders accessible inline sync button in header with compact mobile text and full desktop label', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                uptime: '1d',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);

        const syncButton = screen.getByRole('button', { name: 'Check Updates & Sync' });
        expect(syncButton).toBeInTheDocument();
        expect(within(syncButton).getByText('Sync')).toHaveClass('sm:hidden');
        expect(within(syncButton).getByText('Check Updates & Sync')).toHaveClass('hidden', 'sm:inline');
    });

    it('enforces compact metadata and accessible secondary lifecycle disclosure menu', () => {
        mockServicesPayload = {
            Jellyfin: {
                id: 'jellyfin',
                process: 'jellyfin',
                status: 'running',
                version: '10.9.0',
                uptime: '3d',
                managed_by: 'systemd',
                default_port: 8096,
                active_port: 8096,
            },
        };

        render(<ServicesTab />);

        const jellyfinArticle = screen.getByRole('article', { name: 'Jellyfin service' });
        const manageTrigger = within(jellyfinArticle).getByRole('button', { name: 'Manage Jellyfin service actions' });

        expect(manageTrigger).toHaveAttribute('aria-haspopup', 'menu');
        expect(manageTrigger).toHaveAttribute('aria-expanded', 'false');
        expect(within(jellyfinArticle).queryByRole('menu')).not.toBeInTheDocument();

        fireEvent.click(manageTrigger);
        expect(manageTrigger).toHaveAttribute('aria-expanded', 'true');
        const menuElement = within(jellyfinArticle).getByRole('menu', { name: 'Jellyfin service actions' });
        expect(menuElement).toBeInTheDocument();

        const restartItem = within(menuElement).getByRole('menuitem', { name: 'Restart Jellyfin service' });
        const stopItem = within(menuElement).getByRole('menuitem', { name: 'Stop Jellyfin service' });
        expect(restartItem).toHaveClass('bg-amber-500/10');
        expect(stopItem).toHaveClass('bg-rose-500/15');

        fireEvent.click(manageTrigger);
        expect(manageTrigger).toHaveAttribute('aria-expanded', 'false');
        expect(within(jellyfinArticle).queryByRole('menu')).not.toBeInTheDocument();
    });

    it('provides accessible native details expansion on mobile list without duplicate interactive buttons', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
        };

        render(<ServicesTab />);

        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        const detailsToggle = within(radarrArticle).getByRole('button', { name: 'Toggle details for Radarr' });
        expect(detailsToggle).toHaveClass('sm:hidden');
        expect(detailsToggle).toHaveAttribute('aria-expanded', 'false');

        const accessButtons = within(radarrArticle).getAllByRole('button', { name: 'Connection details for Radarr' });
        expect(accessButtons).toHaveLength(1);

        fireEvent.click(detailsToggle);
        expect(detailsToggle).toHaveAttribute('aria-expanded', 'true');

        fireEvent.click(detailsToggle);
        expect(detailsToggle).toHaveAttribute('aria-expanded', 'false');
    });

    it('maintains strict permission invariants and keeps failure diagnostics prominent', () => {
        mockServicesPayload = {
            BrokenApp: {
                id: 'brokenapp',
                process: 'brokenapp',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'Dependency download failed with exit code 1',
                },
            },
        };

        render(<ServicesTab />);

        const brokenArticle = screen.getByRole('article', { name: 'BrokenApp service' });
        expect(within(brokenArticle).getByText(/Install failed — rollback\/recovery unconfirmed/i)).toBeInTheDocument();
        expect(within(brokenArticle).getByText(/Dependency download failed with exit code 1/i)).toBeInTheDocument();

        const inspectFailureButton = within(brokenArticle).getByRole('button', { name: /Review installation failure/i });
        const guardedStartButton = within(brokenArticle).getByRole('button', { name: /Start Service \(Guarded\)/i });

        expect(inspectFailureButton).toBeVisible();
        expect(guardedStartButton).toBeVisible();
        expect(within(brokenArticle).queryByRole('button', { name: /Manage.*actions/i })).not.toBeInTheDocument();
    });

    it('guarantees five-digit port containment with network and settings on a single baseline', () => {
        mockServicesPayload = {
            Audiobookshelf: {
                id: 'audiobookshelf',
                process: 'audiobookshelf',
                status: 'running',
                version: '2.8.0',
                uptime: '10d',
                managed_by: 'systemd',
                default_port: 13378,
                active_port: 13378,
            },
        };

        render(<ServicesTab />);

        const audiobookshelfArticle = screen.getByRole('article', { name: 'Audiobookshelf service' });
        const portContainer = within(audiobookshelfArticle).getByText(':13378').parentElement;

        expect(portContainer).toHaveClass('flex-wrap');
        expect(portContainer).toHaveClass('@[1250px]:flex-nowrap');
        expect(portContainer).toHaveClass('min-h-[40px]');

        const portColumn = portContainer?.parentElement;
        expect(portColumn).toHaveClass('@[1250px]:w-[180px]');
        expect(portColumn).toHaveClass('relative');
        expect(portColumn).toHaveAttribute('data-access-menu', 'Audiobookshelf');

        const accessButton = within(portContainer!).getByRole('button', { name: 'Connection details for Audiobookshelf' });
        expect(accessButton).toBeInTheDocument();
        expect(within(accessButton).getByText('Connection')).toBeInTheDocument();
        expect(accessButton).toHaveClass('min-h-[44px]', 'sm:min-h-[40px]');

        fireEvent.click(accessButton);
        const accessMenu = screen.getByRole('menu', { name: 'Connection details for Audiobookshelf' });
        expect(accessMenu).toBeInTheDocument();
        expect(accessMenu.parentElement).toBe(portColumn);
        expect(accessMenu).toHaveClass('absolute', 'left-0', 'top-full');

        const ingressButton = screen.getByRole('menuitem', { name: 'Ingress and deployment for Audiobookshelf' });
        const settingsButton = screen.getByRole('menuitem', { name: 'Settings for Audiobookshelf' });

        expect(ingressButton).toBeInTheDocument();
        expect(settingsButton).toBeInTheDocument();
        expect(ingressButton).toHaveClass('min-h-[40px]');
        expect(settingsButton).toHaveClass('min-h-[40px]');

        fireEvent.keyDown(window, { key: 'Escape' });
        expect(screen.queryByRole('menu', { name: 'Connection details for Audiobookshelf' })).not.toBeInTheDocument();

        fireEvent.click(accessButton);
        expect(screen.getByRole('menu', { name: 'Connection details for Audiobookshelf' })).toBeInTheDocument();

        fireEvent.mouseDown(document.body);
        expect(screen.queryByRole('menu', { name: 'Connection details for Audiobookshelf' })).not.toBeInTheDocument();
    });

    it('restores the stable Connection trigger after dismissing ingress opened from its menu', () => {
        mockServicesPayload = {
            Sonarr: { id: 'sonarr', process: 'sonarr', status: 'running', version: '4.0', uptime: '2h', managed_by: 'systemd', default_port: 8989 },
        };
        render(<ServicesTab />);
        const article = screen.getByRole('article', { name: 'Sonarr service' });
        const connectionTrigger = within(article).getByRole('button', { name: 'Connection details for Sonarr' });
        connectionTrigger.focus();
        fireEvent.click(connectionTrigger);
        fireEvent.click(screen.getByRole('menuitem', { name: 'Ingress and deployment for Sonarr' }));
        const dialog = screen.getByRole('dialog', { name: 'sonarr Ingress & Deploy' });
        expect(dialog.contains(document.activeElement)).toBe(true);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'sonarr Ingress & Deploy' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(connectionTrigger);
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('retains running daemon controls alongside failed-install warnings and guards disruptive actions', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr', process: 'sonarr', status: 'running', version: '4.0', uptime: '2h', managed_by: 'systemd', default_port: 8989,
                last_job: { action: 'install', status: 'failed', message: 'installation failed' },
            },
        };
        render(<ServicesTab />);
        const article = screen.getByRole('article', { name: 'Sonarr service' });
        expect(article).toHaveTextContent('Install failed — rollback/recovery unconfirmed');
        expect(article).toHaveTextContent(/running/i);
        expect(article).toHaveTextContent('2h');
        expect(article).not.toHaveTextContent('Not running');
        expect(within(article).queryByRole('button', { name: /Start Service \(Guarded\)/i })).not.toBeInTheDocument();
        expect(within(article).getByRole('button', { name: /Web UI/i })).toBeEnabled();
        const manageTrigger = within(article).getByRole('button', { name: 'Manage Sonarr service actions' });
        fireEvent.click(manageTrigger);
        fireEvent.click(within(article).getByRole('menuitem', { name: 'Restart Sonarr service' }));
        const restartDialog = screen.getByRole('dialog', { name: 'Restart Sonarr?' });
        expect(restartDialog).toHaveTextContent('recovery is unconfirmed');
        expect(document.activeElement).toBe(within(restartDialog).getByRole('button', { name: 'Cancel' }));
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(document.activeElement).toBe(manageTrigger);
        fireEvent.click(manageTrigger);
        fireEvent.click(within(article).getByRole('menuitem', { name: 'Stop Sonarr service' }));
        expect(screen.getByRole('dialog', { name: 'Stop Sonarr?' })).toBeInTheDocument();
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(mockedApiFetch).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Card grid view' }));
        const card = screen.getByRole('article', { name: 'Sonarr service' });
        expect(card).toHaveTextContent('Install failed — rollback/recovery unconfirmed');
        expect(card).toHaveTextContent('2h');
        expect(within(card).getByRole('button', { name: 'Web UI' })).toBeEnabled();
        const restartButton = within(card).getByRole('button', { name: 'Restart' });
        restartButton.focus();
        fireEvent.click(restartButton);
        expect(screen.getByRole('dialog', { name: 'Restart Sonarr?' })).toBeInTheDocument();
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(document.activeElement).toBe(restartButton);
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('enforces bounded mobile actions grid with at most WebUI, Logs, Manage and spans Logs for headless apps', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
            HeadlessApp: {
                id: 'headlessapp',
                process: 'af-headless',
                status: 'running',
                version: '1.0.0',
                uptime: '1d',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);

        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        const radarrWebUi = within(radarrArticle).getByRole('button', { name: /^Web UI$/i });
        const radarrLogs = within(radarrArticle).getByRole('button', { name: /^Logs$/i });
        const radarrManage = within(radarrArticle).getByRole('button', { name: /Manage Radarr service actions/i });

        expect(radarrWebUi).toBeInTheDocument();
        expect(radarrLogs).toBeInTheDocument();
        expect(radarrManage).toBeInTheDocument();

        const radarrFooter = radarrLogs.parentElement;
        expect(radarrFooter).toHaveClass('grid', 'grid-cols-3');

        const headlessArticle = screen.getByRole('article', { name: 'HeadlessApp service' });
        const headlessLogs = within(headlessArticle).getByRole('button', { name: /^Logs$/i });
        const headlessManage = within(headlessArticle).getByRole('button', { name: /Manage HeadlessApp service actions/i });

        expect(within(headlessArticle).queryByRole('button', { name: /^Web UI$/i })).not.toBeInTheDocument();
        expect(headlessLogs).toHaveClass('col-span-2');
        expect(headlessManage).toBeInTheDocument();
    });

    it('keeps collapsed mobile rows compact by deferring secondary managed-by and domain labels to expanded details', () => {
        mockServicesPayload = {
            'AetherFlow API': {
                id: 'aetherflow-api',
                process: 'aetherflow-api',
                status: 'running',
                version: '4.0.0',
                uptime: '2d',
                managed_by: 'systemd',
                public_domain: 'api.seedbox.internal',
            },
        };

        render(<ServicesTab />);

        const apiArticle = screen.getByRole('article', { name: 'AetherFlow API service' });
        const detailsToggle = within(apiArticle).getByRole('button', { name: 'Toggle details for AetherFlow API' });

        expect(detailsToggle).toHaveAttribute('aria-expanded', 'false');

        const systemdBadges = within(apiArticle).getAllByText('systemd');
        expect(systemdBadges).toHaveLength(1);
        expect(systemdBadges[0]).toHaveClass('hidden', 'sm:inline-flex');

        expect(within(apiArticle).queryByText('api.seedbox.internal')).not.toBeInTheDocument();

        fireEvent.click(detailsToggle);
        expect(detailsToggle).toHaveAttribute('aria-expanded', 'true');

        const expandedSystemdBadges = within(apiArticle).getAllByText('systemd');
        expect(expandedSystemdBadges.length).toBeGreaterThanOrEqual(2);
        const mobileSystemdBadge = expandedSystemdBadges.find((element) => !element.className.includes('hidden sm:inline-flex'));
        expect(mobileSystemdBadge).toBeDefined();

        const expandedDomainBadges = within(apiArticle).getAllByText('api.seedbox.internal');
        expect(expandedDomainBadges.length).toBeGreaterThanOrEqual(1);
        const mobileDomainBadge = expandedDomainBadges.find((element) => !element.className.includes('hidden sm:inline-flex'));
        expect(mobileDomainBadge).toBeDefined();
    });

    it('provides accessible mobile filter summary disclosure and truthful counts', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                default_port: 8989,
                active_port: 8989,
            },
        };

        render(<ServicesTab />);

        const mobileFilterToggle = screen.getByRole('button', { name: /Status filter: All \(2\)/i });
        expect(mobileFilterToggle).toBeInTheDocument();
        expect(mobileFilterToggle).toHaveAttribute('aria-expanded', 'false');
        expect(mobileFilterToggle).toHaveAttribute('aria-controls', 'services-status-filter-group');

        fireEvent.click(mobileFilterToggle);
        expect(mobileFilterToggle).toHaveAttribute('aria-expanded', 'true');

        const runningFilter = screen.getByRole('button', { name: 'Running (1)' });
        fireEvent.click(runningFilter);

        expect(screen.getByRole('button', { name: /Status filter: Running \(1\)/i })).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Radarr service' })).toBeInTheDocument();
        expect(screen.queryByRole('article', { name: 'Sonarr service' })).not.toBeInTheDocument();
    });

    it('enforces fixed laptop metadata tracks and single-baseline alignment', () => {
        mockServicesPayload = {
            Audiobookshelf: {
                id: 'audiobookshelf',
                process: 'audiobookshelf',
                status: 'running',
                version: '2.8.0-long-build-identifier',
                uptime: '10d',
                managed_by: 'systemd',
                default_port: 13378,
                active_port: 13378,
            },
        };

        render(<ServicesTab />);

        const serviceArticle = screen.getByRole('article', { name: 'Audiobookshelf service' });
        const versionContainer = within(serviceArticle).getByText(/2\.8\.0-long-build-identifier/).closest('div[class*="sm:w-[130px]"]');
        expect(versionContainer).toBeInTheDocument();
        expect(versionContainer).toHaveClass('sm:w-[130px]', 'shrink-0');

        const portContainer = within(serviceArticle).getByText(':13378').closest('div[class*="sm:w-[180px]"]');
        expect(portContainer).toBeInTheDocument();
        expect(portContainer).toHaveClass('sm:w-[180px]', 'shrink-0');

        const uptimeContainer = within(serviceArticle).getByText('10d').closest('div[class*="sm:w-[90px]"]');
        expect(uptimeContainer).toBeInTheDocument();
        expect(uptimeContainer).toHaveClass('sm:w-[90px]', 'shrink-0');

        const metadataRow = versionContainer?.parentElement;
        expect(metadataRow).toHaveClass('sm:flex-nowrap', 'shrink-0');

        expect(versionContainer).toHaveClass('@[960px]:w-[100px]');
        expect(portContainer).toHaveClass('@[960px]:w-[140px]');
        expect(uptimeContainer).toHaveClass('@[960px]:w-[65px]');

        const actionsContainer = within(serviceArticle).getByRole('button', { name: /Logs/i }).closest('div[class*="@[960px]:w-[280px]"]');
        expect(actionsContainer).toBeInTheDocument();
        expect(actionsContainer).toHaveClass('@[960px]:w-[280px]', '@[1250px]:w-[280px]');

        expect(serviceArticle.className).toContain('@[960px]:grid');
        expect(serviceArticle.className).toContain('@[960px]:grid-cols-[minmax(180px,1fr)_95px_100px_140px_65px_280px]');
        expect(serviceArticle.className).toContain('@[1250px]:grid-cols-[minmax(280px,360px)_120px_130px_minmax(180px,220px)_90px_minmax(280px,auto)]');
    });

    it('renders compact attention banner with truthful recovery context and primary action hierarchy', () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibre-web',
                process: 'calibre-web',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip dependencies could not resolve packages',
                },
            },
            Jellyfin: {
                id: 'jellyfin',
                process: 'jellyfin',
                status: 'running',
                version: '10.9.0',
                uptime: '2d',
                managed_by: 'systemd',
                default_port: 8096,
                active_port: 8096,
            },
        };

        render(<ServicesTab />);

        const attentionBanner = screen.getByRole('region', { name: 'Fleet attention required' });
        expect(attentionBanner).toBeInTheDocument();
        expect(within(attentionBanner).getByText('Calibre-Web')).toBeInTheDocument();
        expect(within(attentionBanner).getByText(/Install failed · Recovery unconfirmed/i)).toBeInTheDocument();

        const calibreArticle = screen.getByRole('article', { name: 'Calibre-Web service' });
        expect(within(calibreArticle).getByText(/Install failed — rollback\/recovery unconfirmed/i)).toBeInTheDocument();
        expect(within(calibreArticle).getByRole('button', { name: /Review installation failure/i })).toBeInTheDocument();
        expect(within(calibreArticle).getByRole('button', { name: /Start Service \(Guarded\)/i })).toBeInTheDocument();

        const jellyfinArticle = screen.getByRole('article', { name: 'Jellyfin service' });
        const webUiButton = within(jellyfinArticle).getByRole('button', { name: 'Web UI' });
        const logsButton = within(jellyfinArticle).getByRole('button', { name: 'Logs' });
        const manageButton = within(jellyfinArticle).getByRole('button', { name: 'Manage Jellyfin service actions' });

        expect(webUiButton).toHaveClass('bg-indigo-600/20', 'text-indigo-200', 'border-indigo-500/40');
        expect(logsButton).toHaveClass('bg-slate-800/90', 'text-slate-200', 'border-slate-700/80');
        expect(manageButton).toHaveClass('bg-slate-800/90', 'text-slate-200', 'border-slate-700/80');
    });

    it('brightens locally useful identifiers, version, uptime, and rose error headings', () => {
        mockServicesPayload = {
            'aetherflow-api': {
                id: 'aetherflow-api',
                process: 'aetherflow-api',
                status: 'error',
                status_message: 'Process exited unexpectedly with code 1',
                version: '4.0.0',
                uptime: 'stopped',
                managed_by: 'systemd',
                default_port: 3000,
                active_port: 3000,
            },
        };

        render(<ServicesTab />);

        const apiArticle = screen.getByRole('article', { name: 'aetherflow-api service' });
        const identifierElement = within(apiArticle).getByText('aetherflow-api');
        expect(identifierElement).toHaveClass('text-slate-300');

        const versionElement = within(apiArticle).getByText('v4.0.0');
        expect(versionElement).toHaveClass('text-slate-300');

        const uptimeElement = within(apiArticle).getByText('Not running');
        expect(uptimeElement).toHaveClass('text-slate-300');

        const errorHeading = within(apiArticle).getByText('error');
        expect(errorHeading).toHaveClass('text-rose-300');

        const portLabel = within(apiArticle).getByText('Port');
        expect(portLabel).toHaveClass('text-slate-400');

        const runtimePill = within(apiArticle).getByText('systemd');
        expect(runtimePill).toHaveClass('text-slate-300');
    });

    it('relocates primary failure diagnostic to a full-width row below identity and status before actions', () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibre-web',
                process: 'calibre-web',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip dependencies could not resolve packages',
                },
            },
        };

        render(<ServicesTab />);

        const calibreArticle = screen.getByRole('article', { name: 'Calibre-Web service' });
        const diagnosticBlock = within(calibreArticle).getByRole('status');

        expect(diagnosticBlock).toHaveClass('w-full');
        expect(diagnosticBlock).toHaveClass('@[1250px]:col-span-full');
        expect(diagnosticBlock).toHaveTextContent('Install failed — rollback/recovery unconfirmed');
        expect(diagnosticBlock).toHaveTextContent('pip dependencies could not resolve packages');

        const failureExplanation = within(diagnosticBlock).getByText('pip dependencies could not resolve packages');
        expect(failureExplanation).toHaveClass('text-sm', 'text-slate-200');

        const identityName = within(calibreArticle).getByText('Calibre-Web');
        const identityContainer = identityName.closest('div.min-w-0.flex-1');
        expect(within(identityContainer as HTMLElement).queryByRole('status')).not.toBeInTheDocument();

        const inspectButton = within(calibreArticle).getByRole('button', { name: /Review installation failure/i });
        const guardedStartButton = within(calibreArticle).getByRole('button', { name: /Start Service \(Guarded\)/i });
        expect(inspectButton).toBeInTheDocument();
        expect(guardedStartButton).toBeInTheDocument();
    });

    it('enforces minimum touch target dimensions on view mode toggles and reset filter controls', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
        };

        render(<ServicesTab />);

        const listModeButton = screen.getByRole('button', { name: /Compact list view/i });
        const cardModeButton = screen.getByRole('button', { name: /Card grid view/i });

        expect(listModeButton).toHaveClass('min-w-[44px]');
        expect(listModeButton).toHaveClass('min-h-[44px]');
        expect(cardModeButton).toHaveClass('min-w-[44px]');
        expect(cardModeButton).toHaveClass('min-h-[44px]');

        const searchInput = screen.getByRole('textbox', { name: 'Search services by name, domain, port' });
        fireEvent.change(searchInput, { target: { value: 'nonexistent-service' } });

        const resetButtons = screen.getAllByRole('button', { name: 'Reset filters' });
        expect(resetButtons).toHaveLength(2);
        for (const resetButton of resetButtons) {
            expect(resetButton).toHaveClass('min-w-[44px]');
            expect(resetButton).toHaveClass('min-h-[44px]');
        }
    });

    it('balances failed-service actions in 2-column mobile layout and reflows identity on narrow screens without ellipsis', () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibre-web',
                process: 'calibre-web',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip dependencies could not resolve packages',
                },
            },
        };

        render(<ServicesTab />);

        const calibreArticle = screen.getByRole('article', { name: 'Calibre-Web service' });
        const titleElement = within(calibreArticle).getByText('Calibre-Web');
        expect(titleElement).toHaveClass('break-words');
        expect(titleElement).not.toHaveClass('sm:truncate');

        const identityHeader = titleElement.closest('div[class*="grid-cols-[1fr_auto]"]');
        expect(identityHeader).toBeInTheDocument();

        const inspectButton = within(calibreArticle).getByRole('button', { name: /Review installation failure/i });
        const guardedStartButton = within(calibreArticle).getByRole('button', { name: /Start Service \(Guarded\)/i });

        expect(inspectButton).toHaveClass('min-h-[44px]');
        expect(guardedStartButton).toHaveClass('min-h-[44px]');

        const statusBlock = within(calibreArticle).getByRole('status');
        expect(statusBlock).not.toContainElement(inspectButton);
        expect(statusBlock).toContainElement(guardedStartButton);
    });

    it('renders filter count badge with text-xs (>= 12px)', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
        };

        render(<ServicesTab />);

        const mobileFilterToggle = screen.getByRole('button', { name: /Status filter: All/i });
        const countBadge = within(mobileFilterToggle).getByText('1');
        expect(countBadge).toHaveClass('text-xs');
    });

    it('houses single semantic recovery actions in full-width failure diagnostic and preserves >=44px touch targets', () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibre-web',
                process: 'calibre-web',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip install failed: wheels missing',
                },
            },
        };

        render(<ServicesTab />);

        const calibreArticle = screen.getByRole('article', { name: 'Calibre-Web service' });
        const inspectButtons = within(calibreArticle).getAllByRole('button', { name: /Review installation failure/i });
        const guardedButtons = within(calibreArticle).getAllByRole('button', { name: /Start Service \(Guarded\)/i });

        expect(inspectButtons).toHaveLength(1);
        expect(guardedButtons).toHaveLength(1);

        const statusBlock = within(calibreArticle).getByRole('status');
        expect(statusBlock).not.toContainElement(inspectButtons[0]);
        expect(statusBlock).toContainElement(guardedButtons[0]);

        expect(inspectButtons[0]).toHaveClass('min-h-[44px]');
        expect(guardedButtons[0]).toHaveClass('min-h-[44px]');

        const detailsToggle = within(calibreArticle).getByRole('button', { name: /Toggle details for Calibre-Web/i });
        expect(detailsToggle).toHaveClass('min-h-[44px]');

        expect(within(calibreArticle).queryByText(/Recovery actions below/i)).not.toBeInTheDocument();
        const failureFooter = guardedButtons[0].closest('div[class*="justify-end"]');
        expect(failureFooter).toBeInTheDocument();
        expect(failureFooter).toHaveClass('justify-end');
    });

    it('enforces >=12px text-xs and high contrast on table headings and metadata labels', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
        };

        render(<ServicesTab />);

        const tableHeadings = screen.getAllByText('Port & Access');
        for (const headingElement of tableHeadings) {
            expect(headingElement.parentElement).toHaveClass('text-slate-300');
            expect(headingElement.parentElement).toHaveClass('text-xs');
        }

        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        const versionLabel = within(radarrArticle).getByText('Version');
        const portLabel = within(radarrArticle).getByText('Port');
        const uptimeLabel = within(radarrArticle).getByText('Uptime');

        expect(versionLabel).toHaveClass('text-slate-400', 'text-xs');
        expect(portLabel).toHaveClass('text-slate-400', 'text-xs');
        expect(uptimeLabel).toHaveClass('text-slate-400', 'text-xs');

        const systemdBadge = within(radarrArticle).getByText('systemd');
        expect(systemdBadge).toHaveClass('text-slate-300', 'text-xs');
    });

    it('requires explicit confirmation dialog rendered via body portal outside Services root before starting failed service and prevents premature POST in both list and card views', async () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibreweb',
                process: 'calibreweb',
                status: 'stopped',
                version: '',
                uptime: 'stopped',
                managed_by: 'systemd',
                default_port: 8083,
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip install failed: wheels missing',
                },
            },
        };
        mockedApiFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ message: 'ok' }),
        } as Response);

        render(
            <div data-testid="services-root-container">
                <ServicesTab />
            </div>
        );

        const servicesRoot = screen.getByTestId('services-root-container');
        const guardedButtonList = screen.getByRole('button', { name: /Start Service \(Guarded\)/i });
        fireEvent.click(guardedButtonList);

        expect(mockedApiFetch).not.toHaveBeenCalled();

        const guardedDialog = screen.getByRole('dialog', { name: 'Start Calibre-Web (Guarded)' });
        expect(guardedDialog).toBeInTheDocument();
        expect(guardedDialog).toHaveAttribute('aria-modal', 'true');
        expect(servicesRoot.querySelector('[role="dialog"][aria-label="Start Calibre-Web (Guarded)"]')).toBeNull();
        expect(document.body.contains(guardedDialog)).toBe(true);

        expect(within(guardedDialog).getByText('Start Calibre-Web (Guarded)?')).toBeInTheDocument();
        expect(within(guardedDialog).getByText(/previous installation of Calibre-Web failed and state recovery or rollback is unconfirmed/i)).toBeInTheDocument();
        expect(within(guardedDialog).getByText(/Review failure logs before attempting manual operations\. No safe recovery is guaranteed\./i)).toBeInTheDocument();

        const cancelButton = within(guardedDialog).getByRole('button', { name: 'Cancel' });
        const startAnywayButton = within(guardedDialog).getByRole('button', { name: 'Start anyway' });
        expect(cancelButton).toBeInTheDocument();
        expect(startAnywayButton).toBeInTheDocument();
        expect(cancelButton).toHaveClass('min-h-[44px]', 'min-w-[44px]');
        expect(startAnywayButton).toHaveClass('min-h-[44px]', 'min-w-[44px]');

        fireEvent.click(cancelButton);
        expect(screen.queryByRole('dialog', { name: 'Start Calibre-Web (Guarded)' })).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();

        fireEvent.click(screen.getByTitle('Card grid view'));
        const guardedButtonCard = screen.getByRole('button', { name: /Start Service \(Guarded\)/i });
        fireEvent.click(guardedButtonCard);

        expect(mockedApiFetch).not.toHaveBeenCalled();
        const cardGuardedDialog = screen.getByRole('dialog', { name: 'Start Calibre-Web (Guarded)' });
        expect(cardGuardedDialog).toBeInTheDocument();
        expect(servicesRoot.querySelector('[role="dialog"][aria-label="Start Calibre-Web (Guarded)"]')).toBeNull();

        fireEvent.click(within(cardGuardedDialog).getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByRole('dialog', { name: 'Start Calibre-Web (Guarded)' })).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('focuses Cancel by default, traps Tab cycling, restores invoker focus on Escape or Cancel without POST, and executes POST with canonical target on Start anyway', async () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibreweb',
                process: 'calibreweb',
                status: 'stopped',
                version: '',
                uptime: 'stopped',
                managed_by: 'systemd',
                default_port: 8083,
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'pip install failed: wheels missing',
                },
            },
        };
        mockedApiFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ message: 'ok' }),
        } as Response);

        render(<ServicesTab />);

        const guardedButton = screen.getByRole('button', { name: /Start Service \(Guarded\)/i });
        guardedButton.focus();
        expect(document.activeElement).toBe(guardedButton);

        fireEvent.click(guardedButton);

        const guardedDialog = screen.getByRole('dialog', { name: 'Start Calibre-Web (Guarded)' });
        expect(guardedDialog).toBeInTheDocument();

        const cancelButton = within(guardedDialog).getByRole('button', { name: 'Cancel' });
        const startAnywayButton = within(guardedDialog).getByRole('button', { name: 'Start anyway' });

        expect(document.activeElement).toBe(cancelButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
        expect(document.activeElement).toBe(startAnywayButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: false });
        expect(document.activeElement).toBe(cancelButton);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Start Calibre-Web (Guarded)' })).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();
        expect(document.activeElement).toBe(guardedButton);

        fireEvent.click(guardedButton);
        const reopenedDialog = screen.getByRole('dialog', { name: 'Start Calibre-Web (Guarded)' });
        expect(reopenedDialog).toBeInTheDocument();

        const backdropOverlay = reopenedDialog.parentElement as HTMLElement;
        fireEvent.click(backdropOverlay);
        expect(screen.queryByRole('dialog', { name: 'Start Calibre-Web (Guarded)' })).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();
        expect(document.activeElement).toBe(guardedButton);

        fireEvent.click(guardedButton);
        const secondReopenedDialog = screen.getByRole('dialog', { name: 'Start Calibre-Web (Guarded)' });
        expect(secondReopenedDialog).toBeInTheDocument();

        fireEvent.click(within(secondReopenedDialog).getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByRole('dialog', { name: 'Start Calibre-Web (Guarded)' })).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();
        expect(document.activeElement).toBe(guardedButton);

        fireEvent.click(guardedButton);
        const thirdReopenedDialog = screen.getByRole('dialog', { name: 'Start Calibre-Web (Guarded)' });
        expect(thirdReopenedDialog).toBeInTheDocument();

        fireEvent.click(within(thirdReopenedDialog).getByRole('button', { name: 'Start anyway' }));
        expect(screen.queryByRole('dialog', { name: 'Start Calibre-Web (Guarded)' })).not.toBeInTheDocument();

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledTimes(1);
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/services/calibreweb/control',
                expect.objectContaining({
                    method: 'POST',
                    body: JSON.stringify({
                        action: 'start',
                        managed_by: 'systemd',
                        process: 'calibreweb',
                    }),
                })
            );
        });
    });

    it('keeps healthy service start normal without confirmation dialog and preserves stop confirmation unchanged', async () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'stopped',
                version: '5.0.0',
                uptime: '-',
                managed_by: 'systemd',
                default_port: 7878,
            },
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 8989,
            },
        };
        mockedApiFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ message: 'ok' }),
        } as Response);

        render(<ServicesTab />);

        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        const startRadarrButton = within(radarrArticle).getByRole('button', { name: /Start Service/i });
        fireEvent.click(startRadarrButton);

        expect(screen.queryByRole('dialog', { name: /Start.*Guarded/i })).not.toBeInTheDocument();

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/services/radarr/control',
                expect.objectContaining({
                    method: 'POST',
                    body: JSON.stringify({
                        action: 'start',
                        managed_by: 'systemd',
                        process: 'radarr',
                    }),
                })
            );
        });

        const sonarrArticle = screen.getByRole('article', { name: 'Sonarr service' });
        const manageSonarrButton = within(sonarrArticle).getByRole('button', { name: 'Manage Sonarr service actions' });
        fireEvent.click(manageSonarrButton);

        const stopSonarrButton = within(sonarrArticle).getByRole('menuitem', { name: 'Stop Sonarr service' });
        fireEvent.click(stopSonarrButton);

        const stopDialog = screen.getByRole('dialog');
        expect(stopDialog).toBeInTheDocument();
        expect(stopDialog).toHaveTextContent('Stop Sonarr?');
        expect(screen.queryByRole('dialog', { name: /Start.*Guarded/i })).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Confirm Stop' }));

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/services/sonarr/control',
                expect.objectContaining({
                    method: 'POST',
                    body: JSON.stringify({
                        action: 'stop',
                        managed_by: 'systemd',
                        process: 'sonarr',
                    }),
                })
            );
        });
    });

    it('focuses safe Stop cancellation, traps focus, restores Manage focus, and never posts on dismissal', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '1.0.0',
                uptime: '2h',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);
        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        const manageButton = within(radarrArticle).getByRole('button', { name: 'Manage Radarr service actions' });
        manageButton.focus();
        fireEvent.click(manageButton);
        fireEvent.click(within(radarrArticle).getByRole('menuitem', { name: 'Stop Radarr service' }));

        const stopDialog = screen.getByRole('dialog', { name: 'Stop Radarr?' });
        const cancelButton = within(stopDialog).getByRole('button', { name: 'Cancel' });
        const confirmButton = within(stopDialog).getByRole('button', { name: 'Confirm Stop' });
        expect(document.activeElement).toBe(cancelButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
        expect(document.activeElement).toBe(confirmButton);
        fireEvent.keyDown(document, { key: 'Tab' });
        expect(document.activeElement).toBe(cancelButton);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Stop Radarr?' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(manageButton);
        expect(mockedApiFetch).not.toHaveBeenCalled();

        fireEvent.click(manageButton);
        fireEvent.click(within(radarrArticle).getByRole('menuitem', { name: 'Stop Radarr service' }));
        const reopenedDialog = screen.getByRole('dialog', { name: 'Stop Radarr?' });
        fireEvent.click(reopenedDialog.parentElement as HTMLElement);
        expect(screen.queryByRole('dialog', { name: 'Stop Radarr?' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(manageButton);
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('supports 4-action variant with honest flex-wrap inside 280px track without overlapping metadata', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '3.0.10',
                latest_version: '4.0.0',
                update_available: true,
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 8989,
                active_port: 8989,
                update_url: 'https://github.com/Sonarr/Sonarr/releases',
            },
        };

        render(<ServicesTab />);

        const sonarrArticle = screen.getByRole('article', { name: 'Sonarr service' });
        expect(sonarrArticle).toBeInTheDocument();

        const updateButton = within(sonarrArticle).getByRole('button', { name: /^Update$/i });
        const webUiButton = within(sonarrArticle).getByRole('button', { name: /Web UI/i });
        const logsButton = within(sonarrArticle).getByRole('button', { name: /Logs/i });
        const manageButton = within(sonarrArticle).getByRole('button', { name: /Manage/i });

        expect(updateButton).toBeInTheDocument();
        expect(updateButton).toHaveAttribute('title', 'Update Sonarr to v4.0.0');
        expect(webUiButton).toBeInTheDocument();
        expect(logsButton).toBeInTheDocument();
        expect(manageButton).toBeInTheDocument();

        const actionsContainer = updateButton.closest('div[class*="@[960px]:w-[280px]"]');
        expect(actionsContainer).toBeInTheDocument();
        expect(actionsContainer).toHaveClass(
            'sm:flex',
            'sm:flex-wrap',
            'sm:justify-end',
            '@[960px]:w-[280px]',
            '@[1250px]:w-[280px]'
        );

        const uptimeContainer = within(sonarrArticle).getByText('5d').closest('div[class*="@[960px]:w-[65px]"]');
        expect(uptimeContainer).toBeInTheDocument();
        expect(uptimeContainer).toHaveClass('@[960px]:w-[65px]', 'shrink-0');
    });

    it('organizes compact two-line identity, subordinate status manager badge, and consolidated port endpoint', () => {
        mockServicesPayload = {
            'aetherflow-api': {
                id: 'aetherflow-api',
                process: 'aetherflow-api',
                status: 'running',
                version: '4.0.0',
                uptime: '2d',
                managed_by: 'systemd',
                default_port: 13378,
                active_port: 13378,
                public_domain: 'api.seedbox.internal',
            },
        };

        render(<ServicesTab />);

        const apiArticle = screen.getByRole('article', { name: 'aetherflow-api service' });
        expect(apiArticle).toBeInTheDocument();

        const humanNameHeading = within(apiArticle).getByText('AetherFlow API');
        expect(humanNameHeading).toHaveClass('text-sm', 'font-semibold', 'text-slate-100');

        const daemonSlug = within(apiArticle).getByText('aetherflow-api');
        expect(daemonSlug).toHaveClass('text-xs', 'font-mono', 'text-slate-300', 'break-all');

        const identityBlock = humanNameHeading.parentElement;
        expect(identityBlock).toHaveClass('flex', 'flex-col', 'justify-center');
        expect(identityBlock).not.toHaveTextContent('systemd');
        expect(identityBlock).not.toHaveTextContent('api.seedbox.internal');

        const statusColumn = within(apiArticle).getByText('running').closest('div[class*="@[960px]:w-[95px]"]');
        expect(statusColumn).toBeInTheDocument();
        const managerBadge = within(statusColumn as HTMLElement).getByText('systemd');
        expect(managerBadge).toBeInTheDocument();
        expect(managerBadge).toHaveClass('hidden', 'sm:inline-flex', 'text-xs', 'text-slate-300');

        const portColumn = within(apiArticle).getByText(':13378').closest('div[class*="@[960px]:w-[140px]"]');
        expect(portColumn).toBeInTheDocument();
        expect(within(portColumn as HTMLElement).queryByText('api.seedbox.internal')).not.toBeInTheDocument();

        const accessTrigger = within(apiArticle).getByRole('button', { name: /Connection details for aetherflow-api/i });
        fireEvent.click(accessTrigger);
        const endpointText = within(apiArticle).getByText('api.seedbox.internal');
        expect(endpointText).toBeInTheDocument();
        expect(endpointText).toHaveClass('break-all');
        expect(endpointText).not.toHaveClass('truncate');
        expect(within(apiArticle).queryByRole('menuitem', { name: /Public Endpoint/i })).not.toBeInTheDocument();
    });

    it('proves reserved mobile identity area and dedicated Details column without horizontal crowding', () => {
        mockServicesPayload = {
            'Calibre-Web': {
                id: 'calibre-web',
                process: 'calibre-web',
                status: 'running',
                version: '0.6.21',
                uptime: '3d',
                managed_by: 'systemd',
                default_port: 8083,
                active_port: 8083,
            },
        };

        render(<ServicesTab />);

        const calibreArticle = screen.getByRole('article', { name: 'Calibre-Web service' });
        expect(calibreArticle).toBeInTheDocument();

        const detailsToggle = within(calibreArticle).getByRole('button', { name: /Toggle details for Calibre-Web/i });
        expect(detailsToggle).toHaveClass('min-h-[44px]', 'min-w-[44px]', 'sm:hidden');

        const detailsColumn = detailsToggle.parentElement;
        expect(detailsColumn).toHaveClass('col-start-2', 'sm:hidden');

        const friendlyName = within(calibreArticle).getByText('Calibre-Web');
        const identityArea = friendlyName.closest('div.col-start-1');
        expect(identityArea).toBeInTheDocument();

        const statusText = within(calibreArticle).getByText('running');
        const statusArea = statusText.closest('div.col-start-1');
        expect(statusArea).toBeInTheDocument();
        expect(identityArea).not.toBe(statusArea);
        expect(statusArea).not.toContainElement(detailsToggle);
        expect(statusArea).toHaveClass('min-h-[20px]', 'sm:min-h-[40px]');
        expect(statusArea).toHaveClass('pl-[42px]', 'sm:pl-0');
    });

    it('proves endpoint nonduplication in collapsed port track and disclosure visibility in Connection menu', () => {
        mockServicesPayload = {
            'aetherflow-frontend': {
                id: 'aetherflow-frontend',
                process: 'aetherflow-frontend',
                status: 'running',
                version: '4.0.0',
                uptime: '4d',
                managed_by: 'systemd',
                default_port: 4310,
                active_port: 4310,
                public_domain: 'dashboard.seedbox.internal',
                internal_domain: 'dashboard.local',
            },
        };

        render(<ServicesTab />);

        const frontendArticle = screen.getByRole('article', { name: 'aetherflow-frontend service' });
        const portTrack = within(frontendArticle).getByText(':4310').parentElement;
        expect(portTrack).toBeInTheDocument();
        expect(within(frontendArticle).queryByText('dashboard.seedbox.internal')).not.toBeInTheDocument();

        const accessButton = within(frontendArticle).getByRole('button', { name: /Connection details for aetherflow-frontend/i });
        fireEvent.click(accessButton);

        const domainText = within(frontendArticle).getByText('dashboard.seedbox.internal');
        expect(domainText).toBeInTheDocument();
        expect(domainText).toHaveClass('break-all');
        expect(domainText).not.toHaveClass('truncate');

        const internalText = within(frontendArticle).getByText('dashboard.local');
        expect(internalText).toBeInTheDocument();
        expect(internalText).toHaveClass('break-all');
        expect(within(frontendArticle).queryByRole('menuitem', { name: /Public Endpoint/i })).not.toBeInTheDocument();
    });

    it('proves bounded wide tracks and matching header/row grid-cols with wrapped action area', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
            },
        };

        render(<ServicesTab />);

        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        expect(radarrArticle).toHaveClass('@[1250px]:grid-cols-[minmax(280px,360px)_120px_130px_minmax(180px,220px)_90px_minmax(280px,auto)]');
        expect(radarrArticle).toHaveClass('@[960px]:grid-cols-[minmax(180px,1fr)_95px_100px_140px_65px_280px]');

        const headers = screen.getAllByText('Port & Access');
        expect(headers.length).toBeGreaterThanOrEqual(1);
        const headerRow = headers[0].parentElement;
        expect(headerRow).toHaveClass('@[1250px]:grid-cols-[minmax(280px,360px)_120px_130px_minmax(180px,220px)_90px_minmax(280px,auto)]');
        expect(headerRow).toHaveClass('@[960px]:grid-cols-[minmax(180px,1fr)_95px_100px_140px_65px_280px]');

        const actionsHeader = within(headerRow as HTMLElement).getByText('Actions');
        expect(actionsHeader).toHaveClass('@[1250px]:text-left');

        const actionTrack = within(radarrArticle).getByRole('button', { name: /Web UI/i }).parentElement;
        expect(actionTrack).toHaveClass('@[960px]:w-[280px]', '@[1250px]:w-[280px]', '@[1250px]:min-w-[280px]', '@[1250px]:justify-start');
    });

    it('proves unique failed inspect action in Actions track and guarded start downstream in status banner without button duplication', () => {
        mockServicesPayload = {
            BrokenService: {
                id: 'broken-service',
                process: 'broken-service',
                status: 'failed',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'binary missing or corrupted',
                },
            },
        };

        render(<ServicesTab />);

        const brokenArticle = screen.getByRole('article', { name: 'BrokenService service' });
        const inspectButtons = within(brokenArticle).getAllByRole('button', { name: /Review installation failure/i });
        const guardedButtons = within(brokenArticle).getAllByRole('button', { name: /Start Service \(Guarded\)/i });

        expect(inspectButtons).toHaveLength(1);
        expect(guardedButtons).toHaveLength(1);

        const statusBlock = within(brokenArticle).getByRole('status');
        expect(statusBlock).not.toContainElement(inspectButtons[0]);
        expect(statusBlock).toContainElement(guardedButtons[0]);
        expect(statusBlock).toHaveClass('order-last', '@[960px]:order-last', '@[1250px]:order-last');

        expect(Boolean(inspectButtons[0].compareDocumentPosition(statusBlock) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
        expect(Boolean(inspectButtons[0].compareDocumentPosition(guardedButtons[0]) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);

        expect(within(brokenArticle).queryByText(/Recovery actions below/i)).not.toBeInTheDocument();
        expect(statusBlock).toHaveTextContent('Confirmation required; starting does not repair the failed installation.');
    });

    it('verifies stable WebUI / Logs / Manage slots in 280px action area and unoccupied slot when WebUI absent', () => {
        mockServicesPayload = {
            Radarr: {
                id: 'radarr',
                process: 'radarr',
                status: 'running',
                version: '5.0.0',
                uptime: '2d',
                managed_by: 'systemd',
                default_port: 7878,
                active_port: 7878,
                update_available: true,
                update_version: '5.1.0',
            },
            HeadlessApp: {
                id: 'headlessapp',
                process: 'headlessapp',
                status: 'running',
                version: '1.0.0',
                uptime: '1d',
                managed_by: 'systemd',
            },
        };

        render(<ServicesTab />);

        const radarrArticle = screen.getByRole('article', { name: 'Radarr service' });
        const radarrActions = within(radarrArticle).getByRole('button', { name: 'Logs' }).closest('div[class*="@[960px]:w-[280px]"]');
        expect(radarrActions).toBeInTheDocument();
        expect(radarrActions).toHaveClass('sm:justify-end', '@[960px]:justify-end', '@[960px]:w-[280px]');

        const updateButton = within(radarrArticle).getByRole('button', { name: 'Update' });
        expect(updateButton).toHaveClass('col-span-3', 'sm:w-full');

        const radarrWebUi = within(radarrArticle).getByRole('button', { name: 'Web UI' });
        expect(radarrWebUi).toHaveClass('sm:w-[88px]');
        const radarrLogs = within(radarrArticle).getByRole('button', { name: 'Logs' });
        expect(radarrLogs).toHaveClass('sm:w-[74px]', 'bg-slate-800/90', 'text-slate-200', 'border-slate-700/80');
        const radarrManage = within(radarrArticle).getByRole('button', { name: 'Manage Radarr service actions' });
        expect(radarrManage).toHaveClass('bg-slate-800/90', 'text-slate-200', 'border-slate-700/80');
        expect(radarrManage.parentElement).toHaveClass('sm:w-[94px]');

        const headlessArticle = screen.getByRole('article', { name: 'HeadlessApp service' });
        expect(within(headlessArticle).queryByRole('button', { name: 'Web UI' })).not.toBeInTheDocument();

        const headlessActions = within(headlessArticle).getByRole('button', { name: 'Logs' }).closest('div[class*="@[960px]:w-[280px]"]');
        expect(headlessActions).toBeInTheDocument();

        const unoccupiedPlaceholder = headlessActions?.querySelector('div[aria-hidden="true"]');
        expect(unoccupiedPlaceholder).toBeInTheDocument();
        expect(unoccupiedPlaceholder).toHaveClass('hidden', 'sm:block', 'sm:w-[88px]', 'shrink-0');

        const headlessLogs = within(headlessArticle).getByRole('button', { name: 'Logs' });
        expect(headlessLogs).toHaveClass('sm:w-[74px]', 'bg-slate-800/90', 'text-slate-200', 'border-slate-700/80');
        const headlessManage = within(headlessArticle).getByRole('button', { name: 'Manage HeadlessApp service actions' });
        expect(headlessManage).toHaveClass('bg-slate-800/90', 'text-slate-200', 'border-slate-700/80');
        expect(headlessManage.parentElement).toHaveClass('sm:w-[94px]');
    });

    it('verifies port and connection sublayout with min-w-[6ch], 12px gap-3, and compact 140px fit', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                uptime: '3d',
                managed_by: 'systemd',
                default_port: 8989,
                active_port: 8990,
            },
        };

        render(<ServicesTab />);

        const sonarrArticle = screen.getByRole('article', { name: 'Sonarr service' });
        const portNumeral = within(sonarrArticle).getByText(':8990');
        expect(portNumeral).toHaveClass('min-w-[6ch]', 'inline-block');

        const defaultPortPill = within(sonarrArticle).getByText('def :8989');
        expect(defaultPortPill).toHaveClass('hidden', '@[1250px]:inline-block');

        const portContainer = portNumeral.parentElement;
        expect(portContainer).toHaveClass('gap-3', 'flex', 'items-center', 'min-h-[40px]', 'flex-wrap', '@[1250px]:flex-nowrap');

        const portColumn = portContainer?.parentElement;
        expect(portColumn).toHaveClass('@[960px]:w-[140px]', '@[1250px]:w-[180px]');

        const accessButton = within(sonarrArticle).getByRole('button', { name: 'Connection details for Sonarr' });
        expect(accessButton).toBeVisible();
        expect(within(accessButton).getByText('Connection')).toBeInTheDocument();
    });

    it('verifies explicit failure flow with review installation failure, unchanged backend report, and downstream guarded start', () => {
        mockServicesPayload = {
            FailingApp: {
                id: 'failingapp',
                process: 'failingapp',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'Compilation failed during package setup',
                },
            },
        };

        render(<ServicesTab />);

        const failingArticle = screen.getByRole('article', { name: 'FailingApp service' });
        const reviewFailureButton = within(failingArticle).getByRole('button', { name: 'Review installation failure' });
        expect(reviewFailureButton).toBeVisible();
        expect(reviewFailureButton).toHaveClass('min-h-[44px]', 'sm:min-h-[40px]');

        fireEvent.click(reviewFailureButton);
        expect(mockLogsModalSpy).toHaveBeenCalledWith(
            expect.objectContaining({
                serviceName: 'failingapp',
            })
        );

        const statusRegion = within(failingArticle).getByRole('status');
        expect(within(statusRegion).getByText('Install failed — rollback/recovery unconfirmed')).toBeVisible();
        expect(within(statusRegion).getByText('Compilation failed during package setup')).toBeVisible();
        expect(within(statusRegion).queryByText(/Next step: review failure logs/i)).not.toBeInTheDocument();
        expect(statusRegion).toHaveTextContent('Confirmation required; starting does not repair the failed installation.');

        const guardedStart = within(statusRegion).getByRole('button', { name: 'Start Service (Guarded)' });
        expect(guardedStart).toBeVisible();
        expect(within(failingArticle).getAllByRole('button', { name: /Review installation failure/i })).toHaveLength(1);
    });

    it('discloses nonzero attention and updates count in readable 12px text in mobile collapsed filter and keeps 44px Change target', () => {
        mockServicesPayload = {
            AppWithUpdate: {
                id: 'appwithupdate',
                process: 'appwithupdate',
                status: 'running',
                version: '1.0.0',
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 3000,
                update_available: true,
                update_version: '2.0.0',
            },
            AppWithAttention: {
                id: 'appwithattention',
                process: 'appwithattention',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'install step failed',
                },
            },
        };

        const { rerender } = render(<ServicesTab />);

        const mobileFilterButton = screen.getByRole('button', {
            name: /Status filter: All \(2\), 1 need attention, 1 update available\. Tap to change filter\./i,
        });
        expect(mobileFilterButton).toBeInTheDocument();
        expect(mobileFilterButton).toHaveClass('min-h-[44px]', 'flex-wrap', 'gap-2');

        const attentionText = within(mobileFilterButton).getByText(/1 attention/i);
        expect(attentionText).toHaveClass('text-xs', 'text-rose-300');

        const singleUpdateText = within(mobileFilterButton).getByText(/1 update$/i);
        expect(singleUpdateText).toHaveClass('text-xs', 'text-amber-300');

        const changeTarget = within(mobileFilterButton).getByText('Change').parentElement;
        expect(changeTarget).toHaveClass('min-h-[44px]', 'min-w-[44px]');

        mockServicesPayload = {
            ...mockServicesPayload,
            SecondAppWithUpdate: {
                id: 'secondapp',
                process: 'secondapp',
                status: 'running',
                version: '1.0.0',
                uptime: '1d',
                managed_by: 'systemd',
                default_port: 3001,
                update_available: true,
                update_version: '2.1.0',
            },
        };
        rerender(<ServicesTab />);

        const multiUpdateFilterButton = screen.getByRole('button', {
            name: /Status filter: All \(3\), 1 need attention, 2 updates available\. Tap to change filter\./i,
        });
        expect(multiUpdateFilterButton).toBeInTheDocument();
        expect(within(multiUpdateFilterButton).getByText(/2 updates/i)).toBeInTheDocument();
    });

    it('verifies Candidate P failure footer action and caveat grouping with readable amber text and adjacent guarded start', () => {
        mockServicesPayload = {
            FailingApp: {
                id: 'failingapp',
                process: 'failingapp',
                status: 'stopped',
                uptime: 'stopped',
                managed_by: 'systemd',
                last_job: {
                    action: 'install',
                    status: 'failed',
                    message: 'Compilation failed during package setup',
                },
            },
        };

        render(<ServicesTab />);

        const failingArticle = screen.getByRole('article', { name: 'FailingApp service' });
        const statusRegion = within(failingArticle).getByRole('status');
        const caveatElement = within(statusRegion).getByText('Confirmation required; starting does not repair the failed installation.');

        expect(caveatElement.parentElement).toHaveClass('text-amber-300/90', 'text-xs', 'sm:text-[13px]');
        const actionCaveatGroup = caveatElement.closest('div[class*="justify-end"]');
        expect(actionCaveatGroup).toBeInTheDocument();
        expect(actionCaveatGroup).toHaveClass('flex-col', 'sm:flex-row', 'justify-end', 'border-t');

        const guardedButton = within(actionCaveatGroup as HTMLElement).getByRole('button', { name: 'Start Service (Guarded)' });
        expect(guardedButton).toBeInTheDocument();
        expect(guardedButton).toHaveClass('text-slate-200', 'min-h-[44px]');
    });

    it('verifies Candidate P strengthened operational text hierarchy for status, version, and uptime at 13px slate300', () => {
        mockServicesPayload = {
            OperationalApp: {
                id: 'operationalapp',
                process: 'operationalapp',
                status: 'running',
                version: '3.4.1',
                uptime: '5d 12h',
                managed_by: 'systemd',
                default_port: 8080,
                active_port: 8080,
            },
        };

        render(<ServicesTab />);

        const serviceArticle = screen.getByRole('article', { name: 'OperationalApp service' });
        const statusText = within(serviceArticle).getByText('running');
        expect(statusText).toHaveClass('text-slate-300', 'text-xs', 'sm:text-[13px]');

        const versionText = within(serviceArticle).getByText('v3.4.1');
        expect(versionText).toHaveClass('text-slate-300', 'text-xs', 'sm:text-[13px]');

        const uptimeText = within(serviceArticle).getByText('5d 12h');
        expect(uptimeText).toHaveClass('text-slate-300', 'text-xs', 'sm:text-[13px]');
    });
});
