import React from 'react';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import ServicesTab from '@/components/tabs/ServicesTab';
import { apiFetch } from '@/lib/fetcher';

let mockUserRole = 'admin';
const mockAddToast = jest.fn();
const mockSetActiveTab = jest.fn();
const mockMutateServices = jest.fn();
const mockGlobalMutate = jest.fn();
const mockLogsModalSpy = jest.fn();
let mockServicesPayload: Record<string, unknown> = {};
let mockServicesError: Error | undefined;
let mockServicesIsValidating = false;
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
                isLoading: false,
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
        const versionBox = screen.getByText('Version').parentElement?.parentElement;
        expect(versionBox).toBeInTheDocument();
        expect(versionBox).toHaveTextContent('-');
        expect(versionBox).not.toHaveTextContent(/latest/i);
        mockServicesPayload = {
            Sonarr: { ...mockServicesPayload.Sonarr as Record<string, unknown>, version: '2.4.1', installed_version: '2.4.1' },
        };
        rerender(<ServicesTab />);
        expect(versionBox).toHaveTextContent('v2.4.1');
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
        const restrictedButtons = screen.getAllByTitle(new RegExp(`${label} binds strictly to 127\\.0\\.0\\.1`, 'i'));
        const ingressButton = screen.getByTitle('Ingress & Deployment');

        expect(webUiButton).toBeDisabled();
        expect(restrictedButtons).toHaveLength(2);
        for (const button of restrictedButtons) {
            expect(button).toBeDisabled();
        }
        expect(ingressButton).not.toBeDisabled();

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

        fireEvent.click(screen.getByTitle('Check for updates'));

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

        fireEvent.click(screen.getByTitle('Check for updates'));

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
        const sharedStopButtons = screen.getAllByTitle(/shared Apache web server/i).filter((element) => element.tagName === 'BUTTON');
        expect(sharedStopButtons.length).toBeGreaterThanOrEqual(2);
        for (const btn of sharedStopButtons) {
            expect(btn).toBeDisabled();
        }

        const restartButton = screen.getByTitle('Restart service');
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
        await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
        mockServicesPayload = { Fixture: service({ job_id: 'accepted-A', job_status: 'updating' }) };
        view.rerender(<ServicesTab />);
        for (let poll = 0; poll < 6; poll++) {
            await act(async () => { await jest.advanceTimersByTimeAsync(60000); });
            if (status === 'deduplicated') {
                mockServicesIsValidating = true; view.rerender(<ServicesTab />);
                mockServicesIsValidating = false; view.rerender(<ServicesTab />);
            } else {
                act(() => mockServicesOptions.onSuccess(mockServicesPayload));
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
