import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import MarketplaceTab from './MarketplaceTab';
import { App, PendingAction } from '@/hooks/useMarketplace';
const mockAddToast = jest.fn();
let mockMarketplaceApps: App[] | undefined;
let mockPendingJobs = new Map<string, PendingAction>();
let mockUnconfirmedJobs = new Map<string, string>();

jest.mock('@/hooks/useMarketplace', () => ({
    ...jest.requireActual('@/hooks/useMarketplace'),
    useMarketplace: () => ({
        apps: mockMarketplaceApps || [
            {
                id: 'jellyfin',
                name: 'Jellyfin',
                desc: 'Media server',
                category: 'Media',
                status: 'installed',
                progress: 100,
            },
        ],
        isLoading: false,
        isError: false,
        mutate: jest.fn(),
        pendingJobs: mockPendingJobs,
        unconfirmedJobs: mockUnconfirmedJobs,
        markPending: (id: string, action: PendingAction) => { mockPendingJobs.set(id, action); },
        clearPending: (id: string) => { mockPendingJobs.delete(id); },
        registerJob: jest.fn((_id: string, receipt: { job_id?: string; started_at?: string }) => receipt.job_id || receipt.started_at),
    }),
    useGithubDownloads: () => 5000,
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/lib/svgl', () => ({
    getSVGLCatalog: jest.fn().mockResolvedValue([]),
    matchSVGLLogo: jest.fn().mockReturnValue(null),
}));

jest.mock('@/components/ingress/ExternalAccessCard', () => ({
    ExternalAccessCard: () => <div data-testid="external-access-card" />,
}));

jest.mock('@/components/deploy/DeploymentStatus', () => ({
    DeploymentStatus: () => <div data-testid="deployment-status" />,
}));

const mockApiFetch = jest.fn();
jest.mock('@/lib/fetcher', () => ({
    apiFetch: (...args: unknown[]) => mockApiFetch(...args),
}));

describe('MarketplaceTab Sandboxed Plugin Runtime Integration', () => {
    beforeEach(() => {
        mockApiFetch.mockReset();
        mockAddToast.mockReset();
        mockMarketplaceApps = undefined;
        mockPendingJobs = new Map();
    });

    it('discovers plugins, renders granted scopes, and mounts UI in an isolated sandbox="allow-scripts" iframe without allow-same-origin', async () => {
        const demoPlugin = {
            id: 'telemetry-inspector',
            name: 'Telemetry Inspector',
            version: '0.1.0',
            sdk: 'rust',
            contract_version: 'v1',
            runtime_status: 'managed',
            description: 'Inspects scoped system telemetry safely.',
            author: 'AetherFlow',
            permissions: ['system:metrics:read'],
            granted_scopes: [
                { method: 'GET', route: '/api/v1/auth/system/metrics' },
            ],
            enabled: true,
            status: 'running',
            healthy: true,
            allocated_port: 21005,
            health_path: '/healthz',
            ui_url: '/api/v1/auth/plugins/telemetry-inspector/ui',
            proxy_base_url: '/api/v1/auth/plugins/telemetry-inspector/proxy',
            slot: 'marketplace',
            capabilities: ['sandbox-iframe', 'postmessage-bridge', 'scoped-proxy'],
        };

        mockApiFetch.mockImplementation(async (url: string) => {
            if (url === '/api/v1/auth/plugins') {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        plugins: [demoPlugin],
                        rejected: [{ id: 'bad-symlink', error: 'Plugin directory cannot be a symbolic link' }],
                    }),
                };
            }
            return {
                ok: true,
                status: 200,
                json: async () => ({}),
            };
        });

        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByTestId('plugin-card-telemetry-inspector')).toBeInTheDocument();
        });

        expect(screen.getByText('Telemetry Inspector')).toBeInTheDocument();
        expect(screen.getByText('GET /api/v1/auth/system/metrics')).toBeInTheDocument();
        expect(screen.getByTestId('rejected-plugins-banner')).toHaveTextContent('bad-symlink');

        // Open sandboxed plugin UI
        fireEvent.click(screen.getByTestId('open-plugin-ui-telemetry-inspector'));

        const iframe = await screen.findByTestId('plugin-sandbox-iframe');
        expect(iframe).toBeInTheDocument();
        expect(iframe).toHaveAttribute('src', '/api/v1/auth/plugins/telemetry-inspector/ui');
        expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');
        expect(iframe.getAttribute('sandbox')).not.toContain('allow-same-origin');
    });

    it('enables a stopped plugin via control endpoint, mounts sandboxed UI, and disables it cleanly', async () => {
        const stoppedPlugin = {
            id: 'telemetry-inspector',
            name: 'Telemetry Inspector',
            version: '1.0.0',
            sdk: 'managed-sample',
            contract_version: 'v1',
            runtime_status: 'managed',
            description: 'Managed loopback telemetry companion.',
            author: 'AetherFlow',
            permissions: ['system:metrics:read'],
            granted_scopes: [
                { method: 'GET', route: '/api/v1/auth/system/metrics' },
            ],
            enabled: false,
            status: 'stopped',
            healthy: false,
            allocated_port: 0,
            health_path: '/healthz',
            ui_url: '/api/v1/auth/plugins/telemetry-inspector/ui',
            proxy_base_url: '/api/v1/auth/plugins/telemetry-inspector/proxy',
            slot: 'marketplace',
            capabilities: ['sandbox-iframe', 'postmessage-bridge', 'scoped-proxy'],
        };

        const runningPlugin = {
            ...stoppedPlugin,
            enabled: true,
            status: 'running',
            healthy: true,
            allocated_port: 21007,
        };

        mockApiFetch.mockImplementation(async (url: string, init?: { body?: string }) => {
            if (url === '/api/v1/auth/plugins') {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        plugins: [stoppedPlugin],
                        rejected: [],
                    }),
                };
            }
            if (url === '/api/v1/admin/plugins/telemetry-inspector/control') {
                const parsed = init?.body ? JSON.parse(init.body) : {};
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        message: `Plugin action ${parsed.action} completed`,
                        plugin: parsed.action === 'start' ? runningPlugin : stoppedPlugin,
                    }),
                };
            }
            return {
                ok: true,
                status: 200,
                json: async () => ({}),
            };
        });

        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByTestId('plugin-card-telemetry-inspector')).toBeInTheDocument();
        });

        expect(screen.queryByTestId('open-plugin-ui-telemetry-inspector')).not.toBeInTheDocument();
        fireEvent.click(screen.getByTestId('toggle-plugin-telemetry-inspector'));

        await waitFor(() => {
            expect(screen.getByTestId('open-plugin-ui-telemetry-inspector')).toBeInTheDocument();
        });
        expect(screen.getByText('Healthy')).toBeInTheDocument();
        expect(screen.getByText('127.0.0.1:21007')).toBeInTheDocument();

        fireEvent.click(screen.getByTestId('open-plugin-ui-telemetry-inspector'));
        expect(await screen.findByTestId('plugin-sandbox-iframe')).toBeInTheDocument();

        fireEvent.click(screen.getByTestId('toggle-plugin-telemetry-inspector'));
        await waitFor(() => {
            expect(screen.queryByTestId('plugin-sandbox-iframe')).not.toBeInTheDocument();
        });
        expect(screen.getByText('Stopped')).toBeInTheDocument();
    });
});

describe('Marketplace lifecycle workflows', () => {
    const app = (extra: Partial<App> = {}): App => ({ id: 'fixture', name: 'Fixture', desc: 'Application', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: true, ...extra });
    beforeEach(() => {
        mockPendingJobs = new Map(); mockUnconfirmedJobs = new Map(); mockMarketplaceApps = [app()]; mockAddToast.mockReset();
        mockApiFetch.mockReset();
        mockApiFetch.mockImplementation(async (url: string) => ({ ok: true, json: async () => url === '/api/v1/auth/plugins' ? { plugins: [] } : { job_id: 'accepted', started_at: 'now' } }));
    });

    it('does not call a superseding client job success for an expired local receipt', async () => {
        const view = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));
        mockMarketplaceApps = [app({ last_job: { job_id: 'other-client-B', action: 'update', status: 'completed', started_at: 'later', finished_at: 'later' } })];
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        mockPendingJobs = new Map();
        mockUnconfirmedJobs = new Map([['fixture', 'accepted']]);
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('receipt may have been superseded'), 'error');
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        expect(screen.getByRole('button', { name: 'Update' })).not.toBeDisabled();
        const count = mockAddToast.mock.calls.length;
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.length).toBe(count);
    });

    it.each(['completed', 'failed', 'interrupted', 'unknown'])('never attributes a stale snapshot to a new update (%s)', async status => {
        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/update', { method: 'POST' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));
        mockMarketplaceApps = [app({ last_job: { job_id: 'older', action: 'update', status: 'completed', started_at: 'old', finished_at: 'old' } })];
        rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        mockMarketplaceApps = [app({ last_job: { job_id: 'accepted', action: 'update', status, started_at: 'now', finished_at: 'later' } })];
        rerender(<MarketplaceTab />);
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining(status === 'completed' ? 'successfully updated' : status === 'failed' ? 'failed' : 'could not be confirmed'), status === 'completed' ? 'success' : 'error');
        expect(mockAddToast.mock.calls.some(call => String(call[0]).includes('previously installed version was kept'))).toBe(false);
        const count = mockAddToast.mock.calls.length;
        rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.length).toBe(count);
    });

    it('requires a deliberate purge confirmation and retains edits through refresh', async () => {
        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('button', { name: 'Permanently purge' })).toBeDisabled();
        fireEvent.change(screen.getByLabelText('Purge confirmation'), { target: { value: 'fixture' } });
        mockMarketplaceApps = [app({ installed_version: '2.0' })];
        rerender(<MarketplaceTab />);
        expect(screen.getByLabelText('Purge confirmation')).toHaveValue('fixture');
        fireEvent.click(screen.getByRole('button', { name: 'Permanently purge' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/uninstall?purge=true', { method: 'POST' }));
    });

    it('defaults to retained-data uninstall and offers an in-place reinstall', async () => {
        const view = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall and keep data' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/uninstall', { method: 'POST' }));
        view.unmount(); mockPendingJobs = new Map();
        render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Reinstall' }));
        fireEvent.click(screen.getByRole('button', { name: 'Reinstall and keep data' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/install', { method: 'POST' }));
    });
});
