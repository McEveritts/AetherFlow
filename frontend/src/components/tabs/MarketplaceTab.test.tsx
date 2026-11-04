import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import MarketplaceTab from './MarketplaceTab';

jest.mock('@/hooks/useMarketplace', () => ({
    useMarketplace: () => ({
        apps: [
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
        pendingJobs: new Map(),
        markPending: jest.fn(),
        clearPending: jest.fn(),
    }),
    useGithubDownloads: () => 5000,
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: jest.fn(),
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
